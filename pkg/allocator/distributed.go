package allocator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// DistributedAllocator wraps IPAllocator with distributed state backing.
// Coordinates with other nodes via the Store interface (CLSet or replica).
type DistributedAllocator struct {
	mu sync.RWMutex

	// Pool configuration
	poolID string

	// Allocators - only one is used based on mode
	allocator      *IPAllocator          // Used for session mode (no expiry)
	epochAllocator *EpochBitmapAllocator // Used for lease mode (epoch-based expiry)

	// Distributed state
	store Store

	// Pool mode determines allocation behavior
	mode PoolMode

	// Epoch period for lease mode
	epochPeriod time.Duration
}

// DistributedStats holds statistics for the distributed allocator.
type DistributedStats struct {
	Allocated   int
	Total       int
	Utilization float64
}

// Store is the interface for distributed state (matches nexus.Store).
type Store interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, value []byte) error
	Delete(ctx context.Context, key string) error
	Query(ctx context.Context, prefix string) ([]KeyValue, error)
	Watch(prefix string, callback func(key string, value []byte, deleted bool))
}

// KeyValue represents a key-value pair.
type KeyValue struct {
	Key   string
	Value []byte
}

// PoolMode determines allocation lifecycle behavior.
type PoolMode string

const (
	// PoolModeSession allocates at RADIUS time, no expiry.
	// - Allocation: triggered by RADIUS Access-Accept
	// - Expiry: none (session-bound, released on disconnect)
	// - Renewals: DHCP renewals are read-only (return cached IP)
	// - Store requirement: "read" mode sufficient (renewals work during partition)
	// Used for: OLT-BNG with RADIUS authentication.
	PoolModeSession PoolMode = "session"

	// PoolModeLease allocates at DHCP time with epoch-based expiry.
	// - Allocation: triggered by DHCP DISCOVER
	// - Expiry: epoch-based (reclaimed when epoch < current - grace period)
	// - Renewals: update epoch to extend lease
	// - Store requirement: "write" mode REQUIRED (must allocate during partition)
	// Used for: WiFi gateways, DHCP-only deployments.
	PoolModeLease PoolMode = "lease"
)

/*
Mode/Capability Matrix:

┌─────────────┬──────────────┬───────────────┬─────────────────────────┐
│ Pool Mode   │ Store Mode   │ New Allocs    │ Renewals During Partition│
├─────────────┼──────────────┼───────────────┼─────────────────────────┤
│ session     │ read         │ Need RADIUS   │ ✅ Work (read-only)      │
│ session     │ write        │ ✅ Local      │ ✅ Work (read-only)      │
│ lease       │ read         │ ❌ Fail       │ ⚠️  Read works, no renew │
│ lease       │ write        │ ✅ Local      │ ✅ Full functionality    │
└─────────────┴──────────────┴───────────────┴─────────────────────────┘

Recommendations:
- OLT-BNG (session mode): "read" is sufficient, "write" for extra resilience
- WiFi Gateway (lease mode): "write" is REQUIRED
*/

// DistributedAllocation represents a stored allocation record for distributed state.
// This extends the base DistributedAllocation with epoch tracking for lease mode.
type DistributedAllocation struct {
	PoolID       string    `json:"pool_id"`
	SubscriberID string    `json:"subscriber_id"`
	Prefix       string    `json:"prefix"` // CIDR notation
	Epoch        uint64    `json:"epoch"`  // For lease mode
	AllocatedAt  time.Time `json:"allocated_at"`
	MAC          string    `json:"mac,omitempty"` // For DHCP correlation
}

// DistributedConfig configures a distributed allocator.
type DistributedConfig struct {
	PoolID      string
	BaseNetwork string
	PrefixLen   int
	Mode        PoolMode
	EpochPeriod time.Duration // For lease mode (e.g., 1 hour)
}

// NewDistributedAllocator creates a new distributed allocator.
func NewDistributedAllocator(cfg DistributedConfig, store Store) (*DistributedAllocator, error) {
	da := &DistributedAllocator{
		poolID:      cfg.PoolID,
		store:       store,
		mode:        cfg.Mode,
		epochPeriod: cfg.EpochPeriod,
	}

	// Set default epoch period
	if da.epochPeriod == 0 {
		da.epochPeriod = 1 * time.Hour
	}

	// Create appropriate allocator based on mode
	switch cfg.Mode {
	case PoolModeLease:
		// Use epoch bitmap allocator for lease mode (O(1) epoch advancement)
		epochCfg := EpochBitmapConfig{
			BaseNetwork:  cfg.BaseNetwork,
			PrefixLength: cfg.PrefixLen,
			GracePeriod:  1, // Default: 1 epoch grace period
		}
		epochAlloc, err := NewEpochBitmapAllocator(epochCfg)
		if err != nil {
			return nil, fmt.Errorf("create epoch allocator: %w", err)
		}
		da.epochAllocator = epochAlloc

	default:
		// Use standard IP allocator for session mode (no expiry)
		allocator, err := NewIPAllocator(cfg.BaseNetwork, cfg.PrefixLen)
		if err != nil {
			return nil, fmt.Errorf("create IP allocator: %w", err)
		}
		da.allocator = allocator
	}

	return da, nil
}

// Start initializes the allocator by loading state and setting up watches.
func (da *DistributedAllocator) Start(ctx context.Context) error {
	// Load existing allocations from store
	if err := da.loadAllocations(ctx); err != nil {
		return fmt.Errorf("load allocations: %w", err)
	}

	// Watch for remote changes
	da.store.Watch(da.keyPrefix(), da.handleRemoteChange)

	// Start epoch ticker for lease mode
	if da.mode == PoolModeLease {
		go da.epochLoop(ctx)
	}

	return nil
}

// Allocate assigns a prefix to a subscriber.
func (da *DistributedAllocator) Allocate(ctx context.Context, subscriberID string) (*net.IPNet, error) {
	da.mu.Lock()
	defer da.mu.Unlock()

	var prefix *net.IPNet
	var epoch uint64

	// Use appropriate allocator based on mode
	if da.mode == PoolModeLease {
		// Lease mode: use epoch bitmap allocator
		ip, err := da.epochAllocator.Allocate(ctx, subscriberID)
		if err != nil {
			return nil, err
		}
		// Convert IP to /32 prefix
		prefix = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		epoch = da.epochAllocator.GetCurrentEpoch()
	} else {
		// Session mode: use standard IP allocator
		var err error
		prefix, err = da.allocator.Allocate(subscriberID)
		if err != nil {
			return nil, err
		}
		epoch = 0 // No epoch for session mode
	}

	// Persist to distributed store
	alloc := &DistributedAllocation{
		PoolID:       da.poolID,
		SubscriberID: subscriberID,
		Prefix:       prefix.String(),
		Epoch:        epoch,
		AllocatedAt:  time.Now().UTC(),
	}

	if err := da.saveAllocation(ctx, alloc); err != nil {
		// Rollback local allocation
		if da.mode == PoolModeLease {
			da.epochAllocator.Release(ctx, subscriberID)
		} else {
			da.allocator.Release(subscriberID)
		}
		return nil, fmt.Errorf("save allocation: %w", err)
	}

	return prefix, nil
}

// AllocateWithMAC assigns a prefix and associates a MAC (for DHCP).
func (da *DistributedAllocator) AllocateWithMAC(ctx context.Context, subscriberID string, mac net.HardwareAddr) (*net.IPNet, error) {
	da.mu.Lock()
	defer da.mu.Unlock()

	var prefix *net.IPNet
	var epoch uint64

	// Use appropriate allocator based on mode
	if da.mode == PoolModeLease {
		ip, err := da.epochAllocator.Allocate(ctx, subscriberID)
		if err != nil {
			return nil, err
		}
		prefix = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		epoch = da.epochAllocator.GetCurrentEpoch()
	} else {
		var err error
		prefix, err = da.allocator.Allocate(subscriberID)
		if err != nil {
			return nil, err
		}
		epoch = 0
	}

	alloc := &DistributedAllocation{
		PoolID:       da.poolID,
		SubscriberID: subscriberID,
		Prefix:       prefix.String(),
		Epoch:        epoch,
		AllocatedAt:  time.Now().UTC(),
		MAC:          mac.String(),
	}

	if err := da.saveAllocation(ctx, alloc); err != nil {
		if da.mode == PoolModeLease {
			da.epochAllocator.Release(ctx, subscriberID)
		} else {
			da.allocator.Release(subscriberID)
		}
		return nil, fmt.Errorf("save allocation: %w", err)
	}

	return prefix, nil
}

// Renew updates the epoch for an existing allocation (lease mode).
func (da *DistributedAllocator) Renew(ctx context.Context, subscriberID string) error {
	if da.mode != PoolModeLease {
		return nil // No-op for session mode
	}

	da.mu.Lock()
	defer da.mu.Unlock()

	// Renew in epoch allocator (updates generation to current epoch)
	if err := da.epochAllocator.Renew(ctx, subscriberID); err != nil {
		return err
	}

	// Update distributed store
	alloc, err := da.getAllocation(ctx, subscriberID)
	if err != nil {
		return err
	}

	alloc.Epoch = da.epochAllocator.GetCurrentEpoch()
	return da.saveAllocation(ctx, alloc)
}

// Release frees a previously allocated prefix.
func (da *DistributedAllocator) Release(ctx context.Context, subscriberID string) error {
	da.mu.Lock()
	defer da.mu.Unlock()

	// Release from appropriate allocator
	if da.mode == PoolModeLease {
		if err := da.epochAllocator.Release(ctx, subscriberID); err != nil {
			return err
		}
	} else {
		if err := da.allocator.Release(subscriberID); err != nil {
			return err
		}
	}

	return da.deleteAllocation(ctx, subscriberID)
}

// Get returns the allocation for a subscriber.
func (da *DistributedAllocator) Get(subscriberID string) (*net.IPNet, bool) {
	da.mu.RLock()
	defer da.mu.RUnlock()

	if da.mode == PoolModeLease {
		ip := da.epochAllocator.Lookup(subscriberID)
		if ip == nil {
			return nil, false
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, true
	}

	prefix := da.allocator.Lookup(subscriberID)
	return prefix, prefix != nil
}

// GetByPrefix returns the subscriber for a given prefix.
func (da *DistributedAllocator) GetByPrefix(prefix *net.IPNet) (string, bool) {
	da.mu.RLock()
	defer da.mu.RUnlock()

	if da.mode == PoolModeLease {
		subID := da.epochAllocator.LookupByIP(prefix.IP)
		return subID, subID != ""
	}

	subID := da.allocator.LookupByPrefix(prefix)
	return subID, subID != ""
}

// Stats returns allocator statistics.
func (da *DistributedAllocator) Stats() DistributedStats {
	da.mu.RLock()
	defer da.mu.RUnlock()

	var allocated, total uint64
	var utilization float64

	if da.mode == PoolModeLease {
		allocated, total, utilization = da.epochAllocator.Stats()
	} else {
		allocated, total, utilization = da.allocator.Stats()
	}

	return DistributedStats{
		Allocated:   int(allocated),
		Total:       int(total),
		Utilization: utilization,
	}
}

// --- Epoch management (lease mode) ---

// epochLoop advances the epoch periodically for lease mode.
// With EpochBitmapAllocator, this is O(1) - just increment a counter.
// Expired allocations are cleaned up lazily during allocation/lookup.
func (da *DistributedAllocator) epochLoop(ctx context.Context) {
	ticker := time.NewTicker(da.epochPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			da.mu.Lock()
			// O(1) epoch advancement - no bitmap scanning!
			newEpoch := da.epochAllocator.AdvanceEpoch()
			da.mu.Unlock()

			// Sync expired allocations from distributed store
			// This is optional but keeps the store clean
			da.cleanupExpiredFromStore(ctx, newEpoch)
		}
	}
}

// cleanupExpiredFromStore removes expired allocations from the distributed store.
// This is a background cleanup task - the epoch allocator handles local expiration lazily.
func (da *DistributedAllocator) cleanupExpiredFromStore(ctx context.Context, currentEpoch uint64) {
	if currentEpoch < 2 {
		return
	}

	threshold := currentEpoch - 2 // Match epoch allocator's grace period logic

	results, err := da.store.Query(ctx, da.keyPrefix())
	if err != nil {
		return
	}

	for _, kv := range results {
		var alloc DistributedAllocation
		if err := json.Unmarshal(kv.Value, &alloc); err != nil {
			continue
		}

		if alloc.Epoch < threshold {
			// Remove from store (local allocator already handles this lazily)
			da.store.Delete(ctx, da.allocationKey(alloc.SubscriberID))
		}
	}
}

// GetCurrentEpoch returns the current epoch (for lease mode).
func (da *DistributedAllocator) GetCurrentEpoch() uint64 {
	da.mu.RLock()
	defer da.mu.RUnlock()

	if da.mode == PoolModeLease && da.epochAllocator != nil {
		return da.epochAllocator.GetCurrentEpoch()
	}
	return 0
}

// AdvanceEpoch manually advances the epoch (useful for testing).
// Returns the new epoch value.
func (da *DistributedAllocator) AdvanceEpoch() uint64 {
	da.mu.Lock()
	defer da.mu.Unlock()

	if da.mode == PoolModeLease && da.epochAllocator != nil {
		return da.epochAllocator.AdvanceEpoch()
	}
	return 0
}

// --- Store operations ---

func (da *DistributedAllocator) keyPrefix() string {
	return fmt.Sprintf("/allocation/%s/", da.poolID)
}

func (da *DistributedAllocator) allocationKey(subscriberID string) string {
	return fmt.Sprintf("/allocation/%s/%s", da.poolID, subscriberID)
}

func (da *DistributedAllocator) saveAllocation(ctx context.Context, alloc *DistributedAllocation) error {
	data, err := json.Marshal(alloc)
	if err != nil {
		return err
	}
	return da.store.Put(ctx, da.allocationKey(alloc.SubscriberID), data)
}

func (da *DistributedAllocator) getAllocation(ctx context.Context, subscriberID string) (*DistributedAllocation, error) {
	data, err := da.store.Get(ctx, da.allocationKey(subscriberID))
	if err != nil {
		return nil, err
	}

	var alloc DistributedAllocation
	if err := json.Unmarshal(data, &alloc); err != nil {
		return nil, err
	}
	return &alloc, nil
}

func (da *DistributedAllocator) deleteAllocation(ctx context.Context, subscriberID string) error {
	return da.store.Delete(ctx, da.allocationKey(subscriberID))
}

func (da *DistributedAllocator) loadAllocations(ctx context.Context) error {
	results, err := da.store.Query(ctx, da.keyPrefix())
	if err != nil {
		return err
	}

	for _, kv := range results {
		var alloc DistributedAllocation
		if err := json.Unmarshal(kv.Value, &alloc); err != nil {
			continue
		}

		// Parse prefix
		_, prefix, err := net.ParseCIDR(alloc.Prefix)
		if err != nil {
			continue
		}

		if da.mode == PoolModeLease {
			// For lease mode, check if allocation is still valid
			currentEpoch := da.epochAllocator.GetCurrentEpoch()
			if currentEpoch >= 2 && alloc.Epoch < currentEpoch-2 {
				// Expired - skip loading and clean up from store
				da.store.Delete(ctx, da.allocationKey(alloc.SubscriberID))
				continue
			}

			// Allocate in epoch allocator (will set correct generation)
			da.epochAllocator.Allocate(ctx, alloc.SubscriberID)
		} else {
			// Session mode: set allocation directly from store
			if err := da.allocator.SetAllocation(alloc.SubscriberID, prefix); err != nil {
				// Log but continue - might be a conflict
				continue
			}
		}
	}

	return nil
}

// handleRemoteChange processes changes from other nodes.
func (da *DistributedAllocator) handleRemoteChange(key string, value []byte, deleted bool) {
	da.mu.Lock()
	defer da.mu.Unlock()

	// Extract subscriber ID from key
	// Key format: /allocation/{poolID}/{subscriberID}
	subscriberID := key[len(da.keyPrefix()):]

	if deleted {
		if da.mode == PoolModeLease {
			da.epochAllocator.Release(context.Background(), subscriberID)
		} else {
			da.allocator.Release(subscriberID)
		}
		return
	}

	var alloc DistributedAllocation
	if err := json.Unmarshal(value, &alloc); err != nil {
		return
	}

	// Parse prefix
	_, prefix, err := net.ParseCIDR(alloc.Prefix)
	if err != nil {
		return
	}

	if da.mode == PoolModeLease {
		// For lease mode, check if allocation is expired
		currentEpoch := da.epochAllocator.GetCurrentEpoch()
		if currentEpoch >= 2 && alloc.Epoch < currentEpoch-2 {
			return // Expired, ignore
		}

		// Check if we already have this allocation
		if existing := da.epochAllocator.Lookup(alloc.SubscriberID); existing != nil {
			return // Already in sync
		}

		// Allocate in epoch allocator
		da.epochAllocator.Allocate(context.Background(), alloc.SubscriberID)
	} else {
		// Session mode: check if we already have this allocation
		if existing := da.allocator.Lookup(alloc.SubscriberID); existing != nil {
			if existing.String() == prefix.String() {
				return // Already in sync
			}
		}

		// Apply remote allocation
		da.allocator.SetAllocation(alloc.SubscriberID, prefix)
	}
}
