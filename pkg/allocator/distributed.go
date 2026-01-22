package allocator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// DistributedAllocator wraps BitmapAllocator with distributed state backing.
// Coordinates with other nodes via the Store interface (CLSet or replica).
type DistributedAllocator struct {
	mu sync.RWMutex

	// Pool configuration
	poolID    string
	config    BitmapConfig
	allocator *BitmapAllocator

	// Distributed state
	store Store

	// Pool mode determines allocation behavior
	mode PoolMode

	// Epoch tracking (for lease mode)
	currentEpoch uint64
	epochMu      sync.RWMutex
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

// Allocation represents a stored allocation record.
type Allocation struct {
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
	bitmapCfg := BitmapConfig{
		BaseNetwork: cfg.BaseNetwork,
		PrefixLen:   cfg.PrefixLen,
	}

	allocator, err := NewBitmapAllocator(bitmapCfg)
	if err != nil {
		return nil, fmt.Errorf("create bitmap allocator: %w", err)
	}

	da := &DistributedAllocator{
		poolID:    cfg.PoolID,
		config:    bitmapCfg,
		allocator: allocator,
		store:     store,
		mode:      cfg.Mode,
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

	// Try local allocation first
	prefix, err := da.allocator.Allocate(subscriberID)
	if err != nil {
		return nil, err
	}

	// Persist to distributed store
	alloc := &Allocation{
		PoolID:       da.poolID,
		SubscriberID: subscriberID,
		Prefix:       prefix.String(),
		Epoch:        da.getCurrentEpoch(),
		AllocatedAt:  time.Now().UTC(),
	}

	if err := da.saveAllocation(ctx, alloc); err != nil {
		// Rollback local allocation
		da.allocator.Release(subscriberID)
		return nil, fmt.Errorf("save allocation: %w", err)
	}

	return prefix, nil
}

// AllocateWithMAC assigns a prefix and associates a MAC (for DHCP).
func (da *DistributedAllocator) AllocateWithMAC(ctx context.Context, subscriberID string, mac net.HardwareAddr) (*net.IPNet, error) {
	da.mu.Lock()
	defer da.mu.Unlock()

	prefix, err := da.allocator.Allocate(subscriberID)
	if err != nil {
		return nil, err
	}

	alloc := &Allocation{
		PoolID:       da.poolID,
		SubscriberID: subscriberID,
		Prefix:       prefix.String(),
		Epoch:        da.getCurrentEpoch(),
		AllocatedAt:  time.Now().UTC(),
		MAC:          mac.String(),
	}

	if err := da.saveAllocation(ctx, alloc); err != nil {
		da.allocator.Release(subscriberID)
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

	// Get existing allocation
	alloc, err := da.getAllocation(ctx, subscriberID)
	if err != nil {
		return err
	}

	// Update epoch
	alloc.Epoch = da.getCurrentEpoch()

	return da.saveAllocation(ctx, alloc)
}

// Release frees a previously allocated prefix.
func (da *DistributedAllocator) Release(ctx context.Context, subscriberID string) error {
	da.mu.Lock()
	defer da.mu.Unlock()

	if err := da.allocator.Release(subscriberID); err != nil {
		return err
	}

	return da.deleteAllocation(ctx, subscriberID)
}

// Get returns the allocation for a subscriber.
func (da *DistributedAllocator) Get(subscriberID string) (*net.IPNet, bool) {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return da.allocator.Get(subscriberID)
}

// GetByPrefix returns the subscriber for a given prefix.
func (da *DistributedAllocator) GetByPrefix(prefix *net.IPNet) (string, bool) {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return da.allocator.GetByPrefix(prefix)
}

// Stats returns allocator statistics.
func (da *DistributedAllocator) Stats() BitmapStats {
	da.mu.RLock()
	defer da.mu.RUnlock()
	return da.allocator.Stats()
}

// --- Epoch management (lease mode) ---

func (da *DistributedAllocator) getCurrentEpoch() uint64 {
	da.epochMu.RLock()
	defer da.epochMu.RUnlock()
	return da.currentEpoch
}

func (da *DistributedAllocator) advanceEpoch() {
	da.epochMu.Lock()
	da.currentEpoch++
	da.epochMu.Unlock()
}

func (da *DistributedAllocator) epochLoop(ctx context.Context) {
	// TODO: Get epoch period from config
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			da.advanceEpoch()
			da.reclaimExpired(ctx)
		}
	}
}

// reclaimExpired releases allocations from epoch < current - 1.
func (da *DistributedAllocator) reclaimExpired(ctx context.Context) {
	currentEpoch := da.getCurrentEpoch()
	if currentEpoch < 2 {
		return // Need at least 2 epochs for grace period
	}

	threshold := currentEpoch - 2 // Two-epoch grace period

	// Query all allocations for this pool
	results, err := da.store.Query(ctx, da.keyPrefix())
	if err != nil {
		return
	}

	for _, kv := range results {
		var alloc Allocation
		if err := json.Unmarshal(kv.Value, &alloc); err != nil {
			continue
		}

		if alloc.Epoch < threshold {
			// Expired - reclaim
			da.Release(ctx, alloc.SubscriberID)
		}
	}
}

// --- Store operations ---

func (da *DistributedAllocator) keyPrefix() string {
	return fmt.Sprintf("/allocation/%s/", da.poolID)
}

func (da *DistributedAllocator) allocationKey(subscriberID string) string {
	return fmt.Sprintf("/allocation/%s/%s", da.poolID, subscriberID)
}

func (da *DistributedAllocator) saveAllocation(ctx context.Context, alloc *Allocation) error {
	data, err := json.Marshal(alloc)
	if err != nil {
		return err
	}
	return da.store.Put(ctx, da.allocationKey(alloc.SubscriberID), data)
}

func (da *DistributedAllocator) getAllocation(ctx context.Context, subscriberID string) (*Allocation, error) {
	data, err := da.store.Get(ctx, da.allocationKey(subscriberID))
	if err != nil {
		return nil, err
	}

	var alloc Allocation
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
		var alloc Allocation
		if err := json.Unmarshal(kv.Value, &alloc); err != nil {
			continue
		}

		// Parse prefix
		_, prefix, err := net.ParseCIDR(alloc.Prefix)
		if err != nil {
			continue
		}

		// Set allocation directly from store (store is authoritative)
		if err := da.allocator.SetAllocation(alloc.SubscriberID, prefix); err != nil {
			// Log but continue - might be a conflict
			continue
		}
	}

	return nil
}

// handleRemoteChange processes changes from other nodes.
func (da *DistributedAllocator) handleRemoteChange(key string, value []byte, deleted bool) {
	da.mu.Lock()
	defer da.mu.Unlock()

	if deleted {
		// Extract subscriber ID from key
		// Key format: /allocation/{poolID}/{subscriberID}
		subscriberID := key[len(da.keyPrefix()):]
		da.allocator.Release(subscriberID)
		return
	}

	var alloc Allocation
	if err := json.Unmarshal(value, &alloc); err != nil {
		return
	}

	// Parse prefix and mark as allocated
	_, prefix, err := net.ParseCIDR(alloc.Prefix)
	if err != nil {
		return
	}

	// Check if we already have this allocation
	if existing, ok := da.allocator.Get(alloc.SubscriberID); ok {
		if existing.String() == prefix.String() {
			return // Already in sync
		}
	}

	// Apply remote allocation (SetAllocation handles conflicts)
	da.allocator.SetAllocation(alloc.SubscriberID, prefix)
}
