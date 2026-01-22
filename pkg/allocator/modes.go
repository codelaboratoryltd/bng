package allocator

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AllocationMode specifies the allocation strategy
type AllocationMode string

const (
	// ModeStandalone uses local bitmap allocation with persistence
	ModeStandalone AllocationMode = "standalone"

	// ModeWiFiGateway uses local allocation with short leases for guest networks
	ModeWiFiGateway AllocationMode = "wifi_gateway"

	// ModeNexus queries central Nexus cluster for allocations
	ModeNexus AllocationMode = "nexus"

	// ModeHybrid combines local allocation with Nexus sync
	ModeHybrid AllocationMode = "hybrid"
)

// AllocationInfo represents detailed information about an IP allocation.
// This extends the basic Allocation type with pool and timestamp information.
type AllocationInfo struct {
	SubscriberID  string
	Prefix        *net.IPNet
	PoolID        string
	AllocatedAt   time.Time
	ExpiresAt     *time.Time
	PartitionFlag bool // True if allocated during network partition
}

// Allocator is the interface for IP allocation strategies.
// Different implementations support various deployment modes:
// - LocalAllocator: standalone deployments
// - NexusAllocator: central Nexus-based allocation
// - HybridAllocator: local with Nexus sync
type Allocator interface {
	// Allocate allocates an IP/prefix for a subscriber from a pool
	Allocate(ctx context.Context, subscriberID, poolID string) (*net.IPNet, error)

	// AllocateWithMAC allocates with MAC address tracking
	AllocateWithMAC(ctx context.Context, subscriberID, poolID, mac string) (*net.IPNet, error)

	// Release releases a subscriber's allocation from a pool
	Release(ctx context.Context, subscriberID, poolID string) error

	// Lookup returns allocations for a subscriber
	Lookup(ctx context.Context, subscriberID string) ([]AllocationInfo, error)

	// LookupByPool returns all allocations in a pool
	LookupByPool(ctx context.Context, poolID string) ([]AllocationInfo, error)

	// LookupByIP returns the allocation for a specific IP
	LookupByIP(ctx context.Context, ip net.IP) (*AllocationInfo, error)

	// Stats returns allocation statistics for a pool
	Stats(ctx context.Context, poolID string) (allocated, total uint64, utilization float64, err error)

	// Close releases resources
	Close() error
}

// PoolConfig defines configuration for an allocation pool
type PoolConfig struct {
	ID            string         // Pool identifier
	CIDR          string         // Base network CIDR
	PrefixLength  int            // Prefix length to allocate
	Gateway       net.IP         // Gateway address
	DNSServers    []net.IP       // DNS servers
	LeaseDuration time.Duration  // Lease duration (0 for indefinite)
	Mode          AllocationMode // Pool-specific mode override
}

// LocalAllocatorConfig configures a LocalAllocator
type LocalAllocatorConfig struct {
	Pools           []PoolConfig
	PersistencePath string      // Path for state persistence (optional)
	Logger          *zap.Logger // Logger instance
}

// LocalAllocator implements Allocator using local bitmap allocation.
// Suitable for standalone deployments and WiFi gateways.
type LocalAllocator struct {
	pools  map[string]*PoolAllocator
	store  *MemoryAllocationStore
	config LocalAllocatorConfig
	mu     sync.RWMutex
	logger *zap.Logger
}

// NewLocalAllocator creates a new local allocator.
func NewLocalAllocator(cfg LocalAllocatorConfig) (*LocalAllocator, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	store := NewMemoryAllocationStore()

	allocator := &LocalAllocator{
		pools:  make(map[string]*PoolAllocator),
		store:  store,
		config: cfg,
		logger: logger,
	}

	// Create pool allocators
	for _, poolCfg := range cfg.Pools {
		pool, err := NewPoolAllocator(poolCfg.ID, poolCfg.CIDR, poolCfg.PrefixLength, store)
		if err != nil {
			return nil, fmt.Errorf("failed to create pool %s: %w", poolCfg.ID, err)
		}
		allocator.pools[poolCfg.ID] = pool

		logger.Info("Created allocation pool",
			zap.String("pool_id", poolCfg.ID),
			zap.String("cidr", poolCfg.CIDR),
			zap.Int("prefix_length", poolCfg.PrefixLength),
		)
	}

	return allocator, nil
}

// Allocate implements Allocator
func (a *LocalAllocator) Allocate(ctx context.Context, subscriberID, poolID string) (*net.IPNet, error) {
	return a.AllocateWithMAC(ctx, subscriberID, poolID, "")
}

// AllocateWithMAC implements Allocator
func (a *LocalAllocator) AllocateWithMAC(ctx context.Context, subscriberID, poolID, mac string) (*net.IPNet, error) {
	a.mu.RLock()
	pool, exists := a.pools[poolID]
	a.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("pool %s not found", poolID)
	}

	prefix, err := pool.Allocate(ctx, subscriberID, mac)
	if err != nil {
		return nil, err
	}

	a.logger.Debug("Allocated address",
		zap.String("subscriber", subscriberID),
		zap.String("pool", poolID),
		zap.String("prefix", prefix.String()),
	)

	return prefix, nil
}

// Release implements Allocator
func (a *LocalAllocator) Release(ctx context.Context, subscriberID, poolID string) error {
	a.mu.RLock()
	pool, exists := a.pools[poolID]
	a.mu.RUnlock()

	if !exists {
		return fmt.Errorf("pool %s not found", poolID)
	}

	if err := pool.Release(ctx, subscriberID); err != nil {
		return err
	}

	a.logger.Debug("Released allocation",
		zap.String("subscriber", subscriberID),
		zap.String("pool", poolID),
	)

	return nil
}

// Lookup implements Allocator
func (a *LocalAllocator) Lookup(ctx context.Context, subscriberID string) ([]AllocationInfo, error) {
	records, err := a.store.GetBySubscriber(ctx, subscriberID)
	if err != nil {
		return nil, err
	}

	allocations := make([]AllocationInfo, len(records))
	for i, r := range records {
		allocations[i] = AllocationInfo{
			SubscriberID: r.SubscriberID,
			Prefix:       r.Prefix,
			PoolID:       r.PoolID,
			AllocatedAt:  r.AllocatedAt,
			ExpiresAt:    r.ExpiresAt,
		}
	}

	return allocations, nil
}

// LookupByPool implements Allocator
func (a *LocalAllocator) LookupByPool(ctx context.Context, poolID string) ([]AllocationInfo, error) {
	records, err := a.store.GetByPool(ctx, poolID)
	if err != nil {
		return nil, err
	}

	allocations := make([]AllocationInfo, len(records))
	for i, r := range records {
		allocations[i] = AllocationInfo{
			SubscriberID: r.SubscriberID,
			Prefix:       r.Prefix,
			PoolID:       r.PoolID,
			AllocatedAt:  r.AllocatedAt,
			ExpiresAt:    r.ExpiresAt,
		}
	}

	return allocations, nil
}

// LookupByIP implements Allocator
func (a *LocalAllocator) LookupByIP(ctx context.Context, ip net.IP) (*AllocationInfo, error) {
	record, err := a.store.GetByIP(ctx, ip)
	if err != nil {
		return nil, err
	}

	return &AllocationInfo{
		SubscriberID: record.SubscriberID,
		Prefix:       record.Prefix,
		PoolID:       record.PoolID,
		AllocatedAt:  record.AllocatedAt,
		ExpiresAt:    record.ExpiresAt,
	}, nil
}

// Stats implements Allocator
func (a *LocalAllocator) Stats(ctx context.Context, poolID string) (allocated, total uint64, utilization float64, err error) {
	a.mu.RLock()
	pool, exists := a.pools[poolID]
	a.mu.RUnlock()

	if !exists {
		return 0, 0, 0, fmt.Errorf("pool %s not found", poolID)
	}

	allocated, total, utilization = pool.Stats()
	return allocated, total, utilization, nil
}

// Close implements Allocator
func (a *LocalAllocator) Close() error {
	// Save state if persistence is configured
	if a.config.PersistencePath != "" {
		a.logger.Info("Saving allocation state", zap.String("path", a.config.PersistencePath))
		// TODO: Implement persistence
	}
	return nil
}

// GetPool returns a specific pool allocator (for direct access)
func (a *LocalAllocator) GetPool(poolID string) (*PoolAllocator, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	pool, exists := a.pools[poolID]
	return pool, exists
}

// ListPools returns all configured pool IDs
func (a *LocalAllocator) ListPools() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	pools := make([]string, 0, len(a.pools))
	for id := range a.pools {
		pools = append(pools, id)
	}
	return pools
}

// WiFiGatewayAllocator is a LocalAllocator with WiFi-specific defaults
type WiFiGatewayAllocator struct {
	*LocalAllocator
	defaultLeaseDuration time.Duration
}

// WiFiGatewayConfig configures a WiFi gateway allocator
type WiFiGatewayConfig struct {
	GuestPool        PoolConfig    // Guest network pool
	LeaseDuration    time.Duration // Default short lease (e.g., 5m for guests)
	CaptivePortalURL string        // Optional captive portal redirect
	Logger           *zap.Logger
}

// NewWiFiGatewayAllocator creates an allocator optimized for WiFi gateways.
func NewWiFiGatewayAllocator(cfg WiFiGatewayConfig) (*WiFiGatewayAllocator, error) {
	// Default lease duration for WiFi guests
	leaseDuration := cfg.LeaseDuration
	if leaseDuration == 0 {
		leaseDuration = 5 * time.Minute
	}

	// Apply lease duration to pool
	cfg.GuestPool.LeaseDuration = leaseDuration

	localAlloc, err := NewLocalAllocator(LocalAllocatorConfig{
		Pools:  []PoolConfig{cfg.GuestPool},
		Logger: cfg.Logger,
	})
	if err != nil {
		return nil, err
	}

	return &WiFiGatewayAllocator{
		LocalAllocator:       localAlloc,
		defaultLeaseDuration: leaseDuration,
	}, nil
}

// AllocateGuest allocates an IP for a guest (unknown MAC) with short lease.
func (w *WiFiGatewayAllocator) AllocateGuest(ctx context.Context, mac string) (*net.IPNet, error) {
	// Use MAC as subscriber ID for guests
	return w.AllocateWithMAC(ctx, mac, w.ListPools()[0], mac)
}

// HybridAllocatorConfig configures a hybrid allocator
type HybridAllocatorConfig struct {
	Pools           []PoolConfig
	NexusURL        string // Central Nexus server URL
	PersistencePath string // Local cache path
	SyncInterval    time.Duration
	Logger          *zap.Logger
}

// HybridAllocator combines local allocation with Nexus synchronization.
// During network partition, it continues using local allocation and
// marks allocations with a partition flag for later reconciliation.
type HybridAllocator struct {
	local           *LocalAllocator
	nexusURL        string
	nexusAvailable  bool
	syncInterval    time.Duration
	partitionActive bool
	mu              sync.RWMutex
	logger          *zap.Logger
	stopSync        chan struct{}
}

// NewHybridAllocator creates a hybrid allocator.
func NewHybridAllocator(cfg HybridAllocatorConfig) (*HybridAllocator, error) {
	localAlloc, err := NewLocalAllocator(LocalAllocatorConfig{
		Pools:           cfg.Pools,
		PersistencePath: cfg.PersistencePath,
		Logger:          cfg.Logger,
	})
	if err != nil {
		return nil, err
	}

	syncInterval := cfg.SyncInterval
	if syncInterval == 0 {
		syncInterval = 30 * time.Second
	}

	allocator := &HybridAllocator{
		local:          localAlloc,
		nexusURL:       cfg.NexusURL,
		nexusAvailable: false, // Will be set by health check
		syncInterval:   syncInterval,
		logger:         cfg.Logger,
		stopSync:       make(chan struct{}),
	}

	// Start sync goroutine
	go allocator.syncLoop()

	return allocator, nil
}

// Allocate implements Allocator
func (h *HybridAllocator) Allocate(ctx context.Context, subscriberID, poolID string) (*net.IPNet, error) {
	return h.AllocateWithMAC(ctx, subscriberID, poolID, "")
}

// AllocateWithMAC implements Allocator
func (h *HybridAllocator) AllocateWithMAC(ctx context.Context, subscriberID, poolID, mac string) (*net.IPNet, error) {
	h.mu.RLock()
	nexusAvailable := h.nexusAvailable
	h.mu.RUnlock()

	if nexusAvailable {
		// TODO: Implement Nexus allocation
		// For now, fall back to local
		h.logger.Debug("Nexus available but not implemented, using local allocation")
	}

	// Use local allocation
	prefix, err := h.local.AllocateWithMAC(ctx, subscriberID, poolID, mac)
	if err != nil {
		return nil, err
	}

	// Mark as partition allocation if Nexus is unavailable
	if !nexusAvailable {
		h.mu.Lock()
		h.partitionActive = true
		h.mu.Unlock()

		h.logger.Warn("Allocated during Nexus partition",
			zap.String("subscriber", subscriberID),
			zap.String("prefix", prefix.String()),
		)
	}

	return prefix, nil
}

// Release implements Allocator
func (h *HybridAllocator) Release(ctx context.Context, subscriberID, poolID string) error {
	// Always release locally
	if err := h.local.Release(ctx, subscriberID, poolID); err != nil {
		return err
	}

	// TODO: Sync release to Nexus when available
	return nil
}

// Lookup implements Allocator
func (h *HybridAllocator) Lookup(ctx context.Context, subscriberID string) ([]AllocationInfo, error) {
	return h.local.Lookup(ctx, subscriberID)
}

// LookupByPool implements Allocator
func (h *HybridAllocator) LookupByPool(ctx context.Context, poolID string) ([]AllocationInfo, error) {
	return h.local.LookupByPool(ctx, poolID)
}

// LookupByIP implements Allocator
func (h *HybridAllocator) LookupByIP(ctx context.Context, ip net.IP) (*AllocationInfo, error) {
	return h.local.LookupByIP(ctx, ip)
}

// Stats implements Allocator
func (h *HybridAllocator) Stats(ctx context.Context, poolID string) (allocated, total uint64, utilization float64, err error) {
	return h.local.Stats(ctx, poolID)
}

// Close implements Allocator
func (h *HybridAllocator) Close() error {
	close(h.stopSync)
	return h.local.Close()
}

// IsPartitionActive returns true if allocations were made during Nexus partition
func (h *HybridAllocator) IsPartitionActive() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.partitionActive
}

// syncLoop periodically syncs with Nexus
func (h *HybridAllocator) syncLoop() {
	ticker := time.NewTicker(h.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.checkNexusHealth()
			if h.nexusAvailable && h.partitionActive {
				h.reconcilePartitionAllocations()
			}
		case <-h.stopSync:
			return
		}
	}
}

// checkNexusHealth checks if Nexus is reachable
func (h *HybridAllocator) checkNexusHealth() {
	// TODO: Implement actual health check
	// For now, just mark as unavailable
	h.mu.Lock()
	defer h.mu.Unlock()

	// In a real implementation, we'd ping the Nexus server
	// h.nexusAvailable = pingNexus(h.nexusURL)
}

// reconcilePartitionAllocations syncs local allocations to Nexus
func (h *HybridAllocator) reconcilePartitionAllocations() {
	h.logger.Info("Reconciling partition allocations with Nexus")

	// TODO: Implement reconciliation
	// 1. Get all local allocations with partition flag
	// 2. Check each against Nexus
	// 3. If conflict, use Nexus-wins strategy (or timestamp-based)
	// 4. Sync local state with Nexus
	// 5. Clear partition flag

	h.mu.Lock()
	h.partitionActive = false
	h.mu.Unlock()
}
