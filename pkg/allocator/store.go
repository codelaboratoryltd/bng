package allocator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	// ErrNotFound is returned when an allocation is not found
	ErrNotFound = errors.New("allocation not found")

	// ErrConflict is returned when an allocation conflicts with existing data
	ErrConflict = errors.New("allocation conflict")
)

// AllocationRecord represents a stored allocation with metadata
type AllocationRecord struct {
	SubscriberID string            `json:"subscriber_id"`
	PoolID       string            `json:"pool_id"`
	Prefix       *net.IPNet        `json:"prefix"`
	MAC          string            `json:"mac,omitempty"`
	AllocatedAt  time.Time         `json:"allocated_at"`
	ExpiresAt    *time.Time        `json:"expires_at,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for AllocationRecord
func (a AllocationRecord) MarshalJSON() ([]byte, error) {
	type Alias AllocationRecord
	return json.Marshal(&struct {
		Prefix string `json:"prefix"`
		*Alias
	}{
		Prefix: a.Prefix.String(),
		Alias:  (*Alias)(&a),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for AllocationRecord
func (a *AllocationRecord) UnmarshalJSON(data []byte) error {
	type Alias AllocationRecord
	aux := &struct {
		Prefix string `json:"prefix"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	_, ipNet, err := net.ParseCIDR(aux.Prefix)
	if err != nil {
		return fmt.Errorf("invalid prefix: %w", err)
	}
	a.Prefix = ipNet
	return nil
}

// AllocationStore provides dual-indexed storage for IP allocations.
// It maintains two indexes:
//   - By pool: /allocation/{pool_id}/{subscriber_id} -> record
//   - By subscriber: /subscriber/{subscriber_id}/{pool_id} -> record
//
// This allows efficient queries both by pool (for ISP operations) and
// by subscriber (for session lookups).
type AllocationStore interface {
	// SaveAllocation stores an allocation (updates both indexes)
	SaveAllocation(ctx context.Context, alloc AllocationRecord) error

	// RemoveAllocation removes an allocation (updates both indexes)
	RemoveAllocation(ctx context.Context, poolID, subscriberID string) error

	// GetBySubscriber returns all allocations for a subscriber
	GetBySubscriber(ctx context.Context, subscriberID string) ([]AllocationRecord, error)

	// GetByPool returns all allocations in a pool
	GetByPool(ctx context.Context, poolID string) ([]AllocationRecord, error)

	// GetByIP returns the allocation for a specific IP/prefix
	GetByIP(ctx context.Context, ip net.IP) (*AllocationRecord, error)

	// GetPoolUtilization returns allocation counts for a pool
	GetPoolUtilization(ctx context.Context, poolID string) (allocated, total int, err error)

	// ListPools returns all pool IDs with allocations
	ListPools(ctx context.Context) ([]string, error)
}

// MemoryAllocationStore is an in-memory implementation of AllocationStore.
// Suitable for standalone deployments and testing.
type MemoryAllocationStore struct {
	mu sync.RWMutex

	// Primary storage: poolID -> subscriberID -> record
	byPool map[string]map[string]AllocationRecord

	// Secondary index: subscriberID -> poolID -> record
	bySubscriber map[string]map[string]AllocationRecord

	// Reverse lookup: IP string -> record
	byIP map[string]*AllocationRecord

	// Pool totals for utilization (set via SetPoolTotal)
	poolTotals map[string]int
}

// NewMemoryAllocationStore creates a new in-memory allocation store.
func NewMemoryAllocationStore() *MemoryAllocationStore {
	return &MemoryAllocationStore{
		byPool:       make(map[string]map[string]AllocationRecord),
		bySubscriber: make(map[string]map[string]AllocationRecord),
		byIP:         make(map[string]*AllocationRecord),
		poolTotals:   make(map[string]int),
	}
}

// SetPoolTotal sets the total capacity for a pool (for utilization calculation)
func (s *MemoryAllocationStore) SetPoolTotal(poolID string, total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.poolTotals[poolID] = total
}

// SaveAllocation implements AllocationStore
func (s *MemoryAllocationStore) SaveAllocation(ctx context.Context, alloc AllocationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for IP conflict
	ipKey := alloc.Prefix.IP.String()
	if existing, exists := s.byIP[ipKey]; exists {
		if existing.SubscriberID != alloc.SubscriberID || existing.PoolID != alloc.PoolID {
			return fmt.Errorf("%w: IP %s already allocated to %s in pool %s",
				ErrConflict, ipKey, existing.SubscriberID, existing.PoolID)
		}
	}

	// Update pool index
	if s.byPool[alloc.PoolID] == nil {
		s.byPool[alloc.PoolID] = make(map[string]AllocationRecord)
	}
	s.byPool[alloc.PoolID][alloc.SubscriberID] = alloc

	// Update subscriber index
	if s.bySubscriber[alloc.SubscriberID] == nil {
		s.bySubscriber[alloc.SubscriberID] = make(map[string]AllocationRecord)
	}
	s.bySubscriber[alloc.SubscriberID][alloc.PoolID] = alloc

	// Update IP index
	s.byIP[ipKey] = &alloc

	return nil
}

// RemoveAllocation implements AllocationStore
func (s *MemoryAllocationStore) RemoveAllocation(ctx context.Context, poolID, subscriberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get existing record for IP cleanup
	var ipKey string
	if poolAllocs, exists := s.byPool[poolID]; exists {
		if alloc, exists := poolAllocs[subscriberID]; exists {
			ipKey = alloc.Prefix.IP.String()
		}
	}

	// Remove from pool index
	if poolAllocs, exists := s.byPool[poolID]; exists {
		delete(poolAllocs, subscriberID)
		if len(poolAllocs) == 0 {
			delete(s.byPool, poolID)
		}
	}

	// Remove from subscriber index
	if subAllocs, exists := s.bySubscriber[subscriberID]; exists {
		delete(subAllocs, poolID)
		if len(subAllocs) == 0 {
			delete(s.bySubscriber, subscriberID)
		}
	}

	// Remove from IP index
	if ipKey != "" {
		delete(s.byIP, ipKey)
	}

	return nil
}

// GetBySubscriber implements AllocationStore
func (s *MemoryAllocationStore) GetBySubscriber(ctx context.Context, subscriberID string) ([]AllocationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	subAllocs, exists := s.bySubscriber[subscriberID]
	if !exists {
		return nil, nil
	}

	result := make([]AllocationRecord, 0, len(subAllocs))
	for _, alloc := range subAllocs {
		result = append(result, alloc)
	}
	return result, nil
}

// GetByPool implements AllocationStore
func (s *MemoryAllocationStore) GetByPool(ctx context.Context, poolID string) ([]AllocationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	poolAllocs, exists := s.byPool[poolID]
	if !exists {
		return nil, nil
	}

	result := make([]AllocationRecord, 0, len(poolAllocs))
	for _, alloc := range poolAllocs {
		result = append(result, alloc)
	}
	return result, nil
}

// GetByIP implements AllocationStore
func (s *MemoryAllocationStore) GetByIP(ctx context.Context, ip net.IP) (*AllocationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alloc, exists := s.byIP[ip.String()]
	if !exists {
		return nil, ErrNotFound
	}

	return alloc, nil
}

// GetPoolUtilization implements AllocationStore
func (s *MemoryAllocationStore) GetPoolUtilization(ctx context.Context, poolID string) (allocated, total int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if poolAllocs, exists := s.byPool[poolID]; exists {
		allocated = len(poolAllocs)
	}

	total = s.poolTotals[poolID]
	return allocated, total, nil
}

// ListPools implements AllocationStore
func (s *MemoryAllocationStore) ListPools(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pools := make([]string, 0, len(s.byPool))
	for poolID := range s.byPool {
		pools = append(pools, poolID)
	}
	return pools, nil
}

// Count returns total allocation count across all pools
func (s *MemoryAllocationStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, poolAllocs := range s.byPool {
		count += len(poolAllocs)
	}
	return count
}

// MarshalJSON implements json.Marshaler for persistence
func (s *MemoryAllocationStore) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Flatten all allocations for serialization
	var allocs []AllocationRecord
	for _, poolAllocs := range s.byPool {
		for _, alloc := range poolAllocs {
			allocs = append(allocs, alloc)
		}
	}

	state := struct {
		Allocations []AllocationRecord `json:"allocations"`
		PoolTotals  map[string]int     `json:"pool_totals"`
	}{
		Allocations: allocs,
		PoolTotals:  s.poolTotals,
	}

	return json.Marshal(state)
}

// UnmarshalJSON implements json.Unmarshaler for persistence
func (s *MemoryAllocationStore) UnmarshalJSON(data []byte) error {
	var state struct {
		Allocations []AllocationRecord `json:"allocations"`
		PoolTotals  map[string]int     `json:"pool_totals"`
	}

	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	// Reinitialize maps
	s.byPool = make(map[string]map[string]AllocationRecord)
	s.bySubscriber = make(map[string]map[string]AllocationRecord)
	s.byIP = make(map[string]*AllocationRecord)
	s.poolTotals = state.PoolTotals

	// Rebuild indexes
	for _, alloc := range state.Allocations {
		// Pool index
		if s.byPool[alloc.PoolID] == nil {
			s.byPool[alloc.PoolID] = make(map[string]AllocationRecord)
		}
		s.byPool[alloc.PoolID][alloc.SubscriberID] = alloc

		// Subscriber index
		if s.bySubscriber[alloc.SubscriberID] == nil {
			s.bySubscriber[alloc.SubscriberID] = make(map[string]AllocationRecord)
		}
		s.bySubscriber[alloc.SubscriberID][alloc.PoolID] = alloc

		// IP index
		allocCopy := alloc
		s.byIP[alloc.Prefix.IP.String()] = &allocCopy
	}

	return nil
}

// PoolAllocator combines an IPAllocator with an AllocationStore
// for integrated allocation and persistence.
type PoolAllocator struct {
	allocator *IPAllocator
	store     AllocationStore
	poolID    string
}

// NewPoolAllocator creates a new pool allocator with integrated persistence.
func NewPoolAllocator(poolID, baseNetwork string, prefixLength int, store AllocationStore) (*PoolAllocator, error) {
	alloc, err := NewIPAllocator(baseNetwork, prefixLength)
	if err != nil {
		return nil, err
	}

	// Set pool total in store for utilization tracking
	if memStore, ok := store.(*MemoryAllocationStore); ok {
		_, total, _ := alloc.Stats()
		memStore.SetPoolTotal(poolID, int(total))
	}

	return &PoolAllocator{
		allocator: alloc,
		store:     store,
		poolID:    poolID,
	}, nil
}

// Allocate allocates a prefix for a subscriber and persists it.
func (p *PoolAllocator) Allocate(ctx context.Context, subscriberID string, mac string) (*net.IPNet, error) {
	prefix, err := p.allocator.Allocate(subscriberID)
	if err != nil {
		return nil, err
	}

	// Persist allocation
	record := AllocationRecord{
		SubscriberID: subscriberID,
		PoolID:       p.poolID,
		Prefix:       prefix,
		MAC:          mac,
		AllocatedAt:  time.Now(),
	}

	if err := p.store.SaveAllocation(ctx, record); err != nil {
		// Rollback allocator state
		p.allocator.Release(subscriberID)
		return nil, fmt.Errorf("failed to persist allocation: %w", err)
	}

	return prefix, nil
}

// Release releases a subscriber's allocation and removes from store.
func (p *PoolAllocator) Release(ctx context.Context, subscriberID string) error {
	if err := p.allocator.Release(subscriberID); err != nil {
		return err
	}

	return p.store.RemoveAllocation(ctx, p.poolID, subscriberID)
}

// Lookup returns the allocation for a subscriber.
func (p *PoolAllocator) Lookup(subscriberID string) *net.IPNet {
	return p.allocator.Lookup(subscriberID)
}

// Stats returns allocation statistics.
func (p *PoolAllocator) Stats() (allocated, total uint64, utilization float64) {
	return p.allocator.Stats()
}

// PoolID returns the pool identifier.
func (p *PoolAllocator) PoolID() string {
	return p.poolID
}
