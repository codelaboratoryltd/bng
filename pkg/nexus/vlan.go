package nexus

import (
	"context"
	"fmt"
	"sync"
)

// VLANRange represents a range of VLAN IDs.
type VLANRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

// VLANAllocatorConfig contains configuration for VLAN allocation.
type VLANAllocatorConfig struct {
	// STagRange is the range of S-TAG (outer VLAN) values.
	STagRange VLANRange

	// CTagRange is the range of C-TAG (inner VLAN) values per S-TAG.
	CTagRange VLANRange
}

// DefaultVLANConfig returns default VLAN ranges.
func DefaultVLANConfig() VLANAllocatorConfig {
	return VLANAllocatorConfig{
		STagRange: VLANRange{Start: 100, End: 4094},
		CTagRange: VLANRange{Start: 100, End: 4094},
	}
}

// VLANAllocation represents an allocated VLAN pair.
type VLANAllocation struct {
	STag   uint16 `json:"s_tag"`
	CTag   uint16 `json:"c_tag"`
	NTEID  string `json:"nte_id"`
	Reason string `json:"reason,omitempty"`
}

// VLANAllocator manages S-TAG/C-TAG allocation for NTEs.
// In a typical setup:
//   - S-TAG (outer VLAN) identifies the service provider or service type
//   - C-TAG (inner VLAN) identifies the individual subscriber
//
// This implements QinQ (802.1ad) double-tagging.
type VLANAllocator struct {
	config VLANAllocatorConfig
	mu     sync.RWMutex

	// allocations maps NTE ID -> allocation
	allocations map[string]*VLANAllocation

	// sTagUsage tracks how many C-TAGs are used per S-TAG
	sTagUsage map[uint16]map[uint16]string // s_tag -> c_tag -> nte_id

	// Current S-TAG for new allocations
	currentSTag uint16
}

// NewVLANAllocator creates a new VLAN allocator.
func NewVLANAllocator(config VLANAllocatorConfig) *VLANAllocator {
	return &VLANAllocator{
		config:      config,
		allocations: make(map[string]*VLANAllocation),
		sTagUsage:   make(map[uint16]map[uint16]string),
		currentSTag: config.STagRange.Start,
	}
}

// Allocate assigns VLANs to an NTE.
func (v *VLANAllocator) Allocate(nteID string) (*VLANAllocation, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Check if already allocated
	if alloc, ok := v.allocations[nteID]; ok {
		return alloc, nil
	}

	// Find available S-TAG/C-TAG pair
	sTag, cTag, err := v.findAvailable()
	if err != nil {
		return nil, err
	}

	alloc := &VLANAllocation{
		STag:  sTag,
		CTag:  cTag,
		NTEID: nteID,
	}

	// Record allocation
	v.allocations[nteID] = alloc
	if v.sTagUsage[sTag] == nil {
		v.sTagUsage[sTag] = make(map[uint16]string)
	}
	v.sTagUsage[sTag][cTag] = nteID

	return alloc, nil
}

// AllocateWithSTag allocates with a specific S-TAG (for ISP-assigned S-TAGs).
func (v *VLANAllocator) AllocateWithSTag(nteID string, sTag uint16) (*VLANAllocation, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Check if already allocated
	if alloc, ok := v.allocations[nteID]; ok {
		if alloc.STag == sTag {
			return alloc, nil
		}
		// Different S-TAG requested, need to reallocate
		v.releaseUnlocked(nteID)
	}

	// Find available C-TAG for this S-TAG
	cTag, err := v.findAvailableCTag(sTag)
	if err != nil {
		return nil, err
	}

	alloc := &VLANAllocation{
		STag:  sTag,
		CTag:  cTag,
		NTEID: nteID,
	}

	// Record allocation
	v.allocations[nteID] = alloc
	if v.sTagUsage[sTag] == nil {
		v.sTagUsage[sTag] = make(map[uint16]string)
	}
	v.sTagUsage[sTag][cTag] = nteID

	return alloc, nil
}

// Release frees VLANs allocated to an NTE.
func (v *VLANAllocator) Release(nteID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.releaseUnlocked(nteID)
}

// releaseUnlocked releases without holding the lock.
func (v *VLANAllocator) releaseUnlocked(nteID string) {
	alloc, ok := v.allocations[nteID]
	if !ok {
		return
	}

	delete(v.allocations, nteID)
	if usage, ok := v.sTagUsage[alloc.STag]; ok {
		delete(usage, alloc.CTag)
		if len(usage) == 0 {
			delete(v.sTagUsage, alloc.STag)
		}
	}
}

// Get returns the allocation for an NTE.
func (v *VLANAllocator) Get(nteID string) (*VLANAllocation, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	alloc, ok := v.allocations[nteID]
	return alloc, ok
}

// findAvailable finds an available S-TAG/C-TAG pair.
func (v *VLANAllocator) findAvailable() (uint16, uint16, error) {
	// Try current S-TAG first
	for sTag := v.currentSTag; sTag <= v.config.STagRange.End; sTag++ {
		cTag, err := v.findAvailableCTag(sTag)
		if err == nil {
			v.currentSTag = sTag
			return sTag, cTag, nil
		}
	}

	// Wrap around and try from start
	for sTag := v.config.STagRange.Start; sTag < v.currentSTag; sTag++ {
		cTag, err := v.findAvailableCTag(sTag)
		if err == nil {
			v.currentSTag = sTag
			return sTag, cTag, nil
		}
	}

	return 0, 0, ErrVLANExhausted
}

// findAvailableCTag finds an available C-TAG for a given S-TAG.
func (v *VLANAllocator) findAvailableCTag(sTag uint16) (uint16, error) {
	usage := v.sTagUsage[sTag]

	// If no usage yet, return first C-TAG
	if usage == nil {
		return v.config.CTagRange.Start, nil
	}

	// Find first available C-TAG
	for cTag := v.config.CTagRange.Start; cTag <= v.config.CTagRange.End; cTag++ {
		if _, used := usage[cTag]; !used {
			return cTag, nil
		}
	}

	return 0, ErrVLANExhausted
}

// Stats returns allocation statistics.
func (v *VLANAllocator) Stats() VLANStats {
	v.mu.RLock()
	defer v.mu.RUnlock()

	stats := VLANStats{
		TotalAllocations: len(v.allocations),
		STagsInUse:       len(v.sTagUsage),
		STagCapacity:     int(v.config.STagRange.End - v.config.STagRange.Start + 1),
		CTagCapacity:     int(v.config.CTagRange.End - v.config.CTagRange.Start + 1),
	}

	// Calculate total capacity
	stats.TotalCapacity = stats.STagCapacity * stats.CTagCapacity

	return stats
}

// VLANStats contains VLAN allocation statistics.
type VLANStats struct {
	TotalAllocations int
	STagsInUse       int
	STagCapacity     int
	CTagCapacity     int
	TotalCapacity    int
}

// LoadFromStore loads existing allocations from the store.
func (v *VLANAllocator) LoadFromStore(ctx context.Context, ntes []*NTE) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, nte := range ntes {
		if nte.STag == 0 || nte.CTag == 0 {
			continue
		}

		alloc := &VLANAllocation{
			STag:  nte.STag,
			CTag:  nte.CTag,
			NTEID: nte.ID,
		}

		v.allocations[nte.ID] = alloc
		if v.sTagUsage[nte.STag] == nil {
			v.sTagUsage[nte.STag] = make(map[uint16]string)
		}
		v.sTagUsage[nte.STag][nte.CTag] = nte.ID
	}

	return nil
}

// SyncToNTE updates an NTE with its VLAN allocation.
func (v *VLANAllocator) SyncToNTE(nte *NTE) error {
	alloc, ok := v.Get(nte.ID)
	if !ok {
		return fmt.Errorf("no VLAN allocation for NTE %s", nte.ID)
	}

	nte.STag = alloc.STag
	nte.CTag = alloc.CTag
	return nil
}
