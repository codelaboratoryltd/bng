// Package allocator provides collision-free IP and prefix allocation using bitmap tracking.
//
// The allocator uses a prefix-based model where each bit in a bitmap represents
// a prefix (not an individual IP). This provides:
//   - Collision-free allocation (no hash conflicts)
//   - Memory efficiency (8KB for 65K prefixes)
//   - Unified model for IPv4/IPv6 addresses and prefix delegation
//
// Examples:
//   - IPv4 /24 pool allocating /32: 256 bits = 32 bytes
//   - IPv6 /48 pool allocating /64: 65K bits = 8 KB
//   - IPv6 /48 pool allocating /56 (PD): 256 bits = 32 bytes
package allocator

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
)

var (
	// ErrPoolExhausted is returned when no more prefixes are available
	ErrPoolExhausted = errors.New("pool exhausted: no available prefixes")

	// ErrAlreadyAllocated is returned when trying to allocate an already-used prefix
	ErrAlreadyAllocated = errors.New("prefix already allocated")

	// ErrNotAllocated is returned when trying to release a non-allocated prefix
	ErrNotAllocated = errors.New("prefix not allocated")

	// ErrOutOfRange is returned when a prefix is outside the pool's range
	ErrOutOfRange = errors.New("prefix outside pool range")

	// ErrInvalidConfig is returned for invalid allocator configuration
	ErrInvalidConfig = errors.New("invalid allocator configuration")
)

// IPAllocator manages allocation of IP prefixes from a pool using bitmap tracking.
// It supports IPv4 addresses (/32), IPv6 addresses (/128 or /64), and IPv6 prefix
// delegation (/56, /60, etc.).
//
// Thread-safe for concurrent use.
type IPAllocator struct {
	mu sync.RWMutex

	// Pool configuration
	baseIP     net.IP     // Starting IP of the pool
	baseMask   net.IPMask // Network mask of the pool
	prefixLen  int        // Length of prefixes being allocated (e.g., 32, 64, 56)
	poolPrefix int        // Length of the pool prefix (e.g., 24, 48)

	// Allocation state
	bitmap         *big.Int          // One bit per allocatable prefix
	totalPrefixes  *big.Int          // Total number of allocatable prefixes
	allocatedCount *big.Int          // Number of allocated prefixes
	step           *big.Int          // IPs per allocated prefix
	nextFree       *big.Int          // Hint for next free prefix (optimization)
	allocated      map[string]uint64 // subscriberID -> prefix index

	// Reverse lookup
	indexToSubscriber map[uint64]string // prefix index -> subscriberID

	// IPv6 flag
	isIPv6 bool
}

// Config holds configuration for creating an IPAllocator
type Config struct {
	// BaseNetwork is the pool's network in CIDR notation (e.g., "10.0.0.0/24", "2001:db8::/48")
	BaseNetwork string `json:"base_network"`

	// PrefixLength is the size of prefixes to allocate (e.g., 32 for IPv4, 64 or 56 for IPv6)
	PrefixLength int `json:"prefix_length"`
}

// Allocation represents a single prefix allocation
type Allocation struct {
	SubscriberID string     `json:"subscriber_id"`
	Prefix       *net.IPNet `json:"prefix"`
	Index        uint64     `json:"index"`
}

// NewIPAllocator creates a new bitmap-based IP allocator.
//
// Parameters:
//   - baseNetwork: The pool's network in CIDR notation (e.g., "10.0.0.0/24")
//   - prefixLength: The prefix length to allocate (e.g., 32 for individual IPv4 addresses)
//
// For IPv4:
//   - baseNetwork="10.0.0.0/24", prefixLength=32 allocates individual /32 addresses
//
// For IPv6 addresses:
//   - baseNetwork="2001:db8::/48", prefixLength=64 allocates /64 subscriber prefixes
//
// For IPv6 prefix delegation:
//   - baseNetwork="2001:db8::/48", prefixLength=56 allocates /56 delegated prefixes
func NewIPAllocator(baseNetwork string, prefixLength int) (*IPAllocator, error) {
	_, ipNet, err := net.ParseCIDR(baseNetwork)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base network: %v", ErrInvalidConfig, err)
	}

	poolPrefix, totalBits := net.IPMask.Size(ipNet.Mask)

	// Validate prefix length
	if prefixLength < poolPrefix || prefixLength > totalBits {
		return nil, fmt.Errorf("%w: prefix length %d must be between %d and %d",
			ErrInvalidConfig, prefixLength, poolPrefix, totalBits)
	}

	isIPv6 := ipNet.IP.To4() == nil

	// Calculate number of allocatable prefixes: 2^(prefixLength - poolPrefix)
	prefixBits := prefixLength - poolPrefix
	totalPrefixes := new(big.Int).Lsh(big.NewInt(1), uint(prefixBits))

	// Calculate step size (IPs per prefix): 2^(totalBits - prefixLength)
	stepBits := totalBits - prefixLength
	step := new(big.Int).Lsh(big.NewInt(1), uint(stepBits))

	return &IPAllocator{
		baseIP:            ipNet.IP,
		baseMask:          ipNet.Mask,
		prefixLen:         prefixLength,
		poolPrefix:        poolPrefix,
		bitmap:            big.NewInt(0),
		totalPrefixes:     totalPrefixes,
		allocatedCount:    big.NewInt(0),
		step:              step,
		nextFree:          big.NewInt(0),
		allocated:         make(map[string]uint64),
		indexToSubscriber: make(map[uint64]string),
		isIPv6:            isIPv6,
	}, nil
}

// Allocate assigns the next available prefix to a subscriber.
// Returns the allocated prefix or an error if the pool is exhausted.
func (a *IPAllocator) Allocate(subscriberID string) (*net.IPNet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if subscriber already has an allocation
	if idx, exists := a.allocated[subscriberID]; exists {
		return a.getPrefixByIndex(idx), nil
	}

	// Find first free prefix
	index, err := a.findFreeIndex()
	if err != nil {
		return nil, err
	}

	// Mark as allocated
	a.bitmap.SetBit(a.bitmap, int(index), 1)
	a.allocatedCount.Add(a.allocatedCount, big.NewInt(1))
	a.allocated[subscriberID] = index
	a.indexToSubscriber[index] = subscriberID

	// Update hint for next allocation
	a.nextFree.SetUint64(index + 1)

	return a.getPrefixByIndex(index), nil
}

// AllocateSpecific allocates a specific prefix to a subscriber.
// Returns an error if the prefix is already allocated or out of range.
func (a *IPAllocator) AllocateSpecific(subscriberID string, prefix *net.IPNet) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	index, err := a.getIndexByPrefix(prefix)
	if err != nil {
		return err
	}

	// Check if already allocated
	if a.bitmap.Bit(int(index)) == 1 {
		existingSubscriber := a.indexToSubscriber[index]
		if existingSubscriber == subscriberID {
			return nil // Already allocated to this subscriber
		}
		return fmt.Errorf("%w: prefix %s allocated to %s", ErrAlreadyAllocated, prefix, existingSubscriber)
	}

	// Check if subscriber has different allocation
	if existingIdx, exists := a.allocated[subscriberID]; exists {
		return fmt.Errorf("%w: subscriber %s already has prefix at index %d",
			ErrAlreadyAllocated, subscriberID, existingIdx)
	}

	// Mark as allocated
	a.bitmap.SetBit(a.bitmap, int(index), 1)
	a.allocatedCount.Add(a.allocatedCount, big.NewInt(1))
	a.allocated[subscriberID] = index
	a.indexToSubscriber[index] = subscriberID

	return nil
}

// Release deallocates a subscriber's prefix, making it available again.
func (a *IPAllocator) Release(subscriberID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	index, exists := a.allocated[subscriberID]
	if !exists {
		return fmt.Errorf("%w: subscriber %s has no allocation", ErrNotAllocated, subscriberID)
	}

	// Clear the bit
	a.bitmap.SetBit(a.bitmap, int(index), 0)
	a.allocatedCount.Sub(a.allocatedCount, big.NewInt(1))
	delete(a.allocated, subscriberID)
	delete(a.indexToSubscriber, index)

	// Update hint if this is before current hint
	if index < a.nextFree.Uint64() {
		a.nextFree.SetUint64(index)
	}

	return nil
}

// ReleasePrefix deallocates a specific prefix regardless of subscriber.
func (a *IPAllocator) ReleasePrefix(prefix *net.IPNet) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	index, err := a.getIndexByPrefix(prefix)
	if err != nil {
		return err
	}

	if a.bitmap.Bit(int(index)) == 0 {
		return fmt.Errorf("%w: prefix %s", ErrNotAllocated, prefix)
	}

	// Find and remove subscriber mapping
	if subscriberID, exists := a.indexToSubscriber[index]; exists {
		delete(a.allocated, subscriberID)
		delete(a.indexToSubscriber, index)
	}

	// Clear the bit
	a.bitmap.SetBit(a.bitmap, int(index), 0)
	a.allocatedCount.Sub(a.allocatedCount, big.NewInt(1))

	// Update hint if this is before current hint
	if index < a.nextFree.Uint64() {
		a.nextFree.SetUint64(index)
	}

	return nil
}

// Lookup returns the allocation for a subscriber, or nil if not allocated.
func (a *IPAllocator) Lookup(subscriberID string) *net.IPNet {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if index, exists := a.allocated[subscriberID]; exists {
		return a.getPrefixByIndex(index)
	}
	return nil
}

// LookupByPrefix returns the subscriber ID for a given prefix, or empty if not allocated.
func (a *IPAllocator) LookupByPrefix(prefix *net.IPNet) string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	index, err := a.getIndexByPrefix(prefix)
	if err != nil {
		return ""
	}

	return a.indexToSubscriber[index]
}

// Contains checks if a prefix is within this allocator's range.
func (a *IPAllocator) Contains(prefix *net.IPNet) bool {
	_, err := a.getIndexByPrefix(prefix)
	return err == nil
}

// IsAllocated checks if a prefix is currently allocated.
func (a *IPAllocator) IsAllocated(prefix *net.IPNet) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	index, err := a.getIndexByPrefix(prefix)
	if err != nil {
		return false
	}

	return a.bitmap.Bit(int(index)) == 1
}

// Stats returns allocation statistics.
func (a *IPAllocator) Stats() (allocated, total uint64, utilization float64) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	alloc := a.allocatedCount.Uint64()
	tot := a.totalPrefixes.Uint64()

	var util float64
	if tot > 0 {
		util = float64(alloc) / float64(tot) * 100
	}

	return alloc, tot, util
}

// IsIPv6 returns true if this allocator is for IPv6 addresses/prefixes.
func (a *IPAllocator) IsIPv6() bool {
	return a.isIPv6
}

// PrefixLength returns the prefix length allocated to each subscriber.
func (a *IPAllocator) PrefixLength() int {
	return a.prefixLen
}

// ListAllocations returns all current allocations.
func (a *IPAllocator) ListAllocations() []Allocation {
	a.mu.RLock()
	defer a.mu.RUnlock()

	allocations := make([]Allocation, 0, len(a.allocated))
	for subscriberID, index := range a.allocated {
		allocations = append(allocations, Allocation{
			SubscriberID: subscriberID,
			Prefix:       a.getPrefixByIndex(index),
			Index:        index,
		})
	}
	return allocations
}

// BaseNetwork returns the pool's base network.
func (a *IPAllocator) BaseNetwork() *net.IPNet {
	return &net.IPNet{
		IP:   a.baseIP,
		Mask: a.baseMask,
	}
}

// findFreeIndex finds the first unallocated prefix index.
func (a *IPAllocator) findFreeIndex() (uint64, error) {
	total := a.totalPrefixes.Uint64()

	// Start from hint
	start := a.nextFree.Uint64()
	if start >= total {
		start = 0
	}

	// Search from hint to end
	for i := start; i < total; i++ {
		if a.bitmap.Bit(int(i)) == 0 {
			return i, nil
		}
	}

	// Wrap around and search from beginning to hint
	for i := uint64(0); i < start; i++ {
		if a.bitmap.Bit(int(i)) == 0 {
			return i, nil
		}
	}

	return 0, ErrPoolExhausted
}

// getPrefixByIndex calculates the prefix for a given index.
func (a *IPAllocator) getPrefixByIndex(index uint64) *net.IPNet {
	// Calculate offset: index * step
	offset := new(big.Int).Mul(big.NewInt(int64(index)), a.step)

	// Add offset to base IP
	ip := addIPOffset(a.baseIP, offset)

	// Create prefix with the allocation prefix length
	var bits int
	if a.isIPv6 {
		bits = 128
	} else {
		bits = 32
	}

	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(a.prefixLen, bits),
	}
}

// getIndexByPrefix calculates the index for a given prefix.
func (a *IPAllocator) getIndexByPrefix(prefix *net.IPNet) (uint64, error) {
	// Verify prefix length matches
	ones, _ := prefix.Mask.Size()
	if ones != a.prefixLen {
		return 0, fmt.Errorf("%w: expected /%d prefix, got /%d", ErrOutOfRange, a.prefixLen, ones)
	}

	// Calculate offset from base
	offset := ipOffset(a.baseIP, prefix.IP)
	if offset.Sign() < 0 {
		return 0, fmt.Errorf("%w: prefix %s is before pool base", ErrOutOfRange, prefix)
	}

	// Calculate index: offset / step
	index := new(big.Int).Div(offset, a.step)

	// Verify within bounds
	if index.Cmp(a.totalPrefixes) >= 0 {
		return 0, fmt.Errorf("%w: prefix %s is beyond pool end", ErrOutOfRange, prefix)
	}

	return index.Uint64(), nil
}

// MarshalJSON implements json.Marshaler for persistence.
func (a *IPAllocator) MarshalJSON() ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	state := struct {
		BaseNetwork string            `json:"base_network"`
		PrefixLen   int               `json:"prefix_length"`
		Bitmap      string            `json:"bitmap"`
		Allocated   map[string]uint64 `json:"allocated"`
	}{
		BaseNetwork: (&net.IPNet{IP: a.baseIP, Mask: a.baseMask}).String(),
		PrefixLen:   a.prefixLen,
		Bitmap:      a.bitmap.Text(16), // Hex encoding for compactness
		Allocated:   a.allocated,
	}

	return json.Marshal(state)
}

// UnmarshalJSON implements json.Unmarshaler for persistence.
func (a *IPAllocator) UnmarshalJSON(data []byte) error {
	var state struct {
		BaseNetwork string            `json:"base_network"`
		PrefixLen   int               `json:"prefix_length"`
		Bitmap      string            `json:"bitmap"`
		Allocated   map[string]uint64 `json:"allocated"`
	}

	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	// Recreate allocator with config
	alloc, err := NewIPAllocator(state.BaseNetwork, state.PrefixLen)
	if err != nil {
		return err
	}

	// Restore bitmap
	bitmap := new(big.Int)
	bitmap.SetString(state.Bitmap, 16)
	alloc.bitmap = bitmap

	// Restore allocations and rebuild reverse lookup
	alloc.allocated = state.Allocated
	alloc.indexToSubscriber = make(map[uint64]string)
	for subID, idx := range state.Allocated {
		alloc.indexToSubscriber[idx] = subID
	}

	// Recalculate allocated count
	alloc.allocatedCount = big.NewInt(int64(len(state.Allocated)))

	*a = *alloc
	return nil
}

// addIPOffset adds a big.Int offset to an IP address.
func addIPOffset(ip net.IP, offset *big.Int) net.IP {
	// Convert IP to big.Int
	ipInt := new(big.Int).SetBytes(ip.To16())

	// Add offset
	ipInt.Add(ipInt, offset)

	// Convert back to IP
	result := ipInt.Bytes()

	// Pad to 16 bytes for IPv6
	if len(result) < 16 {
		padded := make([]byte, 16)
		copy(padded[16-len(result):], result)
		result = padded
	}

	// Return as IPv4 if original was IPv4
	if ip.To4() != nil {
		return result[12:16]
	}
	return result
}

// ipOffset calculates the offset between two IPs as a big.Int.
func ipOffset(base, target net.IP) *big.Int {
	baseInt := new(big.Int).SetBytes(base.To16())
	targetInt := new(big.Int).SetBytes(target.To16())

	return new(big.Int).Sub(targetInt, baseInt)
}

// SetAllocation forcibly sets an allocation (for replaying from distributed store).
// This is used during startup to restore state from the authoritative store.
func (a *IPAllocator) SetAllocation(subscriberID string, prefix *net.IPNet) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx, err := a.getIndexByPrefix(prefix)
	if err != nil {
		return fmt.Errorf("prefix %s out of range for pool: %w", prefix, err)
	}

	// Check if already allocated to someone else
	if existing, exists := a.indexToSubscriber[idx]; exists && existing != subscriberID {
		return fmt.Errorf("prefix %s already allocated to %s", prefix, existing)
	}

	// Clear any existing allocation for this subscriber
	if oldIdx, exists := a.allocated[subscriberID]; exists {
		if oldIdx != idx {
			a.bitmap.SetBit(a.bitmap, int(oldIdx), 0)
			delete(a.indexToSubscriber, oldIdx)
			a.allocatedCount.Sub(a.allocatedCount, big.NewInt(1))
		}
	}

	// Set new allocation
	a.bitmap.SetBit(a.bitmap, int(idx), 1)
	a.allocated[subscriberID] = idx
	a.indexToSubscriber[idx] = subscriberID
	a.allocatedCount.Add(a.allocatedCount, big.NewInt(1))

	return nil
}
