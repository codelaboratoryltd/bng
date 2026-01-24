package allocator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
)

// EpochBitmapAllocator provides IP allocation with O(1) epoch-based expiration.
//
// Each IP slot has a 2-bit generation tag (0-3). The current epoch determines
// which generation is "active". IPs with generations older than the grace period
// are considered free and can be reallocated.
//
// This enables O(1) epoch advancement - just increment the counter, no bitmap scanning.
// Expiration is checked lazily during allocation.
//
// Memory: 2 bits per IP = 16KB for a /16 pool (65K IPs)
//
// Example with grace period of 1:
//
//	Current epoch: 2 (generation = 2 % 4 = 2)
//	Active generations: 1, 2 (current and previous)
//	Free generations: 0, 3 (older than grace period)
type EpochBitmapAllocator struct {
	mu sync.RWMutex

	// Network configuration
	baseIP       net.IP
	mask         net.IPMask
	prefixLength int
	totalIPs     uint64

	// 2-bit generation per IP, packed into bytes
	// Each byte holds 4 IP generations (2 bits each)
	generations []byte

	// Subscriber tracking: subscriberID -> IP index
	subscribers map[string]uint64

	// Reverse lookup: IP index -> subscriberID
	ipToSubscriber map[uint64]string

	// Epoch tracking
	currentEpoch uint64
	gracePeriod  uint64 // Number of epochs before expiration (default: 1)

	// Allocation hint for faster scanning
	nextFreeHint uint64
}

// EpochBitmapConfig contains configuration for EpochBitmapAllocator.
type EpochBitmapConfig struct {
	BaseNetwork  string // e.g., "10.0.0.0/16"
	PrefixLength int    // What to allocate (32 for individual IPs)
	GracePeriod  uint64 // Epochs before expiration (default: 1)
}

// NewEpochBitmapAllocator creates a new epoch-based bitmap allocator.
func NewEpochBitmapAllocator(config EpochBitmapConfig) (*EpochBitmapAllocator, error) {
	_, ipNet, err := net.ParseCIDR(config.BaseNetwork)
	if err != nil {
		return nil, fmt.Errorf("invalid base network: %w", err)
	}

	// Calculate total IPs
	ones, bits := ipNet.Mask.Size()
	if config.PrefixLength < ones || config.PrefixLength > bits {
		return nil, fmt.Errorf("prefix length %d out of range [%d, %d]", config.PrefixLength, ones, bits)
	}

	totalIPs := uint64(1) << (config.PrefixLength - ones)

	// Allocate generation storage: 2 bits per IP = 4 IPs per byte
	genBytes := (totalIPs + 3) / 4

	gracePeriod := config.GracePeriod
	if gracePeriod == 0 {
		gracePeriod = 1 // Default: 1 epoch grace period
	}

	return &EpochBitmapAllocator{
		baseIP:         ipNet.IP.To4(),
		mask:           ipNet.Mask,
		prefixLength:   config.PrefixLength,
		totalIPs:       totalIPs,
		generations:    make([]byte, genBytes), // All zeros = generation 0
		subscribers:    make(map[string]uint64),
		ipToSubscriber: make(map[uint64]string),
		currentEpoch:   2, // Start at epoch 2 so generation 0 is "expired"
		gracePeriod:    gracePeriod,
		nextFreeHint:   1, // Skip network address (index 0)
	}, nil
}

// Allocate assigns an IP to a subscriber.
// Returns the allocated IP or error if pool is exhausted.
func (a *EpochBitmapAllocator) Allocate(ctx context.Context, subscriberID string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if subscriber already has an allocation
	if idx, exists := a.subscribers[subscriberID]; exists {
		// Renew the existing allocation
		a.setGeneration(idx, a.currentGeneration())
		return a.indexToIP(idx), nil
	}

	// Find a free slot
	threshold := a.freeThreshold()

	// Start from hint for faster allocation
	for i := uint64(0); i < a.totalIPs; i++ {
		idx := (a.nextFreeHint + i) % a.totalIPs

		// Skip network address (index 0) and broadcast (last index)
		if idx == 0 || idx == a.totalIPs-1 {
			continue
		}

		gen := a.getGeneration(idx)
		if a.isGenerationFree(gen, threshold) {
			// Found free slot - allocate it
			a.setGeneration(idx, a.currentGeneration())
			a.subscribers[subscriberID] = idx
			a.ipToSubscriber[idx] = subscriberID
			a.nextFreeHint = (idx + 1) % a.totalIPs

			return a.indexToIP(idx), nil
		}
	}

	return nil, ErrPoolExhausted
}

// Renew updates the generation for an existing allocation.
// This extends the lease without changing the IP.
func (a *EpochBitmapAllocator) Renew(ctx context.Context, subscriberID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx, exists := a.subscribers[subscriberID]
	if !exists {
		return ErrNotFound
	}

	// Update to current generation
	a.setGeneration(idx, a.currentGeneration())
	return nil
}

// Release deallocates an IP immediately (before epoch expiry).
func (a *EpochBitmapAllocator) Release(ctx context.Context, subscriberID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx, exists := a.subscribers[subscriberID]
	if !exists {
		return nil // Already released
	}

	// Set to oldest possible generation (will be seen as free)
	oldestGen := (a.currentGeneration() + 2) % 4 // 2 epochs behind
	a.setGeneration(idx, oldestGen)

	delete(a.subscribers, subscriberID)
	delete(a.ipToSubscriber, idx)

	// Update hint if this slot is before current hint
	if idx < a.nextFreeHint {
		a.nextFreeHint = idx
	}

	return nil
}

// Lookup returns the IP allocated to a subscriber, or nil if not found.
func (a *EpochBitmapAllocator) Lookup(subscriberID string) net.IP {
	a.mu.RLock()
	defer a.mu.RUnlock()

	idx, exists := a.subscribers[subscriberID]
	if !exists {
		return nil
	}

	// Check if allocation is still valid (not expired)
	gen := a.getGeneration(idx)
	if a.isGenerationFree(gen, a.freeThreshold()) {
		return nil // Expired
	}

	return a.indexToIP(idx)
}

// LookupByIP returns the subscriber ID for an IP, or empty string if not found.
func (a *EpochBitmapAllocator) LookupByIP(ip net.IP) string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	idx, err := a.ipToIndex(ip)
	if err != nil {
		return ""
	}

	subscriberID, exists := a.ipToSubscriber[idx]
	if !exists {
		return ""
	}

	// Check if allocation is still valid
	gen := a.getGeneration(idx)
	if a.isGenerationFree(gen, a.freeThreshold()) {
		return "" // Expired
	}

	return subscriberID
}

// AdvanceEpoch increments the current epoch.
// This is O(1) - no bitmap scanning required!
// Expired allocations are cleaned up lazily during Allocate/Lookup.
func (a *EpochBitmapAllocator) AdvanceEpoch() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.currentEpoch++

	// Clean up expired subscriber mappings (lazy cleanup)
	// This is optional but helps keep maps small
	threshold := a.freeThreshold()
	for subscriberID, idx := range a.subscribers {
		gen := a.getGeneration(idx)
		if a.isGenerationFree(gen, threshold) {
			delete(a.subscribers, subscriberID)
			delete(a.ipToSubscriber, idx)
		}
	}

	return a.currentEpoch
}

// GetCurrentEpoch returns the current epoch value.
func (a *EpochBitmapAllocator) GetCurrentEpoch() uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.currentEpoch
}

// Stats returns allocation statistics.
func (a *EpochBitmapAllocator) Stats() (allocated, total uint64, utilization float64) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Count active allocations (not expired)
	threshold := a.freeThreshold()
	active := uint64(0)
	for idx := uint64(1); idx < a.totalIPs-1; idx++ {
		gen := a.getGeneration(idx)
		if !a.isGenerationFree(gen, threshold) {
			active++
		}
	}

	// Total usable IPs (excluding network and broadcast)
	usable := a.totalIPs - 2

	return active, usable, float64(active) / float64(usable)
}

// --- Internal helpers ---

// currentGeneration returns the current generation value (0-3).
func (a *EpochBitmapAllocator) currentGeneration() byte {
	return byte(a.currentEpoch % 4)
}

// freeThreshold returns the threshold for determining if a generation is free.
// A generation is free if it's more than gracePeriod epochs behind current.
func (a *EpochBitmapAllocator) freeThreshold() byte {
	// With gracePeriod=1 and 4 generations:
	// Current=0: active=[0,3], free=[1,2]
	// Current=1: active=[1,0], free=[2,3]
	// Current=2: active=[2,1], free=[3,0]
	// Current=3: active=[3,2], free=[0,1]
	return byte((a.currentEpoch - a.gracePeriod) % 4)
}

// isGenerationFree checks if a generation value indicates a free slot.
func (a *EpochBitmapAllocator) isGenerationFree(gen, threshold byte) bool {
	current := a.currentGeneration()

	// Generation is active if it's within gracePeriod of current
	// Using modular arithmetic for wraparound

	// Distance from gen to current (going forward)
	dist := (current - gen + 4) % 4

	// If distance > gracePeriod, it's expired/free
	return dist > byte(a.gracePeriod)
}

// getGeneration returns the 2-bit generation for an IP index.
func (a *EpochBitmapAllocator) getGeneration(idx uint64) byte {
	byteIdx := idx / 4
	bitOffset := (idx % 4) * 2

	return (a.generations[byteIdx] >> bitOffset) & 0x03
}

// setGeneration sets the 2-bit generation for an IP index.
func (a *EpochBitmapAllocator) setGeneration(idx uint64, gen byte) {
	byteIdx := idx / 4
	bitOffset := (idx % 4) * 2

	// Clear the 2 bits, then set new value
	mask := byte(0x03 << bitOffset)
	a.generations[byteIdx] = (a.generations[byteIdx] &^ mask) | ((gen & 0x03) << bitOffset)
}

// indexToIP converts an index to an IP address.
func (a *EpochBitmapAllocator) indexToIP(idx uint64) net.IP {
	ip := make(net.IP, 4)
	copy(ip, a.baseIP)

	// Add index as offset
	offset := uint32(idx)
	ip[0] += byte(offset >> 24)
	ip[1] += byte(offset >> 16)
	ip[2] += byte(offset >> 8)
	ip[3] += byte(offset)

	return ip
}

// ipToIndex converts an IP to an index.
func (a *EpochBitmapAllocator) ipToIndex(ip net.IP) (uint64, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}

	// Calculate offset from base
	offset := uint64(0)
	for i := 0; i < 4; i++ {
		offset = (offset << 8) | uint64(ip4[i]-a.baseIP[i])
	}

	if offset >= a.totalIPs {
		return 0, fmt.Errorf("IP not in pool")
	}

	return offset, nil
}

// --- Serialization ---

// EpochBitmapState represents the serializable state of the allocator.
type EpochBitmapState struct {
	BaseNetwork    string            `json:"base_network"`
	PrefixLength   int               `json:"prefix_length"`
	CurrentEpoch   uint64            `json:"current_epoch"`
	GracePeriod    uint64            `json:"grace_period"`
	Generations    []byte            `json:"generations"`
	Subscribers    map[string]uint64 `json:"subscribers"`
	IPToSubscriber map[uint64]string `json:"ip_to_subscriber"`
}

// MarshalJSON implements json.Marshaler.
func (a *EpochBitmapAllocator) MarshalJSON() ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ones, bits := a.mask.Size()
	baseNetwork := fmt.Sprintf("%s/%d", a.baseIP.String(), ones+(bits-a.prefixLength))

	state := EpochBitmapState{
		BaseNetwork:    baseNetwork,
		PrefixLength:   a.prefixLength,
		CurrentEpoch:   a.currentEpoch,
		GracePeriod:    a.gracePeriod,
		Generations:    a.generations,
		Subscribers:    a.subscribers,
		IPToSubscriber: a.ipToSubscriber,
	}

	return json.Marshal(state)
}

// UnmarshalJSON implements json.Unmarshaler.
func (a *EpochBitmapAllocator) UnmarshalJSON(data []byte) error {
	var state EpochBitmapState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	// Create new allocator with config
	config := EpochBitmapConfig{
		BaseNetwork:  state.BaseNetwork,
		PrefixLength: state.PrefixLength,
		GracePeriod:  state.GracePeriod,
	}

	temp, err := NewEpochBitmapAllocator(config)
	if err != nil {
		return err
	}

	// Restore state
	a.mu.Lock()
	defer a.mu.Unlock()

	a.baseIP = temp.baseIP
	a.mask = temp.mask
	a.prefixLength = temp.prefixLength
	a.totalIPs = temp.totalIPs
	a.generations = state.Generations
	a.subscribers = state.Subscribers
	a.ipToSubscriber = state.IPToSubscriber
	a.currentEpoch = state.CurrentEpoch
	a.gracePeriod = state.GracePeriod

	return nil
}

// Note: ErrPoolExhausted is defined in bitmap.go
