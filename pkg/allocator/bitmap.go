// Package allocator provides bitmap-based IP and prefix allocation.
package allocator

import (
	"fmt"
	"math/big"
	"net"
	"sync"
)

// BitmapAllocator provides collision-free allocation using a bitmap.
// Each bit represents a prefix (not an individual IP), enabling efficient
// allocation of IPv4 addresses, IPv6 addresses, or IPv6 prefix delegations.
//
// Examples:
//   - IPv4 /24 pool allocating /32: 256 bits = 32 bytes
//   - IPv6 /48 pool allocating /64: 65536 bits = 8 KB
//   - IPv6 /48 pool allocating /56 (PD): 256 bits = 32 bytes
type BitmapAllocator struct {
	mu sync.RWMutex

	// Pool configuration
	baseIP    net.IP // Base IP of the pool
	baseMask  int    // Pool prefix length (e.g., 24 for /24)
	prefixLen int    // Allocation prefix length (e.g., 32 for individual IPs)
	isIPv6    bool   // True for IPv6, false for IPv4
	totalBits int    // Total allocatable prefixes

	// Bitmap state
	bitmap *big.Int // One bit per allocatable prefix

	// Allocation tracking
	allocations map[string]int // subscriberID -> bit index
	byIndex     map[int]string // bit index -> subscriberID (reverse lookup)

	// Allocation cursor (for sequential allocation)
	nextFree int

	// Statistics
	allocated int
}

// BitmapConfig configures a bitmap allocator.
type BitmapConfig struct {
	// BaseNetwork is the pool's base network in CIDR notation (e.g., "10.0.0.0/24")
	BaseNetwork string

	// PrefixLen is what we're allocating. For IPv4 addresses, use 32.
	// For IPv6 /64 allocations, use 64. For /56 prefix delegation, use 56.
	PrefixLen int
}

// NewBitmapAllocator creates a new bitmap allocator.
func NewBitmapAllocator(cfg BitmapConfig) (*BitmapAllocator, error) {
	ip, network, err := net.ParseCIDR(cfg.BaseNetwork)
	if err != nil {
		return nil, fmt.Errorf("invalid base network: %w", err)
	}

	baseMask, totalBits := network.Mask.Size()
	isIPv6 := ip.To4() == nil

	// Validate prefix length
	if cfg.PrefixLen < baseMask {
		return nil, fmt.Errorf("prefix length %d cannot be smaller than pool mask %d", cfg.PrefixLen, baseMask)
	}
	if cfg.PrefixLen > totalBits {
		return nil, fmt.Errorf("prefix length %d exceeds address size %d", cfg.PrefixLen, totalBits)
	}

	// Calculate number of allocatable prefixes
	// For a /24 pool allocating /32s: 2^(32-24) = 256 prefixes
	prefixBits := cfg.PrefixLen - baseMask
	numPrefixes := 1 << prefixBits

	// For IPv4, exclude network and broadcast addresses
	// (only when allocating individual addresses, not prefixes)
	if !isIPv6 && cfg.PrefixLen == 32 && numPrefixes > 2 {
		// We'll handle this by marking first and last as unavailable after creation
	}

	baseIP := network.IP
	if isIPv6 {
		baseIP = ip.To16()
	} else {
		baseIP = ip.To4()
	}

	a := &BitmapAllocator{
		baseIP:      baseIP,
		baseMask:    baseMask,
		prefixLen:   cfg.PrefixLen,
		isIPv6:      isIPv6,
		totalBits:   numPrefixes,
		bitmap:      big.NewInt(0),
		allocations: make(map[string]int),
		byIndex:     make(map[int]string),
		nextFree:    0,
	}

	// For IPv4 /32 allocation, mark network (.0) and broadcast (.255) as unavailable
	if !isIPv6 && cfg.PrefixLen == 32 && numPrefixes > 2 {
		a.bitmap.SetBit(a.bitmap, 0, 1)             // Network address
		a.bitmap.SetBit(a.bitmap, numPrefixes-1, 1) // Broadcast address
		a.nextFree = 1
	}

	return a, nil
}

// Allocate assigns a prefix to a subscriber.
// Returns the allocated prefix or an error if the pool is exhausted.
func (a *BitmapAllocator) Allocate(subscriberID string) (*net.IPNet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if already allocated
	if idx, exists := a.allocations[subscriberID]; exists {
		return a.indexToPrefix(idx), nil
	}

	// Find next free bit
	idx, err := a.findFreeBit()
	if err != nil {
		return nil, err
	}

	// Mark as allocated
	a.bitmap.SetBit(a.bitmap, idx, 1)
	a.allocations[subscriberID] = idx
	a.byIndex[idx] = subscriberID
	a.allocated++

	return a.indexToPrefix(idx), nil
}

// Release frees a previously allocated prefix.
func (a *BitmapAllocator) Release(subscriberID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx, exists := a.allocations[subscriberID]
	if !exists {
		return fmt.Errorf("no allocation for subscriber %s", subscriberID)
	}

	// Clear bit
	a.bitmap.SetBit(a.bitmap, idx, 0)
	delete(a.allocations, subscriberID)
	delete(a.byIndex, idx)
	a.allocated--

	// Update cursor if this index is earlier
	if idx < a.nextFree {
		a.nextFree = idx
	}

	return nil
}

// Get returns the allocation for a subscriber.
func (a *BitmapAllocator) Get(subscriberID string) (*net.IPNet, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	idx, exists := a.allocations[subscriberID]
	if !exists {
		return nil, false
	}

	return a.indexToPrefix(idx), true
}

// GetByPrefix returns the subscriber for a given prefix.
func (a *BitmapAllocator) GetByPrefix(prefix *net.IPNet) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	idx := a.prefixToIndex(prefix)
	if idx < 0 || idx >= a.totalBits {
		return "", false
	}

	subscriberID, exists := a.byIndex[idx]
	return subscriberID, exists
}

// Stats returns allocator statistics.
func (a *BitmapAllocator) Stats() BitmapStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Calculate unavailable (reserved) count
	unavailable := 0
	if !a.isIPv6 && a.prefixLen == 32 && a.totalBits > 2 {
		unavailable = 2 // Network and broadcast
	}

	return BitmapStats{
		Total:       a.totalBits - unavailable,
		Allocated:   a.allocated,
		Available:   a.totalBits - unavailable - a.allocated,
		Unavailable: unavailable,
		PrefixLen:   a.prefixLen,
		IsIPv6:      a.isIPv6,
	}
}

// BitmapStats contains allocator statistics.
type BitmapStats struct {
	Total       int
	Allocated   int
	Available   int
	Unavailable int
	PrefixLen   int
	IsIPv6      bool
}

// findFreeBit finds the next available bit index.
func (a *BitmapAllocator) findFreeBit() (int, error) {
	// Start from cursor
	for i := a.nextFree; i < a.totalBits; i++ {
		if a.bitmap.Bit(i) == 0 {
			a.nextFree = i + 1
			return i, nil
		}
	}

	// Wrap around and search from beginning
	for i := 0; i < a.nextFree; i++ {
		if a.bitmap.Bit(i) == 0 {
			a.nextFree = i + 1
			return i, nil
		}
	}

	return 0, ErrPoolExhausted
}

// indexToPrefix converts a bit index to a network prefix.
func (a *BitmapAllocator) indexToPrefix(idx int) *net.IPNet {
	// Calculate the step size (IPs per prefix)
	// For /32 allocation from /24: step = 1
	// For /64 allocation from /48: step = 2^(128-64) - but we work with offsets

	var ip net.IP
	if a.isIPv6 {
		ip = a.indexToIPv6(idx)
	} else {
		ip = a.indexToIPv4(idx)
	}

	bits := 32
	if a.isIPv6 {
		bits = 128
	}

	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(a.prefixLen, bits),
	}
}

// indexToIPv4 converts a bit index to an IPv4 address.
func (a *BitmapAllocator) indexToIPv4(idx int) net.IP {
	ip := make(net.IP, 4)
	copy(ip, a.baseIP.To4())

	// Add offset
	ip[0] += byte((idx >> 24) & 0xFF)
	ip[1] += byte((idx >> 16) & 0xFF)
	ip[2] += byte((idx >> 8) & 0xFF)
	ip[3] += byte(idx & 0xFF)

	return ip
}

// indexToIPv6 converts a bit index to an IPv6 address.
func (a *BitmapAllocator) indexToIPv6(idx int) net.IP {
	ip := make(net.IP, 16)
	copy(ip, a.baseIP.To16())

	// Calculate offset in bits
	// For /64 from /48: each index represents a /64, so we shift by (64-48)=16 bits
	// The offset goes into bits [baseMask : prefixLen]
	shiftBits := 128 - a.prefixLen

	// Convert index to big.Int for math
	offset := big.NewInt(int64(idx))
	offset.Lsh(offset, uint(shiftBits))

	// Add to base IP
	baseInt := new(big.Int).SetBytes(a.baseIP.To16())
	resultInt := new(big.Int).Add(baseInt, offset)

	// Convert back to IP
	resultBytes := resultInt.Bytes()

	// Pad to 16 bytes
	if len(resultBytes) < 16 {
		padded := make([]byte, 16)
		copy(padded[16-len(resultBytes):], resultBytes)
		resultBytes = padded
	}

	copy(ip, resultBytes)
	return ip
}

// prefixToIndex converts a network prefix back to a bit index.
func (a *BitmapAllocator) prefixToIndex(prefix *net.IPNet) int {
	if a.isIPv6 {
		return a.ipv6ToIndex(prefix.IP)
	}
	return a.ipv4ToIndex(prefix.IP)
}

// ipv4ToIndex converts an IPv4 address to a bit index.
func (a *BitmapAllocator) ipv4ToIndex(ip net.IP) int {
	ip4 := ip.To4()
	base := a.baseIP.To4()

	idx := 0
	idx |= int(ip4[0]-base[0]) << 24
	idx |= int(ip4[1]-base[1]) << 16
	idx |= int(ip4[2]-base[2]) << 8
	idx |= int(ip4[3] - base[3])

	return idx
}

// ipv6ToIndex converts an IPv6 address to a bit index.
func (a *BitmapAllocator) ipv6ToIndex(ip net.IP) int {
	ip16 := ip.To16()
	base := a.baseIP.To16()

	ipInt := new(big.Int).SetBytes(ip16)
	baseInt := new(big.Int).SetBytes(base)

	// Calculate offset
	offset := new(big.Int).Sub(ipInt, baseInt)

	// Shift right to get index
	shiftBits := 128 - a.prefixLen
	offset.Rsh(offset, uint(shiftBits))

	return int(offset.Int64())
}

// MarkUnavailable marks a specific prefix as unavailable (e.g., reserved gateway).
func (a *BitmapAllocator) MarkUnavailable(prefix *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx := a.prefixToIndex(prefix)
	if idx >= 0 && idx < a.totalBits {
		a.bitmap.SetBit(a.bitmap, idx, 1)
	}
}
