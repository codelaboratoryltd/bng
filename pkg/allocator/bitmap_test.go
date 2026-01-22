package allocator

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBitmapAllocator_IPv4(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		prefixLen   int
		wantTotal   int
		wantErr     bool
		errContains string
	}{
		{
			name:      "IPv4 /24 allocating /32",
			network:   "10.0.0.0/24",
			prefixLen: 32,
			wantTotal: 254, // 256 - 2 (network + broadcast)
		},
		{
			name:      "IPv4 /16 allocating /24",
			network:   "192.168.0.0/16",
			prefixLen: 24,
			wantTotal: 256, // No reserved addresses for prefix allocation
		},
		{
			name:      "IPv4 /30 allocating /32",
			network:   "10.0.0.0/30",
			prefixLen: 32,
			wantTotal: 2, // 4 - 2 (network + broadcast)
		},
		{
			name:        "invalid prefix length smaller than pool",
			network:     "10.0.0.0/24",
			prefixLen:   16,
			wantErr:     true,
			errContains: "cannot be smaller",
		},
		{
			name:        "invalid prefix length exceeds address size",
			network:     "10.0.0.0/24",
			prefixLen:   64,
			wantErr:     true,
			errContains: "exceeds address size",
		},
		{
			name:        "invalid network CIDR",
			network:     "not-a-cidr",
			prefixLen:   32,
			wantErr:     true,
			errContains: "invalid base network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BitmapConfig{
				BaseNetwork: tt.network,
				PrefixLen:   tt.prefixLen,
			}

			alloc, err := NewBitmapAllocator(cfg)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, alloc)

			stats := alloc.Stats()
			assert.Equal(t, tt.wantTotal, stats.Total)
			assert.Equal(t, 0, stats.Allocated)
			assert.Equal(t, tt.wantTotal, stats.Available)
			assert.False(t, stats.IsIPv6)
		})
	}
}

func TestNewBitmapAllocator_IPv6(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		prefixLen int
		wantTotal int
	}{
		{
			name:      "IPv6 /48 allocating /64",
			network:   "2001:db8::/48",
			prefixLen: 64,
			wantTotal: 65536, // 2^(64-48) = 2^16
		},
		{
			name:      "IPv6 /48 allocating /56 (PD)",
			network:   "2001:db8::/48",
			prefixLen: 56,
			wantTotal: 256, // 2^(56-48) = 2^8
		},
		{
			name:      "IPv6 /120 allocating /128",
			network:   "2001:db8:1234:5678:9abc:def0:1234:5600/120",
			prefixLen: 128,
			wantTotal: 256, // 2^(128-120) = 256 individual addresses
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := BitmapConfig{
				BaseNetwork: tt.network,
				PrefixLen:   tt.prefixLen,
			}

			alloc, err := NewBitmapAllocator(cfg)

			require.NoError(t, err)
			require.NotNil(t, alloc)

			stats := alloc.Stats()
			assert.Equal(t, tt.wantTotal, stats.Total)
			assert.Equal(t, 0, stats.Allocated)
			assert.True(t, stats.IsIPv6)
			assert.Equal(t, 0, stats.Unavailable) // No reserved addresses for IPv6
		})
	}
}

func TestBitmapAllocator_Allocate_IPv4(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	// First allocation should get .1 (skipping .0 network address)
	prefix, err := alloc.Allocate("sub-001")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1/32", prefix.String())

	// Second allocation should get .2
	prefix, err = alloc.Allocate("sub-002")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2/32", prefix.String())

	// Re-allocating same subscriber returns same address
	prefix, err = alloc.Allocate("sub-001")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1/32", prefix.String())

	stats := alloc.Stats()
	assert.Equal(t, 2, stats.Allocated)
	assert.Equal(t, 252, stats.Available)
}

func TestBitmapAllocator_Allocate_IPv6(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "2001:db8::/48",
		PrefixLen:   64,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	// First allocation
	prefix, err := alloc.Allocate("sub-001")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::/64", prefix.String())

	// Second allocation
	prefix, err = alloc.Allocate("sub-002")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8:0:1::/64", prefix.String())

	// Third allocation
	prefix, err = alloc.Allocate("sub-003")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8:0:2::/64", prefix.String())

	stats := alloc.Stats()
	assert.Equal(t, 3, stats.Allocated)
}

func TestBitmapAllocator_PrefixDelegation(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "2001:db8::/48",
		PrefixLen:   56,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	// First /56 delegation
	prefix, err := alloc.Allocate("customer-001")
	require.NoError(t, err)
	ones, bits := prefix.Mask.Size()
	assert.Equal(t, 56, ones)
	assert.Equal(t, 128, bits)
	assert.Equal(t, "2001:db8::/56", prefix.String())

	// Second /56 delegation
	prefix, err = alloc.Allocate("customer-002")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8:0:100::/56", prefix.String())
}

func TestBitmapAllocator_Release(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	// Allocate some addresses
	_, err = alloc.Allocate("sub-001")
	require.NoError(t, err)
	_, err = alloc.Allocate("sub-002")
	require.NoError(t, err)
	_, err = alloc.Allocate("sub-003")
	require.NoError(t, err)

	assert.Equal(t, 3, alloc.Stats().Allocated)

	// Release middle allocation
	err = alloc.Release("sub-002")
	require.NoError(t, err)
	assert.Equal(t, 2, alloc.Stats().Allocated)

	// Releasing again should error
	err = alloc.Release("sub-002")
	assert.Error(t, err)

	// Next allocation should get the released address
	prefix, err := alloc.Allocate("sub-004")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2/32", prefix.String())
}

func TestBitmapAllocator_Get(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	// Get non-existent allocation
	prefix, ok := alloc.Get("sub-001")
	assert.False(t, ok)
	assert.Nil(t, prefix)

	// Allocate and get
	allocated, err := alloc.Allocate("sub-001")
	require.NoError(t, err)

	prefix, ok = alloc.Get("sub-001")
	assert.True(t, ok)
	assert.Equal(t, allocated.String(), prefix.String())
}

func TestBitmapAllocator_GetByPrefix(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	prefix, err := alloc.Allocate("sub-001")
	require.NoError(t, err)

	// Look up by prefix
	subscriberID, ok := alloc.GetByPrefix(prefix)
	assert.True(t, ok)
	assert.Equal(t, "sub-001", subscriberID)

	// Non-allocated prefix
	unallocated := &net.IPNet{
		IP:   net.ParseIP("10.0.0.100"),
		Mask: net.CIDRMask(32, 32),
	}
	subscriberID, ok = alloc.GetByPrefix(unallocated)
	assert.False(t, ok)
	assert.Empty(t, subscriberID)

	// Out of range prefix
	outOfRange := &net.IPNet{
		IP:   net.ParseIP("192.168.1.1"),
		Mask: net.CIDRMask(32, 32),
	}
	subscriberID, ok = alloc.GetByPrefix(outOfRange)
	assert.False(t, ok)
}

func TestBitmapAllocator_PoolExhaustion(t *testing.T) {
	// Small pool for testing exhaustion
	cfg := BitmapConfig{
		BaseNetwork: "10.0.0.0/30",
		PrefixLen:   32,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	stats := alloc.Stats()
	assert.Equal(t, 2, stats.Total) // 4 addresses minus network and broadcast

	// Allocate all available
	_, err = alloc.Allocate("sub-001")
	require.NoError(t, err)
	_, err = alloc.Allocate("sub-002")
	require.NoError(t, err)

	// Pool should be exhausted
	_, err = alloc.Allocate("sub-003")
	assert.ErrorIs(t, err, ErrPoolExhausted)

	// After release, allocation should work
	err = alloc.Release("sub-001")
	require.NoError(t, err)

	prefix, err := alloc.Allocate("sub-003")
	require.NoError(t, err)
	assert.NotNil(t, prefix)
}

func TestBitmapAllocator_MarkUnavailable(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	// Mark gateway as unavailable
	gateway := &net.IPNet{
		IP:   net.ParseIP("10.0.0.1"),
		Mask: net.CIDRMask(32, 32),
	}
	alloc.MarkUnavailable(gateway)

	// First allocation should skip the gateway
	prefix, err := alloc.Allocate("sub-001")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2/32", prefix.String())
}

func TestBitmapAllocator_Concurrency(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "10.0.0.0/16",
		PrefixLen:   32,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	// Concurrently allocate many prefixes
	const numGoroutines = 100
	const allocsPerGoroutine = 10

	var wg sync.WaitGroup
	results := make(chan *net.IPNet, numGoroutines*allocsPerGoroutine)
	errors := make(chan error, numGoroutines*allocsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < allocsPerGoroutine; j++ {
				subscriberID := fmt.Sprintf("sub-%d-%d", goroutineID, j)
				prefix, err := alloc.Allocate(subscriberID)
				if err != nil {
					errors <- err
					return
				}
				results <- prefix
			}
		}(i)
	}

	wg.Wait()
	close(results)
	close(errors)

	// Check no errors
	for err := range errors {
		t.Errorf("concurrent allocation error: %v", err)
	}

	// Check all allocations are unique
	seen := make(map[string]bool)
	for prefix := range results {
		key := prefix.String()
		if seen[key] {
			t.Errorf("duplicate allocation: %s", key)
		}
		seen[key] = true
	}

	assert.Equal(t, numGoroutines*allocsPerGoroutine, len(seen))
	assert.Equal(t, numGoroutines*allocsPerGoroutine, alloc.Stats().Allocated)
}

func TestBitmapAllocator_IPv4_IndexConversion(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	// Allocate several addresses and verify conversion is correct
	addresses := []string{
		"10.0.0.1/32",
		"10.0.0.2/32",
		"10.0.0.3/32",
		"10.0.0.4/32",
		"10.0.0.5/32",
	}

	for i, expected := range addresses {
		subscriberID := fmt.Sprintf("sub-%03d", i+1)
		prefix, err := alloc.Allocate(subscriberID)
		require.NoError(t, err)
		assert.Equal(t, expected, prefix.String(), "allocation %d", i+1)
	}
}

func TestBitmapAllocator_IPv6_IndexConversion(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "2001:db8:abcd::/48",
		PrefixLen:   64,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	// Allocate several /64s and verify
	prefix1, _ := alloc.Allocate("sub-001")
	assert.Equal(t, "2001:db8:abcd::/64", prefix1.String())

	prefix2, _ := alloc.Allocate("sub-002")
	assert.Equal(t, "2001:db8:abcd:1::/64", prefix2.String())

	prefix3, _ := alloc.Allocate("sub-003")
	assert.Equal(t, "2001:db8:abcd:2::/64", prefix3.String())
}

func TestBitmapStats(t *testing.T) {
	cfg := BitmapConfig{
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
	}

	alloc, err := NewBitmapAllocator(cfg)
	require.NoError(t, err)

	stats := alloc.Stats()
	assert.Equal(t, 254, stats.Total)
	assert.Equal(t, 0, stats.Allocated)
	assert.Equal(t, 254, stats.Available)
	assert.Equal(t, 2, stats.Unavailable) // network + broadcast
	assert.Equal(t, 32, stats.PrefixLen)
	assert.False(t, stats.IsIPv6)

	// After some allocations
	alloc.Allocate("sub-001")
	alloc.Allocate("sub-002")

	stats = alloc.Stats()
	assert.Equal(t, 254, stats.Total)
	assert.Equal(t, 2, stats.Allocated)
	assert.Equal(t, 252, stats.Available)
}
