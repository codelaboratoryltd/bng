package allocator

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEpochBitmapAllocator(t *testing.T) {
	tests := []struct {
		name        string
		config      EpochBitmapConfig
		wantErr     bool
		wantTotalIP uint64
	}{
		{
			name: "valid /24 pool",
			config: EpochBitmapConfig{
				BaseNetwork:  "10.0.0.0/24",
				PrefixLength: 32,
				GracePeriod:  1,
			},
			wantErr:     false,
			wantTotalIP: 256,
		},
		{
			name: "valid /16 pool",
			config: EpochBitmapConfig{
				BaseNetwork:  "10.0.0.0/16",
				PrefixLength: 32,
				GracePeriod:  1,
			},
			wantErr:     false,
			wantTotalIP: 65536,
		},
		{
			name: "invalid network",
			config: EpochBitmapConfig{
				BaseNetwork:  "invalid",
				PrefixLength: 32,
			},
			wantErr: true,
		},
		{
			name: "prefix length out of range",
			config: EpochBitmapConfig{
				BaseNetwork:  "10.0.0.0/24",
				PrefixLength: 16, // Less than network prefix
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alloc, err := NewEpochBitmapAllocator(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantTotalIP, alloc.totalIPs)
		})
	}
}

func TestEpochBitmapAllocator_Allocate(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate first subscriber
	ip1, err := alloc.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	assert.NotNil(t, ip1)
	assert.Equal(t, "10.0.0.1", ip1.String()) // First usable IP

	// Allocate second subscriber
	ip2, err := alloc.Allocate(ctx, "sub-002")
	require.NoError(t, err)
	assert.NotNil(t, ip2)
	assert.Equal(t, "10.0.0.2", ip2.String())

	// Re-allocate same subscriber should return same IP
	ip1Again, err := alloc.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	assert.Equal(t, ip1.String(), ip1Again.String())
}

func TestEpochBitmapAllocator_Lookup(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Lookup non-existent subscriber
	ip := alloc.Lookup("sub-001")
	assert.Nil(t, ip)

	// Allocate and lookup
	allocated, err := alloc.Allocate(ctx, "sub-001")
	require.NoError(t, err)

	ip = alloc.Lookup("sub-001")
	assert.Equal(t, allocated.String(), ip.String())
}

func TestEpochBitmapAllocator_LookupByIP(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate
	ip, err := alloc.Allocate(ctx, "sub-001")
	require.NoError(t, err)

	// Lookup by IP
	subscriberID := alloc.LookupByIP(ip)
	assert.Equal(t, "sub-001", subscriberID)

	// Lookup unknown IP
	unknownIP := []byte{10, 0, 0, 100}
	subscriberID = alloc.LookupByIP(unknownIP)
	assert.Empty(t, subscriberID)
}

func TestEpochBitmapAllocator_Release(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate
	ip1, err := alloc.Allocate(ctx, "sub-001")
	require.NoError(t, err)

	// Release
	err = alloc.Release(ctx, "sub-001")
	require.NoError(t, err)

	// Lookup should return nil
	ip := alloc.Lookup("sub-001")
	assert.Nil(t, ip)

	// Allocate again should get same IP (it's now free)
	ip2, err := alloc.Allocate(ctx, "sub-002")
	require.NoError(t, err)
	assert.Equal(t, ip1.String(), ip2.String())
}

func TestEpochBitmapAllocator_Renew(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Renew non-existent should fail
	err = alloc.Renew(ctx, "sub-001")
	assert.Error(t, err)

	// Allocate and renew
	ip, err := alloc.Allocate(ctx, "sub-001")
	require.NoError(t, err)

	err = alloc.Renew(ctx, "sub-001")
	require.NoError(t, err)

	// IP should still be the same
	renewedIP := alloc.Lookup("sub-001")
	assert.Equal(t, ip.String(), renewedIP.String())
}

func TestEpochBitmapAllocator_EpochExpiration(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1, // 1 epoch grace period
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Get initial epoch (starts at 2 so initial zeros are "free")
	initialEpoch := alloc.GetCurrentEpoch()
	t.Logf("Initial epoch: %d", initialEpoch)

	// Allocate at current epoch
	ip1, err := alloc.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	t.Logf("Allocated at epoch %d: %s", initialEpoch, ip1)

	// Advance to next epoch - sub-001 still valid (within grace period)
	alloc.AdvanceEpoch()
	t.Logf("Advanced to epoch %d", alloc.GetCurrentEpoch())

	ip := alloc.Lookup("sub-001")
	assert.NotNil(t, ip, "sub-001 should still be valid (within grace period)")

	// Advance again - sub-001 should expire (now 2 epochs behind)
	alloc.AdvanceEpoch()
	t.Logf("Advanced to epoch %d", alloc.GetCurrentEpoch())

	ip = alloc.Lookup("sub-001")
	assert.Nil(t, ip, "sub-001 should be expired (2 epochs behind)")

	// The IP should be reallocatable
	ip2, err := alloc.Allocate(ctx, "sub-002")
	require.NoError(t, err)
	assert.Equal(t, ip1.String(), ip2.String(), "Expired IP should be reused")
}

func TestEpochBitmapAllocator_RenewalExtendsLease(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate at epoch 0
	ip1, err := alloc.Allocate(ctx, "sub-001")
	require.NoError(t, err)

	// Advance to epoch 1 and renew
	alloc.AdvanceEpoch()
	err = alloc.Renew(ctx, "sub-001")
	require.NoError(t, err)

	// Advance to epoch 2 - sub-001 should still be valid (renewed at epoch 1)
	alloc.AdvanceEpoch()

	ip := alloc.Lookup("sub-001")
	assert.NotNil(t, ip, "sub-001 should still be valid after renewal")
	assert.Equal(t, ip1.String(), ip.String())

	// Advance to epoch 3 - now sub-001 should expire
	alloc.AdvanceEpoch()

	ip = alloc.Lookup("sub-001")
	assert.Nil(t, ip, "sub-001 should be expired at epoch 3")
}

func TestEpochBitmapAllocator_Stats(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Initial stats
	allocated, total, util := alloc.Stats()
	assert.Equal(t, uint64(0), allocated)
	assert.Equal(t, uint64(254), total) // 256 - 2 (network + broadcast)
	assert.Equal(t, 0.0, util)

	// Allocate some IPs
	for i := 0; i < 10; i++ {
		_, err := alloc.Allocate(ctx, fmt.Sprintf("sub-%03d", i))
		require.NoError(t, err)
	}

	allocated, total, util = alloc.Stats()
	assert.Equal(t, uint64(10), allocated)
	assert.Equal(t, uint64(254), total)
	assert.InDelta(t, 10.0/254.0, util, 0.001)
}

func TestEpochBitmapAllocator_PoolExhaustion(t *testing.T) {
	// Small pool for testing exhaustion
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/28", // 16 IPs, 14 usable
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate all usable IPs (14)
	for i := 0; i < 14; i++ {
		_, err := alloc.Allocate(ctx, fmt.Sprintf("sub-%03d", i))
		require.NoError(t, err, "allocation %d should succeed", i)
	}

	// Next allocation should fail
	_, err = alloc.Allocate(ctx, "sub-overflow")
	assert.ErrorIs(t, err, ErrPoolExhausted)
}

func TestEpochBitmapAllocator_GenerationBits(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	// Test get/set generation for various indices
	testCases := []struct {
		idx uint64
		gen byte
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{3, 3},
		{4, 0}, // Next byte
		{5, 1},
		{100, 2},
		{255, 3},
	}

	for _, tc := range testCases {
		alloc.setGeneration(tc.idx, tc.gen)
		got := alloc.getGeneration(tc.idx)
		assert.Equal(t, tc.gen, got, "index %d", tc.idx)
	}

	// Verify no cross-contamination between indices
	alloc.setGeneration(0, 3)
	alloc.setGeneration(1, 2)
	alloc.setGeneration(2, 1)
	alloc.setGeneration(3, 0)

	assert.Equal(t, byte(3), alloc.getGeneration(0))
	assert.Equal(t, byte(2), alloc.getGeneration(1))
	assert.Equal(t, byte(1), alloc.getGeneration(2))
	assert.Equal(t, byte(0), alloc.getGeneration(3))
}

func TestEpochBitmapAllocator_EpochWraparound(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test multiple epoch cycles
	for cycle := 0; cycle < 3; cycle++ {
		// Allocate at start of cycle
		ip, err := alloc.Allocate(ctx, fmt.Sprintf("sub-cycle-%d", cycle))
		require.NoError(t, err)
		t.Logf("Cycle %d, epoch %d: allocated %s", cycle, alloc.GetCurrentEpoch(), ip)

		// Advance 4 epochs (full wrap)
		for i := 0; i < 4; i++ {
			alloc.AdvanceEpoch()
		}

		// Previous allocation should be expired
		ip = alloc.Lookup(fmt.Sprintf("sub-cycle-%d", cycle))
		assert.Nil(t, ip, "Allocation from cycle %d should be expired", cycle)
	}
}

func TestEpochBitmapAllocator_Serialization(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/24",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate some IPs and advance epoch
	_, err = alloc.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	_, err = alloc.Allocate(ctx, "sub-002")
	require.NoError(t, err)

	alloc.AdvanceEpoch()

	_, err = alloc.Allocate(ctx, "sub-003")
	require.NoError(t, err)

	// Serialize
	data, err := json.Marshal(alloc)
	require.NoError(t, err)

	// Deserialize into new allocator
	var restored EpochBitmapAllocator
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	// Verify state matches
	assert.Equal(t, alloc.GetCurrentEpoch(), restored.GetCurrentEpoch())

	// Verify allocations preserved
	ip1 := alloc.Lookup("sub-001")
	ip1Restored := restored.Lookup("sub-001")
	assert.Equal(t, ip1.String(), ip1Restored.String())

	ip2 := alloc.Lookup("sub-002")
	ip2Restored := restored.Lookup("sub-002")
	assert.Equal(t, ip2.String(), ip2Restored.String())

	ip3 := alloc.Lookup("sub-003")
	ip3Restored := restored.Lookup("sub-003")
	assert.Equal(t, ip3.String(), ip3Restored.String())
}

func TestEpochBitmapAllocator_ConcurrentAccess(t *testing.T) {
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/16",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	ctx := context.Background()
	done := make(chan bool)

	// Concurrent allocations
	for i := 0; i < 100; i++ {
		go func(id int) {
			_, err := alloc.Allocate(ctx, fmt.Sprintf("sub-%05d", id))
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	// Concurrent lookups
	for i := 0; i < 100; i++ {
		go func(id int) {
			alloc.Lookup(fmt.Sprintf("sub-%05d", id))
			done <- true
		}(i)
	}

	// Wait for all
	for i := 0; i < 200; i++ {
		<-done
	}

	allocated, _, _ := alloc.Stats()
	assert.Equal(t, uint64(100), allocated)
}

func TestEpochBitmapAllocator_MemoryEfficiency(t *testing.T) {
	// /16 pool = 65536 IPs
	// 2 bits per IP = 16KB for generations
	config := EpochBitmapConfig{
		BaseNetwork:  "10.0.0.0/16",
		PrefixLength: 32,
		GracePeriod:  1,
	}
	alloc, err := NewEpochBitmapAllocator(config)
	require.NoError(t, err)

	// Verify generation array size
	expectedBytes := (65536 + 3) / 4 // 16384 bytes
	assert.Equal(t, expectedBytes, len(alloc.generations))
	t.Logf("Memory for /16 pool: %d bytes (%.2f KB)", len(alloc.generations), float64(len(alloc.generations))/1024)
}
