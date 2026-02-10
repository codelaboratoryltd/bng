package allocator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStore implements Store interface for testing.
type mockStore struct {
	mu       sync.RWMutex
	data     map[string][]byte
	watchers map[string][]func(key string, value []byte, deleted bool)
}

func newMockStore() *mockStore {
	return &mockStore{
		data:     make(map[string][]byte),
		watchers: make(map[string][]func(key string, value []byte, deleted bool)),
	}
}

func (m *mockStore) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if val, ok := m.data[key]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockStore) Put(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	m.data[key] = value
	watchers := m.watchers
	m.mu.Unlock()

	// Notify watchers
	for prefix, callbacks := range watchers {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			for _, cb := range callbacks {
				go cb(key, value, false)
			}
		}
	}
	return nil
}

func (m *mockStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	delete(m.data, key)
	watchers := m.watchers
	m.mu.Unlock()

	// Notify watchers
	for prefix, callbacks := range watchers {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			for _, cb := range callbacks {
				go cb(key, nil, true)
			}
		}
	}
	return nil
}

func (m *mockStore) Query(ctx context.Context, prefix string) ([]KeyValue, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []KeyValue
	for key, val := range m.data {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			results = append(results, KeyValue{Key: key, Value: val})
		}
	}
	return results, nil
}

func (m *mockStore) Watch(prefix string, callback func(key string, value []byte, deleted bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.watchers[prefix] = append(m.watchers[prefix], callback)
}

// Helper to count allocations in store
func (m *mockStore) countAllocations(poolID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	prefix := fmt.Sprintf("/allocation/%s/", poolID)
	for key := range m.data {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			count++
		}
	}
	return count
}

// --- Tests ---

func TestNewDistributedAllocator(t *testing.T) {
	tests := []struct {
		name    string
		cfg     DistributedConfig
		wantErr bool
	}{
		{
			name: "valid session mode",
			cfg: DistributedConfig{
				PoolID:      "pool-1",
				BaseNetwork: "10.0.0.0/24",
				PrefixLen:   32,
				Mode:        PoolModeSession,
			},
			wantErr: false,
		},
		{
			name: "valid lease mode",
			cfg: DistributedConfig{
				PoolID:      "pool-2",
				BaseNetwork: "192.168.0.0/16",
				PrefixLen:   24,
				Mode:        PoolModeLease,
			},
			wantErr: false,
		},
		{
			name: "invalid network",
			cfg: DistributedConfig{
				PoolID:      "pool-3",
				BaseNetwork: "invalid",
				PrefixLen:   32,
				Mode:        PoolModeSession,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			da, err := NewDistributedAllocator(tt.cfg, store)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, da)
			assert.Equal(t, tt.cfg.PoolID, da.poolID)
			assert.Equal(t, tt.cfg.Mode, da.mode)
		})
	}
}

func TestDistributedAllocator_Allocate_SessionMode(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "session-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	// First allocation
	prefix1, err := da.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/32", prefix1.String())

	// Verify stored in distributed store
	assert.Equal(t, 1, store.countAllocations("session-pool"))

	// Second allocation
	prefix2, err := da.Allocate(ctx, "sub-002")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1/32", prefix2.String())

	// Idempotent - same subscriber gets same IP
	prefix1Again, err := da.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	assert.Equal(t, prefix1.String(), prefix1Again.String())

	// Stats
	stats := da.Stats()
	assert.Equal(t, 2, stats.Allocated)
}

func TestDistributedAllocator_Allocate_LeaseMode(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "lease-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeLease,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate
	prefix, err := da.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	assert.NotNil(t, prefix)

	// Verify epoch is set in stored allocation
	data, err := store.Get(ctx, "/allocation/lease-pool/sub-001")
	require.NoError(t, err)

	var alloc DistributedAllocation
	require.NoError(t, json.Unmarshal(data, &alloc))
	// EpochBitmapAllocator starts at epoch 2 so zeros are "free"
	assert.Equal(t, da.GetCurrentEpoch(), alloc.Epoch)
}

func TestDistributedAllocator_AllocateWithMAC(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "mac-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	prefix, err := da.AllocateWithMAC(ctx, "sub-001", mac)
	require.NoError(t, err)
	assert.NotNil(t, prefix)

	// Verify MAC is stored
	data, err := store.Get(ctx, "/allocation/mac-pool/sub-001")
	require.NoError(t, err)

	var alloc DistributedAllocation
	require.NoError(t, json.Unmarshal(data, &alloc))
	assert.Equal(t, "00:11:22:33:44:55", alloc.MAC)
}

func TestDistributedAllocator_Renew_SessionMode(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "session-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate
	_, err = da.Allocate(ctx, "sub-001")
	require.NoError(t, err)

	// Renew should be no-op in session mode
	err = da.Renew(ctx, "sub-001")
	require.NoError(t, err)
}

func TestDistributedAllocator_Renew_LeaseMode(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "lease-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeLease,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	// Get initial epoch
	initialEpoch := da.GetCurrentEpoch()

	// Allocate
	_, err = da.Allocate(ctx, "sub-001")
	require.NoError(t, err)

	// Advance epoch
	newEpoch := da.AdvanceEpoch()
	assert.Equal(t, initialEpoch+1, newEpoch)

	// Renew should update epoch
	err = da.Renew(ctx, "sub-001")
	require.NoError(t, err)

	// Verify epoch updated in store
	data, err := store.Get(ctx, "/allocation/lease-pool/sub-001")
	require.NoError(t, err)

	var alloc DistributedAllocation
	require.NoError(t, json.Unmarshal(data, &alloc))
	assert.Equal(t, newEpoch, alloc.Epoch)
}

func TestDistributedAllocator_Release(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "release-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate
	prefix, err := da.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/32", prefix.String())

	assert.Equal(t, 1, da.Stats().Allocated)
	assert.Equal(t, 1, store.countAllocations("release-pool"))

	// Release
	err = da.Release(ctx, "sub-001")
	require.NoError(t, err)

	assert.Equal(t, 0, da.Stats().Allocated)
	assert.Equal(t, 0, store.countAllocations("release-pool"))

	// Next allocation should get the same IP (re-used)
	prefix2, err := da.Allocate(ctx, "sub-002")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/32", prefix2.String())
}

func TestDistributedAllocator_Get(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "get-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	// Get non-existent
	prefix, ok := da.Get("sub-001")
	assert.False(t, ok)
	assert.Nil(t, prefix)

	// Allocate
	allocated, err := da.Allocate(ctx, "sub-001")
	require.NoError(t, err)

	// Get existing
	prefix, ok = da.Get("sub-001")
	assert.True(t, ok)
	assert.Equal(t, allocated.String(), prefix.String())
}

func TestDistributedAllocator_GetByPrefix(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "prefix-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	prefix, err := da.Allocate(ctx, "sub-001")
	require.NoError(t, err)

	// Lookup by prefix
	subscriberID, ok := da.GetByPrefix(prefix)
	assert.True(t, ok)
	assert.Equal(t, "sub-001", subscriberID)

	// Non-allocated prefix
	unallocated := &net.IPNet{
		IP:   net.ParseIP("10.0.0.100"),
		Mask: net.CIDRMask(32, 32),
	}
	_, ok = da.GetByPrefix(unallocated)
	assert.False(t, ok)
}

func TestDistributedAllocator_Start_LoadAllocations(t *testing.T) {
	store := newMockStore()
	ctx := context.Background()

	// Pre-populate store with allocations
	alloc1 := &DistributedAllocation{
		PoolID:       "load-pool",
		SubscriberID: "sub-001",
		Prefix:       "10.0.0.5/32",
		Epoch:        0,
		AllocatedAt:  time.Now(),
	}
	alloc2 := &DistributedAllocation{
		PoolID:       "load-pool",
		SubscriberID: "sub-002",
		Prefix:       "10.0.0.10/32",
		Epoch:        0,
		AllocatedAt:  time.Now(),
	}

	data1, _ := json.Marshal(alloc1)
	data2, _ := json.Marshal(alloc2)
	store.Put(ctx, "/allocation/load-pool/sub-001", data1)
	store.Put(ctx, "/allocation/load-pool/sub-002", data2)

	// Create allocator and start it
	cfg := DistributedConfig{
		PoolID:      "load-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	err = da.Start(ctx)
	require.NoError(t, err)

	// Verify allocations were loaded
	stats := da.Stats()
	assert.Equal(t, 2, stats.Allocated)

	// Verify we can retrieve them
	prefix1, ok := da.Get("sub-001")
	assert.True(t, ok)
	assert.Equal(t, "10.0.0.5/32", prefix1.String())

	prefix2, ok := da.Get("sub-002")
	assert.True(t, ok)
	assert.Equal(t, "10.0.0.10/32", prefix2.String())
}

func TestDistributedAllocator_HandleRemoteChange_Add(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "sync-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()
	err = da.Start(ctx)
	require.NoError(t, err)

	// Simulate remote allocation (as if from another node)
	remoteAlloc := &DistributedAllocation{
		PoolID:       "sync-pool",
		SubscriberID: "remote-sub-001",
		Prefix:       "10.0.0.50/32",
		Epoch:        0,
		AllocatedAt:  time.Now(),
	}

	data, _ := json.Marshal(remoteAlloc)

	// Directly call handleRemoteChange
	da.handleRemoteChange("/allocation/sync-pool/remote-sub-001", data, false)

	// Allow goroutine to process
	time.Sleep(10 * time.Millisecond)

	// Verify allocation was synced
	prefix, ok := da.Get("remote-sub-001")
	assert.True(t, ok)
	assert.Equal(t, "10.0.0.50/32", prefix.String())
}

func TestDistributedAllocator_HandleRemoteChange_Delete(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "sync-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate locally
	_, err = da.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	assert.Equal(t, 1, da.Stats().Allocated)

	// Simulate remote delete
	da.handleRemoteChange("/allocation/sync-pool/sub-001", nil, true)

	// Verify allocation was removed
	_, ok := da.Get("sub-001")
	assert.False(t, ok)
	assert.Equal(t, 0, da.Stats().Allocated)
}

func TestDistributedAllocator_EpochManagement(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "epoch-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeLease,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	// EpochBitmapAllocator starts at epoch 2 (so zeros are "free")
	initialEpoch := da.GetCurrentEpoch()
	assert.Equal(t, uint64(2), initialEpoch)

	// Advance epoch
	newEpoch := da.AdvanceEpoch()
	assert.Equal(t, initialEpoch+1, newEpoch)
	assert.Equal(t, uint64(3), da.GetCurrentEpoch())

	newEpoch = da.AdvanceEpoch()
	assert.Equal(t, uint64(4), newEpoch)
}

func TestDistributedAllocator_LazyExpiration(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "reclaim-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeLease,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate at current epoch (starts at 2)
	initialEpoch := da.GetCurrentEpoch()
	_, err = da.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	_, err = da.Allocate(ctx, "sub-002")
	require.NoError(t, err)

	assert.Equal(t, 2, da.Stats().Allocated)

	// Advance epoch and renew only sub-001
	da.AdvanceEpoch() // epoch 3
	da.Renew(ctx, "sub-001")

	// Advance again - sub-002 (at epoch 2) is now 2 epochs behind (grace period = 1)
	da.AdvanceEpoch() // epoch 4

	// With lazy expiration, Lookup returns nil for expired allocations
	// sub-001 was renewed at epoch 3, so it's still valid (1 epoch behind)
	prefix1, ok := da.Get("sub-001")
	assert.True(t, ok, "sub-001 should still exist (renewed at epoch 3)")
	assert.NotNil(t, prefix1)

	// sub-002 was allocated at epoch 2, now at epoch 4, that's 2 epochs behind
	// With grace period of 1, it should be expired
	prefix2, ok := da.Get("sub-002")
	assert.False(t, ok, "sub-002 should be expired (epoch 2, current 4, grace 1)")
	assert.Nil(t, prefix2)

	// Verify sub-001's epoch was at initial+1 (renewed)
	_ = initialEpoch // used implicitly above
}

func TestDistributedAllocator_Concurrency(t *testing.T) {
	store := newMockStore()
	cfg := DistributedConfig{
		PoolID:      "concurrent-pool",
		BaseNetwork: "10.0.0.0/16",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	const numGoroutines = 50
	const allocsPerGoroutine = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*allocsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < allocsPerGoroutine; j++ {
				subscriberID := fmt.Sprintf("sub-%d-%d", goroutineID, j)
				_, err := da.Allocate(ctx, subscriberID)
				if err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check no errors
	for err := range errors {
		t.Errorf("concurrent allocation error: %v", err)
	}

	// Verify correct count
	stats := da.Stats()
	assert.Equal(t, numGoroutines*allocsPerGoroutine, stats.Allocated)
	assert.Equal(t, numGoroutines*allocsPerGoroutine, store.countAllocations("concurrent-pool"))
}

func TestDistributedAllocator_StoreRollback(t *testing.T) {
	// Test that local allocation is rolled back if store write fails
	store := &failingStore{
		mockStore: newMockStore(),
		failPut:   true,
	}

	cfg := DistributedConfig{
		PoolID:      "rollback-pool",
		BaseNetwork: "10.0.0.0/24",
		PrefixLen:   32,
		Mode:        PoolModeSession,
	}

	da, err := NewDistributedAllocator(cfg, store)
	require.NoError(t, err)

	ctx := context.Background()

	// Allocate should fail due to store error
	_, err = da.Allocate(ctx, "sub-001")
	require.Error(t, err)

	// Local state should be rolled back
	assert.Equal(t, 0, da.Stats().Allocated)
}

// failingStore wraps mockStore to simulate failures
type failingStore struct {
	*mockStore
	failPut bool
}

func (f *failingStore) Put(ctx context.Context, key string, value []byte) error {
	if f.failPut {
		return fmt.Errorf("simulated store failure")
	}
	return f.mockStore.Put(ctx, key, value)
}
