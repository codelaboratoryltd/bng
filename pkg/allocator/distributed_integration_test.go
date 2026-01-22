package allocator_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/allocator"
	"github.com/codelaboratoryltd/bng/pkg/nexus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeAdapter wraps nexus.DistributedStore to implement allocator.Store interface.
type storeAdapter struct {
	store *nexus.DistributedStore
}

func (s *storeAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	return s.store.Get(ctx, key)
}

func (s *storeAdapter) Put(ctx context.Context, key string, value []byte) error {
	return s.store.Put(ctx, key, value)
}

func (s *storeAdapter) Delete(ctx context.Context, key string) error {
	return s.store.Delete(ctx, key)
}

func (s *storeAdapter) Query(ctx context.Context, prefix string) ([]allocator.KeyValue, error) {
	results, err := s.store.Query(ctx, prefix)
	if err != nil {
		return nil, err
	}
	// Convert nexus.KeyValue to allocator.KeyValue
	kvs := make([]allocator.KeyValue, len(results))
	for i, r := range results {
		kvs[i] = allocator.KeyValue{Key: r.Key, Value: r.Value}
	}
	return kvs, nil
}

func (s *storeAdapter) Watch(prefix string, callback func(key string, value []byte, deleted bool)) {
	s.store.Watch(prefix, callback)
}

// --- Integration Tests ---

func TestDistributedAllocator_WithMemoryStore(t *testing.T) {
	// Create a memory-mode CLSetStore
	cfg := nexus.DefaultDistributedConfig()
	cfg.Mode = nexus.StoreModeMemory

	store, err := nexus.NewDistributedStore(cfg)
	require.NoError(t, err)
	defer store.Close()

	adapter := &storeAdapter{store: store}

	// Create distributed allocator
	daCfg := allocator.DistributedConfig{
		PoolID:      "integration-pool",
		BaseNetwork: "10.100.0.0/16",
		PrefixLen:   32,
		Mode:        allocator.PoolModeSession,
	}

	da, err := allocator.NewDistributedAllocator(daCfg, adapter)
	require.NoError(t, err)

	ctx := context.Background()

	// Start allocator (loads existing state, sets up watches)
	err = da.Start(ctx)
	require.NoError(t, err)

	// Allocate (note: allocator starts at .0, skipping network/broadcast is caller's responsibility)
	prefix1, err := da.Allocate(ctx, "sub-001")
	require.NoError(t, err)
	assert.Equal(t, "10.100.0.0/32", prefix1.String())

	prefix2, err := da.Allocate(ctx, "sub-002")
	require.NoError(t, err)
	assert.Equal(t, "10.100.0.1/32", prefix2.String())

	// Verify persisted in store
	data, err := store.Get(ctx, "/allocation/integration-pool/sub-001")
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Get
	retrieved, ok := da.Get("sub-001")
	assert.True(t, ok)
	assert.Equal(t, prefix1.String(), retrieved.String())

	// Release
	err = da.Release(ctx, "sub-001")
	require.NoError(t, err)

	// Verify removed from store
	_, err = store.Get(ctx, "/allocation/integration-pool/sub-001")
	assert.Error(t, err) // Should not be found

	// Stats
	stats := da.Stats()
	assert.Equal(t, 1, stats.Allocated)
}

func TestDistributedAllocator_WithMemoryStore_LeaseMode(t *testing.T) {
	cfg := nexus.DefaultDistributedConfig()
	cfg.Mode = nexus.StoreModeMemory

	store, err := nexus.NewDistributedStore(cfg)
	require.NoError(t, err)
	defer store.Close()

	adapter := &storeAdapter{store: store}

	daCfg := allocator.DistributedConfig{
		PoolID:      "lease-pool",
		BaseNetwork: "192.168.0.0/24",
		PrefixLen:   32,
		Mode:        allocator.PoolModeLease,
	}

	da, err := allocator.NewDistributedAllocator(daCfg, adapter)
	require.NoError(t, err)

	ctx := context.Background()
	err = da.Start(ctx)
	require.NoError(t, err)

	// Allocate
	_, err = da.Allocate(ctx, "dhcp-client-001")
	require.NoError(t, err)

	// Renew (should update epoch)
	err = da.Renew(ctx, "dhcp-client-001")
	require.NoError(t, err)

	// Verify still allocated
	_, ok := da.Get("dhcp-client-001")
	assert.True(t, ok)
}

func TestDistributedAllocator_WithMemoryStore_Persistence(t *testing.T) {
	// Test that allocator can recover state from store on restart

	cfg := nexus.DefaultDistributedConfig()
	cfg.Mode = nexus.StoreModeMemory

	store, err := nexus.NewDistributedStore(cfg)
	require.NoError(t, err)
	defer store.Close()

	adapter := &storeAdapter{store: store}
	ctx := context.Background()

	// First allocator instance - allocate some IPs
	da1Cfg := allocator.DistributedConfig{
		PoolID:      "persist-pool",
		BaseNetwork: "172.16.0.0/24",
		PrefixLen:   32,
		Mode:        allocator.PoolModeSession,
	}

	da1, err := allocator.NewDistributedAllocator(da1Cfg, adapter)
	require.NoError(t, err)
	err = da1.Start(ctx)
	require.NoError(t, err)

	_, err = da1.Allocate(ctx, "persist-sub-001")
	require.NoError(t, err)
	_, err = da1.Allocate(ctx, "persist-sub-002")
	require.NoError(t, err)
	_, err = da1.Allocate(ctx, "persist-sub-003")
	require.NoError(t, err)

	assert.Equal(t, 3, da1.Stats().Allocated)

	// Simulate restart - create new allocator instance with same store
	da2, err := allocator.NewDistributedAllocator(da1Cfg, adapter)
	require.NoError(t, err)
	err = da2.Start(ctx)
	require.NoError(t, err)

	// Verify state was recovered
	assert.Equal(t, 3, da2.Stats().Allocated)

	// Verify specific allocations
	prefix1, ok := da2.Get("persist-sub-001")
	assert.True(t, ok)
	assert.Equal(t, "172.16.0.0/32", prefix1.String())

	prefix2, ok := da2.Get("persist-sub-002")
	assert.True(t, ok)
	assert.Equal(t, "172.16.0.1/32", prefix2.String())

	prefix3, ok := da2.Get("persist-sub-003")
	assert.True(t, ok)
	assert.Equal(t, "172.16.0.2/32", prefix3.String())

	// New allocation should continue from where we left off
	prefix4, err := da2.Allocate(ctx, "persist-sub-004")
	require.NoError(t, err)
	assert.Equal(t, "172.16.0.3/32", prefix4.String())
}

func TestDistributedAllocator_WithMemoryStore_WatchNotification(t *testing.T) {
	cfg := nexus.DefaultDistributedConfig()
	cfg.Mode = nexus.StoreModeMemory

	store, err := nexus.NewDistributedStore(cfg)
	require.NoError(t, err)
	defer store.Close()

	adapter := &storeAdapter{store: store}

	daCfg := allocator.DistributedConfig{
		PoolID:      "watch-pool",
		BaseNetwork: "10.50.0.0/24",
		PrefixLen:   32,
		Mode:        allocator.PoolModeSession,
	}

	da, err := allocator.NewDistributedAllocator(daCfg, adapter)
	require.NoError(t, err)

	ctx := context.Background()
	err = da.Start(ctx)
	require.NoError(t, err)

	// Track watch notifications
	var notifications []string
	var notifyMu sync.Mutex

	store.Watch("/allocation/watch-pool/", func(key string, value []byte, deleted bool) {
		notifyMu.Lock()
		if deleted {
			notifications = append(notifications, fmt.Sprintf("delete:%s", key))
		} else {
			notifications = append(notifications, fmt.Sprintf("put:%s", key))
		}
		notifyMu.Unlock()
	})

	// Allocate
	_, err = da.Allocate(ctx, "watched-sub-001")
	require.NoError(t, err)

	// Give time for async notification
	time.Sleep(50 * time.Millisecond)

	notifyMu.Lock()
	assert.Len(t, notifications, 1)
	assert.Contains(t, notifications[0], "put:")
	assert.Contains(t, notifications[0], "watched-sub-001")
	notifyMu.Unlock()

	// Release
	err = da.Release(ctx, "watched-sub-001")
	require.NoError(t, err)

	// Give time for async notification
	time.Sleep(50 * time.Millisecond)

	notifyMu.Lock()
	assert.Len(t, notifications, 2)
	assert.Contains(t, notifications[1], "delete:")
	notifyMu.Unlock()
}

func TestDistributedAllocator_WithMemoryStore_Concurrency(t *testing.T) {
	cfg := nexus.DefaultDistributedConfig()
	cfg.Mode = nexus.StoreModeMemory

	store, err := nexus.NewDistributedStore(cfg)
	require.NoError(t, err)
	defer store.Close()

	adapter := &storeAdapter{store: store}

	daCfg := allocator.DistributedConfig{
		PoolID:      "concurrent-pool",
		BaseNetwork: "10.200.0.0/16",
		PrefixLen:   32,
		Mode:        allocator.PoolModeSession,
	}

	da, err := allocator.NewDistributedAllocator(daCfg, adapter)
	require.NoError(t, err)

	ctx := context.Background()
	err = da.Start(ctx)
	require.NoError(t, err)

	const numGoroutines = 20
	const allocsPerGoroutine = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*allocsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < allocsPerGoroutine; j++ {
				subscriberID := fmt.Sprintf("concurrent-sub-%d-%d", goroutineID, j)
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
}

func TestDistributedAllocator_WithMemoryStore_IPv6(t *testing.T) {
	cfg := nexus.DefaultDistributedConfig()
	cfg.Mode = nexus.StoreModeMemory

	store, err := nexus.NewDistributedStore(cfg)
	require.NoError(t, err)
	defer store.Close()

	adapter := &storeAdapter{store: store}

	daCfg := allocator.DistributedConfig{
		PoolID:      "ipv6-pool",
		BaseNetwork: "2001:db8:abcd::/48",
		PrefixLen:   64,
		Mode:        allocator.PoolModeSession,
	}

	da, err := allocator.NewDistributedAllocator(daCfg, adapter)
	require.NoError(t, err)

	ctx := context.Background()
	err = da.Start(ctx)
	require.NoError(t, err)

	// Allocate IPv6 /64 prefix
	prefix1, err := da.Allocate(ctx, "ipv6-sub-001")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8:abcd::/64", prefix1.String())

	prefix2, err := da.Allocate(ctx, "ipv6-sub-002")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8:abcd:1::/64", prefix2.String())

	// Verify
	retrieved, ok := da.Get("ipv6-sub-001")
	assert.True(t, ok)
	assert.Equal(t, prefix1.String(), retrieved.String())
}
