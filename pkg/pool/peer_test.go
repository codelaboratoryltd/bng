package pool

import (
	"context"
	"testing"
	"time"
)

func TestPeerPoolCreate(t *testing.T) {
	cfg := PeerPoolConfig{
		NodeID:     "node-1",
		Peers:      []string{"node-1", "node-2", "node-3"},
		Network:    "10.0.0.0/24",
		Gateway:    "10.0.0.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  24 * time.Hour,
		ListenAddr: ":8081",
	}

	pool, err := NewPeerPool(cfg)
	if err != nil {
		t.Fatalf("failed to create peer pool: %v", err)
	}

	if pool.nodeID != "node-1" {
		t.Errorf("expected node ID 'node-1', got '%s'", pool.nodeID)
	}

	if len(pool.peerNodes) != 3 {
		t.Errorf("expected 3 peer nodes, got %d", len(pool.peerNodes))
	}
}

func TestRendezvousHash(t *testing.T) {
	nodes := []string{"node-0", "node-1", "node-2"}

	// Rendezvous hash should be deterministic
	key := "subscriber-123"
	owner1 := rendezvousHash(key, nodes)
	owner2 := rendezvousHash(key, nodes)

	if owner1 != owner2 {
		t.Errorf("rendezvous hash not deterministic: got '%s' then '%s'", owner1, owner2)
	}

	// Different keys should distribute across nodes
	owners := make(map[string]int)
	for i := 0; i < 100; i++ {
		key := "subscriber-" + string(rune(i))
		owner := rendezvousHash(key, nodes)
		owners[owner]++
	}

	// All nodes should have some assignments
	for _, node := range nodes {
		if owners[node] == 0 {
			t.Errorf("node '%s' has no assignments", node)
		}
	}
}

func TestPeerPoolOwnership(t *testing.T) {
	cfg := PeerPoolConfig{
		NodeID:     "node-1",
		Peers:      []string{"node-0", "node-1", "node-2"},
		Network:    "10.0.0.0/24",
		Gateway:    "10.0.0.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  24 * time.Hour,
		ListenAddr: ":8081",
	}

	pool, err := NewPeerPool(cfg)
	if err != nil {
		t.Fatalf("failed to create peer pool: %v", err)
	}

	// GetOwner should be deterministic
	owner1 := pool.GetOwner("subscriber-123")
	owner2 := pool.GetOwner("subscriber-123")
	if owner1 != owner2 {
		t.Errorf("GetOwner not deterministic")
	}

	// IsLocalOwner should match GetOwner
	isLocal := pool.IsLocalOwner("subscriber-123")
	owner := pool.GetOwner("subscriber-123")
	expectedLocal := owner == "node-1"
	if isLocal != expectedLocal {
		t.Errorf("IsLocalOwner=%v but GetOwner=%s", isLocal, owner)
	}
}

func TestLocalAllocation(t *testing.T) {
	cfg := PeerPoolConfig{
		NodeID:     "node-0",
		Peers:      []string{"node-0"}, // Single node = all local
		Network:    "10.0.0.0/24",
		Gateway:    "10.0.0.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  24 * time.Hour,
		ListenAddr: ":8081",
	}

	pool, err := NewPeerPool(cfg)
	if err != nil {
		t.Fatalf("failed to create peer pool: %v", err)
	}

	ctx := context.Background()

	// Allocate should work for local owner
	resp, err := pool.Allocate(ctx, "subscriber-1", nil)
	if err != nil {
		t.Fatalf("failed to allocate: %v", err)
	}

	if resp.IP == "" {
		t.Error("expected IP to be allocated")
	}

	if resp.NodeID != "node-0" {
		t.Errorf("expected node ID 'node-0', got '%s'", resp.NodeID)
	}

	// Same subscriber should get same IP
	resp2, err := pool.Allocate(ctx, "subscriber-1", nil)
	if err != nil {
		t.Fatalf("failed to reallocate: %v", err)
	}

	if resp2.IP != resp.IP {
		t.Errorf("expected same IP on reallocate, got %s then %s", resp.IP, resp2.IP)
	}

	// Different subscriber should get different IP
	resp3, err := pool.Allocate(ctx, "subscriber-2", nil)
	if err != nil {
		t.Fatalf("failed to allocate subscriber-2: %v", err)
	}

	if resp3.IP == resp.IP {
		t.Error("expected different IP for different subscriber")
	}
}

func TestPoolStats(t *testing.T) {
	cfg := PeerPoolConfig{
		NodeID:     "node-0",
		Peers:      []string{"node-0"},
		Network:    "10.0.0.0/24",
		Gateway:    "10.0.0.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  24 * time.Hour,
		ListenAddr: ":8081",
	}

	pool, err := NewPeerPool(cfg)
	if err != nil {
		t.Fatalf("failed to create peer pool: %v", err)
	}

	stats := pool.Stats()
	if stats.Allocated != 0 {
		t.Errorf("expected 0 allocated, got %d", stats.Allocated)
	}

	// Allocate some IPs
	ctx := context.Background()
	pool.Allocate(ctx, "sub-1", nil)
	pool.Allocate(ctx, "sub-2", nil)

	stats = pool.Stats()
	if stats.Allocated != 2 {
		t.Errorf("expected 2 allocated, got %d", stats.Allocated)
	}
}

func TestReleaseAllocation(t *testing.T) {
	cfg := PeerPoolConfig{
		NodeID:     "node-0",
		Peers:      []string{"node-0"},
		Network:    "10.0.0.0/24",
		Gateway:    "10.0.0.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  24 * time.Hour,
		ListenAddr: ":8081",
	}

	pool, err := NewPeerPool(cfg)
	if err != nil {
		t.Fatalf("failed to create peer pool: %v", err)
	}

	ctx := context.Background()

	// Allocate
	resp, err := pool.Allocate(ctx, "subscriber-1", nil)
	if err != nil {
		t.Fatalf("failed to allocate: %v", err)
	}

	originalIP := resp.IP

	// Release
	err = pool.Release(ctx, "subscriber-1")
	if err != nil {
		t.Fatalf("failed to release: %v", err)
	}

	// After release, Get should return not found
	_, exists := pool.Get("subscriber-1")
	if exists {
		t.Error("expected allocation to not exist after release")
	}

	// Reallocate should give potentially different IP (pool recycles)
	// The IP might be the same if it's the first available, that's OK
	resp2, err := pool.Allocate(ctx, "subscriber-1", nil)
	if err != nil {
		t.Fatalf("failed to reallocate: %v", err)
	}

	// Just verify we got an IP
	if resp2.IP == "" {
		t.Error("expected IP on reallocate")
	}

	t.Logf("Original IP: %s, Reallocated IP: %s", originalIP, resp2.IP)
}
