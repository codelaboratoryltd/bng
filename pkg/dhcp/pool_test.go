package dhcp

import (
	"net"
	"testing"
	"time"
)

func TestNewPool(t *testing.T) {
	cfg := PoolConfig{
		ID:            1,
		Name:          "test-pool",
		Network:       "10.0.1.0/24",
		Gateway:       "10.0.1.1",
		DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
		LeaseTime:     time.Hour,
		ClientClass:   ClientClassResidential,
		VlanID:        100,
		ReservedStart: 10,
		ReservedEnd:   5,
	}

	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	if pool.ID != 1 {
		t.Errorf("Expected pool ID 1, got %d", pool.ID)
	}

	if pool.Name != "test-pool" {
		t.Errorf("Expected pool name 'test-pool', got %s", pool.Name)
	}

	// /24 has 254 usable IPs, minus 10 reserved start, 5 reserved end = 239
	// Gateway (10.0.1.1) falls within reserved start range, so not double-counted
	expectedAvailable := 254 - 10 - 5
	if len(pool.available) != expectedAvailable {
		t.Errorf("Expected %d available IPs, got %d", expectedAvailable, len(pool.available))
	}
}

func TestPoolAllocate(t *testing.T) {
	pool, err := NewPool(PoolConfig{
		ID:         1,
		Name:       "test",
		Network:    "192.168.1.0/24",
		Gateway:    "192.168.1.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// First allocation should succeed
	ip, err := pool.Allocate(mac)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	if ip == nil {
		t.Fatal("Allocated IP is nil")
	}

	// Verify IP is in pool range
	if !pool.Contains(ip) {
		t.Errorf("Allocated IP %s not in pool range", ip)
	}

	// Second allocation for same MAC should return same IP
	ip2, err := pool.Allocate(mac)
	if err != nil {
		t.Fatalf("Second allocate failed: %v", err)
	}

	if !ip.Equal(ip2) {
		t.Errorf("Expected same IP %s, got %s", ip, ip2)
	}
}

func TestPoolRelease(t *testing.T) {
	pool, err := NewPool(PoolConfig{
		ID:         1,
		Name:       "test",
		Network:    "192.168.1.0/28", // Small pool for testing
		Gateway:    "192.168.1.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	initialAvailable := len(pool.available)

	// Allocate
	ip, err := pool.Allocate(mac)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	if len(pool.available) != initialAvailable-1 {
		t.Errorf("Available count should decrease by 1")
	}

	// Release
	pool.Release(ip)

	if len(pool.available) != initialAvailable {
		t.Errorf("Available count should return to %d, got %d", initialAvailable, len(pool.available))
	}
}

func TestPoolContains(t *testing.T) {
	pool, err := NewPool(PoolConfig{
		ID:         1,
		Name:       "test",
		Network:    "10.0.1.0/24",
		Gateway:    "10.0.1.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.1.1", true},
		{"10.0.1.100", true},
		{"10.0.1.254", true},
		{"10.0.2.1", false},
		{"192.168.1.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := pool.Contains(ip)
		if got != tt.expected {
			t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.expected)
		}
	}
}

func TestPoolStats(t *testing.T) {
	pool, err := NewPool(PoolConfig{
		ID:            1,
		Name:          "stats-test",
		Network:       "10.0.1.0/28",
		Gateway:       "10.0.1.1",
		DNSServers:    []string{"8.8.8.8"},
		LeaseTime:     time.Hour,
		ReservedStart: 2,
		ReservedEnd:   2,
	})
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	stats := pool.Stats()
	if stats.ID != 1 {
		t.Errorf("Expected stats ID 1, got %d", stats.ID)
	}
	if stats.Name != "stats-test" {
		t.Errorf("Expected stats name 'stats-test', got %s", stats.Name)
	}
	if stats.Allocated != 0 {
		t.Errorf("Expected 0 allocated, got %d", stats.Allocated)
	}

	// Allocate some IPs
	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	pool.Allocate(mac1)
	pool.Allocate(mac2)

	stats = pool.Stats()
	if stats.Allocated != 2 {
		t.Errorf("Expected 2 allocated, got %d", stats.Allocated)
	}
}

func TestPoolManagerAddPool(t *testing.T) {
	mgr := NewPoolManager(nil, nil)

	pool, err := NewPool(PoolConfig{
		ID:         1,
		Name:       "pool1",
		Network:    "10.0.1.0/24",
		Gateway:    "10.0.1.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	err = mgr.AddPool(pool)
	if err != nil {
		t.Fatalf("AddPool failed: %v", err)
	}

	// Duplicate should fail
	err = mgr.AddPool(pool)
	if err == nil {
		t.Error("Expected error for duplicate pool")
	}

	// Get pool should work
	got := mgr.GetPool(1)
	if got == nil {
		t.Error("GetPool returned nil")
	}
	if got.Name != "pool1" {
		t.Errorf("Expected pool name 'pool1', got %s", got.Name)
	}
}

func TestPoolManagerClassifyClient(t *testing.T) {
	mgr := NewPoolManager(nil, nil)

	pool1, _ := NewPool(PoolConfig{
		ID:         1,
		Name:       "default",
		Network:    "10.0.1.0/24",
		Gateway:    "10.0.1.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})

	mgr.AddPool(pool1)

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	pool := mgr.ClassifyClient(mac)

	if pool == nil {
		t.Fatal("ClassifyClient returned nil")
	}
	if pool.ID != 1 {
		t.Errorf("Expected pool ID 1, got %d", pool.ID)
	}
}
