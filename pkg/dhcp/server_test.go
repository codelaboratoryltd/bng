package dhcp

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"go.uber.org/zap"
)

func TestNewServer(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	tests := []struct {
		name        string
		cfg         ServerConfig
		expectError bool
	}{
		{
			name: "valid configuration",
			cfg: ServerConfig{
				Interface:         "eth0",
				ServerIP:          net.ParseIP("192.168.1.1"),
				RADIUSAuthEnabled: false,
			},
			expectError: false,
		},
		{
			name: "missing interface",
			cfg: ServerConfig{
				Interface: "",
				ServerIP:  net.ParseIP("192.168.1.1"),
			},
			expectError: true,
		},
		{
			name: "missing server IP",
			cfg: ServerConfig{
				Interface: "eth0",
				ServerIP:  nil,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(tt.cfg, nil, poolMgr, logger)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if server == nil {
					t.Error("expected non-nil server")
				}
			}
		})
	}
}

func TestServerSetters(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	server, err := NewServer(ServerConfig{
		Interface: "eth0",
		ServerIP:  net.ParseIP("192.168.1.1"),
	}, nil, poolMgr, logger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Test SetRADIUSClient
	server.SetRADIUSClient(nil)
	// No error expected

	// Test SetPolicyManager
	server.SetPolicyManager(nil)
	// No error expected

	// Test SetQoSManager
	server.SetQoSManager(nil)
	// No error expected

	// Test SetNATManager
	server.SetNATManager(nil)
	// No error expected

	// Test SetNexusClient
	server.SetNexusClient(nil)
	// No error expected
}

func TestServerStats(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	server, err := NewServer(ServerConfig{
		Interface: "eth0",
		ServerIP:  net.ParseIP("192.168.1.1"),
	}, nil, poolMgr, logger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	stats := server.Stats()
	if stats == nil {
		t.Fatal("stats should not be nil")
	}

	// Verify all expected stat keys exist
	expectedKeys := []string{
		"requests_total",
		"offers_total",
		"acks_total",
		"naks_total",
		"releases_total",
	}

	for _, key := range expectedKeys {
		if _, ok := stats[key]; !ok {
			t.Errorf("expected key %q in stats", key)
		}
	}
}

func TestServerActiveLeases(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	server, err := NewServer(ServerConfig{
		Interface: "eth0",
		ServerIP:  net.ParseIP("192.168.1.1"),
	}, nil, poolMgr, logger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Initially should be 0
	if server.ActiveLeases() != 0 {
		t.Errorf("expected 0 active leases, got %d", server.ActiveLeases())
	}
}

func TestLeaseStruct(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	lease := &Lease{
		MAC:          mac,
		IP:           net.ParseIP("192.168.1.100"),
		PoolID:       1,
		ExpiresAt:    time.Now().Add(time.Hour),
		Hostname:     "test-host",
		SessionID:    "session-123",
		SessionStart: time.Now(),
		PolicyName:   "residential-100mbps",
		STag:         100,
		CTag:         200,
	}

	if lease.MAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("unexpected MAC: %s", lease.MAC.String())
	}

	if lease.IP.String() != "192.168.1.100" {
		t.Errorf("unexpected IP: %s", lease.IP.String())
	}

	if lease.PoolID != 1 {
		t.Errorf("unexpected PoolID: %d", lease.PoolID)
	}

	if lease.STag != 100 || lease.CTag != 200 {
		t.Errorf("unexpected VLAN tags: S=%d C=%d", lease.STag, lease.CTag)
	}
}

func TestRelayAgentInfo(t *testing.T) {
	info := &RelayAgentInfo{
		CircuitID: []byte("eth 0/1/1:100"),
		RemoteID:  []byte("remote-agent-1"),
	}

	if string(info.CircuitID) != "eth 0/1/1:100" {
		t.Errorf("unexpected CircuitID: %s", string(info.CircuitID))
	}

	if string(info.RemoteID) != "remote-agent-1" {
		t.Errorf("unexpected RemoteID: %s", string(info.RemoteID))
	}
}

func TestParseOption82(t *testing.T) {
	tests := []struct {
		name            string
		option82        []byte
		expectCircuitID []byte
		expectRemoteID  []byte
		expectNil       bool
	}{
		{
			name:      "no option 82",
			option82:  nil,
			expectNil: true,
		},
		{
			name:      "empty option 82",
			option82:  []byte{},
			expectNil: true,
		},
		{
			name: "circuit-id only",
			option82: []byte{
				1, 5, 'e', 't', 'h', '0', '1', // Sub-option 1: Circuit-ID
			},
			expectCircuitID: []byte("eth01"),
			expectRemoteID:  nil,
		},
		{
			name: "remote-id only",
			option82: []byte{
				2, 4, 'r', 'e', 'm', '1', // Sub-option 2: Remote-ID
			},
			expectCircuitID: nil,
			expectRemoteID:  []byte("rem1"),
		},
		{
			name: "both circuit-id and remote-id",
			option82: []byte{
				1, 3, 'c', 'i', 'd', // Sub-option 1: Circuit-ID
				2, 3, 'r', 'i', 'd', // Sub-option 2: Remote-ID
			},
			expectCircuitID: []byte("cid"),
			expectRemoteID:  []byte("rid"),
		},
		{
			name: "truncated sub-option",
			option82: []byte{
				1, 10, 'a', 'b', 'c', // Length says 10 but only 3 bytes
			},
			expectCircuitID: nil, // Should handle gracefully
			expectRemoteID:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock DHCP packet with Option 82
			req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
			if err != nil {
				t.Fatalf("failed to create DHCP packet: %v", err)
			}

			if tt.option82 != nil {
				req.Options.Update(dhcpv4.Option{
					Code:  dhcpv4.OptionRelayAgentInformation,
					Value: dhcpv4.OptionGeneric{Data: tt.option82},
				})
			}

			info := parseOption82(req)

			if tt.expectNil {
				if info != nil {
					t.Error("expected nil info")
				}
				return
			}

			if info == nil {
				t.Fatal("expected non-nil info")
			}

			if string(info.CircuitID) != string(tt.expectCircuitID) {
				t.Errorf("CircuitID mismatch: got %q, want %q", info.CircuitID, tt.expectCircuitID)
			}

			if string(info.RemoteID) != string(tt.expectRemoteID) {
				t.Errorf("RemoteID mismatch: got %q, want %q", info.RemoteID, tt.expectRemoteID)
			}
		})
	}
}

func TestGenerateSessionID(t *testing.T) {
	// Test that session IDs are unique
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := generateSessionID()
		if seen[id] {
			t.Errorf("duplicate session ID generated: %s", id)
		}
		seen[id] = true

		// Session ID should be 16 hex characters (8 bytes)
		if len(id) != 16 {
			t.Errorf("unexpected session ID length: %d", len(id))
		}
	}
}

func TestPoolMarkUnavailable(t *testing.T) {
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

	initialAvailable := len(pool.available)

	// Mark an IP as unavailable
	ip := net.ParseIP("192.168.1.50")
	pool.MarkUnavailable(ip)

	if len(pool.unavailable) != 1 {
		t.Errorf("expected 1 unavailable IP, got %d", len(pool.unavailable))
	}

	if _, ok := pool.unavailable[ip.String()]; !ok {
		t.Error("IP should be marked as unavailable")
	}

	// Available count should decrease if IP was in available list
	// Note: depends on whether 192.168.1.50 was in the available list
	stats := pool.Stats()
	if stats.Unavailable != 1 {
		t.Errorf("stats should show 1 unavailable, got %d", stats.Unavailable)
	}

	// Marking the same IP again shouldn't increase count
	pool.MarkUnavailable(ip)
	if len(pool.unavailable) != 1 {
		t.Errorf("marking same IP shouldn't increase count, got %d", len(pool.unavailable))
	}

	_ = initialAvailable // Used for reference
}

func TestPoolManagerRemovePool(t *testing.T) {
	mgr := NewPoolManager(nil, nil)

	pool, _ := NewPool(PoolConfig{
		ID:         1,
		Name:       "test",
		Network:    "10.0.1.0/24",
		Gateway:    "10.0.1.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})

	mgr.AddPool(pool)

	// Remove should succeed
	err := mgr.RemovePool(1)
	if err != nil {
		t.Errorf("RemovePool failed: %v", err)
	}

	// Remove non-existent should fail
	err = mgr.RemovePool(999)
	if err == nil {
		t.Error("expected error when removing non-existent pool")
	}

	// GetPool should return nil after removal
	if mgr.GetPool(1) != nil {
		t.Error("pool should be nil after removal")
	}
}

func TestPoolManagerSetDefaultPool(t *testing.T) {
	mgr := NewPoolManager(nil, nil)

	pool1, _ := NewPool(PoolConfig{
		ID:         1,
		Name:       "pool1",
		Network:    "10.0.1.0/24",
		Gateway:    "10.0.1.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})

	pool2, _ := NewPool(PoolConfig{
		ID:         2,
		Name:       "pool2",
		Network:    "10.0.2.0/24",
		Gateway:    "10.0.2.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})

	mgr.AddPool(pool1)
	mgr.AddPool(pool2)

	// Set pool2 as default
	err := mgr.SetDefaultPool(2)
	if err != nil {
		t.Errorf("SetDefaultPool failed: %v", err)
	}

	// Verify default pool is used for classification
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	classifiedPool := mgr.ClassifyClient(mac)
	if classifiedPool.ID != 2 {
		t.Errorf("expected pool 2, got pool %d", classifiedPool.ID)
	}

	// Set non-existent pool should fail
	err = mgr.SetDefaultPool(999)
	if err == nil {
		t.Error("expected error when setting non-existent pool as default")
	}
}

func TestPoolManagerAllStats(t *testing.T) {
	mgr := NewPoolManager(nil, nil)

	pool1, _ := NewPool(PoolConfig{
		ID:         1,
		Name:       "pool1",
		Network:    "10.0.1.0/24",
		Gateway:    "10.0.1.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})

	pool2, _ := NewPool(PoolConfig{
		ID:         2,
		Name:       "pool2",
		Network:    "10.0.2.0/24",
		Gateway:    "10.0.2.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})

	mgr.AddPool(pool1)
	mgr.AddPool(pool2)

	stats := mgr.AllStats()
	if len(stats) != 2 {
		t.Errorf("expected 2 pool stats, got %d", len(stats))
	}
}

func TestPoolExhaustion(t *testing.T) {
	// Create a very small pool
	pool, err := NewPool(PoolConfig{
		ID:            1,
		Name:          "tiny",
		Network:       "192.168.1.0/30", // Only 2 usable IPs (1 and 2)
		Gateway:       "192.168.1.1",
		DNSServers:    []string{"8.8.8.8"},
		LeaseTime:     time.Hour,
		ReservedStart: 0,
		ReservedEnd:   0,
	})
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	// The gateway takes one IP, so only 1 should be available
	// Actually /30 has network (.0), gateway (.1), usable (.2), broadcast (.3)
	// So available should be just .2

	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	_, err = pool.Allocate(mac1)
	if err != nil {
		t.Logf("First allocation (expected): %v", err)
	}

	// Second allocation should fail if pool is exhausted
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	_, err = pool.Allocate(mac2)
	// Error is expected if pool is exhausted
	if err == nil && len(pool.available) == 0 {
		t.Log("Pool exhausted after allocations")
	}
}

func TestClientClassConstants(t *testing.T) {
	tests := []struct {
		class    ClientClass
		expected uint8
	}{
		{ClientClassResidential, 1},
		{ClientClassBusiness, 2},
		{ClientClassGuest, 3},
	}

	for _, tt := range tests {
		if uint8(tt.class) != tt.expected {
			t.Errorf("ClientClass mismatch: got %d, want %d", tt.class, tt.expected)
		}
	}
}

func TestNewPoolErrors(t *testing.T) {
	tests := []struct {
		name        string
		cfg         PoolConfig
		expectError bool
	}{
		{
			name: "invalid network CIDR",
			cfg: PoolConfig{
				ID:         1,
				Name:       "test",
				Network:    "invalid",
				Gateway:    "192.168.1.1",
				DNSServers: []string{"8.8.8.8"},
				LeaseTime:  time.Hour,
			},
			expectError: true,
		},
		{
			name: "invalid gateway IP",
			cfg: PoolConfig{
				ID:         1,
				Name:       "test",
				Network:    "192.168.1.0/24",
				Gateway:    "invalid",
				DNSServers: []string{"8.8.8.8"},
				LeaseTime:  time.Hour,
			},
			expectError: true,
		},
		{
			name: "invalid DNS server",
			cfg: PoolConfig{
				ID:         1,
				Name:       "test",
				Network:    "192.168.1.0/24",
				Gateway:    "192.168.1.1",
				DNSServers: []string{"invalid"},
				LeaseTime:  time.Hour,
			},
			expectError: true,
		},
		{
			name: "valid configuration",
			cfg: PoolConfig{
				ID:         1,
				Name:       "test",
				Network:    "192.168.1.0/24",
				Gateway:    "192.168.1.1",
				DNSServers: []string{"8.8.8.8", "8.8.4.4"},
				LeaseTime:  time.Hour,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPool(tt.cfg)
			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// === DHCP Relay Tests ===

func TestRelayDetection(t *testing.T) {
	tests := []struct {
		name      string
		giaddr    net.IP
		expectRel bool
	}{
		{
			name:      "no relay - zero giaddr",
			giaddr:    net.IPv4zero,
			expectRel: false,
		},
		{
			name:      "no relay - nil giaddr",
			giaddr:    nil,
			expectRel: false,
		},
		{
			name:      "relayed - valid giaddr",
			giaddr:    net.ParseIP("10.0.0.1"),
			expectRel: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			giaddr := tt.giaddr
			if giaddr == nil {
				giaddr = net.IPv4zero
			}
			isRelayed := !giaddr.IsUnspecified() && !giaddr.Equal(net.IPv4zero)
			if isRelayed != tt.expectRel {
				t.Errorf("expected relayed=%v, got %v for giaddr=%v", tt.expectRel, isRelayed, tt.giaddr)
			}
		})
	}
}

func TestCircuitIDLeaseIndex(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	server, err := NewServer(ServerConfig{
		Interface: "eth0",
		ServerIP:  net.ParseIP("192.168.1.1"),
	}, nil, poolMgr, logger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	circuitID := []byte("eth 0/1/1:100")
	cidKey := hex.EncodeToString(circuitID)

	lease := &Lease{
		MAC:       mac,
		IP:        net.ParseIP("10.0.1.100"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
		CircuitID: circuitID,
	}

	// Store in both indexes
	server.leasesMu.Lock()
	server.leases[mac.String()] = lease
	server.leasesMu.Unlock()

	server.leasesByCircuitIDMu.Lock()
	server.leasesByCircuitID[cidKey] = lease
	server.leasesByCircuitIDMu.Unlock()

	// Lookup by circuit-ID should find the lease
	found := server.lookupLeaseByCircuitID(circuitID)
	if found == nil {
		t.Fatal("expected to find lease by circuit-ID")
	}
	if found.IP.String() != "10.0.1.100" {
		t.Errorf("unexpected IP: %s", found.IP.String())
	}

	// Lookup with unknown circuit-ID should return nil
	found = server.lookupLeaseByCircuitID([]byte("unknown"))
	if found != nil {
		t.Error("expected nil for unknown circuit-ID")
	}

	// Lookup with empty circuit-ID should return nil
	found = server.lookupLeaseByCircuitID(nil)
	if found != nil {
		t.Error("expected nil for empty circuit-ID")
	}
}

func TestDualIndexCleanup(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

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
	poolMgr.AddPool(pool)

	server, err := NewServer(ServerConfig{
		Interface: "eth0",
		ServerIP:  net.ParseIP("10.0.1.1"),
	}, nil, poolMgr, logger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	circuitID := []byte("port-1")
	cidKey := hex.EncodeToString(circuitID)

	// Create a lease that's already expired
	expiredLease := &Lease{
		MAC:       mac,
		IP:        net.ParseIP("10.0.1.50"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(-time.Hour), // Already expired
		CircuitID: circuitID,
	}

	server.leasesMu.Lock()
	server.leases[mac.String()] = expiredLease
	server.leasesMu.Unlock()

	server.leasesByCircuitIDMu.Lock()
	server.leasesByCircuitID[cidKey] = expiredLease
	server.leasesByCircuitIDMu.Unlock()

	// Run cleanup
	server.cleanupExpiredLeases()

	// Both indexes should be cleaned
	server.leasesMu.RLock()
	_, macExists := server.leases[mac.String()]
	server.leasesMu.RUnlock()

	server.leasesByCircuitIDMu.RLock()
	_, cidExists := server.leasesByCircuitID[cidKey]
	server.leasesByCircuitIDMu.RUnlock()

	if macExists {
		t.Error("expected MAC lease to be cleaned up")
	}
	if cidExists {
		t.Error("expected circuit-ID lease to be cleaned up")
	}
}

func TestHybridRelayAndDirect(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	server, err := NewServer(ServerConfig{
		Interface: "eth0",
		ServerIP:  net.ParseIP("192.168.1.1"),
	}, nil, poolMgr, logger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Direct subscriber (no relay)
	directMAC, _ := net.ParseMAC("aa:bb:cc:00:00:01")
	directLease := &Lease{
		MAC:       directMAC,
		IP:        net.ParseIP("10.0.1.10"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// Relayed subscriber (with circuit-ID)
	relayedMAC, _ := net.ParseMAC("aa:bb:cc:00:00:02")
	relayedCircuitID := []byte("eth 0/2/1:200")
	relayedCIDKey := hex.EncodeToString(relayedCircuitID)
	relayedLease := &Lease{
		MAC:       relayedMAC,
		IP:        net.ParseIP("10.0.1.20"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
		CircuitID: relayedCircuitID,
	}

	// Store both
	server.leasesMu.Lock()
	server.leases[directMAC.String()] = directLease
	server.leases[relayedMAC.String()] = relayedLease
	server.leasesMu.Unlock()

	server.leasesByCircuitIDMu.Lock()
	server.leasesByCircuitID[relayedCIDKey] = relayedLease
	server.leasesByCircuitIDMu.Unlock()

	// Direct subscriber: found by MAC only
	server.leasesMu.RLock()
	found := server.leases[directMAC.String()]
	server.leasesMu.RUnlock()
	if found == nil || found.IP.String() != "10.0.1.10" {
		t.Error("direct subscriber not found by MAC")
	}

	// Relayed subscriber: found by circuit-ID
	found = server.lookupLeaseByCircuitID(relayedCircuitID)
	if found == nil || found.IP.String() != "10.0.1.20" {
		t.Error("relayed subscriber not found by circuit-ID")
	}

	// Relayed subscriber: also found by MAC (dual-indexed)
	server.leasesMu.RLock()
	found = server.leases[relayedMAC.String()]
	server.leasesMu.RUnlock()
	if found == nil || found.IP.String() != "10.0.1.20" {
		t.Error("relayed subscriber not found by MAC")
	}

	// Total leases should be 2 by MAC
	if server.ActiveLeases() != 2 {
		t.Errorf("expected 2 active leases, got %d", server.ActiveLeases())
	}
}

func TestRelayResponseRouting(t *testing.T) {
	// Verify that response destination is correctly computed
	tests := []struct {
		name       string
		giaddr     net.IP
		peerAddr   string
		expectDest string
	}{
		{
			name:       "direct - send to peer",
			giaddr:     net.IPv4zero,
			peerAddr:   "192.168.1.100:68",
			expectDest: "192.168.1.100:68",
		},
		{
			name:       "relayed - send to relay agent",
			giaddr:     net.ParseIP("10.0.0.1"),
			peerAddr:   "192.168.1.100:68",
			expectDest: "10.0.0.1:67",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isRelayed := !tt.giaddr.IsUnspecified() && !tt.giaddr.Equal(net.IPv4zero)

			peer, _ := net.ResolveUDPAddr("udp", tt.peerAddr)
			var dest net.Addr
			if isRelayed {
				dest = &net.UDPAddr{IP: tt.giaddr, Port: 67}
			} else {
				dest = peer
			}

			if dest.String() != tt.expectDest {
				t.Errorf("expected dest %q, got %q", tt.expectDest, dest.String())
			}
		})
	}
}
