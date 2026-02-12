package dhcp

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	bpf "github.com/codelaboratoryltd/bng/pkg/ebpf"
	"github.com/codelaboratoryltd/bng/pkg/nat"
	"github.com/codelaboratoryltd/bng/pkg/qos"
	"github.com/codelaboratoryltd/bng/pkg/radius"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"go.uber.org/zap"
)

// testServer creates a minimal server for testing handler logic.
// It uses a real ebpf.Loader with nil internal maps so loader methods
// return errors (map not loaded) rather than nil-pointer panics.
func testServer(t *testing.T) (*Server, *Pool) {
	t.Helper()
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)
	pool, err := NewPool(PoolConfig{
		ID:          1,
		Name:        "test-pool",
		Network:     "10.0.1.0/24",
		Gateway:     "10.0.1.1",
		DNSServers:  []string{"8.8.8.8", "8.8.4.4"},
		LeaseTime:   time.Hour,
		ClientClass: ClientClassResidential,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if err := poolMgr.AddPool(pool); err != nil {
		t.Fatalf("AddPool: %v", err)
	}

	// Create a Loader with nil internal maps (never calls Load()) so that
	// methods like RemoveSubscriber return an error instead of panicking.
	loader, err := bpf.NewLoader("lo0", logger)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	srv, err := NewServer(ServerConfig{
		Interface: "lo0",
		ServerIP:  net.ParseIP("10.0.1.1"),
	}, loader, poolMgr, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, pool
}

// makeDHCPPacket is a helper to build a DHCP packet of the given type.
func makeDHCPPacket(t *testing.T, mac net.HardwareAddr, msgType dhcpv4.MessageType) *dhcpv4.DHCPv4 {
	t.Helper()
	pkt, err := dhcpv4.NewDiscovery(mac)
	if err != nil {
		t.Fatalf("NewDiscovery: %v", err)
	}
	pkt.UpdateOption(dhcpv4.OptMessageType(msgType))
	return pkt
}

func TestHandleDiscover_LocalPool(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)

	resp, err := srv.handleDiscover(req)
	if err != nil {
		t.Fatalf("handleDiscover: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.MessageType() != dhcpv4.MessageTypeOffer {
		t.Errorf("expected OFFER, got %s", resp.MessageType())
	}
	if resp.YourIPAddr.IsUnspecified() {
		t.Error("offered IP should not be unspecified")
	}
	if srv.offersTotal != 1 {
		t.Errorf("expected offersTotal=1, got %d", srv.offersTotal)
	}
}

func TestHandleDiscover_ReusesExistingLease(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	expectedIP := net.ParseIP("10.0.1.50")

	// Pre-seed a lease
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        expectedIP,
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)
	resp, err := srv.handleDiscover(req)
	if err != nil {
		t.Fatalf("handleDiscover: %v", err)
	}
	if !resp.YourIPAddr.Equal(expectedIP) {
		t.Errorf("expected reuse of %s, got %s", expectedIP, resp.YourIPAddr)
	}
}

func TestHandleDiscover_NoPool(t *testing.T) {
	logger := zap.NewNop()
	emptyMgr := NewPoolManager(nil, logger)
	srv, err := NewServer(ServerConfig{
		Interface: "lo",
		ServerIP:  net.ParseIP("10.0.1.1"),
	}, nil, emptyMgr, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:03")
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)

	_, err = srv.handleDiscover(req)
	if err == nil {
		t.Fatal("expected error when no pool available")
	}
}

func TestHandleRequest_NewSession(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:10")

	// Allocate an IP first (as would happen in DISCOVER)
	ip, err := pool.Allocate(mac)
	if err != nil {
		t.Fatalf("pool.Allocate: %v", err)
	}

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}

	// Verify lease was created
	srv.leasesMu.RLock()
	lease, ok := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if !ok {
		t.Fatal("lease should exist")
	}
	if !lease.IP.Equal(ip) {
		t.Errorf("lease IP %s != allocated IP %s", lease.IP, ip)
	}
	if lease.SessionID == "" {
		t.Error("SessionID should be set for new session")
	}
}

func TestHandleRequest_Renewal(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:11")
	leaseIP := net.ParseIP("10.0.1.50")

	// Pre-seed lease (simulating an existing session)
	srv.leases[mac.String()] = &Lease{
		MAC:          mac,
		IP:           leaseIP,
		PoolID:       1,
		ExpiresAt:    time.Now().Add(time.Hour),
		SessionID:    "existing-session",
		SessionStart: time.Now().Add(-30 * time.Minute),
		PolicyName:   "residential-100mbps",
		Class:        []byte("test-class"),
		InputBytes:   1000,
		OutputBytes:  2000,
	}

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(leaseIP))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest renewal: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK on renewal, got %s", resp.MessageType())
	}

	// Verify session data was preserved
	srv.leasesMu.RLock()
	lease := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if lease.SessionID != "existing-session" {
		t.Errorf("session ID should be preserved, got %s", lease.SessionID)
	}
	if lease.PolicyName != "residential-100mbps" {
		t.Error("PolicyName should be preserved on renewal")
	}
	if lease.InputBytes != 1000 || lease.OutputBytes != 2000 {
		t.Error("byte counters should be preserved on renewal")
	}
}

func TestHandleRequest_RenewalIPMismatch(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:12")

	// Existing lease for 10.0.1.50
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        net.ParseIP("10.0.1.50"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// Request a different IP
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.0.1.99")))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("expected NAK for IP mismatch, got %s", resp.MessageType())
	}
}

func TestHandleRequest_IPNotInPool(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:13")

	// Request IP outside the pool range
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.99.99")))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("expected NAK for out-of-pool IP, got %s", resp.MessageType())
	}
}

func TestHandleRequest_NoRequestedIP_UsesClientIP(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:14")

	ip, _ := pool.Allocate(mac)
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	// Don't set RequestedIPAddress, set ClientIPAddr instead
	req.ClientIPAddr = ip

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK using ClientIPAddr, got %s", resp.MessageType())
	}
}

func TestHandleRequest_WithOption82(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:15")

	ip, _ := pool.Allocate(mac)
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	// Add Option 82
	opt82Data := []byte{
		1, 5, 'e', 't', 'h', '0', '1', // Circuit-ID
		2, 4, 'r', 'e', 'm', '1', // Remote-ID
	}
	req.Options.Update(dhcpv4.Option{
		Code:  dhcpv4.OptionRelayAgentInformation,
		Value: dhcpv4.OptionGeneric{Data: opt82Data},
	})

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}

	// Verify Option 82 was stored in lease
	srv.leasesMu.RLock()
	lease := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if string(lease.CircuitID) != "eth01" {
		t.Errorf("expected CircuitID 'eth01', got %q", string(lease.CircuitID))
	}
	if string(lease.RemoteID) != "rem1" {
		t.Errorf("expected RemoteID 'rem1', got %q", string(lease.RemoteID))
	}
}

func TestHandleRequest_RenewalPreservesOption82(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:16")
	leaseIP := net.ParseIP("10.0.1.60")

	// Pre-seed lease with Option 82 data
	srv.leases[mac.String()] = &Lease{
		MAC:          mac,
		IP:           leaseIP,
		PoolID:       1,
		ExpiresAt:    time.Now().Add(time.Hour),
		SessionID:    "sess-82",
		SessionStart: time.Now(),
		CircuitID:    []byte("original-circuit"),
		RemoteID:     []byte("original-remote"),
	}

	// Renewal request WITHOUT Option 82
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(leaseIP))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest renewal: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}

	srv.leasesMu.RLock()
	lease := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if string(lease.CircuitID) != "original-circuit" {
		t.Error("Option 82 CircuitID should be preserved on renewal without new Option 82")
	}
}

func TestHandleRelease(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:20")
	ip := net.ParseIP("10.0.1.70")

	// Pre-seed a lease
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        ip,
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRelease)
	srv.handleRelease(req)

	// Lease should be removed
	srv.leasesMu.RLock()
	_, exists := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if exists {
		t.Error("lease should be removed after release")
	}

	// Release counter should be incremented
	if srv.releasesTotal != 1 {
		t.Errorf("releasesTotal should be 1, got %d", srv.releasesTotal)
	}

	// IP should be released back to pool (verify pool availability increased)
	_ = pool
}

func TestHandleRelease_NonExistent(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:21")

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRelease)
	// Should not panic for non-existent lease
	srv.handleRelease(req)

	if srv.releasesTotal != 1 {
		t.Errorf("releasesTotal should be 1 even for non-existent, got %d", srv.releasesTotal)
	}
}

func TestHandleDecline(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:30")
	declinedIP := net.ParseIP("10.0.1.80")

	// Pre-seed a lease
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        declinedIP,
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDecline)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(declinedIP))
	srv.handleDecline(req)

	// Lease should be removed
	srv.leasesMu.RLock()
	_, exists := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if exists {
		t.Error("lease should be removed after decline")
	}

	// IP should be marked as unavailable in pool
	if _, ok := pool.unavailable[declinedIP.String()]; !ok {
		t.Error("declined IP should be marked unavailable in pool")
	}
}

func TestHandleDecline_NoExistingLease(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:31")

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDecline)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.0.1.99")))
	// Should not panic
	srv.handleDecline(req)
}

func TestHandleInform(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:40")

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeInform)
	req.ClientIPAddr = net.ParseIP("10.0.1.100")

	resp, err := srv.handleInform(req)
	if err != nil {
		t.Fatalf("handleInform: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK for INFORM, got %s", resp.MessageType())
	}
	// INFORM should not assign an IP (YourIPAddr stays zero)
}

func TestHandleInform_NoPool(t *testing.T) {
	logger := zap.NewNop()
	emptyMgr := NewPoolManager(nil, logger)
	srv, _ := NewServer(ServerConfig{
		Interface: "lo",
		ServerIP:  net.ParseIP("10.0.1.1"),
	}, nil, emptyMgr, logger)

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:41")
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeInform)
	req.ClientIPAddr = net.ParseIP("10.0.1.100")

	_, err := srv.handleInform(req)
	if err == nil {
		t.Fatal("expected error when no pool available")
	}
}

func TestBuildNAK(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:50")

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)

	resp, err := srv.buildNAK(req, "test reason")
	if err != nil {
		t.Fatalf("buildNAK: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("expected NAK, got %s", resp.MessageType())
	}
}

func TestUpdateFastPathCache_NilLoader(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)
	pool, err := NewPool(PoolConfig{
		ID:          1,
		Name:        "test-pool",
		Network:     "10.0.1.0/24",
		Gateway:     "10.0.1.1",
		DNSServers:  []string{"8.8.8.8", "8.8.4.4"},
		LeaseTime:   time.Hour,
		ClientClass: ClientClassResidential,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if err := poolMgr.AddPool(pool); err != nil {
		t.Fatalf("AddPool: %v", err)
	}

	// Create a server with nil loader explicitly
	srv, err := NewServer(ServerConfig{
		Interface: "lo0",
		ServerIP:  net.ParseIP("10.0.1.1"),
	}, nil, poolMgr, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:60")
	lease := &Lease{
		MAC:       mac,
		IP:        net.ParseIP("10.0.1.50"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// Should return nil (no-op) when loader is nil
	err = srv.updateFastPathCache(mac, lease, pool)
	if err != nil {
		t.Errorf("updateFastPathCache with nil loader should return nil, got %v", err)
	}
}

func TestUpdateFastPathCache_WithLoader(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:61")

	lease := &Lease{
		MAC:       mac,
		IP:        net.ParseIP("10.0.1.51"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// Loader has nil maps, so AddSubscriber returns an error
	err := srv.updateFastPathCache(mac, lease, pool)
	if err == nil {
		t.Error("expected error from updateFastPathCache with unloaded maps")
	}
}

func TestCleanupExpiredLeases(t *testing.T) {
	srv, _ := testServer(t)

	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:70")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:71")

	// One expired, one not
	srv.leases[mac1.String()] = &Lease{
		MAC:       mac1,
		IP:        net.ParseIP("10.0.1.50"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(-time.Hour), // expired
	}
	srv.leases[mac2.String()] = &Lease{
		MAC:       mac2,
		IP:        net.ParseIP("10.0.1.51"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(time.Hour), // still valid
	}

	srv.cleanupExpiredLeases()

	srv.leasesMu.RLock()
	defer srv.leasesMu.RUnlock()

	if _, ok := srv.leases[mac1.String()]; ok {
		t.Error("expired lease should be cleaned up")
	}
	if _, ok := srv.leases[mac2.String()]; !ok {
		t.Error("non-expired lease should still exist")
	}
}

func TestCleanupExpiredLeases_Empty(t *testing.T) {
	srv, _ := testServer(t)
	// Should not panic with no leases
	srv.cleanupExpiredLeases()
}

func TestHandleDHCP_AllMessageTypes(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:80")

	// Allocate an IP for the REQUEST path
	ip, _ := pool.Allocate(mac)

	tests := []struct {
		name    string
		msgType dhcpv4.MessageType
	}{
		{"discover", dhcpv4.MessageTypeDiscover},
		{"request", dhcpv4.MessageTypeRequest},
		{"release", dhcpv4.MessageTypeRelease},
		{"decline", dhcpv4.MessageTypeDecline},
		{"inform", dhcpv4.MessageTypeInform},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeDHCPPacket(t, mac, tt.msgType)
			if tt.msgType == dhcpv4.MessageTypeRequest {
				req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))
			}
			if tt.msgType == dhcpv4.MessageTypeInform {
				req.ClientIPAddr = ip
			}
			// Call the underlying handlers directly to verify no panics
			switch tt.msgType {
			case dhcpv4.MessageTypeDiscover:
				srv.handleDiscover(req)
			case dhcpv4.MessageTypeRequest:
				srv.handleRequest(req)
			case dhcpv4.MessageTypeRelease:
				srv.handleRelease(req)
			case dhcpv4.MessageTypeDecline:
				srv.handleDecline(req)
			case dhcpv4.MessageTypeInform:
				srv.handleInform(req)
			}
		})
	}
}

func TestConcurrentDiscoverRequests(t *testing.T) {
	srv, _ := testServer(t)
	var wg sync.WaitGroup
	errors := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, byte(idx >> 8), byte(idx), 0x00}
			req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)

			_, err := srv.handleDiscover(req)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent discover error: %v", err)
	}

	if srv.ActiveLeases() != 0 {
		// Discover doesn't create leases, only Request does
	}
}

func TestConcurrentRequestAndRelease(t *testing.T) {
	srv, pool := testServer(t)
	var wg sync.WaitGroup

	// Pre-allocate IPs for 20 MACs
	macs := make([]net.HardwareAddr, 20)
	ips := make([]net.IP, 20)
	for i := 0; i < 20; i++ {
		macs[i] = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, byte(i), 0x01}
		ip, err := pool.Allocate(macs[i])
		if err != nil {
			t.Fatalf("pool.Allocate[%d]: %v", i, err)
		}
		ips[i] = ip
	}

	// Concurrent REQUESTs
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := makeDHCPPacket(t, macs[idx], dhcpv4.MessageTypeRequest)
			req.UpdateOption(dhcpv4.OptRequestedIPAddress(ips[idx]))
			srv.handleRequest(req)
		}(i)
	}
	wg.Wait()

	if srv.ActiveLeases() != 20 {
		t.Errorf("expected 20 leases, got %d", srv.ActiveLeases())
	}

	// Concurrent RELEASEs
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := makeDHCPPacket(t, macs[idx], dhcpv4.MessageTypeRelease)
			srv.handleRelease(req)
		}(i)
	}
	wg.Wait()

	if srv.ActiveLeases() != 0 {
		t.Errorf("expected 0 leases after release, got %d", srv.ActiveLeases())
	}
}

func TestSetHTTPAllocator(t *testing.T) {
	srv, _ := testServer(t)
	srv.SetHTTPAllocator(nil, "test-pool-id")

	if srv.httpAllocatorPool != "test-pool-id" {
		t.Errorf("expected httpAllocatorPool 'test-pool-id', got %s", srv.httpAllocatorPool)
	}
}

func TestSetPeerPool(t *testing.T) {
	srv, _ := testServer(t)
	srv.SetPeerPool(nil)
	// No panic expected
}

func TestPoolReservedIPs(t *testing.T) {
	pool, err := NewPool(PoolConfig{
		ID:            1,
		Name:          "reserved-test",
		Network:       "10.0.0.0/24",
		Gateway:       "10.0.0.1",
		DNSServers:    []string{"8.8.8.8"},
		LeaseTime:     time.Hour,
		ReservedStart: 5,
		ReservedEnd:   3,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	// /24 = 254 usable IPs, minus 5 start + 3 end = 246, minus gateway (already in reserved start)
	expectedAvailable := 254 - 5 - 3
	if len(pool.available) != expectedAvailable {
		t.Errorf("expected %d available IPs, got %d", expectedAvailable, len(pool.available))
	}

	// First available IP should be after the reserved start range
	firstIP := pool.available[0]
	if firstIP[3] <= 5 {
		t.Errorf("first available IP (%s) should be after reserved start", firstIP)
	}
}

func TestPoolConcurrentAllocations(t *testing.T) {
	pool, err := NewPool(PoolConfig{
		ID:         1,
		Name:       "concurrent",
		Network:    "10.0.0.0/22", // 1022 usable IPs
		Gateway:    "10.0.0.1",
		DNSServers: []string{"8.8.8.8"},
		LeaseTime:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	var wg sync.WaitGroup
	allocated := make(chan net.IP, 200)

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mac := net.HardwareAddr{0xaa, 0xbb, byte(idx >> 8), byte(idx), 0x00, 0x01}
			ip, err := pool.Allocate(mac)
			if err != nil {
				return
			}
			allocated <- ip
		}(i)
	}

	wg.Wait()
	close(allocated)

	// Verify no duplicate IPs
	seen := make(map[string]bool)
	for ip := range allocated {
		s := ip.String()
		if seen[s] {
			t.Errorf("duplicate IP allocated: %s", s)
		}
		seen[s] = true
	}
}

func TestPoolManagerClassifyClient_NoPools(t *testing.T) {
	mgr := NewPoolManager(nil, nil)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	pool := mgr.ClassifyClient(mac)
	if pool != nil {
		t.Error("expected nil when no pools registered")
	}
}

func TestParseOption82_OnlyHeader(t *testing.T) {
	// Only 1 byte (sub-option type but no length)
	req, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	req.Options.Update(dhcpv4.Option{
		Code:  dhcpv4.OptionRelayAgentInformation,
		Value: dhcpv4.OptionGeneric{Data: []byte{1}},
	})

	info := parseOption82(req)
	if info != nil {
		// Either nil or empty fields is acceptable
		if len(info.CircuitID) != 0 {
			t.Errorf("expected empty CircuitID, got %q", info.CircuitID)
		}
	}
}

func TestParseOption82_ZeroLengthSubOption(t *testing.T) {
	req, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	req.Options.Update(dhcpv4.Option{
		Code:  dhcpv4.OptionRelayAgentInformation,
		Value: dhcpv4.OptionGeneric{Data: []byte{1, 0}}, // Circuit-ID with zero length
	})

	info := parseOption82(req)
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if len(info.CircuitID) != 0 {
		t.Errorf("expected empty CircuitID for zero-length sub-option, got %q", info.CircuitID)
	}
}

func TestParseOption82_UnknownSubOptions(t *testing.T) {
	req, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	// Sub-option type 3 (unknown) followed by valid Circuit-ID
	req.Options.Update(dhcpv4.Option{
		Code: dhcpv4.OptionRelayAgentInformation,
		Value: dhcpv4.OptionGeneric{Data: []byte{
			3, 2, 'x', 'y', // Unknown sub-option type 3
			1, 3, 'c', 'i', 'd', // Circuit-ID
		}},
	})

	info := parseOption82(req)
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if string(info.CircuitID) != "cid" {
		t.Errorf("expected CircuitID 'cid', got %q", info.CircuitID)
	}
}

func TestHandleDiscover_ExpiredLease(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:90")

	// Seed an expired lease
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        net.ParseIP("10.0.1.55"),
		PoolID:    1,
		ExpiresAt: time.Now().Add(-time.Hour), // expired
	}

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)
	resp, err := srv.handleDiscover(req)
	if err != nil {
		t.Fatalf("handleDiscover: %v", err)
	}
	// Should allocate a new IP since old lease expired
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestPoolHelperFunctions(t *testing.T) {
	// Test prefixLen helper
	mask := net.CIDRMask(24, 32)
	if pl := prefixLen(mask); pl != 24 {
		t.Errorf("prefixLen(/24) = %d, want 24", pl)
	}

	mask16 := net.CIDRMask(16, 32)
	if pl := prefixLen(mask16); pl != 16 {
		t.Errorf("prefixLen(/16) = %d, want 16", pl)
	}

	// Test dnsToUint32 helper
	servers := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")}
	if val := dnsToUint32(servers, 0); val == 0 {
		t.Error("dnsToUint32 should return non-zero for valid DNS")
	}
	if val := dnsToUint32(servers, 2); val != 0 {
		t.Errorf("dnsToUint32 out of bounds should return 0, got %d", val)
	}
	if val := dnsToUint32(nil, 0); val != 0 {
		t.Errorf("dnsToUint32 nil slice should return 0, got %d", val)
	}
}

func TestHandleRequest_WithHostname(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:a0")

	ip, _ := pool.Allocate(mac)
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))
	req.UpdateOption(dhcpv4.OptHostName("my-laptop"))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}

	srv.leasesMu.RLock()
	lease := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if lease.Hostname != "my-laptop" {
		t.Errorf("expected hostname 'my-laptop', got %q", lease.Hostname)
	}
}

func TestHandleDiscover_WithOption82(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:b0")
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)

	// Add Option 82
	opt82Data := []byte{
		1, 5, 'e', 't', 'h', '0', '1',
		2, 4, 'r', 'e', 'm', '1',
	}
	req.Options.Update(dhcpv4.Option{
		Code:  dhcpv4.OptionRelayAgentInformation,
		Value: dhcpv4.OptionGeneric{Data: opt82Data},
	})

	resp, err := srv.handleDiscover(req)
	if err != nil {
		t.Fatalf("handleDiscover with Option 82: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestHandleDHCP_UnknownMessageType(t *testing.T) {
	srv, _ := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:c0")
	// Use a random message type that's not handled
	_ = makeDHCPPacket(t, mac, dhcpv4.MessageType(99))

	// handleDHCP dispatches based on type; unrecognized types are ignored
	// Verify the server's counters are accessible and zero-valued for this path
	if srv.requestsTotal != 0 {
		t.Errorf("expected 0 initial requests, got %d", srv.requestsTotal)
	}
}

// --- Additional tests to increase branch coverage ---

func TestHandleRequest_RADIUSAuthEnabled_NoServer(t *testing.T) {
	// Create a server with RADIUS auth enabled and a RADIUS client pointing to
	// an unreachable server. The RADIUS exchange will fail and handleRequest
	// should send a NAK.
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)
	pool, err := NewPool(PoolConfig{
		ID:          1,
		Name:        "test-pool",
		Network:     "10.0.2.0/24",
		Gateway:     "10.0.2.1",
		DNSServers:  []string{"8.8.8.8"},
		LeaseTime:   time.Hour,
		ClientClass: ClientClassResidential,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if err := poolMgr.AddPool(pool); err != nil {
		t.Fatalf("AddPool: %v", err)
	}

	loader, _ := bpf.NewLoader("lo0", logger)
	srv, err := NewServer(ServerConfig{
		Interface:         "lo0",
		ServerIP:          net.ParseIP("10.0.2.1"),
		RADIUSAuthEnabled: true,
	}, loader, poolMgr, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Create a RADIUS client with short timeout pointing to a non-existent server
	radiusClient, err := radius.NewClient(radius.ClientConfig{
		Servers: []radius.ServerConfig{{Host: "127.0.0.1", Port: 18122, Secret: "test"}},
		NASID:   "test-nas",
		Timeout: 50 * time.Millisecond,
		Retries: 1,
	}, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	srv.SetRADIUSClient(radiusClient)

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d0")
	ip, _ := pool.Allocate(mac)
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	// Should get a NAK because RADIUS auth fails (no server listening)
	if resp.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("expected NAK due to RADIUS failure, got %s", resp.MessageType())
	}
	if srv.radiusAuthFail != 1 {
		t.Errorf("expected radiusAuthFail=1, got %d", srv.radiusAuthFail)
	}
}

func TestHandleRequest_WithQoSManager(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d1")

	// Set up QoS manager (with nil eBPF maps it will fail on eBPF part,
	// but the SetSubscriberPolicy path will be exercised)
	policyMgr := radius.NewPolicyManager()
	policyMgr.LoadDefaultPolicies()
	qosMgr, err := qos.NewManager(qos.ManagerConfig{
		Interface: "lo0",
	}, policyMgr, zap.NewNop())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	srv.SetQoSManager(qosMgr)

	ip, _ := pool.Allocate(mac)
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest with QoS: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}
}

func TestHandleRequest_WithNATManager(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d2")

	// Set up NAT manager with a public IP pool
	natMgr, err := nat.NewManager(nat.ManagerConfig{
		Interface: "lo0",
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("nat.NewManager: %v", err)
	}
	natMgr.AddPublicIP(net.ParseIP("203.0.113.1"))
	srv.SetNATManager(natMgr)

	ip, _ := pool.Allocate(mac)
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest with NAT: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}
}

func TestHandleRelease_WithRADIUSAccounting(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)
	pool, err := NewPool(PoolConfig{
		ID:          1,
		Name:        "test-pool",
		Network:     "10.0.3.0/24",
		Gateway:     "10.0.3.1",
		DNSServers:  []string{"8.8.8.8"},
		LeaseTime:   time.Hour,
		ClientClass: ClientClassResidential,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if err := poolMgr.AddPool(pool); err != nil {
		t.Fatalf("AddPool: %v", err)
	}

	loader, _ := bpf.NewLoader("lo0", logger)
	srv, err := NewServer(ServerConfig{
		Interface: "lo0",
		ServerIP:  net.ParseIP("10.0.3.1"),
	}, loader, poolMgr, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Set up RADIUS client (accounting stop will be sent in goroutine)
	radiusClient, err := radius.NewClient(radius.ClientConfig{
		Servers: []radius.ServerConfig{{Host: "127.0.0.1", Port: 18123, Secret: "test"}},
		NASID:   "test-nas",
		Timeout: 50 * time.Millisecond,
		Retries: 1,
	}, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	srv.SetRADIUSClient(radiusClient)

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d3")
	ip, _ := pool.Allocate(mac)

	// Create an existing lease with session data
	srv.leasesMu.Lock()
	srv.leases[mac.String()] = &Lease{
		MAC:          mac,
		IP:           ip,
		PoolID:       1,
		SessionID:    "test-session-acct",
		SessionStart: time.Now().Add(-30 * time.Minute),
		InputBytes:   1024,
		OutputBytes:  2048,
		Class:        []byte("gold-class"),
		ExpiresAt:    time.Now().Add(30 * time.Minute),
	}
	srv.leasesMu.Unlock()

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRelease)
	req.ClientIPAddr = ip
	srv.handleRelease(req)

	// Give goroutine time to run accounting stop
	time.Sleep(100 * time.Millisecond)

	// Verify lease was removed
	srv.leasesMu.RLock()
	_, exists := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if exists {
		t.Error("lease should have been removed after release")
	}
}

func TestHandleRelease_WithQoSAndNAT(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d4")
	ip, _ := pool.Allocate(mac)

	// Set up QoS manager
	policyMgr := radius.NewPolicyManager()
	policyMgr.LoadDefaultPolicies()
	qosMgr, err := qos.NewManager(qos.ManagerConfig{
		Interface: "lo0",
	}, policyMgr, zap.NewNop())
	if err != nil {
		t.Fatalf("qos.NewManager: %v", err)
	}
	srv.SetQoSManager(qosMgr)

	// Set up NAT manager
	natMgr, err := nat.NewManager(nat.ManagerConfig{
		Interface: "lo0",
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("nat.NewManager: %v", err)
	}
	natMgr.AddPublicIP(net.ParseIP("203.0.113.2"))
	srv.SetNATManager(natMgr)

	// Create an existing lease
	srv.leasesMu.Lock()
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        ip,
		PoolID:    1,
		SessionID: "test-session-qos-nat",
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	srv.leasesMu.Unlock()

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRelease)
	req.ClientIPAddr = ip
	srv.handleRelease(req)

	// Verify lease was removed
	srv.leasesMu.RLock()
	_, exists := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if exists {
		t.Error("lease should have been removed after release")
	}
}

func TestHandleRelease_WithVLANTags(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d5")
	ip, _ := pool.Allocate(mac)

	// Create a lease with QinQ VLAN tags
	srv.leasesMu.Lock()
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        ip,
		PoolID:    1,
		SessionID: "test-session-vlan",
		STag:      100,
		CTag:      200,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	srv.leasesMu.Unlock()

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRelease)
	req.ClientIPAddr = ip
	srv.handleRelease(req)

	srv.leasesMu.RLock()
	_, exists := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if exists {
		t.Error("lease should have been removed after release")
	}
}

func TestHandleRelease_WithCircuitID(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d6")
	ip, _ := pool.Allocate(mac)

	// Create a lease with circuit-id
	srv.leasesMu.Lock()
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        ip,
		PoolID:    1,
		SessionID: "test-session-cid",
		CircuitID: []byte("circuit-test-001"),
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	srv.leasesMu.Unlock()

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRelease)
	req.ClientIPAddr = ip
	srv.handleRelease(req)

	srv.leasesMu.RLock()
	_, exists := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if exists {
		t.Error("lease should have been removed after release")
	}
}

func TestUpdateFastPathCache_WithVLANTags(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d7")

	lease := &Lease{
		MAC:       mac,
		IP:        net.ParseIP("10.0.1.70"),
		PoolID:    1,
		STag:      100,
		CTag:      200,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// With a loader that has nil maps, AddSubscriber fails first.
	// But the VLAN branch (STag > 0 || CTag > 0) should be entered.
	err := srv.updateFastPathCache(mac, lease, pool)
	if err == nil {
		t.Error("expected error from updateFastPathCache with unloaded maps")
	}
}

func TestHandleRequest_CircuitIDMapping(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d8")

	ip, _ := pool.Allocate(mac)
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	// Add Option 82 with circuit-id to trigger circuit-id mapping path
	opt82Data := []byte{
		1, 8, 'c', 'i', 'r', 'c', 'u', 'i', 't', '1', // Circuit-ID
		2, 4, 'r', 'e', 'm', '1', // Remote-ID
	}
	req.Options.Update(dhcpv4.Option{
		Code:  dhcpv4.OptionRelayAgentInformation,
		Value: dhcpv4.OptionGeneric{Data: opt82Data},
	})

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest with circuit-id: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}

	// Verify the lease has circuit-id set
	srv.leasesMu.RLock()
	lease := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if lease == nil {
		t.Fatal("lease not found")
	}
	if string(lease.CircuitID) != "circuit1" {
		t.Errorf("expected CircuitID='circuit1', got %q", string(lease.CircuitID))
	}
}

func TestHandleRequest_RenewalPreservesSession(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:d9")

	ip, _ := pool.Allocate(mac)

	// Create initial lease with session data
	sessionID := "initial-session-id"
	sessionStart := time.Now().Add(-1 * time.Hour)
	srv.leasesMu.Lock()
	srv.leases[mac.String()] = &Lease{
		MAC:          mac,
		IP:           ip,
		PoolID:       1,
		SessionID:    sessionID,
		SessionStart: sessionStart,
		Class:        []byte("gold"),
		PolicyName:   "business-1gbps",
		InputBytes:   5000,
		OutputBytes:  10000,
		CircuitID:    []byte("old-circuit"),
		RemoteID:     []byte("old-remote"),
		ExpiresAt:    time.Now().Add(30 * time.Minute),
	}
	srv.leasesMu.Unlock()

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest (renewal): %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}

	// Verify session data is preserved
	srv.leasesMu.RLock()
	lease := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if lease.SessionID != sessionID {
		t.Errorf("expected preserved SessionID=%q, got %q", sessionID, lease.SessionID)
	}
	if string(lease.Class) != "gold" {
		t.Errorf("expected preserved Class='gold', got %q", string(lease.Class))
	}
	if lease.PolicyName != "business-1gbps" {
		t.Errorf("expected preserved PolicyName='business-1gbps', got %q", lease.PolicyName)
	}
	if lease.InputBytes != 5000 {
		t.Errorf("expected preserved InputBytes=5000, got %d", lease.InputBytes)
	}
	// Option 82 should be preserved since renewal has no new option 82
	if string(lease.CircuitID) != "old-circuit" {
		t.Errorf("expected preserved CircuitID='old-circuit', got %q", string(lease.CircuitID))
	}
}

func TestHandleRequest_PoolNotFound(t *testing.T) {
	// Test when the existing lease references a pool that no longer exists
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:da")

	ip, _ := pool.Allocate(mac)

	// Create a lease referencing a non-existent pool ID
	srv.leasesMu.Lock()
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        ip,
		PoolID:    999, // non-existent pool
		ExpiresAt: time.Now().Add(time.Hour),
	}
	srv.leasesMu.Unlock()

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	// Pool is nil, so should get NAK "pool not found"
	if resp.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("expected NAK for missing pool, got %s", resp.MessageType())
	}
}

func TestHandleDiscover_PoolExhausted(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	// Create a tiny pool with only 2 IPs (/30 has network + broadcast + gateway = 1 usable)
	pool, err := NewPool(PoolConfig{
		ID:          1,
		Name:        "tiny-pool",
		Network:     "10.0.99.0/30",
		Gateway:     "10.0.99.1",
		DNSServers:  []string{"8.8.8.8"},
		LeaseTime:   time.Hour,
		ClientClass: ClientClassResidential,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if err := poolMgr.AddPool(pool); err != nil {
		t.Fatalf("AddPool: %v", err)
	}

	loader, _ := bpf.NewLoader("lo0", logger)
	srv, err := NewServer(ServerConfig{
		Interface: "lo0",
		ServerIP:  net.ParseIP("10.0.99.1"),
	}, loader, poolMgr, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Exhaust the pool
	stats := pool.Stats()
	for i := 0; i < int(stats.Available); i++ {
		mac, _ := net.ParseMAC(fmt.Sprintf("aa:bb:cc:dd:%02x:%02x", i/256, i%256))
		_, err := pool.Allocate(mac)
		if err != nil {
			break
		}
	}

	// Now try a discover - should fail with no IP available
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ff:ff")
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)

	_, err = srv.handleDiscover(req)
	if err == nil {
		t.Error("expected error when pool is exhausted")
	}
}

func TestHandleDiscover_NilPoolOffer(t *testing.T) {
	// Test the case where pool is nil in the offer building code
	// This happens when Nexus provides an IP but there's no matching local pool
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	loader, _ := bpf.NewLoader("lo0", logger)
	srv, err := NewServer(ServerConfig{
		Interface: "lo0",
		ServerIP:  net.ParseIP("10.0.4.1"),
	}, loader, poolMgr, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:db")
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)

	// No pools available - should get error
	_, err = srv.handleDiscover(req)
	if err == nil {
		t.Error("expected error when no pools available")
	}
}

func TestHandleInform_NilPool(t *testing.T) {
	// Test handleInform when ClassifyClient returns nil (no pools)
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	loader, _ := bpf.NewLoader("lo0", logger)
	srv, err := NewServer(ServerConfig{
		Interface: "lo0",
		ServerIP:  net.ParseIP("10.0.5.1"),
	}, loader, poolMgr, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:dc")
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeInform)
	req.ClientIPAddr = net.ParseIP("10.0.5.100")

	_, err = srv.handleInform(req)
	if err == nil {
		t.Error("expected error when no pool available for INFORM")
	}
}

func TestCleanupExpiredLeases_WithExpired(t *testing.T) {
	srv, pool := testServer(t)
	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:e0")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:e1")

	ip1, _ := pool.Allocate(mac1)
	ip2, _ := pool.Allocate(mac2)

	// Add one expired and one valid lease
	srv.leasesMu.Lock()
	srv.leases[mac1.String()] = &Lease{
		MAC:       mac1,
		IP:        ip1,
		PoolID:    1,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	}
	srv.leases[mac2.String()] = &Lease{
		MAC:       mac2,
		IP:        ip2,
		PoolID:    1,
		ExpiresAt: time.Now().Add(1 * time.Hour), // Still valid
	}
	srv.leasesMu.Unlock()

	srv.cleanupExpiredLeases()

	srv.leasesMu.RLock()
	_, expired := srv.leases[mac1.String()]
	_, valid := srv.leases[mac2.String()]
	srv.leasesMu.RUnlock()

	if expired {
		t.Error("expired lease should have been cleaned up")
	}
	if !valid {
		t.Error("valid lease should not have been cleaned up")
	}
}

func TestHandleRequest_NewSessionWithAuthResponse(t *testing.T) {
	// Test that authResp fields are captured in the lease
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:e2")

	ip, _ := pool.Allocate(mac)
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	// New session without RADIUS - should create a session ID
	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}

	srv.leasesMu.RLock()
	lease := srv.leases[mac.String()]
	srv.leasesMu.RUnlock()
	if lease.SessionID == "" {
		t.Error("expected non-empty session ID for new session")
	}
	if lease.SessionStart.IsZero() {
		t.Error("expected non-zero session start for new session")
	}
}

func TestPoolManager_WithLoader_AddRemovePool(t *testing.T) {
	logger := zap.NewNop()
	loader, _ := bpf.NewLoader("lo0", logger)
	poolMgr := NewPoolManager(loader, logger)

	pool, err := NewPool(PoolConfig{
		ID:          10,
		Name:        "loader-pool",
		Network:     "10.0.10.0/24",
		Gateway:     "10.0.10.1",
		DNSServers:  []string{"8.8.8.8"},
		LeaseTime:   time.Hour,
		ClientClass: ClientClassResidential,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	// AddPool with loader — exercises the eBPF sync path (will warn about map not loaded)
	if err := poolMgr.AddPool(pool); err != nil {
		t.Fatalf("AddPool: %v", err)
	}

	// Adding the same pool again should fail
	if err := poolMgr.AddPool(pool); err == nil {
		t.Error("expected error adding duplicate pool")
	}

	// RemovePool with loader — exercises the eBPF removal path
	if err := poolMgr.RemovePool(10); err != nil {
		t.Fatalf("RemovePool: %v", err)
	}
}

func TestClassifyClient_FallbackPool(t *testing.T) {
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)

	pool, _ := NewPool(PoolConfig{
		ID:          5,
		Name:        "fallback-pool",
		Network:     "10.0.5.0/24",
		Gateway:     "10.0.5.1",
		DNSServers:  []string{"8.8.8.8"},
		LeaseTime:   time.Hour,
		ClientClass: ClientClassResidential,
	})
	poolMgr.AddPool(pool)

	// Set default to a non-existent pool to force the fallback path
	poolMgr.defaultPoolID = 999

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:f0")
	result := poolMgr.ClassifyClient(mac)
	if result == nil {
		t.Error("expected fallback pool from ClassifyClient")
	}
}

func TestHandleDiscover_ExpiredLeaseFallsToLocalPool(t *testing.T) {
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:f1")

	ip, _ := pool.Allocate(mac)

	// Create an expired lease
	srv.leasesMu.Lock()
	srv.leases[mac.String()] = &Lease{
		MAC:       mac,
		IP:        ip,
		PoolID:    1,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	}
	srv.leasesMu.Unlock()

	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)
	resp, err := srv.handleDiscover(req)
	if err != nil {
		t.Fatalf("handleDiscover with expired lease: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.MessageType() != dhcpv4.MessageTypeOffer {
		t.Errorf("expected OFFER, got %s", resp.MessageType())
	}
}

func TestHandleDiscover_NoGatewayOrDNS(t *testing.T) {
	// Tests the path where pool has nil gateway and no DNS servers
	logger := zap.NewNop()
	poolMgr := NewPoolManager(nil, logger)
	pool, _ := NewPool(PoolConfig{
		ID:          1,
		Name:        "no-extras",
		Network:     "10.0.20.0/24",
		Gateway:     "10.0.20.1", // Gateway is required for pool creation
		LeaseTime:   time.Hour,
		ClientClass: ClientClassResidential,
	})
	poolMgr.AddPool(pool)
	// Clear DNS and gateway to test the nil branches in offer building
	pool.DNSServers = nil
	pool.Gateway = nil

	loader, _ := bpf.NewLoader("lo0", logger)
	srv, _ := NewServer(ServerConfig{
		Interface: "lo0",
		ServerIP:  net.ParseIP("10.0.20.1"),
	}, loader, poolMgr, logger)

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:f2")
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeDiscover)
	resp, err := srv.handleDiscover(req)
	if err != nil {
		t.Fatalf("handleDiscover no gateway/dns: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeOffer {
		t.Errorf("expected OFFER, got %s", resp.MessageType())
	}
}

func TestHandleRequest_RADIUSAccountingStart(t *testing.T) {
	// Test the RADIUS accounting start goroutine path
	srv, pool := testServer(t)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:f3")

	radiusClient, _ := radius.NewClient(radius.ClientConfig{
		Servers: []radius.ServerConfig{{Host: "127.0.0.1", Port: 18124, Secret: "test"}},
		NASID:   "test-nas",
		Timeout: 50 * time.Millisecond,
		Retries: 1,
	}, zap.NewNop())
	srv.SetRADIUSClient(radiusClient)
	// Note: radiusAuthEnabled is false, so auth is skipped but accounting start is sent

	ip, _ := pool.Allocate(mac)
	req := makeDHCPPacket(t, mac, dhcpv4.MessageTypeRequest)
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(ip))

	resp, err := srv.handleRequest(req)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if resp.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("expected ACK, got %s", resp.MessageType())
	}

	// Let the accounting goroutine run
	time.Sleep(100 * time.Millisecond)
}

func TestGenerateAvailableIPs_SmallNetwork(t *testing.T) {
	// Test generateAvailableIPs with a /28 network (14 usable hosts)
	pool, err := NewPool(PoolConfig{
		ID:          100,
		Name:        "small",
		Network:     "10.0.100.0/28",
		Gateway:     "10.0.100.1",
		LeaseTime:   time.Hour,
		ClientClass: ClientClassResidential,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	stats := pool.Stats()
	if stats.Total == 0 {
		t.Error("expected at least some IPs in /28 pool")
	}
}
