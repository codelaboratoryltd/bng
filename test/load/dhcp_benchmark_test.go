package load

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
)

// mockDHCPServer is a simple DHCP server for testing
type mockDHCPServer struct {
	listener *net.UDPConn
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Simulated latency
	fastPathLatency time.Duration
	slowPathLatency time.Duration

	// Statistics
	requests  uint64
	responses uint64

	// Cache simulation
	cache   map[string]net.IP
	cacheMu sync.RWMutex

	// IP allocation
	nextIP uint32
	ipMu   sync.Mutex
}

func newMockDHCPServer(addr string, fastLatency, slowLatency time.Duration) (*mockDHCPServer, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, err
	}

	return &mockDHCPServer{
		listener:        conn,
		stopCh:          make(chan struct{}),
		cache:           make(map[string]net.IP),
		fastPathLatency: fastLatency,
		slowPathLatency: slowLatency,
		nextIP:          0x0A000002, // 10.0.0.2
	}, nil
}

func (s *mockDHCPServer) start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 1500)

		for {
			select {
			case <-s.stopCh:
				return
			default:
			}

			s.listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := s.listener.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				continue
			}

			atomic.AddUint64(&s.requests, 1)

			// Parse request
			req, err := dhcpv4.FromBytes(buf[:n])
			if err != nil {
				continue
			}

			// Simulate fast path vs slow path
			mac := req.ClientHWAddr.String()
			s.cacheMu.RLock()
			_, inCache := s.cache[mac]
			s.cacheMu.RUnlock()

			if inCache {
				// Fast path - simulate eBPF latency
				time.Sleep(s.fastPathLatency)
			} else {
				// Slow path - simulate userspace latency
				time.Sleep(s.slowPathLatency)
			}

			// Get or allocate IP
			var ip net.IP
			s.cacheMu.Lock()
			if cachedIP, ok := s.cache[mac]; ok {
				ip = cachedIP
			} else {
				s.ipMu.Lock()
				ip = net.IPv4(byte(s.nextIP>>24), byte(s.nextIP>>16), byte(s.nextIP>>8), byte(s.nextIP))
				s.nextIP++
				s.ipMu.Unlock()
				s.cache[mac] = ip
			}
			s.cacheMu.Unlock()

			// Build response based on message type
			var resp *dhcpv4.DHCPv4
			switch req.MessageType() {
			case dhcpv4.MessageTypeDiscover:
				resp, _ = dhcpv4.NewReplyFromRequest(req,
					dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
					dhcpv4.WithYourIP(ip),
					dhcpv4.WithServerIP(net.ParseIP("10.0.0.1")),
				)
			case dhcpv4.MessageTypeRequest:
				resp, _ = dhcpv4.NewReplyFromRequest(req,
					dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
					dhcpv4.WithYourIP(ip),
					dhcpv4.WithServerIP(net.ParseIP("10.0.0.1")),
				)
			default:
				continue
			}

			if resp != nil {
				s.listener.WriteToUDP(resp.ToBytes(), addr)
				atomic.AddUint64(&s.responses, 1)
			}
		}
	}()
}

func (s *mockDHCPServer) stop() {
	close(s.stopCh)
	s.listener.Close()
	s.wg.Wait()
}

func (s *mockDHCPServer) addr() string {
	return s.listener.LocalAddr().String()
}

// TestBenchmarkConfig tests the benchmark configuration
func TestBenchmarkConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Concurrency != 100 {
		t.Errorf("Expected default concurrency 100, got %d", cfg.Concurrency)
	}

	if cfg.Duration != 30*time.Second {
		t.Errorf("Expected default duration 30s, got %s", cfg.Duration)
	}

	if cfg.UniqueMACs != 10000 {
		t.Errorf("Expected default unique MACs 10000, got %d", cfg.UniqueMACs)
	}
}

// TestGenerateMACs tests MAC address generation
func TestGenerateMACs(t *testing.T) {
	macs := generateMACs(100)

	if len(macs) != 100 {
		t.Fatalf("Expected 100 MACs, got %d", len(macs))
	}

	// Check uniqueness
	seen := make(map[string]bool)
	for _, mac := range macs {
		s := mac.String()
		if seen[s] {
			t.Errorf("Duplicate MAC found: %s", s)
		}
		seen[s] = true
	}

	// Check format (locally administered)
	for _, mac := range macs {
		if mac[0]&0x02 != 0x02 {
			t.Errorf("MAC %s is not locally administered", mac)
		}
	}
}

// TestBenchmarkResult tests result calculation
func TestBenchmarkResult(t *testing.T) {
	result := &BenchmarkResult{
		Config: &BenchmarkConfig{
			Concurrency: 10,
			UniqueMACs:  1000,
		},
		Duration:          10 * time.Second,
		Requests:          100000,
		Responses:         99000,
		Errors:            500,
		Timeouts:          500,
		RequestsPerSecond: 10000,
		Latencies: []time.Duration{
			10 * time.Microsecond,
			50 * time.Microsecond,
			100 * time.Microsecond,
			500 * time.Microsecond,
			1 * time.Millisecond,
		},
		LatencyP50:   50 * time.Microsecond,
		LatencyP95:   500 * time.Microsecond,
		LatencyP99:   1 * time.Millisecond,
		FastPathHits: 4,
		SlowPathHits: 1,
		CacheHitRate: 0.8,
	}

	// Test MeetsTargets - should fail (RPS too low)
	if result.MeetsTargets() {
		t.Error("Expected MeetsTargets to return false for low RPS")
	}

	// Update RPS to meet target
	result.RequestsPerSecond = 55000
	result.CacheHitRate = 0.96
	result.LatencyP99 = 5 * time.Millisecond

	if !result.MeetsTargets() {
		t.Error("Expected MeetsTargets to return true")
	}
}

// TestPercentile tests the percentile calculation
func TestPercentile(t *testing.T) {
	latencies := []time.Duration{
		1 * time.Millisecond,
		2 * time.Millisecond,
		3 * time.Millisecond,
		4 * time.Millisecond,
		5 * time.Millisecond,
		6 * time.Millisecond,
		7 * time.Millisecond,
		8 * time.Millisecond,
		9 * time.Millisecond,
		10 * time.Millisecond,
	}

	p50 := percentile(latencies, 0.50)
	// With 10 elements (0-9), index = int(9 * 0.50) = 4, which is 5ms
	if p50 != 5*time.Millisecond {
		t.Errorf("Expected P50 = 5ms, got %s", p50)
	}

	p99 := percentile(latencies, 0.99)
	// With 10 elements, index = int(9 * 0.99) = 8, which is 9ms
	// This is expected behavior for small arrays
	if p99 != 9*time.Millisecond {
		t.Errorf("Expected P99 = 9ms (for 10-element array), got %s", p99)
	}

	// Empty slice
	empty := percentile([]time.Duration{}, 0.50)
	if empty != 0 {
		t.Errorf("Expected 0 for empty slice, got %s", empty)
	}

	// Test with 100 elements for more realistic P99
	large := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		large[i] = time.Duration(i+1) * time.Millisecond
	}
	p99Large := percentile(large, 0.99)
	// index = int(99 * 0.99) = 98, which is 99ms
	if p99Large != 99*time.Millisecond {
		t.Errorf("Expected P99 = 99ms for 100-element array, got %s", p99Large)
	}
}

// TestBenchmarkIntegration runs a short integration test with a mock server
func TestBenchmarkIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start mock server
	server, err := newMockDHCPServer("127.0.0.1:0", 10*time.Microsecond, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	server.start()
	defer server.stop()

	// Create benchmark
	cfg := &BenchmarkConfig{
		Target:            server.addr(),
		Interface:         "lo",
		Concurrency:       5,
		Duration:          2 * time.Second,
		RequestsPerSecond: 0,
		UniqueMACs:        100,
		WarmupDuration:    500 * time.Millisecond,
		EnableRenewals:    true,
		RenewalRatio:      0.5,
	}

	benchmark := NewBenchmark(cfg, nil)

	// Run benchmark
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := benchmark.Run(ctx)
	if err != nil {
		t.Fatalf("Benchmark failed: %v", err)
	}

	// Verify basic results
	if result.Requests == 0 {
		t.Error("Expected some requests to be sent")
	}

	if result.Responses == 0 {
		t.Error("Expected some responses to be received")
	}

	if result.RequestsPerSecond <= 0 {
		t.Error("Expected positive RPS")
	}

	t.Logf("Test completed: %d requests, %.2f RPS, P99=%s",
		result.Requests, result.RequestsPerSecond, result.LatencyP99)
}

// BenchmarkDHCPDiscover benchmarks DHCP DISCOVER packet creation
func BenchmarkDHCPDiscover(b *testing.B) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dhcpv4.NewDiscovery(mac)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDHCPParsing benchmarks DHCP packet parsing
func BenchmarkDHCPParsing(b *testing.B) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	discover, _ := dhcpv4.NewDiscovery(mac)
	data := discover.ToBytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dhcpv4.FromBytes(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMACGeneration benchmarks MAC address generation
func BenchmarkMACGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generateMACs(1000)
	}
}

// TestMockDHCPServerBasic tests the mock DHCP server
func TestMockDHCPServerBasic(t *testing.T) {
	server, err := newMockDHCPServer("127.0.0.1:0", 0, 0)
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}
	server.start()
	defer server.stop()

	// Connect and send DISCOVER
	conn, err := net.Dial("udp4", server.addr())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	discover, _ := dhcpv4.NewDiscovery(mac)

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(discover.ToBytes()); err != nil {
		t.Fatalf("Failed to send DISCOVER: %v", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	offer, err := dhcpv4.FromBytes(buf[:n])
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Errorf("Expected OFFER, got %s", offer.MessageType())
	}

	if offer.YourIPAddr == nil || offer.YourIPAddr.IsUnspecified() {
		t.Error("Expected allocated IP in response")
	}

	t.Logf("Received OFFER with IP: %s", offer.YourIPAddr)
}

// TestDHCPServerWithServer4 tests using the actual dhcp library server
func TestDHCPServerWithServer4(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping server test in short mode")
	}

	// This test requires root/admin privileges to bind to port 67
	// Skip if we can't bind
	laddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0, // Use random port for testing
	}

	handler := func(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
		if req.MessageType() != dhcpv4.MessageTypeDiscover {
			return
		}

		resp, _ := dhcpv4.NewReplyFromRequest(req,
			dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
			dhcpv4.WithYourIP(net.ParseIP("10.0.0.100")),
			dhcpv4.WithServerIP(net.ParseIP("10.0.0.1")),
		)

		conn.WriteTo(resp.ToBytes(), peer)
	}

	server, err := server4.NewServer("lo", laddr, handler)
	if err != nil {
		t.Skipf("Cannot create DHCP server (may need privileges): %v", err)
	}

	go server.Serve()
	defer server.Close()

	t.Log("DHCP server started for testing")
}
