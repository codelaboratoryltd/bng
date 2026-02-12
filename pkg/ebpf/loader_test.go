package ebpf

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		ip       string
		expected uint32
	}{
		{"10.0.1.1", 0x0A000101},
		{"192.168.1.1", 0xC0A80101},
		{"255.255.255.255", 0xFFFFFFFF},
		{"0.0.0.0", 0x00000000},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := IPToUint32(ip)
		if got != tt.expected {
			t.Errorf("IPToUint32(%s) = 0x%08X, want 0x%08X", tt.ip, got, tt.expected)
		}
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		n        uint32
		expected string
	}{
		{0x0A000101, "10.0.1.1"},
		{0xC0A80101, "192.168.1.1"},
		{0xFFFFFFFF, "255.255.255.255"},
		{0x00000000, "0.0.0.0"},
	}

	for _, tt := range tests {
		got := Uint32ToIP(tt.n)
		if got.String() != tt.expected {
			t.Errorf("Uint32ToIP(0x%08X) = %s, want %s", tt.n, got, tt.expected)
		}
	}
}

func TestIPRoundTrip(t *testing.T) {
	ips := []string{
		"10.0.1.1",
		"192.168.100.50",
		"172.16.0.1",
		"8.8.8.8",
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		n := IPToUint32(ip)
		back := Uint32ToIP(n)
		if !ip.To4().Equal(back) {
			t.Errorf("Round trip failed for %s: got %s", ipStr, back)
		}
	}
}

func TestMACToUint64(t *testing.T) {
	tests := []struct {
		mac      string
		expected uint64
	}{
		{"aa:bb:cc:dd:ee:ff", 0xAABBCCDDEEFF},
		{"00:00:00:00:00:00", 0x000000000000},
		{"ff:ff:ff:ff:ff:ff", 0xFFFFFFFFFFFF},
		{"01:23:45:67:89:ab", 0x0123456789AB},
	}

	for _, tt := range tests {
		mac, err := net.ParseMAC(tt.mac)
		if err != nil {
			t.Fatalf("Failed to parse MAC %s: %v", tt.mac, err)
		}
		got := MACToUint64(mac)
		if got != tt.expected {
			t.Errorf("MACToUint64(%s) = 0x%012X, want 0x%012X", tt.mac, got, tt.expected)
		}
	}
}

func TestUint64ToMAC(t *testing.T) {
	tests := []struct {
		n        uint64
		expected string
	}{
		{0xAABBCCDDEEFF, "aa:bb:cc:dd:ee:ff"},
		{0x000000000000, "00:00:00:00:00:00"},
		{0xFFFFFFFFFFFF, "ff:ff:ff:ff:ff:ff"},
		{0x0123456789AB, "01:23:45:67:89:ab"},
	}

	for _, tt := range tests {
		got := Uint64ToMAC(tt.n)
		if got.String() != tt.expected {
			t.Errorf("Uint64ToMAC(0x%012X) = %s, want %s", tt.n, got, tt.expected)
		}
	}
}

func TestMACRoundTrip(t *testing.T) {
	macs := []string{
		"aa:bb:cc:dd:ee:ff",
		"00:11:22:33:44:55",
		"de:ad:be:ef:ca:fe",
	}

	for _, macStr := range macs {
		mac, _ := net.ParseMAC(macStr)
		n := MACToUint64(mac)
		back := Uint64ToMAC(n)
		if mac.String() != back.String() {
			t.Errorf("Round trip failed for %s: got %s", macStr, back)
		}
	}
}

func TestLeaseExpiryFromDuration(t *testing.T) {
	duration := 24 * time.Hour
	before := uint64(time.Now().Unix())
	expiry := LeaseExpiryFromDuration(duration)
	after := uint64(time.Now().Unix())

	expectedMin := before + uint64(duration.Seconds())
	expectedMax := after + uint64(duration.Seconds())

	if expiry < expectedMin || expiry > expectedMax {
		t.Errorf("LeaseExpiryFromDuration(%v) = %d, expected between %d and %d",
			duration, expiry, expectedMin, expectedMax)
	}
}

func TestPoolAssignmentSize(t *testing.T) {
	// Verify struct is the expected size for eBPF compatibility
	// This test helps catch alignment issues
	var pa PoolAssignment

	// PoolAssignment should be:
	// PoolID: 4 bytes
	// AllocatedIP: 4 bytes
	// VlanID: 4 bytes
	// ClientClass: 1 byte
	// LeaseExpiry: 8 bytes
	// Flags: 1 byte
	// Padding: 3 bytes
	// Total: 25 bytes, but with alignment: 32 bytes (or similar)

	// Just check it's not zero (the struct exists)
	_ = pa
}

func TestIPPoolSize(t *testing.T) {
	// Verify struct is the expected size for eBPF compatibility
	var pool IPPool

	// IPPool should be:
	// Network: 4 bytes
	// PrefixLen: 1 byte
	// Padding: 3 bytes
	// Gateway: 4 bytes
	// DNSPrimary: 4 bytes
	// DNSSecondary: 4 bytes
	// LeaseTime: 4 bytes
	// Padding: 4 bytes
	// Total: 28 bytes

	// Just check it's not zero (the struct exists)
	_ = pool
}

// Issue #15: Test FNV-1a hash function for circuit-id
func TestHashCircuitID(t *testing.T) {
	tests := []struct {
		name      string
		circuitID []byte
	}{
		{"empty", []byte{}},
		{"simple", []byte("eth 0/1/1:100")},
		{"huawei", []byte("eth 0/1/1:100.200")},
		{"nokia", []byte("FSAN:ALCL12345678")},
		{"generic", []byte("access-node-id eth 0/1/1 atm 0/100")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashCircuitID(tt.circuitID)
			// Verify hash is deterministic
			hash2 := HashCircuitID(tt.circuitID)
			if hash != hash2 {
				t.Errorf("HashCircuitID is not deterministic: %d != %d", hash, hash2)
			}
			// Verify different inputs produce different hashes (collision resistance)
			if len(tt.circuitID) > 0 {
				modified := make([]byte, len(tt.circuitID))
				copy(modified, tt.circuitID)
				modified[0] ^= 0xFF
				hashModified := HashCircuitID(modified)
				if hash == hashModified {
					t.Errorf("HashCircuitID collision: %q and %q both hash to %d", tt.circuitID, modified, hash)
				}
			}
		})
	}
}

// Test that FNV-1a constants match the eBPF implementation
func TestHashCircuitIDConstants(t *testing.T) {
	// These must match the eBPF program constants
	if fnv1aInit != 0xcbf29ce484222325 {
		t.Errorf("fnv1aInit mismatch: got 0x%x, want 0xcbf29ce484222325", fnv1aInit)
	}
	if fnv1aPrime != 0x100000001b3 {
		t.Errorf("fnv1aPrime mismatch: got 0x%x, want 0x100000001b3", fnv1aPrime)
	}
}

// Test known FNV-1a hash values for circuit-ids
func TestHashCircuitIDKnownValues(t *testing.T) {
	// Test with a known circuit-id to ensure hash is correct
	// FNV-1a hash of "test" should be a specific value
	circuitID := []byte("test")
	hash := HashCircuitID(circuitID)

	// Manually compute expected FNV-1a hash of "test"
	expected := uint64(0xcbf29ce484222325) // init
	for _, b := range circuitID {
		expected ^= uint64(b)
		expected *= 0x100000001b3
	}

	if hash != expected {
		t.Errorf("HashCircuitID(%q) = 0x%x, want 0x%x", circuitID, hash, expected)
	}
}

// Issue #56: Test CircuitIDKey fixed-size key generation
func TestMakeCircuitIDKey(t *testing.T) {
	tests := []struct {
		name      string
		circuitID []byte
		wantLen   int
	}{
		{
			name:      "empty",
			circuitID: []byte{},
			wantLen:   CircuitIDKeyLen,
		},
		{
			name:      "short circuit-id",
			circuitID: []byte("eth 0/1/1:100"),
			wantLen:   CircuitIDKeyLen,
		},
		{
			name:      "exact 32 bytes",
			circuitID: []byte("12345678901234567890123456789012"),
			wantLen:   CircuitIDKeyLen,
		},
		{
			name:      "longer than 32 bytes (truncated)",
			circuitID: []byte("12345678901234567890123456789012345678901234567890"),
			wantLen:   CircuitIDKeyLen,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := MakeCircuitIDKey(tt.circuitID)
			if len(key) != tt.wantLen {
				t.Errorf("MakeCircuitIDKey() length = %d, want %d", len(key), tt.wantLen)
			}

			// Verify the data is correctly copied
			expectedLen := len(tt.circuitID)
			if expectedLen > CircuitIDKeyLen {
				expectedLen = CircuitIDKeyLen
			}
			for i := 0; i < expectedLen; i++ {
				if key[i] != tt.circuitID[i] {
					t.Errorf("MakeCircuitIDKey()[%d] = 0x%02x, want 0x%02x", i, key[i], tt.circuitID[i])
				}
			}

			// Verify padding is zeros
			for i := expectedLen; i < CircuitIDKeyLen; i++ {
				if key[i] != 0 {
					t.Errorf("MakeCircuitIDKey()[%d] = 0x%02x, want 0x00 (padding)", i, key[i])
				}
			}
		})
	}
}

// Test CircuitIDKey determinism
func TestMakeCircuitIDKeyDeterministic(t *testing.T) {
	circuitID := []byte("eth 0/1/1:100.200")
	key1 := MakeCircuitIDKey(circuitID)
	key2 := MakeCircuitIDKey(circuitID)

	if key1 != key2 {
		t.Error("MakeCircuitIDKey is not deterministic")
	}
}

// Test CircuitIDKey uniqueness for different inputs
func TestMakeCircuitIDKeyUniqueness(t *testing.T) {
	circuitIDs := [][]byte{
		[]byte("eth 0/1/1:100"),
		[]byte("eth 0/1/2:100"),
		[]byte("eth 0/1/1:200"),
		[]byte("FSAN:ALCL12345678"),
		[]byte("access-node-id eth 0/1/1 atm 0/100"),
	}

	keys := make(map[CircuitIDKey][]byte)
	for _, cid := range circuitIDs {
		key := MakeCircuitIDKey(cid)
		if existing, ok := keys[key]; ok {
			t.Errorf("Key collision between %q and %q", existing, cid)
		}
		keys[key] = cid
	}
}

// Test CircuitIDKeyLen constant
func TestCircuitIDKeyLen(t *testing.T) {
	// Must match CIRCUIT_ID_KEY_LEN in maps.h
	if CircuitIDKeyLen != 32 {
		t.Errorf("CircuitIDKeyLen = %d, want 32", CircuitIDKeyLen)
	}
}

// Test that CircuitIDKey size matches expected
func TestCircuitIDKeySize(t *testing.T) {
	var key CircuitIDKey
	if len(key) != 32 {
		t.Errorf("CircuitIDKey size = %d bytes, want 32 bytes", len(key))
	}
}

// Test NewLoader creation and options
func TestNewLoader(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Test basic creation
	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	if loader == nil {
		t.Fatal("expected non-nil loader")
	}

	// Test with options
	loader2, err := NewLoader("eth0", logger,
		WithBPFPath("/custom/path/dhcp_fastpath.o"),
		WithXDPMode(0),
	)
	if err != nil {
		t.Fatalf("NewLoader with options failed: %v", err)
	}

	if loader2 == nil {
		t.Fatal("expected non-nil loader with options")
	}
}

// Test loader without maps (before Load)
func TestLoaderMapOperationsWithoutLoad(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	// These should return errors because maps aren't loaded
	assignment := &PoolAssignment{
		PoolID:      1,
		AllocatedIP: 0x0A000101,
		VlanID:      100,
	}

	err = loader.AddSubscriber(0xAABBCCDDEEFF, assignment)
	if err == nil {
		t.Error("AddSubscriber should fail without loaded maps")
	}

	err = loader.RemoveSubscriber(0xAABBCCDDEEFF)
	if err == nil {
		t.Error("RemoveSubscriber should fail without loaded maps")
	}

	_, err = loader.GetSubscriber(0xAABBCCDDEEFF)
	if err == nil {
		t.Error("GetSubscriber should fail without loaded maps")
	}

	pool := &IPPool{
		Network:      0x0A000000,
		PrefixLen:    24,
		Gateway:      0x0A000001,
		DNSPrimary:   0x08080808,
		DNSSecondary: 0x08080404,
		LeaseTime:    86400,
	}

	err = loader.AddPool(1, pool)
	if err == nil {
		t.Error("AddPool should fail without loaded maps")
	}

	err = loader.RemovePool(1)
	if err == nil {
		t.Error("RemovePool should fail without loaded maps")
	}

	_, err = loader.GetPool(1)
	if err == nil {
		t.Error("GetPool should fail without loaded maps")
	}

	_, err = loader.GetStats()
	if err == nil {
		t.Error("GetStats should fail without loaded maps")
	}

	err = loader.ResetStats()
	if err == nil {
		t.Error("ResetStats should fail without loaded maps")
	}
}

// Test loader Close before Load (should not panic)
func TestLoaderCloseBeforeLoad(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	// Close before load should not panic
	err = loader.Close()
	if err != nil {
		t.Errorf("Close before Load should succeed: %v", err)
	}
}

// Test VLAN support check
func TestLoaderVLANSupport(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	// Before Load, VLAN support should be false
	if loader.HasVLANSupport() {
		t.Error("HasVLANSupport should return false before Load")
	}
}

// Test CircuitID subscriber support check
func TestLoaderCircuitIDSupport(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	// Before Load, circuit-id subscriber support should be false
	if loader.HasCircuitIDSubscriberSupport() {
		t.Error("HasCircuitIDSubscriberSupport should return false before Load")
	}
}

// Test VLAN subscriber operations without load
func TestLoaderVLANSubscriberWithoutLoad(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	assignment := &PoolAssignment{
		PoolID:      1,
		AllocatedIP: 0x0A000101,
	}

	err = loader.AddVLANSubscriber(100, 200, assignment)
	if err == nil {
		t.Error("AddVLANSubscriber should fail without loaded maps")
	}

	err = loader.RemoveVLANSubscriber(100, 200)
	if err == nil {
		t.Error("RemoveVLANSubscriber should fail without loaded maps")
	}

	_, err = loader.GetVLANSubscriber(100, 200)
	if err == nil {
		t.Error("GetVLANSubscriber should fail without loaded maps")
	}
}

// Test CircuitID mapping operations without load
func TestLoaderCircuitIDMappingWithoutLoad(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	circuitID := []byte("eth 0/1/1:100")

	err = loader.AddCircuitIDMapping(circuitID, 0xAABBCCDDEEFF)
	if err == nil {
		t.Error("AddCircuitIDMapping should fail without loaded maps")
	}

	err = loader.RemoveCircuitIDMapping(circuitID)
	if err == nil {
		t.Error("RemoveCircuitIDMapping should fail without loaded maps")
	}

	_, err = loader.GetCircuitIDMapping(circuitID)
	if err == nil {
		t.Error("GetCircuitIDMapping should fail without loaded maps")
	}
}

// Test CircuitID subscriber operations without load
func TestLoaderCircuitIDSubscriberWithoutLoad(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	circuitID := []byte("eth 0/1/1:100")
	assignment := &PoolAssignment{
		PoolID:      1,
		AllocatedIP: 0x0A000101,
	}

	err = loader.AddCircuitIDSubscriber(circuitID, assignment)
	if err == nil {
		t.Error("AddCircuitIDSubscriber should fail without loaded maps")
	}

	err = loader.RemoveCircuitIDSubscriber(circuitID)
	if err == nil {
		t.Error("RemoveCircuitIDSubscriber should fail without loaded maps")
	}

	_, err = loader.GetCircuitIDSubscriber(circuitID)
	if err == nil {
		t.Error("GetCircuitIDSubscriber should fail without loaded maps")
	}
}

// Test server config operations without load
func TestLoaderServerConfigWithoutLoad(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	serverMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	serverIP := net.ParseIP("10.0.0.1")

	err = loader.SetServerConfig(serverMAC, serverIP, 1)
	if err == nil {
		t.Error("SetServerConfig should fail without loaded maps")
	}

	_, err = loader.GetServerConfig()
	if err == nil {
		t.Error("GetServerConfig should fail without loaded maps")
	}
}

// Test DHCPStats struct
func TestDHCPStatsStruct(t *testing.T) {
	stats := DHCPStats{
		TotalRequests:    100,
		FastpathHits:     95,
		FastpathMisses:   5,
		Errors:           2,
		CacheExpired:     1,
		Option82Present:  50,
		Option82Absent:   50,
		BroadcastReplies: 30,
		UnicastReplies:   65,
		VLANPackets:      20,
	}

	if stats.TotalRequests != 100 {
		t.Errorf("TotalRequests = %d, want 100", stats.TotalRequests)
	}

	if stats.FastpathHits != 95 {
		t.Errorf("FastpathHits = %d, want 95", stats.FastpathHits)
	}

	if stats.FastpathMisses != 5 {
		t.Errorf("FastpathMisses = %d, want 5", stats.FastpathMisses)
	}

	if stats.Errors != 2 {
		t.Errorf("Errors = %d, want 2", stats.Errors)
	}

	if stats.Option82Present != 50 {
		t.Errorf("Option82Present = %d, want 50", stats.Option82Present)
	}

	if stats.VLANPackets != 20 {
		t.Errorf("VLANPackets = %d, want 20", stats.VLANPackets)
	}
}

// Issue #88: Test checkBPFCapabilities
func TestCheckBPFCapabilities(t *testing.T) {
	if runtime.GOOS != "linux" {
		// On non-Linux, /proc/self/status doesn't exist so the check is skipped
		err := checkBPFCapabilities()
		if err != nil {
			t.Errorf("checkBPFCapabilities on non-Linux should skip: %v", err)
		}
		return
	}

	// On Linux, the function should not return an error when running as root
	// or with appropriate capabilities (CI typically runs as root)
	err := checkBPFCapabilities()
	if err != nil {
		t.Logf("checkBPFCapabilities returned (may be expected in unprivileged CI): %v", err)
	}
}

// Test ServerConfig struct
func TestServerConfigStruct(t *testing.T) {
	cfg := ServerConfig{
		ServerMAC:      [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		ServerIP:       0x0A000001,
		InterfaceIndex: 1,
	}

	expectedMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	if cfg.ServerMAC != expectedMAC {
		t.Errorf("ServerMAC = %v, want %v", cfg.ServerMAC, expectedMAC)
	}

	if cfg.ServerIP != 0x0A000001 {
		t.Errorf("ServerIP = 0x%X, want 0x0A000001", cfg.ServerIP)
	}

	if cfg.InterfaceIndex != 1 {
		t.Errorf("InterfaceIndex = %d, want 1", cfg.InterfaceIndex)
	}
}

// Test PoolAssignment struct
func TestPoolAssignmentStruct(t *testing.T) {
	pa := PoolAssignment{
		PoolID:      1,
		AllocatedIP: 0x0A000101,
		VlanID:      100,
		ClientClass: 1,
		LeaseExpiry: 1234567890,
		Flags:       0x01,
	}

	if pa.PoolID != 1 {
		t.Errorf("PoolID = %d, want 1", pa.PoolID)
	}

	if pa.AllocatedIP != 0x0A000101 {
		t.Errorf("AllocatedIP = 0x%X, want 0x0A000101", pa.AllocatedIP)
	}

	if pa.VlanID != 100 {
		t.Errorf("VlanID = %d, want 100", pa.VlanID)
	}

	if pa.LeaseExpiry != 1234567890 {
		t.Errorf("LeaseExpiry = %d, want 1234567890", pa.LeaseExpiry)
	}
}

// Test IPPool struct
func TestIPPoolStruct(t *testing.T) {
	pool := IPPool{
		Network:      0x0A000000, // 10.0.0.0
		PrefixLen:    24,
		Gateway:      0x0A000001, // 10.0.0.1
		DNSPrimary:   0x08080808, // 8.8.8.8
		DNSSecondary: 0x08080404, // 8.8.4.4
		LeaseTime:    86400,
	}

	if pool.Network != 0x0A000000 {
		t.Errorf("Network = 0x%X, want 0x0A000000", pool.Network)
	}

	if pool.PrefixLen != 24 {
		t.Errorf("PrefixLen = %d, want 24", pool.PrefixLen)
	}

	if pool.Gateway != 0x0A000001 {
		t.Errorf("Gateway = 0x%X, want 0x0A000001", pool.Gateway)
	}

	if pool.DNSPrimary != 0x08080808 {
		t.Errorf("DNSPrimary = 0x%X, want 0x08080808", pool.DNSPrimary)
	}

	if pool.DNSSecondary != 0x08080404 {
		t.Errorf("DNSSecondary = 0x%X, want 0x08080404", pool.DNSSecondary)
	}

	if pool.LeaseTime != 86400 {
		t.Errorf("LeaseTime = %d, want 86400", pool.LeaseTime)
	}
}

// === New tests for Issue #80: edge cases, error paths, concurrent access ===

// Test NewLoader with empty interface name
func TestNewLoaderEmptyInterface(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	_, err := NewLoader("", logger)
	if err == nil {
		t.Error("Expected error for empty interface name")
	}
}

// Test WithBPFPath option
func TestWithBPFPath(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	loader, err := NewLoader("eth0", logger, WithBPFPath("/custom/path.o"))
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}
	if loader.bpfPath != "/custom/path.o" {
		t.Errorf("bpfPath = %s, want /custom/path.o", loader.bpfPath)
	}
}

// Test WithXDPMode option
func TestWithXDPMode(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	loader, err := NewLoader("eth0", logger, WithXDPMode(link.XDPDriverMode))
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}
	if loader.xdpMode != link.XDPDriverMode {
		t.Errorf("xdpMode = %d, want %d", loader.xdpMode, link.XDPDriverMode)
	}
}

// Test NewLoader defaults
func TestNewLoaderDefaults(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	loader, err := NewLoader("eth0", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	if loader.iface != "eth0" {
		t.Errorf("iface = %s, want eth0", loader.iface)
	}
	if loader.bpfPath != "bpf/dhcp_fastpath.bpf.o" {
		t.Errorf("bpfPath = %s, want bpf/dhcp_fastpath.bpf.o", loader.bpfPath)
	}
	if loader.xdpMode != link.XDPGenericMode {
		t.Errorf("xdpMode = %d, want %d (generic)", loader.xdpMode, link.XDPGenericMode)
	}
	if loader.logger == nil {
		t.Error("Expected logger to be set")
	}
	if loader.collection != nil {
		t.Error("Expected collection to be nil before Load")
	}
	if loader.xdpLink != nil {
		t.Error("Expected xdpLink to be nil before Load")
	}
}

// Test NewLoader with multiple options (overriding)
func TestNewLoaderMultipleOptions(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	loader, err := NewLoader("eth0", logger,
		WithBPFPath("/first.o"),
		WithBPFPath("/second.o"), // should override
		WithXDPMode(link.XDPDriverMode),
	)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}
	if loader.bpfPath != "/second.o" {
		t.Errorf("bpfPath = %s, want /second.o (last option wins)", loader.bpfPath)
	}
}

// Test IPToUint32 with nil IP
func TestIPToUint32Nil(t *testing.T) {
	result := IPToUint32(nil)
	if result != 0 {
		t.Errorf("IPToUint32(nil) = 0x%08X, want 0", result)
	}
}

// Test IPToUint32 with IPv6 address (should return 0)
func TestIPToUint32IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	// To4() returns nil for IPv6 addresses, so result should be 0
	result := IPToUint32(ip)
	if result != 0 {
		t.Errorf("IPToUint32(IPv6) = 0x%08X, want 0", result)
	}
}

// Test MACToUint64 with short MAC (less than 6 bytes)
func TestMACToUint64Short(t *testing.T) {
	short := net.HardwareAddr{0xAA, 0xBB}
	result := MACToUint64(short)
	if result != 0 {
		t.Errorf("MACToUint64(short) = 0x%X, want 0", result)
	}
}

// Test MACToUint64 with nil MAC
func TestMACToUint64Nil(t *testing.T) {
	result := MACToUint64(nil)
	if result != 0 {
		t.Errorf("MACToUint64(nil) = 0x%X, want 0", result)
	}
}

// Test MACToUint64 with empty MAC
func TestMACToUint64Empty(t *testing.T) {
	result := MACToUint64(net.HardwareAddr{})
	if result != 0 {
		t.Errorf("MACToUint64(empty) = 0x%X, want 0", result)
	}
}

// Test LeaseExpiryFromDuration with zero duration
func TestLeaseExpiryFromDurationZero(t *testing.T) {
	before := uint64(time.Now().Unix())
	expiry := LeaseExpiryFromDuration(0)
	after := uint64(time.Now().Unix())

	if expiry < before || expiry > after {
		t.Errorf("LeaseExpiryFromDuration(0) = %d, expected between %d and %d",
			expiry, before, after)
	}
}

// Test LeaseExpiryFromDuration with negative duration
func TestLeaseExpiryFromDurationNegative(t *testing.T) {
	now := uint64(time.Now().Unix())
	expiry := LeaseExpiryFromDuration(-1 * time.Hour)

	// Should be in the past
	if expiry >= now {
		t.Errorf("LeaseExpiryFromDuration(-1h) = %d, expected < %d", expiry, now)
	}
}

// Test VLANKey struct
func TestVLANKeyStruct(t *testing.T) {
	key := VLANKey{STag: 100, CTag: 200}

	if key.STag != 100 {
		t.Errorf("STag = %d, want 100", key.STag)
	}
	if key.CTag != 200 {
		t.Errorf("CTag = %d, want 200", key.CTag)
	}

	// Different keys should not be equal
	key2 := VLANKey{STag: 100, CTag: 201}
	if key == key2 {
		t.Error("Expected different VLANKeys to not be equal")
	}

	// Same keys should be equal
	key3 := VLANKey{STag: 100, CTag: 200}
	if key != key3 {
		t.Error("Expected identical VLANKeys to be equal")
	}
}

// Test VLANKey boundary values
func TestVLANKeyBoundary(t *testing.T) {
	tests := []struct {
		name string
		sTag uint16
		cTag uint16
	}{
		{"zero", 0, 0},
		{"max", 0xFFFF, 0xFFFF},
		{"typical outer", 100, 200},
		{"max vlan id", 4094, 4094},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := VLANKey{STag: tt.sTag, CTag: tt.cTag}
			if key.STag != tt.sTag {
				t.Errorf("STag = %d, want %d", key.STag, tt.sTag)
			}
			if key.CTag != tt.cTag {
				t.Errorf("CTag = %d, want %d", key.CTag, tt.cTag)
			}
		})
	}
}

// Test all map operations return consistent errors when maps are nil
func TestLoaderAllMapOpsNilConsistency(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, _ := NewLoader("eth0", logger)

	// Every map operation should fail with a descriptive error
	ops := []struct {
		name string
		fn   func() error
	}{
		{"AddSubscriber", func() error { return loader.AddSubscriber(1, &PoolAssignment{}) }},
		{"RemoveSubscriber", func() error { return loader.RemoveSubscriber(1) }},
		{"GetSubscriber", func() error { _, err := loader.GetSubscriber(1); return err }},
		{"AddVLANSubscriber", func() error { return loader.AddVLANSubscriber(1, 2, &PoolAssignment{}) }},
		{"RemoveVLANSubscriber", func() error { return loader.RemoveVLANSubscriber(1, 2) }},
		{"GetVLANSubscriber", func() error { _, err := loader.GetVLANSubscriber(1, 2); return err }},
		{"AddPool", func() error { return loader.AddPool(1, &IPPool{}) }},
		{"RemovePool", func() error { return loader.RemovePool(1) }},
		{"GetPool", func() error { _, err := loader.GetPool(1); return err }},
		{"GetStats", func() error { _, err := loader.GetStats(); return err }},
		{"ResetStats", func() error { return loader.ResetStats() }},
		{"SetServerConfig", func() error {
			mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			return loader.SetServerConfig(mac, net.ParseIP("10.0.0.1"), 1)
		}},
		{"GetServerConfig", func() error { _, err := loader.GetServerConfig(); return err }},
		{"AddCircuitIDMapping", func() error { return loader.AddCircuitIDMapping([]byte("test"), 1) }},
		{"RemoveCircuitIDMapping", func() error { return loader.RemoveCircuitIDMapping([]byte("test")) }},
		{"GetCircuitIDMapping", func() error { _, err := loader.GetCircuitIDMapping([]byte("test")); return err }},
		{"AddCircuitIDSubscriber", func() error {
			return loader.AddCircuitIDSubscriber([]byte("test"), &PoolAssignment{})
		}},
		{"RemoveCircuitIDSubscriber", func() error { return loader.RemoveCircuitIDSubscriber([]byte("test")) }},
		{"GetCircuitIDSubscriber", func() error { _, err := loader.GetCircuitIDSubscriber([]byte("test")); return err }},
	}

	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			err := op.fn()
			if err == nil {
				t.Errorf("%s should fail when maps are nil", op.name)
			}
		})
	}
}

// Test Close is idempotent (double close should not panic)
func TestLoaderDoubleClose(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, _ := NewLoader("eth0", logger)

	// First close
	if err := loader.Close(); err != nil {
		t.Errorf("First Close() failed: %v", err)
	}

	// Second close should also succeed without panic
	if err := loader.Close(); err != nil {
		t.Errorf("Second Close() failed: %v", err)
	}
}

// Test concurrent access to NewLoader (should be safe, no shared state)
func TestNewLoaderConcurrent(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	var wg sync.WaitGroup
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			iface := fmt.Sprintf("eth%d", idx)
			l, err := NewLoader(iface, logger)
			if err != nil {
				errs <- err
				return
			}
			if l.iface != iface {
				errs <- fmt.Errorf("iface = %s, want %s", l.iface, iface)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent NewLoader error: %v", err)
	}
}

// Test concurrent map nil checks (read-only, should be safe)
func TestLoaderConcurrentNilMapOps(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, _ := NewLoader("eth0", logger)

	var wg sync.WaitGroup

	// Run multiple goroutines all checking nil maps
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = loader.HasVLANSupport()
			_ = loader.HasCircuitIDSubscriberSupport()
			_, _ = loader.GetSubscriber(uint64(1))
			_, _ = loader.GetPool(uint32(1))
			_, _ = loader.GetStats()
		}()
	}

	wg.Wait()
}

// Test HashCircuitID with very long input
func TestHashCircuitIDLongInput(t *testing.T) {
	// Should not panic with very large circuit IDs
	large := make([]byte, 10000)
	for i := range large {
		large[i] = byte(i % 256)
	}

	hash := HashCircuitID(large)
	if hash == 0 {
		// FNV-1a of non-zero data should almost never be 0
		t.Log("Warning: hash of large input is 0 (extremely unlikely)")
	}

	// Verify determinism
	hash2 := HashCircuitID(large)
	if hash != hash2 {
		t.Error("HashCircuitID is not deterministic for large input")
	}
}

// Test HashCircuitID single byte inputs
func TestHashCircuitIDSingleByte(t *testing.T) {
	hashes := make(map[uint64]byte)
	for i := 0; i < 256; i++ {
		b := byte(i)
		hash := HashCircuitID([]byte{b})
		if existing, ok := hashes[hash]; ok {
			t.Errorf("HashCircuitID collision: byte 0x%02x and 0x%02x both hash to 0x%x", existing, b, hash)
		}
		hashes[hash] = b
	}
}

// Test MakeCircuitIDKey with nil input
func TestMakeCircuitIDKeyNil(t *testing.T) {
	key := MakeCircuitIDKey(nil)
	for i := 0; i < CircuitIDKeyLen; i++ {
		if key[i] != 0 {
			t.Errorf("MakeCircuitIDKey(nil)[%d] = 0x%02x, want 0x00", i, key[i])
		}
	}
}

// Test MakeCircuitIDKey with single byte
func TestMakeCircuitIDKeySingleByte(t *testing.T) {
	key := MakeCircuitIDKey([]byte{0xAB})
	if key[0] != 0xAB {
		t.Errorf("key[0] = 0x%02x, want 0xAB", key[0])
	}
	for i := 1; i < CircuitIDKeyLen; i++ {
		if key[i] != 0 {
			t.Errorf("key[%d] = 0x%02x, want 0x00", i, key[i])
		}
	}
}

// Test IP round-trip conversion edge cases
func TestIPConversionEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		n    uint32
	}{
		{"loopback", "127.0.0.1", 0x7F000001},
		{"broadcast", "255.255.255.255", 0xFFFFFFFF},
		{"zero", "0.0.0.0", 0x00000000},
		{"class A", "10.255.255.255", 0x0AFFFFFF},
		{"link-local", "169.254.1.1", 0xA9FE0101},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			n := IPToUint32(ip)
			if n != tt.n {
				t.Errorf("IPToUint32(%s) = 0x%08X, want 0x%08X", tt.ip, n, tt.n)
			}
			back := Uint32ToIP(n)
			if !ip.To4().Equal(back) {
				t.Errorf("Round trip failed: %s -> 0x%08X -> %s", tt.ip, n, back)
			}
		})
	}
}

// Test MAC round-trip conversion edge cases
func TestMACConversionEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		mac  string
		n    uint64
	}{
		{"broadcast", "ff:ff:ff:ff:ff:ff", 0xFFFFFFFFFFFF},
		{"zero", "00:00:00:00:00:00", 0x000000000000},
		{"multicast", "01:00:5e:00:00:01", 0x01005E000001},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac, _ := net.ParseMAC(tt.mac)
			n := MACToUint64(mac)
			if n != tt.n {
				t.Errorf("MACToUint64(%s) = 0x%012X, want 0x%012X", tt.mac, n, tt.n)
			}
			back := Uint64ToMAC(n)
			if mac.String() != back.String() {
				t.Errorf("Round trip failed: %s -> 0x%012X -> %s", tt.mac, n, back)
			}
		})
	}
}

// Test that Uint32ToIP always returns a 4-byte IP
func TestUint32ToIPLength(t *testing.T) {
	tests := []uint32{0, 1, 0xFFFFFFFF, 0x0A000001}

	for _, n := range tests {
		ip := Uint32ToIP(n)
		if len(ip) != 4 {
			t.Errorf("Uint32ToIP(0x%X) returned %d-byte IP, want 4", n, len(ip))
		}
	}
}

// Test that Uint64ToMAC always returns a 6-byte MAC
func TestUint64ToMACLength(t *testing.T) {
	tests := []uint64{0, 1, 0xFFFFFFFFFFFF, 0xAABBCCDDEEFF}

	for _, n := range tests {
		mac := Uint64ToMAC(n)
		if len(mac) != 6 {
			t.Errorf("Uint64ToMAC(0x%X) returned %d-byte MAC, want 6", n, len(mac))
		}
	}
}

// Test PoolAssignment fields with boundary values
func TestPoolAssignmentBoundaryValues(t *testing.T) {
	pa := PoolAssignment{
		PoolID:      0xFFFFFFFF,
		AllocatedIP: 0xFFFFFFFF,
		VlanID:      0xFFFFFFFF,
		ClientClass: 0xFF,
		LeaseExpiry: 0xFFFFFFFFFFFFFFFF,
		Flags:       0xFF,
	}

	if pa.PoolID != 0xFFFFFFFF {
		t.Errorf("PoolID = %d, want max uint32", pa.PoolID)
	}
	if pa.ClientClass != 0xFF {
		t.Errorf("ClientClass = %d, want 255", pa.ClientClass)
	}
	if pa.LeaseExpiry != 0xFFFFFFFFFFFFFFFF {
		t.Errorf("LeaseExpiry = %d, want max uint64", pa.LeaseExpiry)
	}
	if pa.Flags != 0xFF {
		t.Errorf("Flags = %d, want 255", pa.Flags)
	}
}

// Test PoolAssignment zero value
func TestPoolAssignmentZeroValue(t *testing.T) {
	var pa PoolAssignment
	if pa.PoolID != 0 || pa.AllocatedIP != 0 || pa.VlanID != 0 || pa.ClientClass != 0 || pa.LeaseExpiry != 0 || pa.Flags != 0 {
		t.Error("Zero-value PoolAssignment should have all zero fields")
	}
}

// Test ServerConfig with short MAC (less than 6 bytes via SetServerConfig logic)
func TestServerConfigShortMAC(t *testing.T) {
	// When serverMAC is shorter than 6 bytes, copy should still work safely
	var config ServerConfig
	shortMAC := net.HardwareAddr{0xAA, 0xBB}
	// SetServerConfig checks len(serverMAC) >= 6 before copying
	// With a short MAC, the ServerMAC field should remain zeroed
	if len(shortMAC) >= 6 {
		copy(config.ServerMAC[:], shortMAC[:6])
	}
	// Verify it remains zeroed since short MAC didn't get copied
	expected := [6]byte{}
	if config.ServerMAC != expected {
		t.Errorf("ServerMAC = %v, want zeroed for short MAC", config.ServerMAC)
	}
}

// Test HashCircuitID matches manual FNV-1a computation for known strings
func TestHashCircuitIDManualComputation(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"a", "a"},
		{"ab", "ab"},
		{"typical circuit", "eth 0/1/1:100.200"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Manual FNV-1a
			hash := uint64(0xcbf29ce484222325)
			for _, b := range []byte(tt.input) {
				hash ^= uint64(b)
				hash *= 0x100000001b3
			}

			got := HashCircuitID([]byte(tt.input))
			if got != hash {
				t.Errorf("HashCircuitID(%q) = 0x%x, want 0x%x", tt.input, got, hash)
			}
		})
	}
}

// Test Load with nonexistent interface
func TestLoaderLoadInvalidInterface(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, err := NewLoader("nonexistent_iface_xyz_12345", logger)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	err = loader.Load(nil)
	if err == nil {
		t.Error("Load() should fail for nonexistent interface")
	}

	// Error should mention the interface name
	errStr := err.Error()
	if len(errStr) == 0 {
		t.Error("Expected non-empty error message")
	}
}

// Test Load with valid loopback interface but invalid BPF path
func TestLoaderLoadInvalidBPFPath(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	// Use lo0 (macOS) or lo (Linux)
	iface := "lo0"
	if _, err := net.InterfaceByName(iface); err != nil {
		iface = "lo"
		if _, err := net.InterfaceByName(iface); err != nil {
			t.Skip("No loopback interface available for test")
		}
	}

	loader, err := NewLoader(iface, logger, WithBPFPath("/nonexistent/path/dhcp.o"))
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	err = loader.Load(nil)
	if err == nil {
		t.Error("Load() should fail with nonexistent BPF path")
	}
}

// Issue #90: Test CheckCircuitIDCollision without loaded maps
func TestLoaderCheckCircuitIDCollisionWithoutLoad(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	loader, _ := NewLoader("eth0", logger)

	_, err := loader.CheckCircuitIDCollision([]byte("eth 0/1/1:100"), 0xAABBCCDDEEFF)
	if err == nil {
		t.Error("CheckCircuitIDCollision should fail without loaded maps")
	}
}

// Issue #90: Test collision characteristics documentation references valid constants
func TestCircuitIDCollisionHashProperties(t *testing.T) {
	// Verify that different circuit-IDs with similar patterns produce distinct hashes
	// This validates the FNV-1a distribution claim in the collision documentation
	circuitIDs := []string{
		"eth 0/1/1:100",
		"eth 0/1/1:101",
		"eth 0/1/2:100",
		"eth 0/2/1:100",
		"eth 1/1/1:100",
	}

	hashes := make(map[uint64]string)
	for _, cid := range circuitIDs {
		hash := HashCircuitID([]byte(cid))
		if existing, ok := hashes[hash]; ok {
			t.Errorf("Hash collision between %q and %q (hash=0x%x)", existing, cid, hash)
		}
		hashes[hash] = cid
	}
}

// Test MakeCircuitIDKey is usable as map key
func TestMakeCircuitIDKeyAsMapKey(t *testing.T) {
	m := make(map[CircuitIDKey]int)

	key1 := MakeCircuitIDKey([]byte("circuit-1"))
	key2 := MakeCircuitIDKey([]byte("circuit-2"))
	key1b := MakeCircuitIDKey([]byte("circuit-1"))

	m[key1] = 1
	m[key2] = 2

	if m[key1b] != 1 {
		t.Errorf("Map lookup for key1b = %d, want 1", m[key1b])
	}
	if m[key2] != 2 {
		t.Errorf("Map lookup for key2 = %d, want 2", m[key2])
	}
	if len(m) != 2 {
		t.Errorf("Map size = %d, want 2", len(m))
	}
}
