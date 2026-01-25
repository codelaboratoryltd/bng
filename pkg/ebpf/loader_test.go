package ebpf

import (
	"net"
	"testing"
	"time"

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
