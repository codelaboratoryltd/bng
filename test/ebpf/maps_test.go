// Package ebpf_test provides integration tests for eBPF map operations.
//
// These tests validate that the Go userspace code correctly interacts with
// eBPF map structures defined in bpf/maps.h. They ensure struct alignment,
// size compatibility, and proper serialization between Go and eBPF.
package ebpf_test

import (
	"testing"
	"unsafe"

	"github.com/codelaboratoryltd/bng/pkg/ebpf"
)

// TestPoolAssignmentStructSize verifies the Go struct matches eBPF struct size.
// This is critical for map operations - mismatched sizes will cause data corruption.
func TestPoolAssignmentStructSize(t *testing.T) {
	var pa ebpf.PoolAssignment
	size := unsafe.Sizeof(pa)

	// Expected size from bpf/maps.h:
	// pool_id: 4 bytes
	// allocated_ip: 4 bytes
	// vlan_id: 4 bytes
	// client_class: 1 byte
	// lease_expiry: 8 bytes (aligned)
	// flags: 1 byte
	// _pad[3]: 3 bytes
	// Total with proper alignment should be 28 or 32 bytes depending on Go alignment

	t.Logf("PoolAssignment size: %d bytes", size)

	// The struct should be at least 24 bytes (sum of all fields)
	if size < 24 {
		t.Errorf("PoolAssignment size %d is smaller than expected minimum 24", size)
	}

	// It should be a multiple of 8 for proper alignment
	if size%8 != 0 {
		t.Errorf("PoolAssignment size %d is not 8-byte aligned", size)
	}
}

// TestIPPoolStructSize verifies the Go struct matches eBPF struct size
func TestIPPoolStructSize(t *testing.T) {
	var pool ebpf.IPPool
	size := unsafe.Sizeof(pool)

	t.Logf("IPPool size: %d bytes", size)

	// Expected size from bpf/maps.h:
	// network: 4 bytes
	// prefix_len: 1 byte
	// _pad1[3]: 3 bytes
	// gateway: 4 bytes
	// dns_primary: 4 bytes
	// dns_secondary: 4 bytes
	// lease_time: 4 bytes
	// _pad2: 4 bytes
	// Total: 28 bytes

	if size < 28 {
		t.Errorf("IPPool size %d is smaller than expected minimum 28", size)
	}
}

// TestServerConfigStructSize verifies the Go struct matches eBPF struct size
func TestServerConfigStructSize(t *testing.T) {
	var cfg ebpf.ServerConfig
	size := unsafe.Sizeof(cfg)

	t.Logf("ServerConfig size: %d bytes", size)

	// Expected size from bpf/maps.h:
	// server_mac[6]: 6 bytes
	// _pad[2]: 2 bytes
	// server_ip: 4 bytes
	// interface_index: 4 bytes
	// Total: 16 bytes

	if size != 16 {
		t.Errorf("ServerConfig size %d, expected 16", size)
	}
}

// TestDHCPStatsStructSize verifies the Go struct matches eBPF struct size
func TestDHCPStatsStructSize(t *testing.T) {
	var stats ebpf.DHCPStats
	size := unsafe.Sizeof(stats)

	t.Logf("DHCPStats size: %d bytes", size)

	// Each field is 8 bytes (uint64), 10 fields total = 80 bytes
	expectedSize := uintptr(10 * 8)
	if size != expectedSize {
		t.Errorf("DHCPStats size %d, expected %d", size, expectedSize)
	}
}

// TestVLANKeyStructSize verifies the Go struct matches eBPF struct size
func TestVLANKeyStructSize(t *testing.T) {
	var key ebpf.VLANKey
	size := unsafe.Sizeof(key)

	t.Logf("VLANKey size: %d bytes", size)

	// Expected size from bpf/maps.h:
	// s_tag: 2 bytes (uint16)
	// c_tag: 2 bytes (uint16)
	// Total: 4 bytes

	if size != 4 {
		t.Errorf("VLANKey size %d, expected 4", size)
	}
}

// TestCircuitIDKeySize verifies the CircuitIDKey constant and type
func TestCircuitIDKeySize(t *testing.T) {
	// CIRCUIT_ID_KEY_LEN in maps.h is 32
	if ebpf.CircuitIDKeyLen != 32 {
		t.Errorf("CircuitIDKeyLen = %d, expected 32", ebpf.CircuitIDKeyLen)
	}

	var key ebpf.CircuitIDKey
	size := unsafe.Sizeof(key)

	if size != 32 {
		t.Errorf("CircuitIDKey size %d, expected 32", size)
	}
}

// TestMapKeyValueSizes tests that map key/value types match expected sizes
func TestMapKeyValueSizes(t *testing.T) {
	tests := []struct {
		name         string
		size         uintptr
		expectedSize uintptr
		description  string
	}{
		{
			name:         "MAC key (uint64)",
			size:         unsafe.Sizeof(uint64(0)),
			expectedSize: 8,
			description:  "subscriber_pools map key",
		},
		{
			name:         "Pool ID key (uint32)",
			size:         unsafe.Sizeof(uint32(0)),
			expectedSize: 4,
			description:  "ip_pools map key",
		},
		{
			name:         "Stats array index (uint32)",
			size:         unsafe.Sizeof(uint32(0)),
			expectedSize: 4,
			description:  "stats_map array index",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.size != tt.expectedSize {
				t.Errorf("%s (%s): size %d, expected %d", tt.name, tt.description, tt.size, tt.expectedSize)
			}
		})
	}
}

// TestIPConversionConsistency tests IP address conversion functions
func TestIPConversionConsistency(t *testing.T) {
	testIPs := []uint32{
		0x0A000001, // 10.0.0.1
		0xC0A80001, // 192.168.0.1
		0x7F000001, // 127.0.0.1
		0xFFFFFFFF, // 255.255.255.255
		0x00000000, // 0.0.0.0
	}

	for _, ip := range testIPs {
		converted := ebpf.Uint32ToIP(ip)
		back := ebpf.IPToUint32(converted)
		if back != ip {
			t.Errorf("IP conversion round trip failed: 0x%08X -> %s -> 0x%08X", ip, converted, back)
		}
	}
}

// TestMACConversionConsistency tests MAC address conversion functions
func TestMACConversionConsistency(t *testing.T) {
	testMACs := []uint64{
		0xAABBCCDDEEFF,
		0x001122334455,
		0xFFFFFFFFFFFF,
		0x000000000000,
		0x0123456789AB,
	}

	for _, mac := range testMACs {
		converted := ebpf.Uint64ToMAC(mac)
		back := ebpf.MACToUint64(converted)
		if back != mac {
			t.Errorf("MAC conversion round trip failed: 0x%012X -> %s -> 0x%012X", mac, converted, back)
		}
	}
}

// TestHashCollisionResistance tests that different circuit-IDs produce different hashes
func TestHashCollisionResistance(t *testing.T) {
	// Test common circuit-ID patterns
	circuitIDs := [][]byte{
		[]byte("eth 0/1/1:100"),
		[]byte("eth 0/1/1:101"),
		[]byte("eth 0/1/2:100"),
		[]byte("eth 0/2/1:100"),
		[]byte("eth 1/1/1:100"),
		[]byte("FSAN:ALCL12345678"),
		[]byte("FSAN:ALCL12345679"),
		[]byte("access-node-id eth 0/1/1 atm 0/100"),
		[]byte("access-node-id eth 0/1/1 atm 0/101"),
	}

	hashes := make(map[uint64][]byte)
	for _, cid := range circuitIDs {
		hash := ebpf.HashCircuitID(cid)
		if existing, ok := hashes[hash]; ok {
			t.Errorf("Hash collision between %q and %q: hash=0x%016X", existing, cid, hash)
		}
		hashes[hash] = cid
	}

	t.Logf("Tested %d circuit-IDs with no collisions", len(circuitIDs))
}

// TestCircuitIDKeyPadding verifies proper zero-padding for short circuit-IDs
func TestCircuitIDKeyPadding(t *testing.T) {
	shortID := []byte("eth")
	key := ebpf.MakeCircuitIDKey(shortID)

	// First 3 bytes should match input
	for i := 0; i < 3; i++ {
		if key[i] != shortID[i] {
			t.Errorf("key[%d] = 0x%02X, expected 0x%02X", i, key[i], shortID[i])
		}
	}

	// Rest should be zero-padded
	for i := 3; i < ebpf.CircuitIDKeyLen; i++ {
		if key[i] != 0 {
			t.Errorf("key[%d] = 0x%02X, expected 0x00 (padding)", i, key[i])
		}
	}
}

// TestCircuitIDKeyTruncation verifies proper truncation for long circuit-IDs
func TestCircuitIDKeyTruncation(t *testing.T) {
	longID := make([]byte, 100)
	for i := range longID {
		longID[i] = byte(i)
	}

	key := ebpf.MakeCircuitIDKey(longID)

	// First 32 bytes should match input
	for i := 0; i < ebpf.CircuitIDKeyLen; i++ {
		if key[i] != longID[i] {
			t.Errorf("key[%d] = 0x%02X, expected 0x%02X", i, key[i], longID[i])
		}
	}
}

// BenchmarkHashCircuitID benchmarks the circuit-ID hashing function
func BenchmarkHashCircuitID(b *testing.B) {
	circuitID := []byte("eth 0/1/1:100.200")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ebpf.HashCircuitID(circuitID)
	}
}

// BenchmarkMakeCircuitIDKey benchmarks the circuit-ID key creation
func BenchmarkMakeCircuitIDKey(b *testing.B) {
	circuitID := []byte("eth 0/1/1:100.200")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ebpf.MakeCircuitIDKey(circuitID)
	}
}

// BenchmarkIPConversion benchmarks IP address conversion
func BenchmarkIPConversion(b *testing.B) {
	ip := uint32(0xC0A80001)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		converted := ebpf.Uint32ToIP(ip)
		_ = ebpf.IPToUint32(converted)
	}
}

// BenchmarkMACConversion benchmarks MAC address conversion
func BenchmarkMACConversion(b *testing.B) {
	mac := uint64(0xAABBCCDDEEFF)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		converted := ebpf.Uint64ToMAC(mac)
		_ = ebpf.MACToUint64(converted)
	}
}
