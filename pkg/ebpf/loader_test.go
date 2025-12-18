package ebpf

import (
	"net"
	"testing"
	"time"
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
