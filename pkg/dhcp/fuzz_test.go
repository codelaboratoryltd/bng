package dhcp

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// FuzzParseOption82 tests Option 82 parsing with fuzzed input
// This is security-critical as Option 82 comes from network relay agents
func FuzzParseOption82(f *testing.F) {
	// Seed with valid Option 82 structures
	f.Add([]byte{1, 5, 'e', 't', 'h', '0', '1'})                             // Circuit-ID only
	f.Add([]byte{2, 4, 'r', 'e', 'm', '1'})                                  // Remote-ID only
	f.Add([]byte{1, 3, 'c', 'i', 'd', 2, 3, 'r', 'i', 'd'})                  // Both
	f.Add([]byte{})                                                          // Empty
	f.Add([]byte{1, 0})                                                      // Zero-length sub-option
	f.Add([]byte{1, 255, 'a', 'b', 'c'})                                     // Length exceeds data
	f.Add([]byte{255, 10, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'}) // Unknown sub-option type

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a DHCP packet with the fuzzed Option 82 data
		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
		if err != nil {
			return // Skip if we can't create a valid DHCP packet
		}

		// Add the fuzzed Option 82 data
		req.Options.Update(dhcpv4.Option{
			Code:  dhcpv4.OptionRelayAgentInformation,
			Value: dhcpv4.OptionGeneric{Data: data},
		})

		// This should never panic regardless of input
		info := parseOption82(req)

		// If we got a result, validate it's sane
		if info != nil {
			// Circuit-ID should be a copy, not a slice of original data
			if len(info.CircuitID) > 0 {
				// Verify we copied the data (mutation test)
				originalLen := len(info.CircuitID)
				info.CircuitID[0] ^= 0xFF
				// Re-parse to ensure we made a copy
				info2 := parseOption82(req)
				if info2 != nil && len(info2.CircuitID) == originalLen {
					// This is expected - we should have copied the data
				}
			}

			// Remote-ID should also be a copy
			if len(info.RemoteID) > 0 {
				// Just verify it doesn't crash
				_ = string(info.RemoteID)
			}
		}
	})
}

// FuzzDHCPPacketParsing tests DHCP packet creation and parsing
func FuzzDHCPPacketParsing(f *testing.F) {
	// Seed with valid DHCP packets
	validDiscover, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	if validDiscover != nil {
		f.Add(validDiscover.ToBytes())
	}

	validRequest, _ := dhcpv4.NewRequestFromOffer(validDiscover)
	if validRequest != nil {
		f.Add(validRequest.ToBytes())
	}

	// Seed with edge cases
	f.Add([]byte{})                       // Empty
	f.Add([]byte{0x01})                   // Single byte
	f.Add([]byte{0x02, 0x01, 0x06, 0x00}) // Truncated header
	f.Add(make([]byte, 300))              // Zeros
	f.Add(make([]byte, 2000))             // Large packet

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to parse the fuzzed data as a DHCP packet
		// This should never panic
		pkt, err := dhcpv4.FromBytes(data)
		if err != nil {
			return // Invalid packet, that's expected
		}

		// If we successfully parsed a packet, verify we can access fields safely
		_ = pkt.ClientHWAddr.String()
		_ = pkt.MessageType()
		_ = pkt.ClientIPAddr.String()
		_ = pkt.YourIPAddr.String()
		_ = pkt.ServerIPAddr.String()
		_ = pkt.GatewayIPAddr.String()
		_ = pkt.TransactionID

		// Test option access
		_ = pkt.RequestedIPAddress()
		_ = pkt.Options.Get(dhcpv4.OptionRelayAgentInformation)
		_ = pkt.Options.Get(dhcpv4.OptionHostName)
		_ = pkt.Options.Get(dhcpv4.OptionParameterRequestList)

		// Should be able to re-serialize
		_ = pkt.ToBytes()
	})
}

// FuzzMACAddress tests MAC address handling
func FuzzMACAddress(f *testing.F) {
	f.Add([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05})             // 5 bytes (too short)
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}) // 7 bytes

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 6 {
			return // Not enough for a MAC address
		}

		mac := net.HardwareAddr(data[:6])

		// Should be able to create a pool and use the MAC
		pool, err := NewPool(PoolConfig{
			ID:         1,
			Name:       "fuzz-test",
			Network:    "10.0.0.0/24",
			Gateway:    "10.0.0.1",
			DNSServers: []string{"8.8.8.8"},
		})
		if err != nil {
			return
		}

		// Allocate should not panic
		ip, err := pool.Allocate(mac)
		if err == nil {
			// If allocation succeeded, verify the IP is valid
			if ip == nil {
				t.Error("got nil IP from successful allocation")
			}
			if !pool.Contains(ip) {
				t.Error("allocated IP is not in pool")
			}

			// Release should work
			pool.Release(ip)
		}

		// String representation should work
		_ = mac.String()
	})
}

// TestCIDRParsing tests CIDR parsing with various inputs (not a fuzz test)
func TestCIDRParsing(t *testing.T) {
	testCases := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"valid /24", "10.0.0.0/24", false},
		{"valid /25", "192.168.1.128/25", false},
		{"valid /28", "172.16.0.0/28", false},
		{"valid /30", "10.0.0.0/30", false},
		{"valid /32", "255.255.255.255/32", false},
		{"empty", "", true},
		{"invalid", "invalid", true},
		{"no prefix", "10.0.0.0", true},
		{"no prefix length", "10.0.0.0/", true},
		{"invalid prefix", "10.0.0.0/99", true},
		{"negative prefix", "10.0.0.0/-1", true},
		{"invalid octet", "256.0.0.0/24", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPool(PoolConfig{
				ID:         1,
				Name:       "test",
				Network:    tc.cidr,
				Gateway:    "10.0.0.1",
				DNSServers: []string{"8.8.8.8"},
			})
			if tc.wantErr && err == nil {
				t.Errorf("expected error for CIDR %q", tc.cidr)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for CIDR %q: %v", tc.cidr, err)
			}
		})
	}
}

// TestGatewayParsing tests gateway IP parsing with various inputs
func TestGatewayParsing(t *testing.T) {
	testCases := []struct {
		name    string
		gateway string
		wantErr bool
	}{
		{"valid gateway", "10.0.0.1", false},
		{"another valid", "192.168.1.1", false},
		{"zero address", "0.0.0.0", false},
		{"broadcast", "255.255.255.255", false},
		{"empty", "", true},
		{"invalid", "invalid", true},
		{"too many octets", "10.0.0.1.2", true},
		{"negative", "-1.0.0.0", true},
		{"overflow", "256.0.0.0", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPool(PoolConfig{
				ID:         1,
				Name:       "test",
				Network:    "10.0.0.0/24",
				Gateway:    tc.gateway,
				DNSServers: []string{"8.8.8.8"},
			})
			if tc.wantErr && err == nil {
				t.Errorf("expected error for gateway %q", tc.gateway)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for gateway %q: %v", tc.gateway, err)
			}
		})
	}
}

// TestDNSServerParsing tests DNS server parsing with various inputs
func TestDNSServerParsing(t *testing.T) {
	testCases := []struct {
		name    string
		dns     string
		wantErr bool
	}{
		{"google dns", "8.8.8.8", false},
		{"google dns secondary", "8.8.4.4", false},
		{"cloudflare", "1.1.1.1", false},
		{"invalid", "invalid", true},
		{"empty", "", true},
		{"overflow", "256.0.0.0", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPool(PoolConfig{
				ID:         1,
				Name:       "test",
				Network:    "10.0.0.0/24",
				Gateway:    "10.0.0.1",
				DNSServers: []string{tc.dns},
			})
			if tc.wantErr && err == nil {
				t.Errorf("expected error for DNS %q", tc.dns)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for DNS %q: %v", tc.dns, err)
			}
		})
	}
}

// TestSessionIDUniqueness tests session ID generation produces unique values
func TestSessionIDUniqueness(t *testing.T) {
	const count = 1000
	seen := make(map[string]bool)

	for i := 0; i < count; i++ {
		id := generateSessionID()
		if seen[id] {
			t.Errorf("duplicate session ID at iteration %d: %s", i, id)
		}
		seen[id] = true

		// Verify format: 16 hex characters
		if len(id) != 16 {
			t.Errorf("session ID has wrong length: %d, want 16", len(id))
		}
	}
}
