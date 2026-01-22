package slaac

import (
	"net"
	"runtime"
	"testing"
	"time"
)

// loopbackInterface returns the loopback interface name for the current platform
func loopbackInterface() string {
	if runtime.GOOS == "darwin" {
		return "lo0"
	}
	return "lo"
}

func TestServerConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			cfg: Config{
				Interface:       loopbackInterface(),
				Prefixes:        []string{"2001:db8::/64"},
				DNSServers:      []string{"2001:4860:4860::8888"},
				DefaultLifetime: 1800,
			},
			wantErr: false,
		},
		{
			name: "missing interface",
			cfg: Config{
				Interface: "",
				Prefixes:  []string{"2001:db8::/64"},
			},
			wantErr: true,
			errMsg:  "interface required",
		},
		{
			name: "invalid prefix",
			cfg: Config{
				Interface: loopbackInterface(),
				Prefixes:  []string{"invalid"},
			},
			wantErr: true,
			errMsg:  "invalid prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(tt.cfg, nil)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestServerDefaultIntervals(t *testing.T) {
	cfg := Config{
		Interface:     loopbackInterface(),
		MinRAInterval: 0,
		MaxRAInterval: 0,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check defaults are applied per RFC 4861
	if server.minRAInterval != 200*time.Second {
		t.Errorf("minRAInterval = %v, want 200s", server.minRAInterval)
	}
	if server.maxRAInterval != 600*time.Second {
		t.Errorf("maxRAInterval = %v, want 600s", server.maxRAInterval)
	}
	if server.defaultLifetime != 1800 {
		t.Errorf("defaultLifetime = %v, want 1800", server.defaultLifetime)
	}
}

func TestServerDNSParsing(t *testing.T) {
	cfg := Config{
		Interface:  loopbackInterface(),
		DNSServers: []string{"2001:4860:4860::8888", "2001:4860:4860::8844", "192.168.1.1"},
		DNSDomains: []string{"example.com", "test.local"},
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only IPv6 addresses should be kept
	if len(server.dnsServers) != 2 {
		t.Errorf("dnsServers count = %d, want 2 (IPv4 should be filtered)", len(server.dnsServers))
	}

	// Domains should be preserved
	if len(server.dnsDomains) != 2 {
		t.Errorf("dnsDomains count = %d, want 2", len(server.dnsDomains))
	}
}

func TestServerPrefixParsing(t *testing.T) {
	cfg := Config{
		Interface: loopbackInterface(),
		Prefixes:  []string{"2001:db8:1::/64", "2001:db8:2::/64"},
		Managed:   false,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(server.prefixes) != 2 {
		t.Errorf("prefixes count = %d, want 2", len(server.prefixes))
	}

	// Check prefix config defaults
	for _, p := range server.prefixes {
		if !p.OnLink {
			t.Error("expected OnLink = true")
		}
		if !p.Autonomous {
			t.Error("expected Autonomous = true (Managed=false)")
		}
		if p.ValidLifetime == 0 {
			t.Error("expected ValidLifetime to be set")
		}
		if p.PreferredLifetime == 0 {
			t.Error("expected PreferredLifetime to be set")
		}
	}
}

func TestServerManagedMode(t *testing.T) {
	cfg := Config{
		Interface: loopbackInterface(),
		Prefixes:  []string{"2001:db8::/64"},
		Managed:   true, // M flag set - no SLAAC
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With Managed=true, Autonomous should be false
	for _, p := range server.prefixes {
		if p.Autonomous {
			t.Error("expected Autonomous = false when Managed=true")
		}
	}

	if !server.managed {
		t.Error("expected server.managed = true")
	}
}

func TestBuildRA(t *testing.T) {
	cfg := Config{
		Interface:       loopbackInterface(),
		Prefixes:        []string{"2001:db8::/64"},
		MTU:             1500,
		Managed:         false,
		Other:           true,
		DNSServers:      []string{"2001:4860:4860::8888"},
		DNSDomains:      []string{"example.com"},
		DefaultLifetime: 1800,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ra := server.buildRA()

	// Check ICMPv6 type
	if ra[0] != ICMPv6RouterAdvertisement {
		t.Errorf("ICMPv6 type = %d, want %d", ra[0], ICMPv6RouterAdvertisement)
	}

	// Check hop limit
	if ra[4] != 64 {
		t.Errorf("hop limit = %d, want 64", ra[4])
	}

	// Check flags (O flag should be set, M flag should not)
	flags := ra[5]
	if flags&RAFlagManaged != 0 {
		t.Error("M flag should not be set")
	}
	if flags&RAFlagOther == 0 {
		t.Error("O flag should be set")
	}

	// RA should be at least 16 bytes (header) + 8 (source LL) = 24 bytes
	// Plus prefix option (32) + MTU (8) + RDNSS + DNSSL
	if len(ra) < 24 {
		t.Errorf("RA too short: %d bytes", len(ra))
	}
}

func TestBuildPrefixOption(t *testing.T) {
	_, prefix, _ := net.ParseCIDR("2001:db8::/64")
	cfg := PrefixConfig{
		Prefix:            prefix,
		OnLink:            true,
		Autonomous:        true,
		ValidLifetime:     2592000, // 30 days
		PreferredLifetime: 604800,  // 7 days
	}

	server := &Server{}
	opt := server.buildPrefixOption(cfg)

	// Prefix info option is 32 bytes
	if len(opt) != 32 {
		t.Errorf("prefix option length = %d, want 32", len(opt))
	}

	// Check option type
	if opt[0] != OptPrefixInfo {
		t.Errorf("option type = %d, want %d", opt[0], OptPrefixInfo)
	}

	// Check option length (in 8-byte units)
	if opt[1] != 4 {
		t.Errorf("option length = %d, want 4", opt[1])
	}

	// Check prefix length
	if opt[2] != 64 {
		t.Errorf("prefix length = %d, want 64", opt[2])
	}

	// Check flags
	flags := opt[3]
	if flags&PrefixFlagOnLink == 0 {
		t.Error("L flag should be set")
	}
	if flags&PrefixFlagAutonomous == 0 {
		t.Error("A flag should be set")
	}
}

func TestAddRemovePrefix(t *testing.T) {
	cfg := Config{
		Interface: loopbackInterface(),
		Prefixes:  []string{"2001:db8:1::/64"},
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Initial state
	if len(server.prefixes) != 1 {
		t.Fatalf("initial prefixes count = %d, want 1", len(server.prefixes))
	}

	// Add prefix
	_, newPrefix, _ := net.ParseCIDR("2001:db8:2::/64")
	server.AddPrefix(PrefixConfig{
		Prefix:            newPrefix,
		OnLink:            true,
		Autonomous:        true,
		ValidLifetime:     2592000,
		PreferredLifetime: 604800,
	})

	if len(server.prefixes) != 2 {
		t.Errorf("after add: prefixes count = %d, want 2", len(server.prefixes))
	}

	// Remove prefix
	server.RemovePrefix("2001:db8:2::/64")

	if len(server.prefixes) != 1 {
		t.Errorf("after remove: prefixes count = %d, want 1", len(server.prefixes))
	}
}

func TestGetStats(t *testing.T) {
	cfg := Config{
		Interface: loopbackInterface(),
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats := server.GetStats()

	// Check stats keys exist
	if _, ok := stats["ras_sent"]; !ok {
		t.Error("expected 'ras_sent' in stats")
	}
	if _, ok := stats["rss_received"]; !ok {
		t.Error("expected 'rss_received' in stats")
	}
}

func TestBuildRDNSSOption(t *testing.T) {
	server := &Server{
		dnsServers: []net.IP{
			net.ParseIP("2001:4860:4860::8888"),
			net.ParseIP("2001:4860:4860::8844"),
		},
		defaultLifetime: 1800,
	}

	opt := server.buildRDNSSOption()

	// RDNSS: type(1) + length(1) + reserved(2) + lifetime(4) + 2 addresses(32)
	expectedLen := 8 + 32
	if len(opt) != expectedLen {
		t.Errorf("RDNSS option length = %d, want %d", len(opt), expectedLen)
	}

	if opt[0] != OptRDNSS {
		t.Errorf("option type = %d, want %d", opt[0], OptRDNSS)
	}
}

func TestBuildDNSSLOption(t *testing.T) {
	server := &Server{
		dnsDomains:      []string{"example.com", "test.local"},
		defaultLifetime: 1800,
	}

	opt := server.buildDNSSLOption()

	if opt[0] != OptDNSSL {
		t.Errorf("option type = %d, want %d", opt[0], OptDNSSL)
	}

	// Length should be a multiple of 8 bytes
	if len(opt)%8 != 0 {
		t.Errorf("DNSSL option not padded to 8-byte boundary: %d bytes", len(opt))
	}
}

// Note: TestEncodeDNSLabel and TestSplitDomain are defined in slaac_test.go
