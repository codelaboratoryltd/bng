package slaac

import (
	"net"
	"testing"
)

func TestGenerateSLAACAddress(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		mac    string
		want   string
	}{
		{
			name:   "standard prefix and mac",
			prefix: "2001:db8::/64",
			mac:    "00:11:22:33:44:55",
			want:   "2001:db8::211:22ff:fe33:4455",
		},
		{
			name:   "different prefix",
			prefix: "fd00:1234::/64",
			mac:    "aa:bb:cc:dd:ee:ff",
			want:   "fd00:1234::a8bb:ccff:fedd:eeff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, prefix, _ := net.ParseCIDR(tt.prefix)
			mac, _ := net.ParseMAC(tt.mac)

			got := GenerateSLAACAddress(prefix, mac)
			want := net.ParseIP(tt.want)

			if !got.Equal(want) {
				t.Errorf("GenerateSLAACAddress() = %v, want %v", got, want)
			}
		})
	}
}

func TestGenerateSLAACAddress_InvalidMAC(t *testing.T) {
	_, prefix, _ := net.ParseCIDR("2001:db8::/64")

	// Invalid MAC (too short)
	got := GenerateSLAACAddress(prefix, []byte{0x00, 0x11, 0x22})
	if got != nil {
		t.Errorf("Expected nil for invalid MAC, got %v", got)
	}
}

func TestGenerateStablePrivacyAddress(t *testing.T) {
	_, prefix, _ := net.ParseCIDR("2001:db8::/64")
	interfaceID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	secretKey := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}

	ip := GenerateStablePrivacyAddress(prefix, interfaceID, secretKey)

	if ip == nil {
		t.Fatal("Expected non-nil IP")
	}

	// Verify prefix is preserved
	if !ip[:8].Equal(prefix.IP.To16()[:8]) {
		t.Error("Prefix not preserved in generated address")
	}

	// Verify universal/local bit is cleared
	if ip[8]&0x02 != 0 {
		t.Error("Universal/local bit should be cleared")
	}

	// Verify deterministic
	ip2 := GenerateStablePrivacyAddress(prefix, interfaceID, secretKey)
	if !ip.Equal(ip2) {
		t.Error("Expected deterministic address generation")
	}

	// Verify different input gives different output
	ip3 := GenerateStablePrivacyAddress(prefix, interfaceID, []byte{0x00})
	if ip.Equal(ip3) {
		t.Error("Different secret should give different address")
	}
}

func TestIsLinkLocal(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"fe80::1", true},
		{"fe80::1234:5678:abcd:ef01", true},
		{"2001:db8::1", false},
		{"::1", false},
		{"169.254.1.1", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := IsLinkLocal(ip)
			if got != tt.want {
				t.Errorf("IsLinkLocal(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsGlobalUnicast(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"2001:db8::1", true},
		{"2001:4860:4860::8888", true},
		{"fe80::1", false},
		{"::1", false},
		{"ff02::1", false},
		{"192.168.1.1", false}, // Private
		{"10.0.0.1", false},    // Private
		{"8.8.8.8", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := IsGlobalUnicast(ip)
			if got != tt.want {
				t.Errorf("IsGlobalUnicast(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestDefaultRouterConfig(t *testing.T) {
	cfg := DefaultRouterConfig()

	if cfg.CurHopLimit != 64 {
		t.Errorf("CurHopLimit = %d, want 64", cfg.CurHopLimit)
	}
	if cfg.Managed {
		t.Error("Expected Managed = false")
	}
	if cfg.Other {
		t.Error("Expected Other = false")
	}
	if cfg.MinRAInterval == 0 {
		t.Error("Expected MinRAInterval to be set")
	}
	if cfg.MaxRAInterval == 0 {
		t.Error("Expected MaxRAInterval to be set")
	}
}

func TestDefaultPrefixAdvertisement(t *testing.T) {
	_, prefix, _ := net.ParseCIDR("2001:db8::/64")
	adv := DefaultPrefixAdvertisement(prefix)

	if !adv.OnLink {
		t.Error("Expected OnLink = true")
	}
	if !adv.Autonomous {
		t.Error("Expected Autonomous = true")
	}
	if adv.ValidLifetime == 0 {
		t.Error("Expected ValidLifetime to be set")
	}
	if adv.PreferredLifetime == 0 {
		t.Error("Expected PreferredLifetime to be set")
	}
	if adv.PreferredLifetime > adv.ValidLifetime {
		t.Error("PreferredLifetime should be <= ValidLifetime")
	}
}

func TestEncodeDNSLabel(t *testing.T) {
	tests := []struct {
		domain string
		want   []byte
	}{
		{
			domain: "example.com",
			want:   []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			domain: "test",
			want:   []byte{4, 't', 'e', 's', 't', 0},
		},
		{
			domain: "a.b.c",
			want:   []byte{1, 'a', 1, 'b', 1, 'c', 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := encodeDNSLabel(tt.domain)
			if len(got) != len(tt.want) {
				t.Errorf("encodeDNSLabel(%s) length = %d, want %d", tt.domain, len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("encodeDNSLabel(%s)[%d] = %d, want %d", tt.domain, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSplitDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   []string
	}{
		{"example.com", []string{"example", "com"}},
		{"a.b.c.d", []string{"a", "b", "c", "d"}},
		{"single", []string{"single"}},
		{"", []string{}},
		{"trailing.", []string{"trailing"}},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := splitDomain(tt.domain)
			if len(got) != len(tt.want) {
				t.Errorf("splitDomain(%s) = %v, want %v", tt.domain, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitDomain(%s)[%d] = %s, want %s", tt.domain, i, got[i], tt.want[i])
				}
			}
		})
	}
}
