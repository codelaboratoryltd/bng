package ztp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name  string
		iface string
	}{
		{name: "eth0 interface", iface: "eth0"},
		{name: "mgmt0 interface", iface: "mgmt0"},
		{name: "empty interface", iface: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.iface)
			require.NotNil(t, client)
			assert.Equal(t, tt.iface, client.iface)
		})
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		IP:        net.ParseIP("10.0.0.100"),
		Mask:      net.CIDRMask(24, 32),
		Gateway:   net.ParseIP("10.0.0.1"),
		DNS:       []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		NexusURL:  "http://nexus.example.com:9000",
		LeaseTime: 24 * time.Hour,
	}

	assert.Equal(t, "10.0.0.100", result.IP.String())
	assert.Equal(t, "ffffff00", result.Mask.String())
	assert.Equal(t, "10.0.0.1", result.Gateway.String())
	assert.Len(t, result.DNS, 2)
	assert.Equal(t, "http://nexus.example.com:9000", result.NexusURL)
	assert.Equal(t, 24*time.Hour, result.LeaseTime)
}

func TestResult_EmptyFields(t *testing.T) {
	result := Result{}

	assert.Nil(t, result.IP)
	assert.Nil(t, result.Mask)
	assert.Nil(t, result.Gateway)
	assert.Nil(t, result.DNS)
	assert.Empty(t, result.NexusURL)
	assert.Zero(t, result.LeaseTime)
}

func TestResult_IPv6(t *testing.T) {
	result := Result{
		IP:        net.ParseIP("2001:db8::1"),
		Mask:      net.CIDRMask(64, 128),
		Gateway:   net.ParseIP("2001:db8::ffff"),
		DNS:       []net.IP{net.ParseIP("2001:4860:4860::8888")},
		NexusURL:  "http://[2001:db8::100]:9000",
		LeaseTime: 12 * time.Hour,
	}

	assert.Equal(t, "2001:db8::1", result.IP.String())
	assert.Len(t, result.DNS, 1)
	assert.Contains(t, result.NexusURL, "2001:db8")
}
