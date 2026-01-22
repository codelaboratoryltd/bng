//go:build linux

package ztp

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractNexusURL_Option224(t *testing.T) {
	msg, err := dhcpv4.New()
	require.NoError(t, err)

	expectedURL := "http://nexus.example.com:9000"
	msg.Options[224] = []byte(expectedURL)

	result := extractNexusURL(msg)
	assert.Equal(t, expectedURL, result)
}

func TestExtractNexusURL_VendorOption43(t *testing.T) {
	msg, err := dhcpv4.New()
	require.NoError(t, err)

	// Vendor option 43 with TLV: Type=1, Length=len, Value=URL
	url := "http://nexus.local:9000"
	vendorData := []byte{0x01, byte(len(url))}
	vendorData = append(vendorData, []byte(url)...)
	msg.Options[43] = vendorData

	result := extractNexusURL(msg)
	assert.Equal(t, url, result)
}

func TestExtractNexusURL_Option224TakesPrecedence(t *testing.T) {
	msg, err := dhcpv4.New()
	require.NoError(t, err)

	// Set both options - 224 should take precedence
	option224URL := "http://option224.example.com:9000"
	option43URL := "http://option43.example.com:9000"

	msg.Options[224] = []byte(option224URL)
	vendorData := []byte{0x01, byte(len(option43URL))}
	vendorData = append(vendorData, []byte(option43URL)...)
	msg.Options[43] = vendorData

	result := extractNexusURL(msg)
	assert.Equal(t, option224URL, result)
}

func TestExtractNexusURL_NoOptions(t *testing.T) {
	msg, err := dhcpv4.New()
	require.NoError(t, err)

	result := extractNexusURL(msg)
	assert.Empty(t, result)
}

func TestExtractNexusURL_EmptyOption224(t *testing.T) {
	msg, err := dhcpv4.New()
	require.NoError(t, err)

	msg.Options[224] = []byte{}

	result := extractNexusURL(msg)
	assert.Empty(t, result)
}

func TestParseVendorOptions(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "valid nexus URL (type 1)",
			data:     append([]byte{0x01, 0x11}, []byte("http://nexus:9000")...),
			expected: "http://nexus:9000",
		},
		{
			name:     "wrong type (type 2)",
			data:     append([]byte{0x02, 0x05}, []byte("hello")...),
			expected: "",
		},
		{
			name: "multiple options with type 1 second",
			data: func() []byte {
				// Type 2, length 3, "foo"
				d := []byte{0x02, 0x03, 'f', 'o', 'o'}
				// Type 1, length 3, "bar"
				d = append(d, 0x01, 0x03, 'b', 'a', 'r')
				return d
			}(),
			expected: "bar",
		},
		{
			name:     "truncated data - length exceeds available",
			data:     []byte{0x01, 0x10, 'h', 't', 't', 'p'}, // length says 16 but only 4 bytes
			expected: "",
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "single byte - no length field",
			data:     []byte{0x01},
			expected: "",
		},
		{
			name:     "zero length value",
			data:     []byte{0x01, 0x00},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVendorOptions(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskSize(t *testing.T) {
	tests := []struct {
		bits     int
		expected int
	}{
		{24, 24},
		{16, 16},
		{32, 32},
		{8, 8},
		{0, 0},
	}

	for _, tt := range tests {
		mask := make([]byte, 4)
		for i := 0; i < tt.bits/8; i++ {
			mask[i] = 0xff
		}
		if tt.bits%8 != 0 {
			mask[tt.bits/8] = byte(0xff << (8 - tt.bits%8))
		}
		result := maskSize(mask)
		assert.Equal(t, tt.expected, result)
	}
}
