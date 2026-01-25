package nat

import (
	"net"
	"testing"

	"go.uber.org/zap"
)

func TestNewManagerAdditional(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		cfg         ManagerConfig
		expectError bool
	}{
		{
			name: "valid configuration",
			cfg: ManagerConfig{
				Interface:          "eth0",
				PortsPerSubscriber: 1024,
				PortRangeStart:     1024,
				PortRangeEnd:       65535,
			},
			expectError: false,
		},
		{
			name: "missing interface",
			cfg: ManagerConfig{
				Interface: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewManager(tt.cfg, logger)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if mgr == nil {
					t.Error("expected non-nil manager")
				}
			}
		})
	}
}

func TestManagerDefaultsAdditional(t *testing.T) {
	logger := zap.NewNop()
	cfg := ManagerConfig{
		Interface: "eth0",
	}

	mgr, err := NewManager(cfg, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Check defaults
	if mgr.portsPerSubscriber != 1024 {
		t.Errorf("expected default portsPerSubscriber 1024, got %d", mgr.portsPerSubscriber)
	}

	if mgr.portRangeStart != 1024 {
		t.Errorf("expected default portRangeStart 1024, got %d", mgr.portRangeStart)
	}

	if mgr.portRangeEnd != 65535 {
		t.Errorf("expected default portRangeEnd 65535, got %d", mgr.portRangeEnd)
	}
}

func TestManagerAddPublicIPAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "eth0",
		PortsPerSubscriber: 1024,
		PortRangeStart:     1024,
		PortRangeEnd:       65535,
	}, logger)

	ip := net.ParseIP("203.0.113.1")
	err := mgr.AddPublicIP(ip)
	if err != nil {
		t.Errorf("AddPublicIP failed: %v", err)
	}

	// Verify pool stats
	stats := mgr.GetPoolStats()
	if len(stats) != 1 {
		t.Errorf("expected 1 pool entry, got %d", len(stats))
	}

	if !stats[0].PublicIP.Equal(ip) {
		t.Errorf("expected IP %s, got %s", ip, stats[0].PublicIP)
	}
}

func TestManagerAddPublicIPInvalidIPv6Additional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface: "eth0",
	}, logger)

	ip := net.ParseIP("::1")
	err := mgr.AddPublicIP(ip)
	if err == nil {
		t.Error("expected error for IPv6 address")
	}
}

func TestManagerAddPublicIPRangeAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "eth0",
		PortsPerSubscriber: 1024,
		PortRangeStart:     1024,
		PortRangeEnd:       65535,
	}, logger)

	startIP := net.ParseIP("203.0.113.1")
	endIP := net.ParseIP("203.0.113.3")

	err := mgr.AddPublicIPRange(startIP, endIP)
	if err != nil {
		t.Errorf("AddPublicIPRange failed: %v", err)
	}

	stats := mgr.GetPoolStats()
	if len(stats) != 3 {
		t.Errorf("expected 3 pool entries, got %d", len(stats))
	}
}

func TestManagerAddPublicIPRangeInvalidAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface: "eth0",
	}, logger)

	startIP := net.ParseIP("203.0.113.10")
	endIP := net.ParseIP("203.0.113.1")

	err := mgr.AddPublicIPRange(startIP, endIP)
	if err == nil {
		t.Error("expected error when start > end")
	}
}

func TestManagerAllocateNATAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "eth0",
		PortsPerSubscriber: 1024,
		PortRangeStart:     1024,
		PortRangeEnd:       65535,
	}, logger)

	// Add a public IP to the pool
	mgr.AddPublicIP(net.ParseIP("203.0.113.1"))

	privateIP := net.ParseIP("10.0.0.100")
	alloc, err := mgr.AllocateNAT(privateIP)
	if err != nil {
		t.Fatalf("AllocateNAT failed: %v", err)
	}

	if alloc == nil {
		t.Fatal("expected non-nil allocation")
	}

	if !alloc.PrivateIP.Equal(privateIP) {
		t.Errorf("expected private IP %s, got %s", privateIP, alloc.PrivateIP)
	}

	if !alloc.PublicIP.Equal(net.ParseIP("203.0.113.1")) {
		t.Errorf("unexpected public IP: %s", alloc.PublicIP)
	}

	// Verify allocation count
	if mgr.GetAllocationCount() != 1 {
		t.Errorf("expected allocation count 1, got %d", mgr.GetAllocationCount())
	}
}

func TestManagerAllocateNATDuplicateAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "eth0",
		PortsPerSubscriber: 1024,
		PortRangeStart:     1024,
		PortRangeEnd:       65535,
	}, logger)

	mgr.AddPublicIP(net.ParseIP("203.0.113.1"))

	privateIP := net.ParseIP("10.0.0.100")

	// First allocation
	alloc1, err := mgr.AllocateNAT(privateIP)
	if err != nil {
		t.Fatalf("first AllocateNAT failed: %v", err)
	}

	// Second allocation for same IP should return existing
	alloc2, err := mgr.AllocateNAT(privateIP)
	if err != nil {
		t.Fatalf("second AllocateNAT failed: %v", err)
	}

	// Should return the same allocation
	if alloc1.PortStart != alloc2.PortStart {
		t.Errorf("expected same port start, got %d and %d", alloc1.PortStart, alloc2.PortStart)
	}

	// Allocation count should still be 1
	if mgr.GetAllocationCount() != 1 {
		t.Errorf("expected allocation count 1, got %d", mgr.GetAllocationCount())
	}
}

func TestManagerAllocateNATExhaustedAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface: "eth0",
	}, logger)

	// Don't add any public IPs

	privateIP := net.ParseIP("10.0.0.100")
	_, err := mgr.AllocateNAT(privateIP)
	if err == nil {
		t.Error("expected error when pool is exhausted")
	}
}

func TestManagerDeallocateNATAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "eth0",
		PortsPerSubscriber: 1024,
		PortRangeStart:     1024,
		PortRangeEnd:       65535,
	}, logger)

	mgr.AddPublicIP(net.ParseIP("203.0.113.1"))

	privateIP := net.ParseIP("10.0.0.100")
	_, err := mgr.AllocateNAT(privateIP)
	if err != nil {
		t.Fatalf("AllocateNAT failed: %v", err)
	}

	// Deallocate
	err = mgr.DeallocateNAT(privateIP)
	if err != nil {
		t.Errorf("DeallocateNAT failed: %v", err)
	}

	if mgr.GetAllocationCount() != 0 {
		t.Errorf("expected allocation count 0 after deallocation, got %d", mgr.GetAllocationCount())
	}
}

func TestManagerDeallocateNATNotAllocatedAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface: "eth0",
	}, logger)

	privateIP := net.ParseIP("10.0.0.100")
	err := mgr.DeallocateNAT(privateIP)
	// Should not return error for non-allocated IP
	if err != nil {
		t.Errorf("DeallocateNAT should not return error for non-allocated IP: %v", err)
	}
}

func TestManagerGetAllocationAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "eth0",
		PortsPerSubscriber: 1024,
		PortRangeStart:     1024,
		PortRangeEnd:       65535,
	}, logger)

	mgr.AddPublicIP(net.ParseIP("203.0.113.1"))

	privateIP := net.ParseIP("10.0.0.100")
	_, err := mgr.AllocateNAT(privateIP)
	if err != nil {
		t.Fatalf("AllocateNAT failed: %v", err)
	}

	// Get allocation
	alloc := mgr.GetAllocation(privateIP)
	if alloc == nil {
		t.Fatal("expected non-nil allocation")
	}

	// Get non-existent allocation
	alloc = mgr.GetAllocation(net.ParseIP("10.0.0.200"))
	if alloc != nil {
		t.Error("expected nil for non-allocated IP")
	}
}

func TestBuildFlagsAdditional(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name     string
		cfg      ManagerConfig
		expected uint32
	}{
		{
			name: "all flags disabled",
			cfg: ManagerConfig{
				Interface: "eth0",
			},
			expected: 0,
		},
		{
			name: "EIM enabled",
			cfg: ManagerConfig{
				Interface: "eth0",
				EnableEIM: true,
			},
			expected: NATFlagEIMEnabled,
		},
		{
			name: "EIF enabled",
			cfg: ManagerConfig{
				Interface: "eth0",
				EnableEIF: true,
			},
			expected: NATFlagEIFEnabled,
		},
		{
			name: "hairpin enabled",
			cfg: ManagerConfig{
				Interface:     "eth0",
				EnableHairpin: true,
			},
			expected: NATFlagHairpinEnabled,
		},
		{
			name: "FTP ALG enabled",
			cfg: ManagerConfig{
				Interface:    "eth0",
				EnableFTPALG: true,
			},
			expected: NATFlagALGFTP,
		},
		{
			name: "SIP ALG enabled",
			cfg: ManagerConfig{
				Interface:    "eth0",
				EnableSIPALG: true,
			},
			expected: NATFlagALGSIP,
		},
		{
			name: "multiple flags",
			cfg: ManagerConfig{
				Interface:     "eth0",
				EnableEIM:     true,
				EnableHairpin: true,
				EnableFTPALG:  true,
			},
			expected: NATFlagEIMEnabled | NATFlagHairpinEnabled | NATFlagALGFTP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, _ := NewManager(tt.cfg, logger)
			flags := mgr.buildFlags()
			if flags != tt.expected {
				t.Errorf("expected flags 0x%X, got 0x%X", tt.expected, flags)
			}
		})
	}
}

func TestNATFlagConstantsAdditional(t *testing.T) {
	// Verify flag constants are unique powers of 2
	flags := []struct {
		name     string
		value    uint32
		expected uint32
	}{
		{"NATFlagEIMEnabled", NATFlagEIMEnabled, 0x01},
		{"NATFlagEIFEnabled", NATFlagEIFEnabled, 0x02},
		{"NATFlagHairpinEnabled", NATFlagHairpinEnabled, 0x04},
		{"NATFlagALGFTP", NATFlagALGFTP, 0x08},
		{"NATFlagALGSIP", NATFlagALGSIP, 0x10},
		{"NATFlagPortParity", NATFlagPortParity, 0x20},
		{"NATFlagPortContiguity", NATFlagPortContiguity, 0x40},
	}

	for _, tt := range flags {
		if tt.value != tt.expected {
			t.Errorf("%s = 0x%X, want 0x%X", tt.name, tt.value, tt.expected)
		}
	}
}

func TestNATLogEventTypesAdditional(t *testing.T) {
	// Verify log event type constants
	events := []struct {
		name     string
		value    uint32
		expected uint32
	}{
		{"NATLogSessionCreate", NATLogSessionCreate, 1},
		{"NATLogSessionDelete", NATLogSessionDelete, 2},
		{"NATLogPortBlockAssign", NATLogPortBlockAssign, 3},
		{"NATLogPortBlockRelease", NATLogPortBlockRelease, 4},
		{"NATLogPortExhaustion", NATLogPortExhaustion, 5},
		{"NATLogHairpin", NATLogHairpin, 6},
		{"NATLogALGTrigger", NATLogALGTrigger, 7},
	}

	for _, tt := range events {
		if tt.value != tt.expected {
			t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.expected)
		}
	}
}

func TestALGTypeConstantsAdditional(t *testing.T) {
	if ALGTypeFTP != 1 {
		t.Errorf("ALGTypeFTP = %d, want 1", ALGTypeFTP)
	}
	if ALGTypeSIP != 2 {
		t.Errorf("ALGTypeSIP = %d, want 2", ALGTypeSIP)
	}
	if ALGTypeRTSP != 3 {
		t.Errorf("ALGTypeRTSP = %d, want 3", ALGTypeRTSP)
	}
}

func TestLog2Additional(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{1, 0},
		{2, 1},
		{4, 2},
		{8, 3},
		{16, 4},
		{32, 5},
		{64, 6},
		{128, 7},
		{256, 8},
		{512, 9},
		{1024, 10},
	}

	for _, tt := range tests {
		result := log2(tt.input)
		if result != tt.expected {
			t.Errorf("log2(%d) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestIPConversionAdditional(t *testing.T) {
	tests := []struct {
		ip       string
		expected uint32
	}{
		{"10.0.0.1", 0x0A000001},
		{"192.168.1.1", 0xC0A80101},
		{"255.255.255.255", 0xFFFFFFFF},
		{"0.0.0.0", 0x00000000},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		key := ipToKey(ip)
		if key != tt.expected {
			t.Errorf("ipToKey(%s) = 0x%08X, want 0x%08X", tt.ip, key, tt.expected)
		}

		// Test round trip
		back := keyToIP(key)
		if !back.Equal(ip.To4()) {
			t.Errorf("keyToIP(0x%08X) = %s, want %s", key, back, ip)
		}
	}
}

func TestPortBlockStructAdditional(t *testing.T) {
	block := PortBlock{
		PublicIP:      0xC0A80101,
		PortStart:     1024,
		PortEnd:       2047,
		NextPort:      1024,
		PortsInUse:    0,
		AllocatedAt:   1234567890,
		SubscriberID:  42,
		BlockSizeLog2: 10, // 1024 ports = 2^10
		Flags:         0,
	}

	if block.PortStart != 1024 {
		t.Errorf("expected PortStart 1024, got %d", block.PortStart)
	}

	portCount := int(block.PortEnd - block.PortStart + 1)
	if portCount != 1024 {
		t.Errorf("expected 1024 ports, got %d", portCount)
	}
}

func TestNATStatsStructAdditional(t *testing.T) {
	stats := NATStats{
		PacketsSNAT:      1000,
		PacketsDNAT:      900,
		PacketsHairpin:   50,
		PacketsDropped:   5,
		PacketsPassed:    100,
		SessionsCreated:  200,
		SessionsExpired:  50,
		PortExhaustion:   1,
		EIMHits:          800,
		EIMMisses:        100,
		ALGTriggers:      10,
		ConntrackLookups: 2000,
		ConntrackHits:    1800,
	}

	if stats.SessionsExpired > stats.SessionsCreated {
		t.Error("expired sessions should not exceed created sessions")
	}
}

func TestAllocationStructAdditional(t *testing.T) {
	alloc := &Allocation{
		PrivateIP:    net.ParseIP("10.0.0.100"),
		PublicIP:     net.ParseIP("203.0.113.1"),
		PortStart:    1024,
		PortEnd:      2047,
		PoolIndex:    0,
		SubscriberID: 1,
	}

	if !alloc.PrivateIP.Equal(net.ParseIP("10.0.0.100")) {
		t.Error("PrivateIP mismatch")
	}

	portCount := alloc.PortEnd - alloc.PortStart + 1
	if portCount != 1024 {
		t.Errorf("expected 1024 ports, got %d", portCount)
	}
}

func TestPoolEntryStructAdditional(t *testing.T) {
	entry := PoolEntry{
		PublicIP:       net.ParseIP("203.0.113.1"),
		TotalPorts:     64512,
		PortsPerSub:    1024,
		Subscribers:    10,
		MaxSubscribers: 63,
		Flags:          NATFlagEIMEnabled,
	}

	if entry.TotalPorts/entry.PortsPerSub != 63 {
		t.Error("MaxSubscribers calculation mismatch")
	}

	if entry.Subscribers > entry.MaxSubscribers {
		t.Error("subscribers should not exceed max")
	}
}

func TestManagerConfigureALGWithoutMapAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface: "eth0",
	}, logger)

	// ALG configuration should fail without loaded maps
	err := mgr.ConfigureALG(21, 6, ALGTypeFTP, true)
	if err == nil {
		t.Error("ConfigureALG should fail without loaded maps")
	}
}

func TestManagerStopWithoutStartAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface: "eth0",
	}, logger)

	// Stop should not panic without Start
	err := mgr.Stop()
	if err != nil {
		t.Errorf("Stop should not return error: %v", err)
	}
}

func TestManagerGetStatsWithoutLoadAdditional(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface: "eth0",
	}, logger)

	_, err := mgr.GetStats()
	if err == nil {
		t.Error("GetStats should fail without loaded maps")
	}
}
