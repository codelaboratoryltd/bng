package routing_test

import (
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/routing"
	"go.uber.org/zap"
)

func TestBGPState_String(t *testing.T) {
	tests := []struct {
		state    routing.BGPState
		expected string
	}{
		{routing.BGPStateIdle, "Idle"},
		{routing.BGPStateConnect, "Connect"},
		{routing.BGPStateActive, "Active"},
		{routing.BGPStateOpenSent, "OpenSent"},
		{routing.BGPStateOpenConfirm, "OpenConfirm"},
		{routing.BGPStateEstablished, "Established"},
		{routing.BGPState(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("BGPState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

func TestParseBGPState(t *testing.T) {
	tests := []struct {
		input    string
		expected routing.BGPState
	}{
		{"Idle", routing.BGPStateIdle},
		{"idle", routing.BGPStateIdle},
		{"IDLE", routing.BGPStateIdle},
		{"Connect", routing.BGPStateConnect},
		{"Active", routing.BGPStateActive},
		{"OpenSent", routing.BGPStateOpenSent},
		{"OpenConfirm", routing.BGPStateOpenConfirm},
		{"Established", routing.BGPStateEstablished},
		{"established", routing.BGPStateEstablished},
		{"unknown", routing.BGPStateIdle},
	}

	for _, tt := range tests {
		if got := routing.ParseBGPState(tt.input); got != tt.expected {
			t.Errorf("ParseBGPState(%s) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestDefaultBGPConfig(t *testing.T) {
	config := routing.DefaultBGPConfig()

	if config.VtyshPath == "" {
		t.Error("VtyshPath should not be empty")
	}

	if config.MonitorInterval == 0 {
		t.Error("MonitorInterval should not be 0")
	}

	if config.CommandTimeout == 0 {
		t.Error("CommandTimeout should not be 0")
	}
}

func TestNewBGPController(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultBGPConfig()
	config.LocalAS = 64500
	config.RouterID = net.ParseIP("10.0.0.1")

	controller := routing.NewBGPController(config, logger)
	if controller == nil {
		t.Fatal("NewBGPController returned nil")
	}

	// Verify initial state
	neighbors := controller.ListNeighbors()
	if len(neighbors) != 0 {
		t.Errorf("Expected 0 initial neighbors, got %d", len(neighbors))
	}

	announcements := controller.ListAnnouncements()
	if len(announcements) != 0 {
		t.Errorf("Expected 0 initial announcements, got %d", len(announcements))
	}
}

func TestBGPController_Callbacks(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultBGPConfig()
	config.LocalAS = 64500
	config.RouterID = net.ParseIP("10.0.0.1")

	controller := routing.NewBGPController(config, logger)

	upCalled := false
	downCalled := false

	controller.OnNeighborUp(func(neighbor string) {
		upCalled = true
	})

	controller.OnNeighborDown(func(neighbor string) {
		downCalled = true
	})

	// Callbacks are registered but not triggered without FRR
	_ = upCalled
	_ = downCalled
}

func TestBGPController_Stats(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultBGPConfig()
	config.LocalAS = 64500
	config.RouterID = net.ParseIP("10.0.0.1")

	controller := routing.NewBGPController(config, logger)

	stats := controller.Stats()

	if stats.TotalNeighbors != 0 {
		t.Errorf("Expected 0 neighbors, got %d", stats.TotalNeighbors)
	}

	if stats.EstablishedNeighbors != 0 {
		t.Errorf("Expected 0 established, got %d", stats.EstablishedNeighbors)
	}

	if stats.TotalAnnouncements != 0 {
		t.Errorf("Expected 0 announcements, got %d", stats.TotalAnnouncements)
	}
}

func TestBGPController_GenerateConfig(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultBGPConfig()
	config.LocalAS = 64500
	config.RouterID = net.ParseIP("10.0.0.1")

	controller := routing.NewBGPController(config, logger)

	// Generate config (without neighbors/announcements)
	cfg := controller.GenerateConfig()

	if cfg == "" {
		t.Error("Generated config should not be empty")
	}

	// Check for expected content
	expectedStrings := []string{
		"router bgp 64500",
		"address-family ipv4 unicast",
	}

	for _, s := range expectedStrings {
		if !contains(cfg, s) {
			t.Errorf("Config should contain %q", s)
		}
	}
}

func TestBGPNeighbor_Fields(t *testing.T) {
	neighbor := &routing.BGPNeighbor{
		Address:      net.ParseIP("10.0.0.1"),
		RemoteAS:     64501,
		Description:  "ISP-A Primary",
		State:        routing.BGPStateEstablished,
		Uptime:       10 * time.Minute,
		PrefixesRecv: 5,
		PrefixesSent: 2,
		BFDEnabled:   true,
		NextHopSelf:  true,
	}

	if !neighbor.Address.Equal(net.ParseIP("10.0.0.1")) {
		t.Error("Address mismatch")
	}

	if neighbor.RemoteAS != 64501 {
		t.Errorf("RemoteAS = %d, want 64501", neighbor.RemoteAS)
	}

	if neighbor.State != routing.BGPStateEstablished {
		t.Errorf("State = %v, want Established", neighbor.State)
	}

	if !neighbor.BFDEnabled {
		t.Error("BFDEnabled should be true")
	}
}

func TestBGPAnnouncement_Fields(t *testing.T) {
	_, prefix, _ := net.ParseCIDR("100.64.0.0/22")

	announcement := &routing.BGPAnnouncement{
		Prefix:    prefix,
		NextHop:   net.ParseIP("10.0.0.1"),
		Community: "64500:100",
		LocalPref: 200,
		MED:       50,
	}

	if announcement.Prefix.String() != "100.64.0.0/22" {
		t.Errorf("Prefix = %s, want 100.64.0.0/22", announcement.Prefix.String())
	}

	if announcement.LocalPref != 200 {
		t.Errorf("LocalPref = %d, want 200", announcement.LocalPref)
	}

	if announcement.MED != 50 {
		t.Errorf("MED = %d, want 50", announcement.MED)
	}
}

func TestBGPSummary_Fields(t *testing.T) {
	summary := &routing.BGPSummary{
		RouterID:       net.ParseIP("10.0.0.1"),
		LocalAS:        64500,
		TotalNeighbors: 3,
		EstablishedNbr: 2,
		TotalPrefixes:  10,
	}

	if summary.LocalAS != 64500 {
		t.Errorf("LocalAS = %d, want 64500", summary.LocalAS)
	}

	if summary.TotalNeighbors != 3 {
		t.Errorf("TotalNeighbors = %d, want 3", summary.TotalNeighbors)
	}

	if summary.EstablishedNbr != 2 {
		t.Errorf("EstablishedNbr = %d, want 2", summary.EstablishedNbr)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Integration tests - require FRR to be running
// These are skipped by default

func TestBGPController_Integration(t *testing.T) {
	// Skip if not running integration tests
	t.Skip("Skipping integration test - requires FRR")

	logger, _ := zap.NewDevelopment()
	config := routing.DefaultBGPConfig()
	config.LocalAS = 64500
	config.RouterID = net.ParseIP("10.0.0.1")

	controller := routing.NewBGPController(config, logger)

	// Start controller
	if err := controller.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer controller.Stop()

	// Add neighbor
	neighbor := &routing.BGPNeighbor{
		Address:     net.ParseIP("10.0.0.2"),
		RemoteAS:    64501,
		Description: "Test Peer",
		BFDEnabled:  false,
	}

	if err := controller.AddNeighbor(neighbor); err != nil {
		t.Fatalf("AddNeighbor failed: %v", err)
	}

	// Announce prefix
	_, prefix, _ := net.ParseCIDR("100.64.0.0/22")
	if err := controller.AnnouncePrefix(prefix); err != nil {
		t.Fatalf("AnnouncePrefix failed: %v", err)
	}

	// Get summary
	summary, err := controller.GetSummary()
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	t.Logf("BGP Summary: AS=%d, Neighbors=%d", summary.LocalAS, summary.TotalNeighbors)

	// Withdraw prefix
	if err := controller.WithdrawPrefix(prefix); err != nil {
		t.Fatalf("WithdrawPrefix failed: %v", err)
	}

	// Remove neighbor
	if err := controller.RemoveNeighbor(net.ParseIP("10.0.0.2")); err != nil {
		t.Fatalf("RemoveNeighbor failed: %v", err)
	}
}
