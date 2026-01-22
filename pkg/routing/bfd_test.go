package routing_test

import (
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/routing"
	"go.uber.org/zap"
)

func TestBFDState_String(t *testing.T) {
	tests := []struct {
		state    routing.BFDState
		expected string
	}{
		{routing.BFDStateAdminDown, "AdminDown"},
		{routing.BFDStateDown, "Down"},
		{routing.BFDStateInit, "Init"},
		{routing.BFDStateUp, "Up"},
		{routing.BFDState(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("BFDState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

func TestParseBFDState(t *testing.T) {
	tests := []struct {
		input    string
		expected routing.BFDState
	}{
		{"Up", routing.BFDStateUp},
		{"up", routing.BFDStateUp},
		{"Down", routing.BFDStateDown},
		{"down", routing.BFDStateDown},
		{"Init", routing.BFDStateInit},
		{"init", routing.BFDStateInit},
		{"AdminDown", routing.BFDStateAdminDown},
		{"admin down", routing.BFDStateAdminDown},
		{"unknown", routing.BFDStateDown},
	}

	for _, tt := range tests {
		if got := routing.ParseBFDState(tt.input); got != tt.expected {
			t.Errorf("ParseBFDState(%s) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestDefaultBFDConfig(t *testing.T) {
	config := routing.DefaultBFDConfig()

	if config.VtyshPath == "" {
		t.Error("VtyshPath should not be empty")
	}

	if config.DefaultMinRxInterval == 0 {
		t.Error("DefaultMinRxInterval should not be 0")
	}

	if config.DefaultMinTxInterval == 0 {
		t.Error("DefaultMinTxInterval should not be 0")
	}

	if config.DefaultDetectMultiplier == 0 {
		t.Error("DefaultDetectMultiplier should not be 0")
	}

	// Check detection time calculation: 100ms * 3 = 300ms
	detectionTime := config.DefaultMinRxInterval * config.DefaultDetectMultiplier
	if detectionTime != 300 {
		t.Errorf("Detection time = %dms, want 300ms", detectionTime)
	}
}

func TestAggressiveBFDConfig(t *testing.T) {
	config := routing.AggressiveBFDConfig()

	// Check more aggressive timers: 50ms * 3 = 150ms
	detectionTime := config.DefaultMinRxInterval * config.DefaultDetectMultiplier
	if detectionTime != 150 {
		t.Errorf("Detection time = %dms, want 150ms", detectionTime)
	}
}

func TestNewBFDManager(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultBFDConfig()

	manager := routing.NewBFDManager(config, logger)
	if manager == nil {
		t.Fatal("NewBFDManager returned nil")
	}

	// Verify initial state
	peers := manager.ListPeers()
	if len(peers) != 0 {
		t.Errorf("Expected 0 initial peers, got %d", len(peers))
	}
}

func TestBFDManager_Callbacks(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultBFDConfig()

	manager := routing.NewBFDManager(config, logger)

	upCalled := false
	downCalled := false

	manager.OnPeerUp(func(peerIP string) {
		upCalled = true
	})

	manager.OnPeerDown(func(peerIP string) {
		downCalled = true
	})

	// Callbacks are registered but not triggered without FRR
	_ = upCalled
	_ = downCalled
}

func TestBFDManager_Stats(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultBFDConfig()

	manager := routing.NewBFDManager(config, logger)

	stats := manager.Stats()

	if stats.TotalPeers != 0 {
		t.Errorf("Expected 0 peers, got %d", stats.TotalPeers)
	}

	if stats.PeersUp != 0 {
		t.Errorf("Expected 0 up, got %d", stats.PeersUp)
	}
}

func TestBFDPeer_DetectionTime(t *testing.T) {
	peer := &routing.BFDPeer{
		MinRxInterval:    100,
		DetectMultiplier: 3,
	}

	if peer.DetectionTime() != 300 {
		t.Errorf("DetectionTime = %d, want 300", peer.DetectionTime())
	}

	// Aggressive settings
	peer.MinRxInterval = 50
	if peer.DetectionTime() != 150 {
		t.Errorf("DetectionTime = %d, want 150", peer.DetectionTime())
	}
}

func TestBFDPeer_IsHealthy(t *testing.T) {
	peer := &routing.BFDPeer{
		State: routing.BFDStateUp,
	}

	if !peer.IsHealthy() {
		t.Error("Peer should be healthy when Up")
	}

	peer.State = routing.BFDStateDown
	if peer.IsHealthy() {
		t.Error("Peer should not be healthy when Down")
	}
}

func TestBFDPeer_Fields(t *testing.T) {
	peer := &routing.BFDPeer{
		PeerIP:           net.ParseIP("192.168.1.1"),
		LocalIP:          net.ParseIP("192.168.1.2"),
		Interface:        "eth0",
		State:            routing.BFDStateUp,
		MinRxInterval:    100,
		MinTxInterval:    100,
		DetectMultiplier: 3,
		EchoMode:         false,
		Multihop:         false,
		LinkedToBGP:      true,
		Uptime:           10 * time.Minute,
	}

	if !peer.PeerIP.Equal(net.ParseIP("192.168.1.1")) {
		t.Error("PeerIP mismatch")
	}

	if peer.State != routing.BFDStateUp {
		t.Errorf("State = %v, want Up", peer.State)
	}

	if !peer.LinkedToBGP {
		t.Error("LinkedToBGP should be true")
	}

	if peer.DetectionTime() != 300 {
		t.Errorf("DetectionTime = %d, want 300", peer.DetectionTime())
	}
}

func TestBFDManager_GenerateConfig(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultBFDConfig()

	manager := routing.NewBFDManager(config, logger)

	// Generate config (without peers)
	cfg := manager.GenerateConfig()

	if cfg == "" {
		t.Error("Generated config should not be empty")
	}

	// Check for expected content
	if !contains(cfg, "bfd") {
		t.Error("Config should contain 'bfd'")
	}
}

func TestBFDStats_Fields(t *testing.T) {
	stats := routing.BFDStats{
		TotalPeers:      5,
		PeersUp:         3,
		PeersDown:       1,
		PeersInit:       1,
		PeersAdminDown:  0,
		TotalUpEvents:   10,
		TotalDownEvents: 2,
	}

	if stats.TotalPeers != 5 {
		t.Errorf("TotalPeers = %d, want 5", stats.TotalPeers)
	}

	if stats.PeersUp != 3 {
		t.Errorf("PeersUp = %d, want 3", stats.PeersUp)
	}

	if stats.TotalUpEvents != 10 {
		t.Errorf("TotalUpEvents = %d, want 10", stats.TotalUpEvents)
	}
}

// Integration tests - require FRR to be running
func TestBFDManager_Integration(t *testing.T) {
	t.Skip("Skipping integration test - requires FRR")

	logger, _ := zap.NewDevelopment()
	config := routing.DefaultBFDConfig()

	manager := routing.NewBFDManager(config, logger)

	// Start manager
	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	// Add peer
	peerIP := net.ParseIP("192.168.1.1")
	if err := manager.AddPeer(peerIP); err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}

	// Get peer
	peer, found := manager.GetPeer(peerIP)
	if !found {
		t.Fatal("Peer not found")
	}

	t.Logf("BFD Peer: %s, State: %s", peer.PeerIP.String(), peer.State.String())

	// Remove peer
	if err := manager.RemovePeer(peerIP); err != nil {
		t.Fatalf("RemovePeer failed: %v", err)
	}
}
