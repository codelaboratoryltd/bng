package walledgarden_test

import (
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/walledgarden"
	"go.uber.org/zap"
)

func TestSubscriberState_String(t *testing.T) {
	tests := []struct {
		state    walledgarden.SubscriberState
		expected string
	}{
		{walledgarden.StateUnknown, "UNKNOWN"},
		{walledgarden.StateWalledGarden, "WALLED_GARDEN"},
		{walledgarden.StateProvisioned, "PROVISIONED"},
		{walledgarden.StateBlocked, "BLOCKED"},
		{walledgarden.SubscriberState(99), "INVALID"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("SubscriberState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

func TestManager_SetAndGetState(t *testing.T) {
	logger := zap.NewNop()
	config := walledgarden.DefaultConfig()
	manager := walledgarden.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	// Initially unknown
	state := manager.GetSubscriberState(mac)
	if state != walledgarden.StateUnknown {
		t.Errorf("Expected UNKNOWN state initially, got %s", state)
	}

	// Set to walled garden
	err := manager.SetSubscriberState(mac, walledgarden.StateWalledGarden)
	if err != nil {
		t.Fatalf("SetSubscriberState failed: %v", err)
	}

	state = manager.GetSubscriberState(mac)
	if state != walledgarden.StateWalledGarden {
		t.Errorf("Expected WALLED_GARDEN state, got %s", state)
	}

	// Set to provisioned
	err = manager.SetSubscriberState(mac, walledgarden.StateProvisioned)
	if err != nil {
		t.Fatalf("SetSubscriberState failed: %v", err)
	}

	state = manager.GetSubscriberState(mac)
	if state != walledgarden.StateProvisioned {
		t.Errorf("Expected PROVISIONED state, got %s", state)
	}
}

func TestManager_AddToWalledGarden(t *testing.T) {
	logger := zap.NewNop()
	config := walledgarden.DefaultConfig()
	manager := walledgarden.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	mac := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	err := manager.AddToWalledGarden(mac, 100)
	if err != nil {
		t.Fatalf("AddToWalledGarden failed: %v", err)
	}

	state := manager.GetSubscriberState(mac)
	if state != walledgarden.StateWalledGarden {
		t.Errorf("Expected WALLED_GARDEN state, got %s", state)
	}

	// Check it appears in the list
	macs := manager.ListWalledGardenMACs()
	found := false
	for _, m := range macs {
		if m.String() == mac.String() {
			found = true
			break
		}
	}
	if !found {
		t.Error("MAC not found in ListWalledGardenMACs")
	}
}

func TestManager_ReleaseFromWalledGarden(t *testing.T) {
	logger := zap.NewNop()
	config := walledgarden.DefaultConfig()
	manager := walledgarden.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	mac := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	// Add to walled garden
	err := manager.AddToWalledGarden(mac, 200)
	if err != nil {
		t.Fatalf("AddToWalledGarden failed: %v", err)
	}

	// Release
	err = manager.ReleaseFromWalledGarden(mac)
	if err != nil {
		t.Fatalf("ReleaseFromWalledGarden failed: %v", err)
	}

	state := manager.GetSubscriberState(mac)
	if state != walledgarden.StateProvisioned {
		t.Errorf("Expected PROVISIONED state after release, got %s", state)
	}

	// Should not appear in walled garden list
	macs := manager.ListWalledGardenMACs()
	for _, m := range macs {
		if m.String() == mac.String() {
			t.Error("MAC should not be in walled garden list after release")
		}
	}
}

func TestManager_BlockMAC(t *testing.T) {
	logger := zap.NewNop()
	config := walledgarden.DefaultConfig()
	manager := walledgarden.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	mac := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}

	err := manager.BlockMAC(mac)
	if err != nil {
		t.Fatalf("BlockMAC failed: %v", err)
	}

	state := manager.GetSubscriberState(mac)
	if state != walledgarden.StateBlocked {
		t.Errorf("Expected BLOCKED state, got %s", state)
	}
}

func TestManager_RemoveMAC(t *testing.T) {
	logger := zap.NewNop()
	config := walledgarden.DefaultConfig()
	manager := walledgarden.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	mac := net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}

	// Add and then remove
	manager.AddToWalledGarden(mac, 300)
	err := manager.RemoveMAC(mac)
	if err != nil {
		t.Fatalf("RemoveMAC failed: %v", err)
	}

	state := manager.GetSubscriberState(mac)
	if state != walledgarden.StateUnknown {
		t.Errorf("Expected UNKNOWN state after remove, got %s", state)
	}
}

func TestManager_Stats(t *testing.T) {
	logger := zap.NewNop()
	config := walledgarden.DefaultConfig()
	manager := walledgarden.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Add various MACs with different states
	macs := []struct {
		mac   net.HardwareAddr
		state walledgarden.SubscriberState
	}{
		{net.HardwareAddr{0x01, 0x01, 0x01, 0x01, 0x01, 0x01}, walledgarden.StateWalledGarden},
		{net.HardwareAddr{0x02, 0x02, 0x02, 0x02, 0x02, 0x02}, walledgarden.StateWalledGarden},
		{net.HardwareAddr{0x03, 0x03, 0x03, 0x03, 0x03, 0x03}, walledgarden.StateProvisioned},
		{net.HardwareAddr{0x04, 0x04, 0x04, 0x04, 0x04, 0x04}, walledgarden.StateBlocked},
	}

	for _, m := range macs {
		manager.SetSubscriberState(m.mac, m.state)
	}

	stats := manager.Stats()
	if stats.Total != 4 {
		t.Errorf("Expected 4 total, got %d", stats.Total)
	}
	if stats.InWalledGarden != 2 {
		t.Errorf("Expected 2 in walled garden, got %d", stats.InWalledGarden)
	}
	if stats.Provisioned != 1 {
		t.Errorf("Expected 1 provisioned, got %d", stats.Provisioned)
	}
	if stats.Blocked != 1 {
		t.Errorf("Expected 1 blocked, got %d", stats.Blocked)
	}
}

func TestManager_ListWalledGardenMACs(t *testing.T) {
	logger := zap.NewNop()
	config := walledgarden.DefaultConfig()
	manager := walledgarden.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Add some MACs to walled garden
	walledGardenMACs := []net.HardwareAddr{
		{0xAA, 0x00, 0x00, 0x00, 0x00, 0x01},
		{0xAA, 0x00, 0x00, 0x00, 0x00, 0x02},
		{0xAA, 0x00, 0x00, 0x00, 0x00, 0x03},
	}

	for _, mac := range walledGardenMACs {
		manager.AddToWalledGarden(mac, 100)
	}

	// Add one provisioned (shouldn't be in list)
	provisionedMAC := net.HardwareAddr{0xBB, 0x00, 0x00, 0x00, 0x00, 0x01}
	manager.SetSubscriberState(provisionedMAC, walledgarden.StateProvisioned)

	macs := manager.ListWalledGardenMACs()
	if len(macs) != 3 {
		t.Errorf("Expected 3 MACs in walled garden, got %d", len(macs))
	}
}

func TestDefaultConfig(t *testing.T) {
	config := walledgarden.DefaultConfig()

	if config.PortalIP == nil {
		t.Error("PortalIP should not be nil")
	}
	if config.PortalPort == 0 {
		t.Error("PortalPort should not be 0")
	}
	if len(config.AllowedDNS) == 0 {
		t.Error("AllowedDNS should not be empty")
	}
	if config.DefaultTimeout == 0 {
		t.Error("DefaultTimeout should not be 0")
	}
	if config.MaxEntries == 0 {
		t.Error("MaxEntries should not be 0")
	}
}

func TestManager_StartStop(t *testing.T) {
	logger := zap.NewNop()
	config := walledgarden.DefaultConfig()
	manager := walledgarden.NewManager(config, logger)

	// Start
	err := manager.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Allow some time for goroutines to start
	time.Sleep(10 * time.Millisecond)

	// Stop
	err = manager.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}
