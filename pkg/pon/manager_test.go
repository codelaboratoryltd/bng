package pon_test

import (
	"sync"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/nexus"
	"github.com/codelaboratoryltd/bng/pkg/pon"
	"go.uber.org/zap"
)

func setupTestManager(t *testing.T) (*pon.Manager, *nexus.Client) {
	logger := zap.NewNop()
	store := nexus.NewMemoryStore()

	nexusConfig := nexus.DefaultClientConfig()
	nexusConfig.DeviceID = "test-olt-001"
	nexusClient := nexus.NewClient(nexusConfig, store, logger)

	if err := nexusClient.Start(); err != nil {
		t.Fatalf("Failed to start nexus client: %v", err)
	}

	vlanConfig := nexus.DefaultVLANConfig()
	vlanAlloc := nexus.NewVLANAllocator(vlanConfig)

	config := pon.DefaultManagerConfig()
	config.DeviceID = "test-olt-001"
	config.DefaultISPID = "test-isp"
	config.DiscoveryRetries = 1
	config.DiscoveryRetryDelay = 10 * time.Millisecond

	manager := pon.NewManager(config, nexusClient, vlanAlloc, logger)

	return manager, nexusClient
}

func TestManager_HandleDiscovery(t *testing.T) {
	manager, _ := setupTestManager(t)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Set up result channel
	results := make(chan *pon.ProvisioningResult, 1)
	manager.OnNTEProvisioned(func(result *pon.ProvisioningResult) {
		results <- result
	})

	// Submit discovery event
	event := &pon.DiscoveryEvent{
		SerialNumber: "GPON12345678",
		PONPort:      "pon0/1",
		Timestamp:    time.Now(),
		State:        pon.NTEStateConnected,
	}

	manager.HandleDiscovery(event)

	// Wait for provisioning result
	select {
	case result := <-results:
		if !result.Success {
			t.Errorf("Expected successful provisioning, got error: %v", result.Error)
		}
		if result.NTEID != "GPON12345678" {
			t.Errorf("Expected NTE ID 'GPON12345678', got '%s'", result.NTEID)
		}
		if result.STag != 100 {
			t.Errorf("Expected S-TAG 100, got %d", result.STag)
		}
		if result.CTag != 100 {
			t.Errorf("Expected C-TAG 100, got %d", result.CTag)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for provisioning result")
	}

	// Check NTE state
	state := manager.GetNTEState("GPON12345678")
	if state != pon.NTEStateConnected {
		t.Errorf("Expected state CONNECTED, got %s", state)
	}
}

func TestManager_HandleMultipleDiscoveries(t *testing.T) {
	manager, _ := setupTestManager(t)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Set up result collection
	var mu sync.Mutex
	results := make(map[string]*pon.ProvisioningResult)
	var wg sync.WaitGroup

	wg.Add(3)
	manager.OnNTEProvisioned(func(result *pon.ProvisioningResult) {
		mu.Lock()
		results[result.NTEID] = result
		mu.Unlock()
		wg.Done()
	})

	// Submit multiple discovery events
	serials := []string{"GPON00000001", "GPON00000002", "GPON00000003"}
	for _, serial := range serials {
		event := &pon.DiscoveryEvent{
			SerialNumber: serial,
			PONPort:      "pon0/1",
			Timestamp:    time.Now(),
			State:        pon.NTEStateConnected,
		}
		manager.HandleDiscovery(event)
	}

	// Wait for all results
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for all provisioning results")
	}

	// Verify all NTEs were provisioned
	mu.Lock()
	defer mu.Unlock()

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	for _, serial := range serials {
		result, ok := results[serial]
		if !ok {
			t.Errorf("Missing result for %s", serial)
			continue
		}
		if !result.Success {
			t.Errorf("Provisioning failed for %s: %v", serial, result.Error)
		}
	}

	// Check stats
	stats := manager.Stats()
	if stats.ConnectedNTEs != 3 {
		t.Errorf("Expected 3 connected NTEs, got %d", stats.ConnectedNTEs)
	}
}

func TestManager_HandleDisconnect(t *testing.T) {
	manager, _ := setupTestManager(t)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Set up channels
	provisioned := make(chan *pon.ProvisioningResult, 1)
	disconnected := make(chan string, 1)

	manager.OnNTEProvisioned(func(result *pon.ProvisioningResult) {
		provisioned <- result
	})
	manager.OnNTEDisconnected(func(serial string) {
		disconnected <- serial
	})

	// Discover NTE
	event := &pon.DiscoveryEvent{
		SerialNumber: "GPON-DISC-001",
		PONPort:      "pon0/2",
		Timestamp:    time.Now(),
		State:        pon.NTEStateConnected,
	}
	manager.HandleDiscovery(event)

	// Wait for provisioning
	select {
	case <-provisioned:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for provisioning")
	}

	// Disconnect
	manager.HandleDisconnect("GPON-DISC-001")

	// Wait for disconnect callback
	select {
	case serial := <-disconnected:
		if serial != "GPON-DISC-001" {
			t.Errorf("Expected 'GPON-DISC-001', got '%s'", serial)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for disconnect callback")
	}

	// Check state
	state := manager.GetNTEState("GPON-DISC-001")
	if state != pon.NTEStateDisconnected {
		t.Errorf("Expected state DISCONNECTED, got %s", state)
	}
}

func TestManager_DiscoveryCallback(t *testing.T) {
	manager, _ := setupTestManager(t)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	discovered := make(chan *pon.DiscoveryEvent, 1)
	manager.OnNTEDiscovered(func(event *pon.DiscoveryEvent) {
		discovered <- event
	})

	event := &pon.DiscoveryEvent{
		SerialNumber: "GPON-CB-001",
		PONPort:      "pon0/1",
		Timestamp:    time.Now(),
		State:        pon.NTEStateConnected,
	}
	manager.HandleDiscovery(event)

	select {
	case got := <-discovered:
		if got.SerialNumber != "GPON-CB-001" {
			t.Errorf("Expected 'GPON-CB-001', got '%s'", got.SerialNumber)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for discovery callback")
	}
}

func TestManager_ListMethods(t *testing.T) {
	manager, _ := setupTestManager(t)

	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Wait for provisioning
	done := make(chan struct{})
	count := 0
	var mu sync.Mutex

	manager.OnNTEProvisioned(func(_ *pon.ProvisioningResult) {
		mu.Lock()
		count++
		if count == 2 {
			close(done)
		}
		mu.Unlock()
	})

	// Discover two NTEs
	for _, serial := range []string{"LIST-001", "LIST-002"} {
		manager.HandleDiscovery(&pon.DiscoveryEvent{
			SerialNumber: serial,
			PONPort:      "pon0/1",
			Timestamp:    time.Now(),
			State:        pon.NTEStateConnected,
		})
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out waiting for provisioning")
	}

	// Test ListConnectedNTEs
	connected := manager.ListConnectedNTEs()
	if len(connected) != 2 {
		t.Errorf("Expected 2 connected NTEs, got %d", len(connected))
	}

	// Disconnect one
	manager.HandleDisconnect("LIST-001")

	connected = manager.ListConnectedNTEs()
	if len(connected) != 1 {
		t.Errorf("Expected 1 connected NTE after disconnect, got %d", len(connected))
	}
}

func TestManager_Stats(t *testing.T) {
	manager, _ := setupTestManager(t)

	// Initial stats
	stats := manager.Stats()
	if stats.TotalNTEs != 0 {
		t.Errorf("Expected 0 total NTEs initially, got %d", stats.TotalNTEs)
	}
}

func TestNTEState_String(t *testing.T) {
	tests := []struct {
		state    pon.NTEState
		expected string
	}{
		{pon.NTEStateUnknown, "UNKNOWN"},
		{pon.NTEStateConnected, "CONNECTED"},
		{pon.NTEStateDisconnected, "DISCONNECTED"},
		{pon.NTEStateUnconfigured, "UNCONFIGURED"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("NTEState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}
