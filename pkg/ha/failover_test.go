package ha

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestDefaultFailoverConfig(t *testing.T) {
	config := DefaultFailoverConfig()

	if !config.Enabled {
		t.Error("Enabled = false, want true")
	}
	if config.FailoverDelay != 10*time.Second {
		t.Errorf("FailoverDelay = %v, want 10s", config.FailoverDelay)
	}
	if config.FailbackDelay != 30*time.Second {
		t.Errorf("FailbackDelay = %v, want 30s", config.FailbackDelay)
	}
	if !config.FailbackEnabled {
		t.Error("FailbackEnabled = false, want true")
	}
	if config.PreemptEnabled {
		t.Error("PreemptEnabled = true, want false")
	}
	if config.GracePeriod != 5*time.Second {
		t.Errorf("GracePeriod = %v, want 5s", config.GracePeriod)
	}
}

func TestFailoverState_String(t *testing.T) {
	tests := []struct {
		state FailoverState
		want  string
	}{
		{FailoverStateNormal, "normal"},
		{FailoverStatePending, "pending"},
		{FailoverStateInProgress, "in_progress"},
		{FailoverStateComplete, "complete"},
		{FailoverStateFailbackPending, "failback_pending"},
		{FailoverState(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("FailoverState(%d).String() = %v, want %v", tt.state, got, tt.want)
		}
	}
}

func createTestHealthMonitor(t *testing.T, healthy bool) (*HealthMonitor, *httptest.Server) {
	logger, _ := zap.NewDevelopment()

	var isHealthy int32
	if healthy {
		isHealthy = 1
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&isHealthy) == 1 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"role":    "active",
				"node_id": "partner-node",
			})
		} else {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		}
	}))

	config := DefaultHealthConfig()
	config.CheckInterval = 20 * time.Millisecond
	config.FailureThreshold = 2
	config.RecoveryThreshold = 2

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(config, partner, logger)

	return monitor, ts
}

func TestFailoverController_StartStop(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	monitor, ts := createTestHealthMonitor(t, true)
	defer ts.Close()

	if err := monitor.Start(); err != nil {
		t.Fatalf("Health monitor start error: %v", err)
	}
	defer monitor.Stop()

	config := DefaultFailoverConfig()
	config.FailoverDelay = 50 * time.Millisecond

	controller := NewFailoverController(config, "node-1", RoleStandby, 1, monitor, logger)

	err := controller.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Let it run
	time.Sleep(50 * time.Millisecond)

	controller.Stop()
}

func TestFailoverController_DisabledFailover(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	monitor, ts := createTestHealthMonitor(t, false)
	defer ts.Close()

	config := DefaultFailoverConfig()
	config.Enabled = false

	controller := NewFailoverController(config, "node-1", RoleStandby, 1, monitor, logger)

	err := controller.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer controller.Stop()

	// Should not failover even if partner is down
	time.Sleep(100 * time.Millisecond)

	if controller.CurrentRole() != RoleStandby {
		t.Error("Role should remain standby when failover is disabled")
	}
}

func TestFailoverController_CurrentRole(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	monitor, ts := createTestHealthMonitor(t, true)
	defer ts.Close()

	config := DefaultFailoverConfig()

	controller := NewFailoverController(config, "node-1", RoleStandby, 1, monitor, logger)

	if controller.CurrentRole() != RoleStandby {
		t.Errorf("CurrentRole() = %v, want standby", controller.CurrentRole())
	}
	if controller.OriginalRole() != RoleStandby {
		t.Errorf("OriginalRole() = %v, want standby", controller.OriginalRole())
	}
}

func TestFailoverController_State(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	monitor, ts := createTestHealthMonitor(t, true)
	defer ts.Close()

	config := DefaultFailoverConfig()

	controller := NewFailoverController(config, "node-1", RoleStandby, 1, monitor, logger)

	if controller.State() != FailoverStateNormal {
		t.Errorf("State() = %v, want normal", controller.State())
	}
	if controller.IsFailedOver() {
		t.Error("IsFailedOver() = true, want false")
	}
}

func TestFailoverController_Stats(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	monitor, ts := createTestHealthMonitor(t, true)
	defer ts.Close()

	config := DefaultFailoverConfig()

	controller := NewFailoverController(config, "node-1", RoleStandby, 1, monitor, logger)

	initiated, completed, canceled, failbacks := controller.Stats()
	if initiated != 0 || completed != 0 || canceled != 0 || failbacks != 0 {
		t.Error("Initial stats should all be 0")
	}
}

func TestFailoverController_ForceFailoverAlreadyActive(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	monitor, ts := createTestHealthMonitor(t, true)
	defer ts.Close()

	config := DefaultFailoverConfig()

	// Start as active
	controller := NewFailoverController(config, "node-1", RoleActive, 1, monitor, logger)

	err := controller.ForceFailover("test")
	if err == nil {
		t.Error("Expected error when forcing failover on active node")
	}
}

func TestFailoverController_ForceFailbackAtOriginalRole(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	monitor, ts := createTestHealthMonitor(t, true)
	defer ts.Close()

	config := DefaultFailoverConfig()

	controller := NewFailoverController(config, "node-1", RoleStandby, 1, monitor, logger)

	err := controller.ForceFailback("test")
	if err == nil {
		t.Error("Expected error when forcing failback when already at original role")
	}
}

func TestFailoverController_Status(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	monitor, ts := createTestHealthMonitor(t, true)
	defer ts.Close()

	if err := monitor.Start(); err != nil {
		t.Fatalf("Health monitor start error: %v", err)
	}
	defer monitor.Stop()

	// Wait for health check
	time.Sleep(100 * time.Millisecond)

	config := DefaultFailoverConfig()

	controller := NewFailoverController(config, "node-1", RoleStandby, 5, monitor, logger)

	status := controller.Status()

	if status.NodeID != "node-1" {
		t.Errorf("NodeID = %v, want node-1", status.NodeID)
	}
	if status.OriginalRole != RoleStandby {
		t.Errorf("OriginalRole = %v, want standby", status.OriginalRole)
	}
	if status.CurrentRole != RoleStandby {
		t.Errorf("CurrentRole = %v, want standby", status.CurrentRole)
	}
	if status.State != FailoverStateNormal {
		t.Errorf("State = %v, want normal", status.State)
	}
	if status.IsFailedOver {
		t.Error("IsFailedOver = true, want false")
	}
	if !status.PartnerHealthy {
		t.Error("PartnerHealthy = false, want true")
	}
	if status.Priority != 5 {
		t.Errorf("Priority = %v, want 5", status.Priority)
	}
}

func TestFailoverController_AutomaticFailover(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create partner that will go down
	var healthy int32 = 1
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"role":    "active",
				"node_id": "partner-node",
			})
		} else {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer ts.Close()

	healthConfig := DefaultHealthConfig()
	healthConfig.CheckInterval = 20 * time.Millisecond
	healthConfig.FailureThreshold = 2

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(healthConfig, partner, logger)
	if err := monitor.Start(); err != nil {
		t.Fatalf("Health monitor start error: %v", err)
	}
	defer monitor.Stop()

	// Wait for initial healthy state
	time.Sleep(100 * time.Millisecond)

	failoverConfig := DefaultFailoverConfig()
	failoverConfig.FailoverDelay = 50 * time.Millisecond
	failoverConfig.GracePeriod = 10 * time.Millisecond

	controller := NewFailoverController(failoverConfig, "node-1", RoleStandby, 1, monitor, logger)

	// Track role change
	var roleChanged int32
	var newRole Role
	controller.SetRoleChangeCallback(func(role Role) error {
		atomic.StoreInt32(&roleChanged, 1)
		newRole = role
		return nil
	})

	// Track events
	var failoverInitiated, failoverCompleted int32
	controller.OnFailoverEvent(func(event FailoverEvent) {
		switch event.Type {
		case FailoverEventInitiated:
			atomic.StoreInt32(&failoverInitiated, 1)
		case FailoverEventCompleted:
			atomic.StoreInt32(&failoverCompleted, 1)
		}
	})

	if err := controller.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer controller.Stop()

	// Partner goes down
	atomic.StoreInt32(&healthy, 0)

	// Wait for failover
	time.Sleep(500 * time.Millisecond)

	// Verify failover occurred
	if controller.CurrentRole() != RoleActive {
		t.Errorf("CurrentRole() = %v, want active", controller.CurrentRole())
	}
	if !controller.IsFailedOver() {
		t.Error("IsFailedOver() = false, want true")
	}
	if controller.State() != FailoverStateComplete {
		t.Errorf("State() = %v, want complete", controller.State())
	}
	if atomic.LoadInt32(&roleChanged) != 1 {
		t.Error("Role change callback was not called")
	}
	if newRole != RoleActive {
		t.Errorf("New role = %v, want active", newRole)
	}

	// Check stats
	initiated, completed, _, _ := controller.Stats()
	if initiated == 0 {
		t.Error("Expected failovers initiated > 0")
	}
	if completed == 0 {
		t.Error("Expected failovers completed > 0")
	}
}

func TestFailoverController_CanceledFailover(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create partner that goes down then recovers
	var healthy int32 = 1
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"role":    "active",
				"node_id": "partner-node",
			})
		} else {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer ts.Close()

	healthConfig := DefaultHealthConfig()
	healthConfig.CheckInterval = 20 * time.Millisecond
	healthConfig.FailureThreshold = 2
	healthConfig.RecoveryThreshold = 2

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(healthConfig, partner, logger)
	if err := monitor.Start(); err != nil {
		t.Fatalf("Health monitor start error: %v", err)
	}
	defer monitor.Stop()

	// Wait for initial healthy state
	time.Sleep(100 * time.Millisecond)

	failoverConfig := DefaultFailoverConfig()
	failoverConfig.FailoverDelay = 200 * time.Millisecond // Long delay
	failoverConfig.GracePeriod = 10 * time.Millisecond

	controller := NewFailoverController(failoverConfig, "node-1", RoleStandby, 1, monitor, logger)

	// Track events
	var failoverCanceled int32
	controller.OnFailoverEvent(func(event FailoverEvent) {
		if event.Type == FailoverEventCanceled {
			atomic.StoreInt32(&failoverCanceled, 1)
		}
	})

	if err := controller.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer controller.Stop()

	// Partner goes down
	atomic.StoreInt32(&healthy, 0)

	// Wait for pending state
	time.Sleep(100 * time.Millisecond)

	if controller.State() != FailoverStatePending {
		t.Errorf("State() = %v, want pending", controller.State())
	}

	// Partner recovers before failover completes
	atomic.StoreInt32(&healthy, 1)

	// Wait for recovery
	time.Sleep(150 * time.Millisecond)

	// Failover should have been canceled
	if controller.State() != FailoverStateNormal {
		t.Errorf("State() = %v, want normal (canceled)", controller.State())
	}
	if controller.CurrentRole() != RoleStandby {
		t.Errorf("CurrentRole() = %v, want standby", controller.CurrentRole())
	}
	if atomic.LoadInt32(&failoverCanceled) != 1 {
		t.Error("Expected FailoverEventCanceled")
	}

	// Check canceled stat
	_, _, canceled, _ := controller.Stats()
	if canceled == 0 {
		t.Error("Expected canceled count > 0")
	}
}

func TestFailoverController_AutomaticFailback(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Partner starts healthy, goes down, then recovers
	var healthy int32 = 1
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"role":    "active",
				"node_id": "partner-node",
			})
		} else {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer ts.Close()

	healthConfig := DefaultHealthConfig()
	healthConfig.CheckInterval = 20 * time.Millisecond
	healthConfig.FailureThreshold = 2
	healthConfig.RecoveryThreshold = 2

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(healthConfig, partner, logger)
	if err := monitor.Start(); err != nil {
		t.Fatalf("Health monitor start error: %v", err)
	}
	defer monitor.Stop()

	// Wait for initial healthy state
	time.Sleep(100 * time.Millisecond)

	failoverConfig := DefaultFailoverConfig()
	failoverConfig.FailoverDelay = 50 * time.Millisecond
	failoverConfig.FailbackDelay = 50 * time.Millisecond
	failoverConfig.FailbackEnabled = true
	failoverConfig.GracePeriod = 10 * time.Millisecond

	controller := NewFailoverController(failoverConfig, "node-1", RoleStandby, 1, monitor, logger)

	controller.SetRoleChangeCallback(func(role Role) error {
		return nil
	})

	// Track failback event
	var failbackCompleted int32
	controller.OnFailoverEvent(func(event FailoverEvent) {
		if event.Type == FailoverEventFailbackCompleted {
			atomic.StoreInt32(&failbackCompleted, 1)
		}
	})

	if err := controller.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer controller.Stop()

	// Partner goes down
	atomic.StoreInt32(&healthy, 0)

	// Wait for failover to complete
	time.Sleep(300 * time.Millisecond)

	if controller.CurrentRole() != RoleActive {
		t.Fatalf("Expected to be active after failover, got %v", controller.CurrentRole())
	}

	// Partner recovers
	atomic.StoreInt32(&healthy, 1)

	// Wait for failback
	time.Sleep(400 * time.Millisecond)

	// Should have failed back to standby
	if controller.CurrentRole() != RoleStandby {
		t.Errorf("CurrentRole() = %v, want standby after failback", controller.CurrentRole())
	}
	if controller.IsFailedOver() {
		t.Error("IsFailedOver() = true, want false after failback")
	}
	if atomic.LoadInt32(&failbackCompleted) != 1 {
		t.Error("Expected FailoverEventFailbackCompleted")
	}

	// Check stats
	_, _, _, failbacks := controller.Stats()
	if failbacks == 0 {
		t.Error("Expected failbacks count > 0")
	}
}

func TestFailoverController_FailbackDisabled(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	var healthy int32 = 1
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"role":    "active",
				"node_id": "partner-node",
			})
		} else {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer ts.Close()

	healthConfig := DefaultHealthConfig()
	healthConfig.CheckInterval = 20 * time.Millisecond
	healthConfig.FailureThreshold = 2
	healthConfig.RecoveryThreshold = 2

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(healthConfig, partner, logger)
	if err := monitor.Start(); err != nil {
		t.Fatalf("Health monitor start error: %v", err)
	}
	defer monitor.Stop()

	time.Sleep(100 * time.Millisecond)

	failoverConfig := DefaultFailoverConfig()
	failoverConfig.FailoverDelay = 50 * time.Millisecond
	failoverConfig.FailbackEnabled = false // Disabled
	failoverConfig.GracePeriod = 10 * time.Millisecond

	controller := NewFailoverController(failoverConfig, "node-1", RoleStandby, 1, monitor, logger)
	controller.SetRoleChangeCallback(func(role Role) error { return nil })

	if err := controller.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer controller.Stop()

	// Partner goes down, then recovers
	atomic.StoreInt32(&healthy, 0)
	time.Sleep(200 * time.Millisecond)

	atomic.StoreInt32(&healthy, 1)
	time.Sleep(200 * time.Millisecond)

	// Should remain active (no failback)
	if controller.CurrentRole() != RoleActive {
		t.Errorf("CurrentRole() = %v, want active (no failback)", controller.CurrentRole())
	}
}

func TestFailoverController_MultipleHandlers(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	monitor, ts := createTestHealthMonitor(t, true)
	defer ts.Close()

	config := DefaultFailoverConfig()

	controller := NewFailoverController(config, "node-1", RoleStandby, 1, monitor, logger)

	var handler1Called, handler2Called int32
	controller.OnFailoverEvent(func(event FailoverEvent) {
		atomic.AddInt32(&handler1Called, 1)
	})
	controller.OnFailoverEvent(func(event FailoverEvent) {
		atomic.AddInt32(&handler2Called, 1)
	})

	// Trigger an event by calling initiateFailover
	controller.initiateFailover("test")

	// Both handlers should be called
	time.Sleep(50 * time.Millisecond)

	if atomic.LoadInt32(&handler1Called) == 0 {
		t.Error("Handler 1 was not called")
	}
	if atomic.LoadInt32(&handler2Called) == 0 {
		t.Error("Handler 2 was not called")
	}
}
