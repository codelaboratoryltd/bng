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

func TestDefaultHealthConfig(t *testing.T) {
	config := DefaultHealthConfig()

	if config.CheckInterval != 5*time.Second {
		t.Errorf("CheckInterval = %v, want 5s", config.CheckInterval)
	}
	if config.Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want 3s", config.Timeout)
	}
	if config.FailureThreshold != 3 {
		t.Errorf("FailureThreshold = %v, want 3", config.FailureThreshold)
	}
	if config.RecoveryThreshold != 2 {
		t.Errorf("RecoveryThreshold = %v, want 2", config.RecoveryThreshold)
	}
}

func TestHealthMonitor_StartStopNoPartner(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultHealthConfig()

	monitor := NewHealthMonitor(config, nil, logger)

	err := monitor.Start()
	if err == nil {
		t.Error("Expected error when starting without partner info")
		monitor.Stop()
	}
}

func TestHealthMonitor_StartStop(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultHealthConfig()
	config.CheckInterval = 100 * time.Millisecond

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: "127.0.0.1:9999",
	}

	monitor := NewHealthMonitor(config, partner, logger)

	err := monitor.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	monitor.Stop()
}

func TestHealthMonitor_HealthyPartner(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create mock healthy partner
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ha/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"role":    "active",
				"node_id": "partner-node",
				"details": map[string]int{
					"sessions_synced": 100,
				},
			})
		}
	}))
	defer ts.Close()

	config := DefaultHealthConfig()
	config.CheckInterval = 50 * time.Millisecond
	config.FailureThreshold = 3

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(config, partner, logger)

	// Track events
	var events []HealthEvent
	monitor.OnHealthChange(func(event HealthEvent) {
		events = append(events, event)
	})

	err := monitor.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer monitor.Stop()

	// Wait for health checks
	time.Sleep(200 * time.Millisecond)

	// Should be healthy
	health := monitor.Health()
	if !health.Healthy {
		t.Error("Expected partner to be healthy")
	}
	if !monitor.IsPartnerHealthy() {
		t.Error("IsPartnerHealthy() = false, want true")
	}
	if health.PartnerNodeID != "partner-node" {
		t.Errorf("PartnerNodeID = %v, want partner-node", health.PartnerNodeID)
	}
	if health.PartnerRole != RoleActive {
		t.Errorf("PartnerRole = %v, want active", health.PartnerRole)
	}
	if health.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %v, want 0", health.ConsecutiveFailures)
	}

	// Check stats
	totalChecks, totalFailures, _ := monitor.Stats()
	if totalChecks == 0 {
		t.Error("Expected some health checks to have been performed")
	}
	if totalFailures != 0 {
		t.Errorf("totalFailures = %v, want 0", totalFailures)
	}
}

func TestHealthMonitor_UnhealthyPartner(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create mock that returns errors
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	config := DefaultHealthConfig()
	config.CheckInterval = 30 * time.Millisecond
	config.FailureThreshold = 2

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(config, partner, logger)

	// Track partner down event
	var partnerDownReceived int32
	monitor.OnHealthChange(func(event HealthEvent) {
		if event.Type == HealthEventPartnerDown {
			atomic.AddInt32(&partnerDownReceived, 1)
		}
	})

	err := monitor.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer monitor.Stop()

	// Wait for failures to accumulate
	time.Sleep(200 * time.Millisecond)

	// Should be unhealthy
	if monitor.IsPartnerHealthy() {
		t.Error("Expected partner to be unhealthy")
	}

	health := monitor.Health()
	if health.Healthy {
		t.Error("Health.Healthy = true, want false")
	}
	if health.ConsecutiveFailures < config.FailureThreshold {
		t.Errorf("ConsecutiveFailures = %v, want >= %v", health.ConsecutiveFailures, config.FailureThreshold)
	}
	if health.LastError == "" {
		t.Error("LastError should be set")
	}

	// Should have received partner down event
	if atomic.LoadInt32(&partnerDownReceived) == 0 {
		t.Error("Expected to receive HealthEventPartnerDown")
	}

	// Check stats
	_, totalFailures, _ := monitor.Stats()
	if totalFailures == 0 {
		t.Error("Expected failure count to be > 0")
	}
}

func TestHealthMonitor_PartnerRecovery(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Start unhealthy, then become healthy
	var healthy int32 = 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ha/health" {
			if atomic.LoadInt32(&healthy) == 0 {
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			} else {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  "healthy",
					"role":    "standby",
					"node_id": "partner-node",
				})
			}
		}
	}))
	defer ts.Close()

	config := DefaultHealthConfig()
	config.CheckInterval = 30 * time.Millisecond
	config.FailureThreshold = 2
	config.RecoveryThreshold = 2

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(config, partner, logger)

	var partnerDownReceived, partnerUpReceived int32
	monitor.OnHealthChange(func(event HealthEvent) {
		switch event.Type {
		case HealthEventPartnerDown:
			atomic.AddInt32(&partnerDownReceived, 1)
		case HealthEventPartnerUp:
			atomic.AddInt32(&partnerUpReceived, 1)
		}
	})

	err := monitor.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer monitor.Stop()

	// Wait for failures
	time.Sleep(150 * time.Millisecond)

	if monitor.IsPartnerHealthy() {
		t.Error("Partner should be unhealthy initially")
	}

	// Switch to healthy
	atomic.StoreInt32(&healthy, 1)

	// Wait for recovery
	time.Sleep(200 * time.Millisecond)

	if !monitor.IsPartnerHealthy() {
		t.Error("Partner should have recovered")
	}

	// Check recovery event was received
	if atomic.LoadInt32(&partnerDownReceived) == 0 {
		t.Error("Expected to receive HealthEventPartnerDown")
	}
	if atomic.LoadInt32(&partnerUpReceived) == 0 {
		t.Error("Expected to receive HealthEventPartnerUp")
	}

	// Check stats
	_, _, totalRecovery := monitor.Stats()
	if totalRecovery == 0 {
		t.Error("Expected recovery count to be > 0")
	}
}

func TestHealthMonitor_CheckNow(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"role":    "active",
			"node_id": "partner-node",
		})
	}))
	defer ts.Close()

	config := DefaultHealthConfig()
	config.CheckInterval = time.Hour // Don't auto-check

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(config, partner, logger)

	// Manual check before starting
	err := monitor.CheckNow()
	if err != nil {
		t.Errorf("CheckNow() error = %v", err)
	}

	if !monitor.IsPartnerHealthy() {
		t.Error("Partner should be healthy after CheckNow")
	}
}

func TestHealthMonitor_SetPartner(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultHealthConfig()

	partner1 := &PartnerInfo{
		NodeID:   "partner-1",
		Endpoint: "127.0.0.1:9001",
	}
	partner2 := &PartnerInfo{
		NodeID:   "partner-2",
		Endpoint: "127.0.0.1:9002",
	}

	monitor := NewHealthMonitor(config, partner1, logger)

	// Simulate some state
	monitor.mu.Lock()
	monitor.health.ConsecutiveFailures = 5
	monitor.health.Healthy = false
	monitor.mu.Unlock()

	// Change partner
	monitor.SetPartner(partner2)

	// Health should be reset
	health := monitor.Health()
	if health.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %v, want 0 after SetPartner", health.ConsecutiveFailures)
	}
	if !health.Healthy {
		t.Error("Healthy should be true after SetPartner")
	}
}

func TestHealthMonitor_ResponseTime(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // Add delay
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"role":    "active",
			"node_id": "partner-node",
		})
	}))
	defer ts.Close()

	config := DefaultHealthConfig()
	config.Timeout = 5 * time.Second

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(config, partner, logger)

	err := monitor.CheckNow()
	if err != nil {
		t.Fatalf("CheckNow() error = %v", err)
	}

	health := monitor.Health()
	if health.ResponseTime < 50*time.Millisecond {
		t.Errorf("ResponseTime = %v, expected >= 50ms", health.ResponseTime)
	}
}

func TestHealthMonitor_InvalidResponse(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	config := DefaultHealthConfig()

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(config, partner, logger)

	err := monitor.CheckNow()
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}

	health := monitor.Health()
	if health.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %v, want 1", health.ConsecutiveFailures)
	}
}

func TestHealthMonitor_UnhealthyStatusResponse(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "unhealthy",
			"role":    "active",
			"node_id": "partner-node",
		})
	}))
	defer ts.Close()

	config := DefaultHealthConfig()

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(config, partner, logger)

	err := monitor.CheckNow()
	if err == nil {
		t.Error("Expected error when partner reports unhealthy")
	}

	health := monitor.Health()
	if health.LastError == "" {
		t.Error("LastError should contain unhealthy message")
	}
}

func TestHealthMonitor_MultipleHandlers(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count <= 3 {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"role":    "active",
				"node_id": "partner-node",
			})
		}
	}))
	defer ts.Close()

	config := DefaultHealthConfig()
	config.CheckInterval = 20 * time.Millisecond
	config.FailureThreshold = 2
	config.RecoveryThreshold = 2

	partner := &PartnerInfo{
		NodeID:   "partner-node",
		Endpoint: ts.Listener.Addr().String(),
	}

	monitor := NewHealthMonitor(config, partner, logger)

	// Register multiple handlers
	var handler1Count, handler2Count int32
	monitor.OnHealthChange(func(event HealthEvent) {
		atomic.AddInt32(&handler1Count, 1)
	})
	monitor.OnHealthChange(func(event HealthEvent) {
		atomic.AddInt32(&handler2Count, 1)
	})

	err := monitor.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer monitor.Stop()

	// Wait for events
	time.Sleep(300 * time.Millisecond)

	// Both handlers should have been called
	if atomic.LoadInt32(&handler1Count) == 0 {
		t.Error("Handler 1 was not called")
	}
	if atomic.LoadInt32(&handler2Count) == 0 {
		t.Error("Handler 2 was not called")
	}
	if atomic.LoadInt32(&handler1Count) != atomic.LoadInt32(&handler2Count) {
		t.Error("Both handlers should receive same number of events")
	}
}
