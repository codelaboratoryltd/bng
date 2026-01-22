package resilience

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

// mockHealthChecker is a mock implementation of HealthChecker.
type mockHealthChecker struct {
	nexusError  error
	radiusError error
}

func (m *mockHealthChecker) CheckNexus(ctx context.Context) error {
	return m.nexusError
}

func (m *mockHealthChecker) CheckRADIUS(ctx context.Context) error {
	return m.radiusError
}

func TestManagerState(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	config.HealthCheckInterval = 100 * time.Millisecond
	config.HealthCheckRetries = 2

	healthChecker := &mockHealthChecker{}

	manager := NewManager(config, "test-site", healthChecker, logger)

	// Initial state should be online
	if manager.State() != StateOnline {
		t.Errorf("Expected initial state to be online, got %v", manager.State())
	}

	// Not partitioned initially
	if manager.IsPartitioned() {
		t.Error("Expected not to be partitioned initially")
	}

	// Partition duration should be 0
	if manager.PartitionDuration() != 0 {
		t.Errorf("Expected partition duration to be 0, got %v", manager.PartitionDuration())
	}
}

func TestManagerPartitionTransition(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	config.HealthCheckInterval = 50 * time.Millisecond
	config.HealthCheckRetries = 2

	healthChecker := &mockHealthChecker{
		nexusError: context.DeadlineExceeded,
	}

	manager := NewManager(config, "test-site", healthChecker, logger)

	// Track state changes
	var stateChanges []PartitionEvent
	manager.OnPartitionChange(func(event PartitionEvent) {
		stateChanges = append(stateChanges, event)
	})

	// Start manager
	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Wait for partition detection
	time.Sleep(300 * time.Millisecond)

	// Should be partitioned now
	if manager.State() != StatePartitioned {
		t.Errorf("Expected state to be partitioned, got %v", manager.State())
	}

	if !manager.IsPartitioned() {
		t.Error("Expected to be partitioned")
	}

	if len(stateChanges) == 0 {
		t.Error("Expected at least one state change event")
	}

	// Verify partition duration is non-zero
	if manager.PartitionDuration() == 0 {
		t.Error("Expected non-zero partition duration")
	}

	// Clear errors to simulate recovery
	healthChecker.nexusError = nil

	// Wait for recovery
	time.Sleep(200 * time.Millisecond)

	// Should transition through recovering to online
	if manager.State() == StatePartitioned {
		t.Error("Expected to have recovered from partition")
	}
}

func TestManagerStats(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	healthChecker := &mockHealthChecker{}

	manager := NewManager(config, "test-site", healthChecker, logger)

	stats := manager.Stats()

	if stats.CurrentState != StateOnline {
		t.Errorf("Expected current state to be online, got %v", stats.CurrentState)
	}

	if stats.TotalPartitions != 0 {
		t.Errorf("Expected 0 total partitions, got %d", stats.TotalPartitions)
	}
}

func TestManagerShortLease(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	config.ShortLeaseEnabled = true
	config.ShortLeaseThreshold = 0.9
	config.ShortLeaseDuration = 5 * time.Minute

	healthChecker := &mockHealthChecker{
		nexusError: context.DeadlineExceeded,
	}

	manager := NewManager(config, "test-site", healthChecker, logger)

	// When not partitioned, should not use short lease
	if manager.ShouldUseShortLease("pool-1") {
		t.Error("Should not use short lease when not partitioned")
	}

	// Verify short lease duration
	if manager.GetShortLeaseDuration() != 5*time.Minute {
		t.Errorf("Expected 5 minute short lease duration, got %v", manager.GetShortLeaseDuration())
	}
}

func TestManagerRADIUSMode(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	config.RADIUSPartitionMode = RADIUSModeCached

	healthChecker := &mockHealthChecker{}

	manager := NewManager(config, "test-site", healthChecker, logger)

	if manager.GetRADIUSPartitionMode() != RADIUSModeCached {
		t.Errorf("Expected RADIUS mode to be cached, got %v", manager.GetRADIUSPartitionMode())
	}
}
