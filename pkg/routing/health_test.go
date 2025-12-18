package routing_test

import (
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/routing"
	"go.uber.org/zap"
)

func TestHealthChecker_AddRemoveTarget(t *testing.T) {
	logger := zap.NewNop()
	checker := routing.NewHealthChecker(1*time.Second, 500*time.Millisecond, logger)

	target := net.ParseIP("8.8.8.8")
	checker.AddTarget("google-dns", target)

	// Check target exists
	ht, exists := checker.GetTarget("google-dns")
	if !exists {
		t.Error("Target should exist")
	}
	if ht.Name != "google-dns" {
		t.Errorf("Target name = %s, want google-dns", ht.Name)
	}
	if !ht.Target.Equal(target) {
		t.Errorf("Target IP = %s, want %s", ht.Target, target)
	}

	// Initial state should be down
	if ht.State {
		t.Error("Initial state should be false (down)")
	}

	// Remove target
	checker.RemoveTarget("google-dns")

	_, exists = checker.GetTarget("google-dns")
	if exists {
		t.Error("Target should not exist after removal")
	}
}

func TestHealthChecker_IsUp(t *testing.T) {
	logger := zap.NewNop()
	checker := routing.NewHealthChecker(1*time.Second, 500*time.Millisecond, logger)

	target := net.ParseIP("192.168.1.1")
	checker.AddTarget("gateway", target)

	// Initially down
	if checker.IsUp("gateway") {
		t.Error("Target should initially be down")
	}

	// Non-existent target
	if checker.IsUp("nonexistent") {
		t.Error("Non-existent target should return false")
	}
}

func TestHealthChecker_GetAllStates(t *testing.T) {
	logger := zap.NewNop()
	checker := routing.NewHealthChecker(1*time.Second, 500*time.Millisecond, logger)

	checker.AddTarget("target1", net.ParseIP("192.168.1.1"))
	checker.AddTarget("target2", net.ParseIP("192.168.1.2"))
	checker.AddTarget("target3", net.ParseIP("192.168.1.3"))

	states := checker.GetAllStates()

	if len(states) != 3 {
		t.Errorf("Expected 3 states, got %d", len(states))
	}

	for name, state := range states {
		if state {
			t.Errorf("Target %s should initially be down", name)
		}
	}
}

func TestHealthChecker_OnStateChange(t *testing.T) {
	logger := zap.NewNop()
	checker := routing.NewHealthChecker(100*time.Millisecond, 50*time.Millisecond, logger)

	stateChanges := make(map[string]bool)
	checker.OnStateChange(func(name string, up bool) {
		stateChanges[name] = up
	})

	// Add target
	checker.AddTarget("test", net.ParseIP("192.168.1.1"))

	// State changes are triggered during CheckAll - we'd need a mock platform
	// to fully test this. This just verifies callback registration works.
	if len(stateChanges) != 0 {
		t.Error("No state changes should have occurred yet")
	}
}

func TestHealthTarget_Fields(t *testing.T) {
	target := &routing.HealthTarget{
		Name:            "test",
		Target:          net.ParseIP("192.168.1.1"),
		State:           true,
		LastCheck:       time.Now(),
		LastSuccess:     time.Now(),
		ConsecutiveFail: 0,
		ConsecutiveOK:   3,
		RTT:             10 * time.Millisecond,
	}

	if target.Name != "test" {
		t.Errorf("Name = %s, want test", target.Name)
	}

	if !target.State {
		t.Error("State should be true")
	}

	if target.RTT != 10*time.Millisecond {
		t.Errorf("RTT = %v, want 10ms", target.RTT)
	}
}

func TestNewHealthChecker(t *testing.T) {
	logger := zap.NewNop()
	interval := 5 * time.Second
	timeout := 2 * time.Second

	checker := routing.NewHealthChecker(interval, timeout, logger)

	if checker == nil {
		t.Fatal("NewHealthChecker returned nil")
	}

	// Verify initial state by checking no targets exist
	states := checker.GetAllStates()
	if len(states) != 0 {
		t.Errorf("Expected 0 initial states, got %d", len(states))
	}
}
