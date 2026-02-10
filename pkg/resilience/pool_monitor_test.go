package resilience

import (
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestPoolMonitorLevelCalculation(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()

	monitor := NewPoolMonitor(config, logger)

	tests := []struct {
		utilization float64
		expected    PoolUtilizationLevel
	}{
		{0.0, LevelNormal},
		{0.5, LevelNormal},
		{0.79, LevelNormal},
		{0.80, LevelWarning},
		{0.85, LevelWarning},
		{0.89, LevelWarning},
		{0.90, LevelCritical},
		{0.94, LevelCritical},
		{0.95, LevelExhausted},
		{0.99, LevelExhausted},
		{1.0, LevelExhausted},
	}

	for _, tt := range tests {
		level := monitor.calculateLevel(tt.utilization)
		if level != tt.expected {
			t.Errorf("calculateLevel(%.2f) = %v, want %v", tt.utilization, level, tt.expected)
		}
	}
}

func TestPoolMonitorAlerts(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()

	monitor := NewPoolMonitor(config, logger)

	var mu sync.Mutex
	var receivedAlerts []struct {
		pool  PoolStatus
		level PoolUtilizationLevel
	}

	monitor.OnAlert(func(pool PoolStatus, level PoolUtilizationLevel) {
		mu.Lock()
		receivedAlerts = append(receivedAlerts, struct {
			pool  PoolStatus
			level PoolUtilizationLevel
		}{pool, level})
		mu.Unlock()
	})

	// Create a pool status that should trigger warning
	status := &PoolStatus{
		PoolID:      "pool-1",
		PoolName:    "Test Pool",
		Total:       100,
		Allocated:   85,
		Available:   15,
		Utilization: 0.85,
	}

	monitor.UpdatePoolStatus(status)

	// Wait for async alert
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	alertCount := len(receivedAlerts)
	var firstLevel PoolUtilizationLevel
	if alertCount > 0 {
		firstLevel = receivedAlerts[0].level
	}
	mu.Unlock()

	if alertCount != 1 {
		t.Errorf("Expected 1 alert, got %d", alertCount)
	}

	if alertCount > 0 && firstLevel != LevelWarning {
		t.Errorf("Expected warning level, got %v", firstLevel)
	}
}

func TestPoolMonitorShortLease(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	config.ShortLeaseEnabled = true
	config.ShortLeaseThreshold = 0.90

	monitor := NewPoolMonitor(config, logger)

	// Pool below threshold
	status1 := &PoolStatus{
		PoolID:      "pool-1",
		PoolName:    "Test Pool 1",
		Utilization: 0.85,
	}
	monitor.UpdatePoolStatus(status1)

	if monitor.IsShortLeaseActive("pool-1") {
		t.Error("Short lease should not be active below threshold")
	}

	// Pool above threshold
	status2 := &PoolStatus{
		PoolID:      "pool-2",
		PoolName:    "Test Pool 2",
		Utilization: 0.95,
	}
	monitor.UpdatePoolStatus(status2)

	if !monitor.IsShortLeaseActive("pool-2") {
		t.Error("Short lease should be active above threshold")
	}
}

func TestPoolMonitorAllocationRate(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()

	monitor := NewPoolMonitor(config, logger)

	// Record allocations
	for i := 0; i < 10; i++ {
		monitor.RecordAllocation("pool-1")
	}

	// Rate should be 2/minute (10 allocations in 5 minutes window)
	// But since we recorded them all at once, rate calculation depends on timing
	// Just verify the history is recorded
	monitor.mu.RLock()
	history := monitor.allocationHistory["pool-1"]
	monitor.mu.RUnlock()

	if len(history) != 10 {
		t.Errorf("Expected 10 allocations in history, got %d", len(history))
	}
}

func TestPoolMonitorGetCriticalPools(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()

	monitor := NewPoolMonitor(config, logger)

	// Add normal pool
	monitor.UpdatePoolStatus(&PoolStatus{
		PoolID:      "pool-1",
		PoolName:    "Normal Pool",
		Utilization: 0.50,
	})

	// Add critical pool
	monitor.UpdatePoolStatus(&PoolStatus{
		PoolID:      "pool-2",
		PoolName:    "Critical Pool",
		Utilization: 0.92,
	})

	// Add exhausted pool
	monitor.UpdatePoolStatus(&PoolStatus{
		PoolID:      "pool-3",
		PoolName:    "Exhausted Pool",
		Utilization: 0.98,
	})

	criticalPools := monitor.GetCriticalPools()
	if len(criticalPools) != 2 {
		t.Errorf("Expected 2 critical pools, got %d", len(criticalPools))
	}

	if !monitor.HasExhaustedPools() {
		t.Error("Expected to have exhausted pools")
	}
}
