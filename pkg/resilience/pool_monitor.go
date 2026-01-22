package resilience

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// PoolInfoProvider provides pool information for monitoring.
type PoolInfoProvider interface {
	// GetPoolStatus returns the current status of a pool.
	GetPoolStatus(poolID string) (*PoolStatus, error)
	// ListPools returns all pool IDs.
	ListPools() []string
}

// PoolMonitor monitors IP pool utilization and triggers alerts.
type PoolMonitor struct {
	config   PartitionConfig
	logger   *zap.Logger
	provider PoolInfoProvider

	mu            sync.RWMutex
	poolStates    map[string]*poolState
	alertHandlers []PoolAlertHandler

	// Allocation tracking for rate calculation
	allocationHistory map[string][]time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// poolState tracks the state of a pool.
type poolState struct {
	LastStatus *PoolStatus
	LastLevel  PoolUtilizationLevel
	LastCheck  time.Time
	AlertSent  map[PoolUtilizationLevel]time.Time
	ShortLease bool
}

// NewPoolMonitor creates a new pool monitor.
func NewPoolMonitor(config PartitionConfig, logger *zap.Logger) *PoolMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	return &PoolMonitor{
		config:            config,
		logger:            logger,
		poolStates:        make(map[string]*poolState),
		allocationHistory: make(map[string][]time.Time),
		ctx:               ctx,
		cancel:            cancel,
	}
}

// SetProvider sets the pool info provider.
func (m *PoolMonitor) SetProvider(provider PoolInfoProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.provider = provider
}

// Start begins pool monitoring.
func (m *PoolMonitor) Start() error {
	m.logger.Info("Starting pool monitor")

	m.wg.Add(1)
	go m.monitorLoop()

	return nil
}

// Stop shuts down the pool monitor.
func (m *PoolMonitor) Stop() {
	m.logger.Info("Stopping pool monitor")
	m.cancel()
	m.wg.Wait()
}

// OnAlert registers an alert handler.
func (m *PoolMonitor) OnAlert(handler PoolAlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertHandlers = append(m.alertHandlers, handler)
}

// GetUtilization returns the current utilization for a pool.
func (m *PoolMonitor) GetUtilization(poolID string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, ok := m.poolStates[poolID]; ok && state.LastStatus != nil {
		return state.LastStatus.Utilization
	}
	return 0
}

// GetPoolStatus returns the current status for a pool.
func (m *PoolMonitor) GetPoolStatus(poolID string) *PoolStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, ok := m.poolStates[poolID]; ok {
		return state.LastStatus
	}
	return nil
}

// GetAllPoolStatuses returns status for all pools.
func (m *PoolMonitor) GetAllPoolStatuses() []*PoolStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	statuses := make([]*PoolStatus, 0, len(m.poolStates))
	for _, state := range m.poolStates {
		if state.LastStatus != nil {
			statuses = append(statuses, state.LastStatus)
		}
	}
	return statuses
}

// IsShortLeaseActive returns whether short lease mode is active for a pool.
func (m *PoolMonitor) IsShortLeaseActive(poolID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, ok := m.poolStates[poolID]; ok {
		return state.ShortLease
	}
	return false
}

// RecordAllocation records an IP allocation for rate tracking.
func (m *PoolMonitor) RecordAllocation(poolID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.allocationHistory[poolID] = append(m.allocationHistory[poolID], now)

	// Keep only last 10 minutes of history
	cutoff := now.Add(-10 * time.Minute)
	filtered := make([]time.Time, 0)
	for _, t := range m.allocationHistory[poolID] {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	m.allocationHistory[poolID] = filtered
}

// monitorLoop periodically checks pool utilization.
func (m *PoolMonitor) monitorLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkPools()
		}
	}
}

// checkPools checks all pools for utilization thresholds.
func (m *PoolMonitor) checkPools() {
	m.mu.RLock()
	provider := m.provider
	m.mu.RUnlock()

	if provider == nil {
		return
	}

	poolIDs := provider.ListPools()

	for _, poolID := range poolIDs {
		status, err := provider.GetPoolStatus(poolID)
		if err != nil {
			m.logger.Warn("Failed to get pool status",
				zap.String("pool_id", poolID),
				zap.Error(err),
			)
			continue
		}

		m.processPoolStatus(poolID, status)
	}
}

// processPoolStatus processes a pool status update.
func (m *PoolMonitor) processPoolStatus(poolID string, status *PoolStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get or create pool state
	state, ok := m.poolStates[poolID]
	if !ok {
		state = &poolState{
			AlertSent: make(map[PoolUtilizationLevel]time.Time),
		}
		m.poolStates[poolID] = state
	}

	// Calculate allocation rate
	rate := m.calculateAllocationRate(poolID)
	status.AllocationRate = rate

	// Estimate time to exhaustion
	if rate > 0 && status.Available > 0 {
		minutesToExhaustion := float64(status.Available) / rate
		status.EstimatedTTL = time.Duration(minutesToExhaustion) * time.Minute
	}

	// Determine utilization level
	level := m.calculateLevel(status.Utilization)
	status.Level = level

	// Determine if short lease should be active
	shouldShortLease := m.config.ShortLeaseEnabled && status.Utilization >= m.config.ShortLeaseThreshold
	if shouldShortLease != state.ShortLease {
		state.ShortLease = shouldShortLease
		m.logger.Info("Short lease mode changed",
			zap.String("pool_id", poolID),
			zap.Bool("active", shouldShortLease),
			zap.Float64("utilization", status.Utilization),
		)
	}
	status.ShortLeaseActive = state.ShortLease

	// Update state
	state.LastStatus = status
	state.LastCheck = time.Now()

	// Check if we need to send an alert
	if level > LevelNormal && level > state.LastLevel {
		// Level increased, send alert
		m.sendAlert(status, level)
		state.AlertSent[level] = time.Now()
	} else if level < state.LastLevel {
		// Level decreased, log recovery
		m.logger.Info("Pool utilization recovered",
			zap.String("pool_id", poolID),
			zap.String("old_level", state.LastLevel.String()),
			zap.String("new_level", level.String()),
			zap.Float64("utilization", status.Utilization),
		)
	}

	state.LastLevel = level
}

// calculateLevel determines the utilization level from the ratio.
func (m *PoolMonitor) calculateLevel(utilization float64) PoolUtilizationLevel {
	switch {
	case utilization >= m.config.PoolExhaustedThreshold:
		return LevelExhausted
	case utilization >= m.config.PoolCriticalThreshold:
		return LevelCritical
	case utilization >= m.config.PoolWarningThreshold:
		return LevelWarning
	default:
		return LevelNormal
	}
}

// calculateAllocationRate calculates allocations per minute.
func (m *PoolMonitor) calculateAllocationRate(poolID string) float64 {
	history := m.allocationHistory[poolID]
	if len(history) < 2 {
		return 0
	}

	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)

	count := 0
	for _, t := range history {
		if t.After(cutoff) {
			count++
		}
	}

	// Rate per minute over the last 5 minutes
	return float64(count) / 5.0
}

// sendAlert sends an alert to all handlers.
func (m *PoolMonitor) sendAlert(status *PoolStatus, level PoolUtilizationLevel) {
	m.logger.Warn("Pool utilization alert",
		zap.String("pool_id", status.PoolID),
		zap.String("pool_name", status.PoolName),
		zap.String("level", level.String()),
		zap.Float64("utilization", status.Utilization),
		zap.Int("available", status.Available),
		zap.Int("allocated", status.Allocated),
		zap.Float64("allocation_rate", status.AllocationRate),
		zap.Duration("estimated_ttl", status.EstimatedTTL),
	)

	handlers := make([]PoolAlertHandler, len(m.alertHandlers))
	copy(handlers, m.alertHandlers)

	// Send alerts outside lock
	go func() {
		for _, handler := range handlers {
			handler(*status, level)
		}
	}()
}

// UpdatePoolStatus manually updates a pool's status (for testing or external updates).
func (m *PoolMonitor) UpdatePoolStatus(status *PoolStatus) {
	m.processPoolStatus(status.PoolID, status)
}

// GetPoolsAtLevel returns pools at or above a given level.
func (m *PoolMonitor) GetPoolsAtLevel(minLevel PoolUtilizationLevel) []*PoolStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var pools []*PoolStatus
	for _, state := range m.poolStates {
		if state.LastStatus != nil && state.LastLevel >= minLevel {
			pools = append(pools, state.LastStatus)
		}
	}
	return pools
}

// GetCriticalPools returns pools at critical or exhausted level.
func (m *PoolMonitor) GetCriticalPools() []*PoolStatus {
	return m.GetPoolsAtLevel(LevelCritical)
}

// HasExhaustedPools returns true if any pool is exhausted.
func (m *PoolMonitor) HasExhaustedPools() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, state := range m.poolStates {
		if state.LastLevel == LevelExhausted {
			return true
		}
	}
	return false
}
