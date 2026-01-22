package resilience

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HealthChecker is the interface for checking connectivity to remote services.
type HealthChecker interface {
	// CheckNexus checks connectivity to the Nexus server.
	CheckNexus(ctx context.Context) error
	// CheckRADIUS checks connectivity to RADIUS servers.
	CheckRADIUS(ctx context.Context) error
}

// Manager coordinates partition detection, handling, and recovery.
type Manager struct {
	config PartitionConfig
	logger *zap.Logger
	siteID string

	// Health checking
	healthChecker HealthChecker

	// State
	mu               sync.RWMutex
	state            PartitionState
	partitionStart   time.Time
	lastHealthCheck  time.Time
	consecutiveFails int

	// Pool monitoring
	poolMonitor *PoolMonitor

	// Request queue
	requestQueue *RequestQueue

	// RADIUS resilience
	radiusHandler *RADIUSHandler

	// Conflict detection
	conflictDetector *ConflictDetector

	// Event handlers
	partitionHandlers []PartitionEventHandler
	poolHandlers      []PoolAlertHandler
	conflictHandlers  []ConflictHandler

	// Statistics
	stats PartitionStats

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new partition manager.
func NewManager(config PartitionConfig, siteID string, healthChecker HealthChecker, logger *zap.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:        config,
		logger:        logger,
		siteID:        siteID,
		healthChecker: healthChecker,
		state:         StateOnline,
		ctx:           ctx,
		cancel:        cancel,
	}

	// Initialize sub-components
	m.poolMonitor = NewPoolMonitor(config, logger)
	m.requestQueue = NewRequestQueue(config.RequestQueueSize, config.RequestQueueTimeout, logger)
	m.radiusHandler = NewRADIUSHandler(config, logger)
	m.conflictDetector = NewConflictDetector(siteID, logger)

	return m
}

// Start begins partition monitoring and handling.
func (m *Manager) Start() error {
	m.logger.Info("Starting partition manager",
		zap.String("site_id", m.siteID),
		zap.String("radius_mode", string(m.config.RADIUSPartitionMode)),
	)

	// Start health check loop
	m.wg.Add(1)
	go m.healthCheckLoop()

	// Start request queue processor
	m.wg.Add(1)
	go m.processQueueLoop()

	// Start pool monitor
	if err := m.poolMonitor.Start(); err != nil {
		return fmt.Errorf("start pool monitor: %w", err)
	}

	// Forward pool alerts
	m.poolMonitor.OnAlert(func(pool PoolStatus, level PoolUtilizationLevel) {
		m.handlePoolAlert(pool, level)
	})

	m.logger.Info("Partition manager started")
	return nil
}

// Stop shuts down the partition manager.
func (m *Manager) Stop() error {
	m.logger.Info("Stopping partition manager")
	m.cancel()
	m.wg.Wait()
	m.poolMonitor.Stop()
	m.logger.Info("Partition manager stopped")
	return nil
}

// State returns the current partition state.
func (m *Manager) State() PartitionState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// IsPartitioned returns true if currently in a network partition.
func (m *Manager) IsPartitioned() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state == StatePartitioned || m.state == StateRecovering
}

// PartitionDuration returns how long we've been partitioned.
func (m *Manager) PartitionDuration() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state == StateOnline || m.partitionStart.IsZero() {
		return 0
	}
	return time.Since(m.partitionStart)
}

// OnPartitionChange registers a handler for partition state changes.
func (m *Manager) OnPartitionChange(handler PartitionEventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.partitionHandlers = append(m.partitionHandlers, handler)
}

// OnPoolAlert registers a handler for pool utilization alerts.
func (m *Manager) OnPoolAlert(handler PoolAlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.poolHandlers = append(m.poolHandlers, handler)
}

// OnConflict registers a handler for IP allocation conflicts.
func (m *Manager) OnConflict(handler ConflictHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conflictHandlers = append(m.conflictHandlers, handler)
}

// Stats returns current partition statistics.
func (m *Manager) Stats() PartitionStats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()
	stats := m.stats
	stats.CurrentState = m.State()
	return stats
}

// healthCheckLoop periodically checks connectivity to remote services.
func (m *Manager) healthCheckLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkHealth()
		}
	}
}

// checkHealth performs a health check and updates partition state.
func (m *Manager) checkHealth() {
	ctx, cancel := context.WithTimeout(m.ctx, m.config.HealthCheckTimeout)
	defer cancel()

	// Check Nexus connectivity
	nexusErr := m.healthChecker.CheckNexus(ctx)
	radiusErr := m.healthChecker.CheckRADIUS(ctx)

	m.mu.Lock()
	m.lastHealthCheck = time.Now()

	if nexusErr != nil || radiusErr != nil {
		m.consecutiveFails++
		m.logger.Warn("Health check failed",
			zap.Error(nexusErr),
			zap.Error(radiusErr),
			zap.Int("consecutive_fails", m.consecutiveFails),
		)

		// Transition to partitioned after threshold failures
		if m.consecutiveFails >= m.config.HealthCheckRetries && m.state == StateOnline {
			m.transitionToPartitioned()
		}
	} else {
		m.consecutiveFails = 0

		// Transition back to online if partitioned
		if m.state == StatePartitioned {
			m.transitionToRecovering()
		}
	}
	m.mu.Unlock()
}

// transitionToPartitioned handles the transition to partitioned state.
// Must be called with m.mu held. The lock remains held on return.
func (m *Manager) transitionToPartitioned() {
	oldState := m.state
	m.state = StatePartitioned
	m.partitionStart = time.Now()

	m.stats.mu.Lock()
	m.stats.TotalPartitions++
	m.stats.mu.Unlock()

	// Copy handlers while holding the lock
	handlers := make([]PartitionEventHandler, len(m.partitionHandlers))
	copy(handlers, m.partitionHandlers)

	// Capture values needed for event before releasing lock
	partitionStart := m.partitionStart

	// Release lock before calling handlers to avoid deadlock
	m.mu.Unlock()

	event := PartitionEvent{
		OldState:  oldState,
		NewState:  StatePartitioned,
		Timestamp: partitionStart,
		Reason:    "health check failures exceeded threshold",
	}

	m.logger.Warn("Entering partitioned state",
		zap.String("old_state", oldState.String()),
		zap.Time("partition_start", partitionStart),
	)

	// Notify handlers without holding the lock
	for _, handler := range handlers {
		handler(event)
	}

	// Re-acquire lock for caller
	m.mu.Lock()
}

// transitionToRecovering handles the transition to recovering state.
// Must be called with m.mu held. The lock remains held on return.
func (m *Manager) transitionToRecovering() {
	oldState := m.state
	m.state = StateRecovering
	partitionDuration := time.Since(m.partitionStart)

	m.stats.mu.Lock()
	m.stats.TotalPartitionTime += partitionDuration
	m.stats.LastPartitionTime = m.partitionStart
	m.stats.mu.Unlock()

	// Copy handlers while holding the lock
	handlers := make([]PartitionEventHandler, len(m.partitionHandlers))
	copy(handlers, m.partitionHandlers)

	// Release lock before calling handlers to avoid deadlock
	m.mu.Unlock()

	event := PartitionEvent{
		OldState:  oldState,
		NewState:  StateRecovering,
		Timestamp: time.Now(),
		Duration:  partitionDuration,
		Reason:    "connectivity restored",
	}

	m.logger.Info("Entering recovery state",
		zap.String("old_state", oldState.String()),
		zap.Duration("partition_duration", partitionDuration),
	)

	// Notify handlers without holding the lock
	for _, handler := range handlers {
		handler(event)
	}

	// Start reconciliation in background
	go m.performReconciliation()

	// Re-acquire lock for caller
	m.mu.Lock()
}

// performReconciliation reconciles state after partition recovery.
func (m *Manager) performReconciliation() {
	ctx, cancel := context.WithTimeout(m.ctx, m.config.ReconciliationTimeout)
	defer cancel()

	m.logger.Info("Starting partition reconciliation")
	startTime := time.Now()

	result := &ReconciliationResult{
		StartedAt: startTime,
	}

	// Step 1: Detect and resolve IP allocation conflicts
	conflicts := m.conflictDetector.DetectConflicts(ctx)
	result.ConflictsFound = len(conflicts)

	for _, conflict := range conflicts {
		if err := m.resolveConflict(ctx, &conflict); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("resolve conflict %s: %v", conflict.IP, err))
		} else {
			result.ConflictsResolved++
		}
		result.Conflicts = append(result.Conflicts, conflict)
	}

	// Step 2: Queue re-authentication for degraded sessions
	degradedSessions := m.radiusHandler.GetDegradedSessions()
	result.ReauthsQueued = len(degradedSessions)

	for _, session := range degradedSessions {
		m.radiusHandler.QueueReauth(session)
	}

	// Step 3: Process re-authentications with rate limiting
	completed, failed := m.radiusHandler.ProcessReauths(ctx, m.config.ReauthRateLimit)
	result.ReauthsCompleted = completed
	m.stats.mu.Lock()
	m.stats.ReauthsCompleted += int64(completed)
	m.stats.ReauthsFailed += int64(failed)
	m.stats.mu.Unlock()

	// Step 4: Sync buffered accounting records
	synced := m.radiusHandler.SyncBufferedAccounting(ctx, m.config.AccountingSyncBatchSize)
	result.AcctRecordsSynced = synced
	m.stats.mu.Lock()
	m.stats.AcctRecordsSynced += int64(synced)
	m.stats.mu.Unlock()

	// Step 5: Process queued requests
	m.requestQueue.ProcessAll(ctx)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	m.logger.Info("Partition reconciliation complete",
		zap.Duration("duration", result.Duration),
		zap.Int("conflicts_found", result.ConflictsFound),
		zap.Int("conflicts_resolved", result.ConflictsResolved),
		zap.Int("reauths_completed", result.ReauthsCompleted),
		zap.Int("acct_synced", result.AcctRecordsSynced),
		zap.Int("errors", len(result.Errors)),
	)

	// Transition to online
	m.mu.Lock()
	oldState := m.state
	m.state = StateOnline
	m.partitionStart = time.Time{}
	m.mu.Unlock()

	event := PartitionEvent{
		OldState:  oldState,
		NewState:  StateOnline,
		Timestamp: time.Now(),
		Duration:  result.Duration,
		Reason:    "reconciliation complete",
	}

	m.mu.RLock()
	handlers := make([]PartitionEventHandler, len(m.partitionHandlers))
	copy(handlers, m.partitionHandlers)
	m.mu.RUnlock()

	for _, handler := range handlers {
		handler(event)
	}
}

// resolveConflict attempts to resolve an IP allocation conflict.
func (m *Manager) resolveConflict(ctx context.Context, conflict *AllocationConflict) error {
	// Validate conflict data
	if conflict == nil {
		return fmt.Errorf("conflict is nil")
	}
	if conflict.IP == nil {
		return fmt.Errorf("conflict IP is nil")
	}
	if conflict.LocalAlloc.MAC == nil {
		return fmt.Errorf("local allocation MAC is nil for IP %s", conflict.IP)
	}
	if conflict.RemoteAlloc.MAC == nil {
		return fmt.Errorf("remote allocation MAC is nil for IP %s", conflict.IP)
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled while resolving conflict for IP %s: %w", conflict.IP, ctx.Err())
	default:
	}

	m.logger.Info("Resolving IP conflict",
		zap.String("ip", conflict.IP.String()),
		zap.String("local_mac", conflict.LocalAlloc.MAC.String()),
		zap.String("remote_mac", conflict.RemoteAlloc.MAC.String()),
	)

	// Resolution strategy:
	// 1. If allocations have same MAC, keep the most recent one
	// 2. If different MACs, prefer pre-partition allocation (Nexus is source of truth)
	// 3. If both during partition, prefer most recent

	var resolution ConflictResolution
	var affectedMAC net.HardwareAddr

	localMAC := conflict.LocalAlloc.MAC.String()
	remoteMAC := conflict.RemoteAlloc.MAC.String()

	if localMAC == remoteMAC {
		// Same MAC, same subscriber - just merge
		if conflict.LocalAlloc.AllocatedAt.After(conflict.RemoteAlloc.AllocatedAt) {
			resolution = ResolutionLocalWins
		} else {
			resolution = ResolutionRemoteWins
		}
	} else if !conflict.LocalAlloc.IsPartition && conflict.RemoteAlloc.IsPartition {
		// Local was pre-partition (Nexus source of truth), remote was during partition
		resolution = ResolutionLocalWins
		affectedMAC = conflict.RemoteAlloc.MAC
	} else if conflict.LocalAlloc.IsPartition && !conflict.RemoteAlloc.IsPartition {
		// Remote was pre-partition (Nexus source of truth), local was during partition
		resolution = ResolutionRemoteWins
		affectedMAC = conflict.LocalAlloc.MAC
	} else {
		// Both during partition - prefer most recent
		if conflict.LocalAlloc.AllocatedAt.After(conflict.RemoteAlloc.AllocatedAt) {
			resolution = ResolutionLocalWins
			affectedMAC = conflict.RemoteAlloc.MAC
		} else {
			resolution = ResolutionRemoteWins
			affectedMAC = conflict.LocalAlloc.MAC
		}
	}

	conflict.Resolution = resolution
	conflict.ResolvedAt = time.Now()
	conflict.AffectedMAC = affectedMAC

	// Update statistics
	m.stats.mu.Lock()
	m.stats.ConflictsResolved++
	if resolution == ResolutionLocalWins {
		m.stats.LocalWins++
	} else {
		m.stats.RemoteWins++
	}
	m.stats.mu.Unlock()

	// Notify handlers
	m.mu.RLock()
	handlers := make([]ConflictHandler, len(m.conflictHandlers))
	copy(handlers, m.conflictHandlers)
	m.mu.RUnlock()

	for _, handler := range handlers {
		handler(*conflict)
	}

	m.logger.Info("IP conflict resolved",
		zap.String("ip", conflict.IP.String()),
		zap.String("resolution", string(resolution)),
		zap.String("affected_mac", affectedMAC.String()),
	)

	return nil
}

// handlePoolAlert handles pool utilization alerts.
func (m *Manager) handlePoolAlert(pool PoolStatus, level PoolUtilizationLevel) {
	m.stats.mu.Lock()
	switch level {
	case LevelWarning:
		m.stats.PoolWarnings++
	case LevelCritical:
		m.stats.PoolCriticals++
	case LevelExhausted:
		m.stats.PoolExhaustions++
	}
	m.stats.mu.Unlock()

	m.logger.Warn("Pool utilization alert",
		zap.String("pool_id", pool.PoolID),
		zap.String("pool_name", pool.PoolName),
		zap.Float64("utilization", pool.Utilization),
		zap.String("level", level.String()),
		zap.Bool("short_lease_active", pool.ShortLeaseActive),
	)

	// Notify handlers
	m.mu.RLock()
	handlers := make([]PoolAlertHandler, len(m.poolHandlers))
	copy(handlers, m.poolHandlers)
	m.mu.RUnlock()

	for _, handler := range handlers {
		handler(pool, level)
	}
}

// processQueueLoop processes queued requests when partition heals.
func (m *Manager) processQueueLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// Only process when recovering or online
			state := m.State()
			if state == StateRecovering || state == StateOnline {
				m.requestQueue.ExpireOld()
			}
		}
	}
}

// QueueRequest queues a request during partition.
func (m *Manager) QueueRequest(req *QueuedRequest) error {
	if m.State() == StateOnline {
		return fmt.Errorf("not in partition state, cannot queue request")
	}

	if err := m.requestQueue.Enqueue(req); err != nil {
		m.stats.mu.Lock()
		m.stats.RequestsExpired++
		m.stats.mu.Unlock()
		return err
	}

	m.stats.mu.Lock()
	m.stats.RequestsQueued++
	if m.requestQueue.Len() > m.stats.QueueHighWaterMark {
		m.stats.QueueHighWaterMark = m.requestQueue.Len()
	}
	m.stats.mu.Unlock()

	return nil
}

// PoolMonitor returns the pool monitor for external configuration.
func (m *Manager) PoolMonitor() *PoolMonitor {
	return m.poolMonitor
}

// RADIUSHandler returns the RADIUS handler for external configuration.
func (m *Manager) RADIUSHandler() *RADIUSHandler {
	return m.radiusHandler
}

// ConflictDetector returns the conflict detector for external configuration.
func (m *Manager) ConflictDetector() *ConflictDetector {
	return m.conflictDetector
}

// ShouldUseShortLease returns whether short leases should be used for a pool.
func (m *Manager) ShouldUseShortLease(poolID string) bool {
	if !m.config.ShortLeaseEnabled {
		return false
	}
	if m.State() != StatePartitioned {
		return false
	}
	return m.poolMonitor.GetUtilization(poolID) >= m.config.ShortLeaseThreshold
}

// GetShortLeaseDuration returns the short lease duration.
func (m *Manager) GetShortLeaseDuration() time.Duration {
	return m.config.ShortLeaseDuration
}

// RecordShortLease records that a short lease was issued.
func (m *Manager) RecordShortLease() {
	m.stats.mu.Lock()
	m.stats.ShortLeasesIssued++
	m.stats.mu.Unlock()
}

// GetRADIUSPartitionMode returns the configured RADIUS partition mode.
func (m *Manager) GetRADIUSPartitionMode() RADIUSPartitionMode {
	return m.config.RADIUSPartitionMode
}
