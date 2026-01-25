package ha

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// FailoverConfig contains configuration for automatic failover.
type FailoverConfig struct {
	// Enabled controls whether automatic failover is enabled.
	Enabled bool

	// FailoverDelay is how long to wait after detecting partner failure
	// before initiating failover. This helps prevent split-brain from
	// transient network issues.
	FailoverDelay time.Duration

	// FailbackDelay is how long to wait after partner recovery before
	// failing back to the original roles.
	FailbackDelay time.Duration

	// FailbackEnabled controls whether automatic failback is enabled.
	// If false, manual intervention is required to restore original roles.
	FailbackEnabled bool

	// PreemptEnabled controls whether a higher-priority node can take
	// over from a lower-priority node when both are healthy.
	PreemptEnabled bool

	// GracePeriod is the time given to drain traffic before completing failover.
	GracePeriod time.Duration
}

// DefaultFailoverConfig returns sensible defaults for failover configuration.
func DefaultFailoverConfig() FailoverConfig {
	return FailoverConfig{
		Enabled:         true,
		FailoverDelay:   10 * time.Second,
		FailbackDelay:   30 * time.Second,
		FailbackEnabled: true,
		PreemptEnabled:  false,
		GracePeriod:     5 * time.Second,
	}
}

// FailoverState represents the current failover state.
type FailoverState int

const (
	// FailoverStateNormal indicates normal operation.
	FailoverStateNormal FailoverState = iota
	// FailoverStatePending indicates failover is pending (waiting for delay).
	FailoverStatePending
	// FailoverStateInProgress indicates failover is in progress.
	FailoverStateInProgress
	// FailoverStateComplete indicates failover is complete.
	FailoverStateComplete
	// FailoverStateFailbackPending indicates failback is pending.
	FailoverStateFailbackPending
)

// String returns a human-readable state name.
func (s FailoverState) String() string {
	switch s {
	case FailoverStateNormal:
		return "normal"
	case FailoverStatePending:
		return "pending"
	case FailoverStateInProgress:
		return "in_progress"
	case FailoverStateComplete:
		return "complete"
	case FailoverStateFailbackPending:
		return "failback_pending"
	default:
		return "unknown"
	}
}

// FailoverEvent represents a failover-related event.
type FailoverEvent struct {
	// Type is the type of failover event.
	Type FailoverEventType `json:"type"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// OldRole is the role before the event.
	OldRole Role `json:"old_role"`

	// NewRole is the role after the event.
	NewRole Role `json:"new_role"`

	// Reason is the reason for the event.
	Reason string `json:"reason,omitempty"`

	// PartnerState describes the partner's state at event time.
	PartnerState string `json:"partner_state,omitempty"`
}

// FailoverEventType identifies the type of failover event.
type FailoverEventType string

const (
	// FailoverEventInitiated indicates failover was initiated.
	FailoverEventInitiated FailoverEventType = "initiated"

	// FailoverEventCompleted indicates failover completed successfully.
	FailoverEventCompleted FailoverEventType = "completed"

	// FailoverEventCanceled indicates failover was canceled.
	FailoverEventCanceled FailoverEventType = "canceled"

	// FailoverEventFailbackInitiated indicates failback was initiated.
	FailoverEventFailbackInitiated FailoverEventType = "failback_initiated"

	// FailoverEventFailbackCompleted indicates failback completed.
	FailoverEventFailbackCompleted FailoverEventType = "failback_completed"

	// FailoverEventRoleChanged indicates the node's role changed.
	FailoverEventRoleChanged FailoverEventType = "role_changed"
)

// FailoverEventHandler is called when failover events occur.
type FailoverEventHandler func(event FailoverEvent)

// RoleChangeCallback is called when the role needs to be changed.
// It should return an error if the role change cannot be completed.
type RoleChangeCallback func(newRole Role) error

// FailoverController manages automatic failover between HA pairs.
type FailoverController struct {
	config        FailoverConfig
	logger        *zap.Logger
	nodeID        string
	originalRole  Role
	currentRole   Role
	priority      int // Higher priority takes precedence
	healthMonitor *HealthMonitor

	// Callbacks
	onRoleChange RoleChangeCallback

	// State
	mu             sync.RWMutex
	state          FailoverState
	failoverTime   time.Time
	failbackTime   time.Time
	lastRoleChange time.Time

	// Timers
	failoverTimer *time.Timer
	failbackTimer *time.Timer

	// Statistics
	failoversInitiated uint64
	failoversCompleted uint64
	failoversCanceled  uint64
	failbacksCompleted uint64

	// Event handlers
	handlers []FailoverEventHandler

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewFailoverController creates a new failover controller.
func NewFailoverController(
	config FailoverConfig,
	nodeID string,
	role Role,
	priority int,
	healthMonitor *HealthMonitor,
	logger *zap.Logger,
) *FailoverController {
	ctx, cancel := context.WithCancel(context.Background())

	return &FailoverController{
		config:        config,
		logger:        logger,
		nodeID:        nodeID,
		originalRole:  role,
		currentRole:   role,
		priority:      priority,
		healthMonitor: healthMonitor,
		state:         FailoverStateNormal,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start begins failover monitoring.
func (c *FailoverController) Start() error {
	if !c.config.Enabled {
		c.logger.Info("Automatic failover is disabled")
		return nil
	}

	c.logger.Info("Starting failover controller",
		zap.String("node_id", c.nodeID),
		zap.String("role", string(c.currentRole)),
		zap.Int("priority", c.priority),
	)

	// Register for health events
	c.healthMonitor.OnHealthChange(c.handleHealthEvent)

	c.wg.Add(1)
	go c.controlLoop()

	return nil
}

// Stop stops the failover controller.
func (c *FailoverController) Stop() {
	c.logger.Info("Stopping failover controller")
	c.cancel()

	c.mu.Lock()
	if c.failoverTimer != nil {
		c.failoverTimer.Stop()
	}
	if c.failbackTimer != nil {
		c.failbackTimer.Stop()
	}
	c.mu.Unlock()

	c.wg.Wait()
	c.logger.Info("Failover controller stopped")
}

// SetRoleChangeCallback sets the callback for role changes.
func (c *FailoverController) SetRoleChangeCallback(cb RoleChangeCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onRoleChange = cb
}

// OnFailoverEvent registers a handler for failover events.
func (c *FailoverController) OnFailoverEvent(handler FailoverEventHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers = append(c.handlers, handler)
}

// CurrentRole returns the current role.
func (c *FailoverController) CurrentRole() Role {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentRole
}

// OriginalRole returns the original (configured) role.
func (c *FailoverController) OriginalRole() Role {
	return c.originalRole
}

// State returns the current failover state.
func (c *FailoverController) State() FailoverState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// IsFailedOver returns true if currently operating in a failed-over state.
func (c *FailoverController) IsFailedOver() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentRole != c.originalRole
}

// Stats returns failover statistics.
func (c *FailoverController) Stats() (initiated, completed, canceled, failbacks uint64) {
	return atomic.LoadUint64(&c.failoversInitiated),
		atomic.LoadUint64(&c.failoversCompleted),
		atomic.LoadUint64(&c.failoversCanceled),
		atomic.LoadUint64(&c.failbacksCompleted)
}

// ForceFailover forces an immediate failover (for manual intervention).
func (c *FailoverController) ForceFailover(reason string) error {
	c.logger.Warn("Forcing failover",
		zap.String("reason", reason),
	)
	return c.initiateFailover(reason)
}

// ForceFailback forces an immediate failback (for manual intervention).
func (c *FailoverController) ForceFailback(reason string) error {
	c.logger.Info("Forcing failback",
		zap.String("reason", reason),
	)
	return c.initiateFailback(reason)
}

// controlLoop monitors state and manages failover timing.
func (c *FailoverController) controlLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.evaluateState()
		}
	}
}

// handleHealthEvent handles health state changes from the monitor.
func (c *FailoverController) handleHealthEvent(event HealthEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch event.Type {
	case HealthEventPartnerDown:
		// Partner is unhealthy - consider failover if we're standby
		if c.currentRole == RoleStandby && c.state == FailoverStateNormal {
			c.logger.Warn("Partner down detected, scheduling failover",
				zap.Duration("delay", c.config.FailoverDelay),
			)
			c.state = FailoverStatePending
			c.failoverTime = time.Now().Add(c.config.FailoverDelay)

			// Set timer
			if c.failoverTimer != nil {
				c.failoverTimer.Stop()
			}
			c.failoverTimer = time.AfterFunc(c.config.FailoverDelay, func() {
				c.executeFailover("partner health check failure")
			})
		}

	case HealthEventPartnerUp:
		// Partner is healthy again
		if c.state == FailoverStatePending {
			// Cancel pending failover
			c.logger.Info("Partner recovered, canceling pending failover")
			if c.failoverTimer != nil {
				c.failoverTimer.Stop()
			}
			c.state = FailoverStateNormal
			atomic.AddUint64(&c.failoversCanceled, 1)

			c.notifyHandlers(FailoverEvent{
				Type:      FailoverEventCanceled,
				Timestamp: time.Now(),
				OldRole:   c.currentRole,
				NewRole:   c.currentRole,
				Reason:    "partner recovered",
			})
		} else if c.state == FailoverStateComplete && c.config.FailbackEnabled {
			// Consider failback
			c.logger.Info("Partner recovered after failover, scheduling failback",
				zap.Duration("delay", c.config.FailbackDelay),
			)
			c.state = FailoverStateFailbackPending
			c.failbackTime = time.Now().Add(c.config.FailbackDelay)

			if c.failbackTimer != nil {
				c.failbackTimer.Stop()
			}
			c.failbackTimer = time.AfterFunc(c.config.FailbackDelay, func() {
				c.executeFailback("partner recovered")
			})
		}
	}
}

// evaluateState periodically evaluates the current state.
func (c *FailoverController) evaluateState() {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()

	// Additional state checks can be added here
	switch state {
	case FailoverStateFailbackPending:
		// Verify partner is still healthy before failback
		if !c.healthMonitor.IsPartnerHealthy() {
			c.mu.Lock()
			if c.failbackTimer != nil {
				c.failbackTimer.Stop()
			}
			c.state = FailoverStateComplete
			c.logger.Warn("Partner unhealthy during failback delay, canceling failback")
			c.mu.Unlock()
		}
	}
}

// initiateFailover starts the failover process.
func (c *FailoverController) initiateFailover(reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.currentRole == RoleActive {
		return fmt.Errorf("already active, cannot failover")
	}

	c.state = FailoverStateInProgress
	atomic.AddUint64(&c.failoversInitiated, 1)

	c.notifyHandlers(FailoverEvent{
		Type:         FailoverEventInitiated,
		Timestamp:    time.Now(),
		OldRole:      c.currentRole,
		NewRole:      RoleActive,
		Reason:       reason,
		PartnerState: "unhealthy",
	})

	return nil
}

// executeFailover performs the actual failover.
func (c *FailoverController) executeFailover(reason string) {
	c.mu.Lock()

	if c.state != FailoverStatePending && c.state != FailoverStateInProgress {
		c.mu.Unlock()
		return
	}

	c.state = FailoverStateInProgress
	oldRole := c.currentRole
	newRole := RoleActive
	onRoleChange := c.onRoleChange
	c.mu.Unlock()

	c.logger.Info("Executing failover",
		zap.String("reason", reason),
		zap.String("old_role", string(oldRole)),
		zap.String("new_role", string(newRole)),
	)

	atomic.AddUint64(&c.failoversInitiated, 1)

	// Apply grace period for traffic draining
	if c.config.GracePeriod > 0 {
		c.logger.Info("Applying grace period before failover",
			zap.Duration("duration", c.config.GracePeriod),
		)
		time.Sleep(c.config.GracePeriod)
	}

	// Call role change callback
	if onRoleChange != nil {
		if err := onRoleChange(newRole); err != nil {
			c.logger.Error("Role change callback failed",
				zap.Error(err),
			)
			c.mu.Lock()
			c.state = FailoverStateNormal
			c.mu.Unlock()
			return
		}
	}

	c.mu.Lock()
	c.currentRole = newRole
	c.state = FailoverStateComplete
	c.lastRoleChange = time.Now()
	c.mu.Unlock()

	atomic.AddUint64(&c.failoversCompleted, 1)

	c.logger.Info("Failover completed",
		zap.String("new_role", string(newRole)),
	)

	c.notifyHandlers(FailoverEvent{
		Type:         FailoverEventCompleted,
		Timestamp:    time.Now(),
		OldRole:      oldRole,
		NewRole:      newRole,
		Reason:       reason,
		PartnerState: "unhealthy",
	})

	c.notifyHandlers(FailoverEvent{
		Type:      FailoverEventRoleChanged,
		Timestamp: time.Now(),
		OldRole:   oldRole,
		NewRole:   newRole,
		Reason:    "failover",
	})
}

// initiateFailback starts the failback process.
func (c *FailoverController) initiateFailback(reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.currentRole == c.originalRole {
		return fmt.Errorf("already at original role, cannot failback")
	}

	c.notifyHandlers(FailoverEvent{
		Type:         FailoverEventFailbackInitiated,
		Timestamp:    time.Now(),
		OldRole:      c.currentRole,
		NewRole:      c.originalRole,
		Reason:       reason,
		PartnerState: "healthy",
	})

	return nil
}

// executeFailback performs the actual failback.
func (c *FailoverController) executeFailback(reason string) {
	c.mu.Lock()

	if c.state != FailoverStateFailbackPending {
		c.mu.Unlock()
		return
	}

	// Verify partner is still healthy
	if !c.healthMonitor.IsPartnerHealthy() {
		c.logger.Warn("Partner not healthy, canceling failback")
		c.state = FailoverStateComplete
		c.mu.Unlock()
		return
	}

	oldRole := c.currentRole
	newRole := c.originalRole
	onRoleChange := c.onRoleChange
	c.mu.Unlock()

	c.logger.Info("Executing failback",
		zap.String("reason", reason),
		zap.String("old_role", string(oldRole)),
		zap.String("new_role", string(newRole)),
	)

	// Apply grace period
	if c.config.GracePeriod > 0 {
		c.logger.Info("Applying grace period before failback",
			zap.Duration("duration", c.config.GracePeriod),
		)
		time.Sleep(c.config.GracePeriod)
	}

	// Call role change callback
	if onRoleChange != nil {
		if err := onRoleChange(newRole); err != nil {
			c.logger.Error("Role change callback failed during failback",
				zap.Error(err),
			)
			c.mu.Lock()
			c.state = FailoverStateComplete
			c.mu.Unlock()
			return
		}
	}

	c.mu.Lock()
	c.currentRole = newRole
	c.state = FailoverStateNormal
	c.lastRoleChange = time.Now()
	c.mu.Unlock()

	atomic.AddUint64(&c.failbacksCompleted, 1)

	c.logger.Info("Failback completed",
		zap.String("new_role", string(newRole)),
	)

	c.notifyHandlers(FailoverEvent{
		Type:         FailoverEventFailbackCompleted,
		Timestamp:    time.Now(),
		OldRole:      oldRole,
		NewRole:      newRole,
		Reason:       reason,
		PartnerState: "healthy",
	})

	c.notifyHandlers(FailoverEvent{
		Type:      FailoverEventRoleChanged,
		Timestamp: time.Now(),
		OldRole:   oldRole,
		NewRole:   newRole,
		Reason:    "failback",
	})
}

// notifyHandlers notifies all registered handlers of an event.
func (c *FailoverController) notifyHandlers(event FailoverEvent) {
	handlers := make([]FailoverEventHandler, len(c.handlers))
	copy(handlers, c.handlers)

	for _, handler := range handlers {
		handler(event)
	}
}

// FailoverStatus returns comprehensive failover status.
type FailoverStatus struct {
	NodeID         string         `json:"node_id"`
	OriginalRole   Role           `json:"original_role"`
	CurrentRole    Role           `json:"current_role"`
	State          FailoverState  `json:"state"`
	IsFailedOver   bool           `json:"is_failed_over"`
	PartnerHealthy bool           `json:"partner_healthy"`
	LastRoleChange time.Time      `json:"last_role_change,omitempty"`
	Priority       int            `json:"priority"`
	Config         FailoverConfig `json:"config"`
}

// Status returns comprehensive failover status.
func (c *FailoverController) Status() FailoverStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return FailoverStatus{
		NodeID:         c.nodeID,
		OriginalRole:   c.originalRole,
		CurrentRole:    c.currentRole,
		State:          c.state,
		IsFailedOver:   c.currentRole != c.originalRole,
		PartnerHealthy: c.healthMonitor.IsPartnerHealthy(),
		LastRoleChange: c.lastRoleChange,
		Priority:       c.priority,
		Config:         c.config,
	}
}
