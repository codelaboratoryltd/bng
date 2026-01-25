package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// HealthConfig contains configuration for health monitoring.
type HealthConfig struct {
	// CheckInterval is how often to check partner health.
	CheckInterval time.Duration

	// Timeout is the timeout for health check requests.
	Timeout time.Duration

	// FailureThreshold is the number of consecutive failures before
	// considering the partner unhealthy.
	FailureThreshold int

	// RecoveryThreshold is the number of consecutive successes needed
	// to consider a previously unhealthy partner as recovered.
	RecoveryThreshold int
}

// DefaultHealthConfig returns sensible defaults for health monitoring.
func DefaultHealthConfig() HealthConfig {
	return HealthConfig{
		CheckInterval:     5 * time.Second,
		Timeout:           3 * time.Second,
		FailureThreshold:  3,
		RecoveryThreshold: 2,
	}
}

// PartnerHealth represents the health state of the HA partner.
type PartnerHealth struct {
	// Healthy indicates whether the partner is considered healthy.
	Healthy bool `json:"healthy"`

	// LastCheck is when we last checked the partner's health.
	LastCheck time.Time `json:"last_check"`

	// LastSuccess is when we last had a successful health check.
	LastSuccess time.Time `json:"last_success,omitempty"`

	// LastFailure is when we last had a failed health check.
	LastFailure time.Time `json:"last_failure,omitempty"`

	// ConsecutiveFailures is the number of consecutive failed checks.
	ConsecutiveFailures int `json:"consecutive_failures"`

	// ConsecutiveSuccesses is the number of consecutive successful checks.
	ConsecutiveSuccesses int `json:"consecutive_successes"`

	// LastError is the last error message from a failed check.
	LastError string `json:"last_error,omitempty"`

	// ResponseTime is the response time of the last successful check.
	ResponseTime time.Duration `json:"response_time,omitempty"`

	// PartnerNodeID is the partner's node ID (from health response).
	PartnerNodeID string `json:"partner_node_id,omitempty"`

	// PartnerRole is the partner's HA role (from health response).
	PartnerRole Role `json:"partner_role,omitempty"`

	// PartnerSessions is the number of sessions on the partner.
	PartnerSessions int `json:"partner_sessions,omitempty"`
}

// HealthMonitor monitors the health of the HA partner.
type HealthMonitor struct {
	config  HealthConfig
	logger  *zap.Logger
	partner *PartnerInfo
	client  *http.Client

	// State
	mu     sync.RWMutex
	health PartnerHealth

	// Statistics
	totalChecks   uint64
	totalFailures uint64
	totalRecovery uint64

	// Event handlers
	handlers []HealthEventHandler

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// HealthEvent represents a health state change event.
type HealthEvent struct {
	// Type is the type of health event.
	Type HealthEventType `json:"type"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Health is the current health state.
	Health PartnerHealth `json:"health"`

	// Error is the error that caused the event (if applicable).
	Error string `json:"error,omitempty"`
}

// HealthEventType identifies the type of health event.
type HealthEventType string

const (
	// HealthEventPartnerDown indicates the partner is now considered unhealthy.
	HealthEventPartnerDown HealthEventType = "partner_down"

	// HealthEventPartnerUp indicates the partner has recovered.
	HealthEventPartnerUp HealthEventType = "partner_up"

	// HealthEventCheckFailed indicates a single health check failed.
	HealthEventCheckFailed HealthEventType = "check_failed"

	// HealthEventCheckSucceeded indicates a single health check succeeded.
	HealthEventCheckSucceeded HealthEventType = "check_succeeded"
)

// HealthEventHandler is called when health state changes.
type HealthEventHandler func(event HealthEvent)

// NewHealthMonitor creates a new health monitor.
func NewHealthMonitor(config HealthConfig, partner *PartnerInfo, logger *zap.Logger) *HealthMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	return &HealthMonitor{
		config:  config,
		logger:  logger,
		partner: partner,
		client:  &http.Client{Timeout: config.Timeout},
		health: PartnerHealth{
			Healthy: true, // Assume healthy until proven otherwise
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins health monitoring.
func (m *HealthMonitor) Start() error {
	if m.partner == nil {
		return fmt.Errorf("partner info required for health monitoring")
	}

	m.logger.Info("Starting health monitor",
		zap.String("partner", m.partner.Endpoint),
		zap.Duration("interval", m.config.CheckInterval),
	)

	m.wg.Add(1)
	go m.monitorLoop()

	return nil
}

// Stop stops health monitoring.
func (m *HealthMonitor) Stop() {
	m.logger.Info("Stopping health monitor")
	m.cancel()
	m.wg.Wait()
	m.logger.Info("Health monitor stopped")
}

// Health returns the current partner health state.
func (m *HealthMonitor) Health() PartnerHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.health
}

// IsPartnerHealthy returns whether the partner is considered healthy.
func (m *HealthMonitor) IsPartnerHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.health.Healthy
}

// OnHealthChange registers a handler for health state changes.
func (m *HealthMonitor) OnHealthChange(handler HealthEventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// Stats returns monitoring statistics.
func (m *HealthMonitor) Stats() (totalChecks, totalFailures, totalRecovery uint64) {
	return atomic.LoadUint64(&m.totalChecks), atomic.LoadUint64(&m.totalFailures), atomic.LoadUint64(&m.totalRecovery)
}

// CheckNow performs an immediate health check.
func (m *HealthMonitor) CheckNow() error {
	return m.performCheck()
}

// monitorLoop runs periodic health checks.
func (m *HealthMonitor) monitorLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	// Initial check
	m.performCheck()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performCheck()
		}
	}
}

// performCheck performs a single health check.
func (m *HealthMonitor) performCheck() error {
	atomic.AddUint64(&m.totalChecks, 1)

	url := fmt.Sprintf("http://%s/ha/health", m.partner.Endpoint)
	startTime := time.Now()

	ctx, cancel := context.WithTimeout(m.ctx, m.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return m.recordFailure(fmt.Errorf("create request: %w", err))
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return m.recordFailure(fmt.Errorf("request failed: %w", err))
	}
	defer resp.Body.Close()

	responseTime := time.Since(startTime)

	if resp.StatusCode != http.StatusOK {
		return m.recordFailure(fmt.Errorf("unhealthy status: %d", resp.StatusCode))
	}

	// Parse the health response
	var healthResp struct {
		Status  string          `json:"status"`
		Role    string          `json:"role"`
		NodeID  string          `json:"node_id"`
		Stats   json.RawMessage `json:"stats,omitempty"`
		Details struct {
			Sessions int `json:"sessions_synced,omitempty"`
		} `json:"details,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		return m.recordFailure(fmt.Errorf("decode response: %w", err))
	}

	if healthResp.Status != "healthy" {
		return m.recordFailure(fmt.Errorf("partner reported unhealthy: %s", healthResp.Status))
	}

	// Record success
	m.recordSuccess(responseTime, healthResp.NodeID, Role(healthResp.Role), healthResp.Details.Sessions)
	return nil
}

// recordFailure records a failed health check.
func (m *HealthMonitor) recordFailure(err error) error {
	m.mu.Lock()

	wasHealthy := m.health.Healthy
	m.health.LastCheck = time.Now()
	m.health.LastFailure = time.Now()
	m.health.ConsecutiveFailures++
	m.health.ConsecutiveSuccesses = 0
	m.health.LastError = err.Error()

	// Check if we should mark as unhealthy
	if wasHealthy && m.health.ConsecutiveFailures >= m.config.FailureThreshold {
		m.health.Healthy = false
		atomic.AddUint64(&m.totalFailures, 1)

		// Copy handlers for notification
		handlers := make([]HealthEventHandler, len(m.handlers))
		copy(handlers, m.handlers)
		health := m.health

		m.mu.Unlock()

		event := HealthEvent{
			Type:      HealthEventPartnerDown,
			Timestamp: time.Now(),
			Health:    health,
			Error:     err.Error(),
		}

		m.logger.Warn("Partner marked unhealthy",
			zap.String("partner", m.partner.Endpoint),
			zap.Int("consecutive_failures", health.ConsecutiveFailures),
			zap.Error(err),
		)

		for _, handler := range handlers {
			handler(event)
		}
	} else {
		handlers := make([]HealthEventHandler, len(m.handlers))
		copy(handlers, m.handlers)
		health := m.health
		m.mu.Unlock()

		m.logger.Debug("Health check failed",
			zap.String("partner", m.partner.Endpoint),
			zap.Int("consecutive_failures", health.ConsecutiveFailures),
			zap.Error(err),
		)

		// Notify of individual failure
		event := HealthEvent{
			Type:      HealthEventCheckFailed,
			Timestamp: time.Now(),
			Health:    health,
			Error:     err.Error(),
		}

		for _, handler := range handlers {
			handler(event)
		}
	}

	return err
}

// recordSuccess records a successful health check.
func (m *HealthMonitor) recordSuccess(responseTime time.Duration, partnerID string, partnerRole Role, sessions int) {
	m.mu.Lock()

	wasUnhealthy := !m.health.Healthy
	m.health.LastCheck = time.Now()
	m.health.LastSuccess = time.Now()
	m.health.ConsecutiveSuccesses++
	m.health.ConsecutiveFailures = 0
	m.health.ResponseTime = responseTime
	m.health.PartnerNodeID = partnerID
	m.health.PartnerRole = partnerRole
	m.health.PartnerSessions = sessions
	m.health.LastError = ""

	// Check if we should mark as healthy (recovered)
	if wasUnhealthy && m.health.ConsecutiveSuccesses >= m.config.RecoveryThreshold {
		m.health.Healthy = true
		atomic.AddUint64(&m.totalRecovery, 1)

		// Copy handlers for notification
		handlers := make([]HealthEventHandler, len(m.handlers))
		copy(handlers, m.handlers)
		health := m.health

		m.mu.Unlock()

		event := HealthEvent{
			Type:      HealthEventPartnerUp,
			Timestamp: time.Now(),
			Health:    health,
		}

		m.logger.Info("Partner recovered",
			zap.String("partner", m.partner.Endpoint),
			zap.Int("consecutive_successes", health.ConsecutiveSuccesses),
			zap.Duration("response_time", responseTime),
		)

		for _, handler := range handlers {
			handler(event)
		}
	} else {
		handlers := make([]HealthEventHandler, len(m.handlers))
		copy(handlers, m.handlers)
		health := m.health
		m.mu.Unlock()

		m.logger.Debug("Health check succeeded",
			zap.String("partner", m.partner.Endpoint),
			zap.Duration("response_time", responseTime),
			zap.String("partner_role", string(partnerRole)),
		)

		// Notify of individual success
		event := HealthEvent{
			Type:      HealthEventCheckSucceeded,
			Timestamp: time.Now(),
			Health:    health,
		}

		for _, handler := range handlers {
			handler(event)
		}
	}
}

// SetPartner updates the partner info (useful for dynamic configuration).
func (m *HealthMonitor) SetPartner(partner *PartnerInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.partner = partner
	// Reset health state when partner changes
	m.health = PartnerHealth{
		Healthy: true,
	}
}
