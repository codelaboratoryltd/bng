package routing

import (
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HealthChecker monitors upstream gateway health.
type HealthChecker struct {
	interval time.Duration
	timeout  time.Duration
	logger   *zap.Logger

	mu      sync.RWMutex
	targets map[string]*HealthTarget

	onStateChange func(name string, up bool)
}

// HealthTarget represents a health check target.
type HealthTarget struct {
	Name            string
	Target          net.IP
	State           bool // true = up
	LastCheck       time.Time
	LastSuccess     time.Time
	ConsecutiveFail int
	ConsecutiveOK   int
	RTT             time.Duration
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(interval, timeout time.Duration, logger *zap.Logger) *HealthChecker {
	return &HealthChecker{
		interval: interval,
		timeout:  timeout,
		logger:   logger,
		targets:  make(map[string]*HealthTarget),
	}
}

// OnStateChange registers a callback for state changes.
func (h *HealthChecker) OnStateChange(callback func(name string, up bool)) {
	h.onStateChange = callback
}

// AddTarget adds a health check target.
func (h *HealthChecker) AddTarget(name string, target net.IP) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.targets[name] = &HealthTarget{
		Name:   name,
		Target: target,
		State:  false, // Start as unknown/down
	}

	h.logger.Debug("Added health check target",
		zap.String("name", name),
		zap.String("target", target.String()),
	)
}

// RemoveTarget removes a health check target.
func (h *HealthChecker) RemoveTarget(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.targets, name)
}

// GetTarget returns a health target by name.
func (h *HealthChecker) GetTarget(name string) (*HealthTarget, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	t, ok := h.targets[name]
	return t, ok
}

// CheckAll performs health checks on all targets.
func (h *HealthChecker) CheckAll(platform RoutingPlatform) {
	h.mu.Lock()
	targets := make([]*HealthTarget, 0, len(h.targets))
	for _, t := range h.targets {
		targets = append(targets, t)
	}
	h.mu.Unlock()

	for _, target := range targets {
		h.checkTarget(target, platform)
	}
}

// checkTarget checks a single target.
func (h *HealthChecker) checkTarget(target *HealthTarget, platform RoutingPlatform) {
	var rtt time.Duration
	var err error

	if platform != nil {
		rtt, err = platform.Ping(target.Target, h.timeout)
	} else {
		// Fallback: simple TCP connect to common port
		rtt, err = h.tcpPing(target.Target, h.timeout)
	}

	h.mu.Lock()
	target.LastCheck = time.Now()

	wasUp := target.State

	if err != nil {
		target.ConsecutiveFail++
		target.ConsecutiveOK = 0
		// Mark down after 3 consecutive failures
		if target.ConsecutiveFail >= 3 {
			target.State = false
		}
	} else {
		target.ConsecutiveOK++
		target.ConsecutiveFail = 0
		target.LastSuccess = time.Now()
		target.RTT = rtt
		// Mark up after 2 consecutive successes
		if target.ConsecutiveOK >= 2 {
			target.State = true
		}
	}

	stateChanged := wasUp != target.State
	currentState := target.State
	name := target.Name
	h.mu.Unlock()

	if stateChanged && h.onStateChange != nil {
		h.onStateChange(name, currentState)
	}
}

// tcpPing attempts a TCP connection as a health check.
func (h *HealthChecker) tcpPing(target net.IP, timeout time.Duration) (time.Duration, error) {
	start := time.Now()

	// Try common ports
	ports := []int{80, 443, 53}
	var lastErr error

	for _, port := range ports {
		addr := &net.TCPAddr{IP: target, Port: port}
		conn, err := net.DialTimeout("tcp", addr.String(), timeout)
		if err == nil {
			conn.Close()
			return time.Since(start), nil
		}
		lastErr = err
	}

	return 0, lastErr
}

// IsUp returns whether a target is considered up.
func (h *HealthChecker) IsUp(name string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if target, ok := h.targets[name]; ok {
		return target.State
	}
	return false
}

// GetAllStates returns the state of all targets.
func (h *HealthChecker) GetAllStates() map[string]bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	states := make(map[string]bool)
	for name, target := range h.targets {
		states[name] = target.State
	}
	return states
}
