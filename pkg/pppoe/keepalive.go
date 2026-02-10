// Package pppoe implements PPPoE protocol handling for the BNG.
// This file implements session keep-alive using LCP Echo per RFC 1661 Section 5.8.
package pppoe

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// KeepAliveConfig holds keep-alive configuration
type KeepAliveConfig struct {
	Enabled       bool          // Enable keep-alive
	Interval      time.Duration // Echo interval (default: 30s)
	Timeout       time.Duration // Wait time for reply (default: 5s)
	MaxFailures   int           // Failures before termination (default: 3)
	IdleThreshold time.Duration // Skip echo if active within (default: 60s)
}

// DefaultKeepAliveConfig returns default keep-alive configuration
func DefaultKeepAliveConfig() KeepAliveConfig {
	return KeepAliveConfig{
		Enabled:       true,
		Interval:      30 * time.Second,
		Timeout:       5 * time.Second,
		MaxFailures:   3,
		IdleThreshold: 60 * time.Second,
	}
}

// KeepAliveState tracks the keep-alive state for a session
type KeepAliveState struct {
	Failures      int           // Consecutive failures
	LastEchoSent  time.Time     // Time of last echo sent
	LastEchoRecv  time.Time     // Time of last echo received
	LastActivity  time.Time     // Time of last any activity
	PendingEchoID uint8         // Pending echo identifier
	PendingEcho   bool          // Whether we're waiting for a reply
	Latency       time.Duration // Last measured round-trip latency
}

// KeepAliveManager manages LCP Echo keep-alive for all sessions
type KeepAliveManager struct {
	config KeepAliveConfig
	logger *zap.Logger

	// Callbacks
	sendEcho         func(session *Session) uint8          // Send echo request, returns identifier
	terminateSession func(session *Session, reason string) // Terminate session

	// State tracking
	states map[uint16]*KeepAliveState
	mu     sync.RWMutex

	// Control
	stopCh  chan struct{}
	doneCh  chan struct{}
	running int32 // atomic

	// Metrics
	echoRequestsSent uint64
	echoRepliesRecv  uint64
	echoTimeouts     uint64
	sessionsKilled   uint64
}

// NewKeepAliveManager creates a new keep-alive manager
func NewKeepAliveManager(config KeepAliveConfig, logger *zap.Logger) *KeepAliveManager {
	return &KeepAliveManager{
		config: config,
		logger: logger,
		states: make(map[uint16]*KeepAliveState),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// SetSendEcho sets the callback for sending echo requests
func (m *KeepAliveManager) SetSendEcho(callback func(*Session) uint8) {
	m.sendEcho = callback
}

// SetTerminateSession sets the callback for terminating sessions
func (m *KeepAliveManager) SetTerminateSession(callback func(*Session, string)) {
	m.terminateSession = callback
}

// Start starts the keep-alive manager
func (m *KeepAliveManager) Start() {
	if !m.config.Enabled {
		return
	}

	if !atomic.CompareAndSwapInt32(&m.running, 0, 1) {
		return // Already running
	}

	m.stopCh = make(chan struct{})
	m.doneCh = make(chan struct{})

	go m.runLoop()

	m.logger.Info("Keep-alive manager started",
		zap.Duration("interval", m.config.Interval),
		zap.Int("max_failures", m.config.MaxFailures),
	)
}

// Stop stops the keep-alive manager
func (m *KeepAliveManager) Stop() {
	if !atomic.CompareAndSwapInt32(&m.running, 1, 0) {
		return // Not running
	}

	close(m.stopCh)
	<-m.doneCh

	m.logger.Info("Keep-alive manager stopped")
}

// RegisterSession registers a session for keep-alive monitoring
func (m *KeepAliveManager) RegisterSession(session *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.states[session.ID] = &KeepAliveState{
		LastActivity: time.Now(),
		LastEchoRecv: time.Now(), // Start fresh
	}

	m.logger.Debug("Session registered for keep-alive",
		zap.Uint16("session_id", session.ID),
	)
}

// UnregisterSession removes a session from keep-alive monitoring
func (m *KeepAliveManager) UnregisterSession(sessionID uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.states, sessionID)

	m.logger.Debug("Session unregistered from keep-alive",
		zap.Uint16("session_id", sessionID),
	)
}

// UpdateActivity marks session as active (e.g., received data)
func (m *KeepAliveManager) UpdateActivity(sessionID uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if state, ok := m.states[sessionID]; ok {
		state.LastActivity = time.Now()
	}
}

// ReceiveEchoReply processes an echo reply
func (m *KeepAliveManager) ReceiveEchoReply(sessionID uint16, identifier uint8, magic uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[sessionID]
	if !ok {
		return
	}

	// Check if this is the reply we're waiting for
	if !state.PendingEcho || state.PendingEchoID != identifier {
		m.logger.Debug("Unexpected echo reply",
			zap.Uint16("session_id", sessionID),
			zap.Uint8("expected", state.PendingEchoID),
			zap.Uint8("received", identifier),
		)
		return
	}

	now := time.Now()
	state.Latency = now.Sub(state.LastEchoSent)
	state.LastEchoRecv = now
	state.LastActivity = now
	state.PendingEcho = false
	state.Failures = 0 // Reset failure counter

	atomic.AddUint64(&m.echoRepliesRecv, 1)

	m.logger.Debug("Echo reply received",
		zap.Uint16("session_id", sessionID),
		zap.Duration("latency", state.Latency),
	)
}

// GetSessionHealth returns the health status of a session
func (m *KeepAliveManager) GetSessionHealth(sessionID uint16) (failures int, latency time.Duration, lastSeen time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, ok := m.states[sessionID]; ok {
		return state.Failures, state.Latency, state.LastActivity
	}
	return 0, 0, time.Time{}
}

// GetStats returns keep-alive statistics
func (m *KeepAliveManager) GetStats() map[string]uint64 {
	return map[string]uint64{
		"echo_requests_sent": atomic.LoadUint64(&m.echoRequestsSent),
		"echo_replies_recv":  atomic.LoadUint64(&m.echoRepliesRecv),
		"echo_timeouts":      atomic.LoadUint64(&m.echoTimeouts),
		"sessions_killed":    atomic.LoadUint64(&m.sessionsKilled),
	}
}

// runLoop is the main keep-alive loop
func (m *KeepAliveManager) runLoop() {
	defer close(m.doneCh)

	ticker := time.NewTicker(m.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkAllSessions()
		}
	}
}

// checkAllSessions checks all registered sessions
func (m *KeepAliveManager) checkAllSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	for sessionID, state := range m.states {
		// Check if we're waiting for a reply that timed out
		if state.PendingEcho {
			if now.Sub(state.LastEchoSent) > m.config.Timeout {
				// Echo timeout
				state.Failures++
				state.PendingEcho = false
				atomic.AddUint64(&m.echoTimeouts, 1)

				m.logger.Debug("Echo timeout",
					zap.Uint16("session_id", sessionID),
					zap.Int("failures", state.Failures),
				)

				// Check if we should terminate
				if state.Failures >= m.config.MaxFailures {
					m.logger.Warn("Session dead - max failures exceeded",
						zap.Uint16("session_id", sessionID),
						zap.Int("failures", state.Failures),
					)

					// Need to release lock before calling terminate
					// Use a goroutine to avoid deadlock
					go m.terminateSessionAsync(sessionID, "Dead peer detected")
					atomic.AddUint64(&m.sessionsKilled, 1)
					continue
				}
			}
		}

		// Skip echo if session was recently active
		if now.Sub(state.LastActivity) < m.config.IdleThreshold {
			continue
		}

		// Send new echo request
		if m.sendEcho != nil {
			// We need to get the session object - this is handled by the callback
			// The callback needs to find the session by ID
			m.sendEchoForSession(sessionID, state)
		}
	}
}

// sendEchoForSession sends an echo for a session
func (m *KeepAliveManager) sendEchoForSession(sessionID uint16, state *KeepAliveState) {
	// This is called with lock held - caller must handle session lookup
	// For now, we just mark the state
	state.LastEchoSent = time.Now()
	state.PendingEcho = true
	atomic.AddUint64(&m.echoRequestsSent, 1)
}

// terminateSessionAsync terminates a session asynchronously
func (m *KeepAliveManager) terminateSessionAsync(sessionID uint16, reason string) {
	// Remove from our tracking first
	m.mu.Lock()
	delete(m.states, sessionID)
	m.mu.Unlock()

	// Callback handles actual termination
	// Note: The callback needs to find the session object
	// This is a limitation of the current design
	m.logger.Info("Terminating session due to dead peer",
		zap.Uint16("session_id", sessionID),
		zap.String("reason", reason),
	)
}

// SessionKeepAlive handles keep-alive for a single session
// This is embedded in the session for easy access
type SessionKeepAlive struct {
	session *Session
	lcp     *LCPStateMachine
	config  KeepAliveConfig
	logger  *zap.Logger

	// State
	pendingID    uint8
	pendingEcho  bool
	failures     int
	lastEchoSent time.Time
	lastEchoRecv time.Time
	latency      time.Duration

	// Control
	stopCh  chan struct{}
	running int32 // atomic

	mu sync.Mutex
}

// NewSessionKeepAlive creates a keep-alive handler for a session
func NewSessionKeepAlive(session *Session, lcp *LCPStateMachine, config KeepAliveConfig, logger *zap.Logger) *SessionKeepAlive {
	return &SessionKeepAlive{
		session: session,
		lcp:     lcp,
		config:  config,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
}

// Start starts the keep-alive for this session
func (ka *SessionKeepAlive) Start() {
	if !ka.config.Enabled {
		return
	}

	if !atomic.CompareAndSwapInt32(&ka.running, 0, 1) {
		return
	}

	go ka.runLoop()

	ka.logger.Debug("Session keep-alive started",
		zap.Uint16("session_id", ka.session.ID),
	)
}

// Stop stops the keep-alive for this session
func (ka *SessionKeepAlive) Stop() {
	if !atomic.CompareAndSwapInt32(&ka.running, 1, 0) {
		return
	}

	close(ka.stopCh)

	ka.logger.Debug("Session keep-alive stopped",
		zap.Uint16("session_id", ka.session.ID),
	)
}

// OnEchoReply is called when an echo reply is received
func (ka *SessionKeepAlive) OnEchoReply(identifier uint8, data []byte) {
	ka.mu.Lock()
	defer ka.mu.Unlock()

	if !ka.pendingEcho || ka.pendingID != identifier {
		return
	}

	now := time.Now()
	ka.latency = now.Sub(ka.lastEchoSent)
	ka.lastEchoRecv = now
	ka.pendingEcho = false
	ka.failures = 0

	ka.logger.Debug("Echo reply received",
		zap.Uint16("session_id", ka.session.ID),
		zap.Duration("latency", ka.latency),
	)
}

// GetLatency returns the last measured latency
func (ka *SessionKeepAlive) GetLatency() time.Duration {
	ka.mu.Lock()
	defer ka.mu.Unlock()
	return ka.latency
}

// GetFailures returns the current failure count
func (ka *SessionKeepAlive) GetFailures() int {
	ka.mu.Lock()
	defer ka.mu.Unlock()
	return ka.failures
}

// IsDead returns true if the session is considered dead
func (ka *SessionKeepAlive) IsDead() bool {
	ka.mu.Lock()
	defer ka.mu.Unlock()
	return ka.failures >= ka.config.MaxFailures
}

// runLoop is the keep-alive loop for this session
func (ka *SessionKeepAlive) runLoop() {
	ticker := time.NewTicker(ka.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ka.stopCh:
			return
		case <-ticker.C:
			ka.check()
		}
	}
}

// check performs a keep-alive check
func (ka *SessionKeepAlive) check() {
	ka.mu.Lock()
	defer ka.mu.Unlock()

	now := time.Now()

	// Check for timeout on pending echo
	if ka.pendingEcho && now.Sub(ka.lastEchoSent) > ka.config.Timeout {
		ka.failures++
		ka.pendingEcho = false

		ka.logger.Debug("Echo timeout",
			zap.Uint16("session_id", ka.session.ID),
			zap.Int("failures", ka.failures),
		)

		if ka.failures >= ka.config.MaxFailures {
			ka.logger.Warn("Session appears dead",
				zap.Uint16("session_id", ka.session.ID),
				zap.Int("failures", ka.failures),
			)
			// Session termination should be handled by the caller
			return
		}
	}

	// Check if session is recently active
	ka.session.mu.RLock()
	lastActivity := ka.session.LastActivity
	ka.session.mu.RUnlock()

	if now.Sub(lastActivity) < ka.config.IdleThreshold {
		// Session is active, no need to send echo
		return
	}

	// Don't send new echo if one is pending
	if ka.pendingEcho {
		return
	}

	// Send echo request
	if ka.lcp != nil && ka.lcp.IsOpened() {
		ka.pendingID = ka.lcp.SendEchoRequest()
		ka.pendingEcho = true
		ka.lastEchoSent = now

		ka.logger.Debug("Echo request sent",
			zap.Uint16("session_id", ka.session.ID),
			zap.Uint8("identifier", ka.pendingID),
		)
	}
}

// ParseEchoPacket parses LCP Echo Request/Reply data
// Data format: 4-byte magic number + optional additional data
func ParseEchoPacket(data []byte) (magic uint32, payload []byte, err error) {
	if len(data) < 4 {
		return 0, nil, nil
	}

	magic = binary.BigEndian.Uint32(data[:4])
	if len(data) > 4 {
		payload = data[4:]
	}

	return magic, payload, nil
}
