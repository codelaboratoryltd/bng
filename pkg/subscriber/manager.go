package subscriber

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Authenticator is the interface for authentication backends.
type Authenticator interface {
	// Authenticate attempts to authenticate a session request.
	Authenticate(ctx context.Context, req *SessionRequest) (*AuthResult, error)
}

// AddressAllocator is the interface for IP address allocation.
type AddressAllocator interface {
	// AllocateIPv4 allocates an IPv4 address for a session.
	AllocateIPv4(ctx context.Context, session *Session, poolID string) (net.IP, net.IPMask, net.IP, error)
	// AllocateIPv6 allocates an IPv6 address for a session.
	AllocateIPv6(ctx context.Context, session *Session, poolID string) (net.IP, *net.IPNet, error)
	// ReleaseIPv4 releases an IPv4 address.
	ReleaseIPv4(ctx context.Context, ip net.IP) error
	// ReleaseIPv6 releases an IPv6 address.
	ReleaseIPv6(ctx context.Context, ip net.IP) error
}

// EventHandler is called when session events occur.
type EventHandler func(event *SessionEvent)

// Manager manages subscriber sessions.
type Manager struct {
	config    ManagerConfig
	logger    *zap.Logger
	auth      Authenticator
	allocator AddressAllocator
	handlers  []EventHandler

	mu       sync.RWMutex
	sessions map[string]*Session // ID -> Session
	byMAC    map[string]string   // MAC -> session ID
	byIP     map[string]string   // IP -> session ID

	stats ManagerStats

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new session manager.
func NewManager(config ManagerConfig, auth Authenticator, allocator AddressAllocator, logger *zap.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		config:    config,
		logger:    logger,
		auth:      auth,
		allocator: allocator,
		sessions:  make(map[string]*Session),
		byMAC:     make(map[string]string),
		byIP:      make(map[string]string),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start starts the session manager.
func (m *Manager) Start() error {
	m.logger.Info("Starting session manager")

	// Start cleanup loop
	m.wg.Add(1)
	go m.cleanupLoop()

	m.logger.Info("Session manager started")
	return nil
}

// Stop stops the session manager.
func (m *Manager) Stop() error {
	m.logger.Info("Stopping session manager")
	m.cancel()
	m.wg.Wait()
	m.logger.Info("Session manager stopped")
	return nil
}

// OnEvent registers an event handler.
func (m *Manager) OnEvent(handler EventHandler) {
	m.handlers = append(m.handlers, handler)
}

// emitEvent sends an event to all handlers.
func (m *Manager) emitEvent(event *SessionEvent) {
	for _, handler := range m.handlers {
		handler(event)
	}
}

// CreateSession creates a new session from a request.
func (m *Manager) CreateSession(ctx context.Context, req *SessionRequest) (*Session, error) {
	m.mu.Lock()

	// Check capacity
	if len(m.sessions) >= m.config.MaxSessions {
		m.mu.Unlock()
		return nil, fmt.Errorf("max sessions reached")
	}

	// Check for existing session with same MAC
	if existingID, exists := m.byMAC[req.MAC.String()]; exists {
		m.mu.Unlock()
		return nil, fmt.Errorf("session already exists for MAC: %s (session %s)", req.MAC, existingID)
	}

	now := time.Now()
	session := &Session{
		ID:             uuid.New().String(),
		CreatedAt:      now,
		UpdatedAt:      now,
		MAC:            req.MAC,
		NTEID:          req.NTEID,
		ONUID:          req.ONUID,
		PONPort:        req.PONPort,
		STag:           req.STag,
		CTag:           req.CTag,
		Type:           req.Type,
		Username:       req.Username,
		State:          StateInit,
		StartTime:      now,
		LastActivity:   now,
		SessionTimeout: m.config.DefaultSessionTimeout,
		IdleTimeout:    m.config.DefaultIdleTimeout,
		InterfaceName:  req.InterfaceName,
		InterfaceID:    req.InterfaceID,
		Metadata:       make(map[string]string),
	}

	// Store circuit info in metadata
	if req.CircuitID != "" {
		session.Metadata["circuit_id"] = req.CircuitID
	}
	if req.RemoteID != "" {
		session.Metadata["remote_id"] = req.RemoteID
	}
	if req.Hostname != "" {
		session.Metadata["hostname"] = req.Hostname
	}

	// Add to maps
	m.sessions[session.ID] = session
	m.byMAC[req.MAC.String()] = session.ID

	m.stats.TotalSessionsCreated++
	m.mu.Unlock()

	m.logger.Info("Session created",
		zap.String("session_id", session.ID),
		zap.String("mac", req.MAC.String()),
		zap.String("type", string(req.Type)),
	)

	m.emitEvent(&SessionEvent{
		Type:      EventSessionCreate,
		SessionID: session.ID,
		Timestamp: now,
		NewState:  StateInit,
	})

	return session, nil
}

// Authenticate authenticates a session.
func (m *Manager) Authenticate(ctx context.Context, sessionID string) (*AuthResult, error) {
	m.mu.Lock()
	session, exists := m.sessions[sessionID]
	if !exists {
		m.mu.Unlock()
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	oldState := session.State
	session.State = StateAuthenticating
	session.UpdatedAt = time.Now()
	m.mu.Unlock()

	// Build auth request from session
	req := &SessionRequest{
		MAC:      session.MAC,
		NTEID:    session.NTEID,
		STag:     session.STag,
		CTag:     session.CTag,
		Type:     session.Type,
		Username: session.Username,
	}

	// Call authenticator
	authCtx, cancel := context.WithTimeout(ctx, m.config.AuthTimeout)
	defer cancel()

	result, err := m.auth.Authenticate(authCtx, req)
	if err != nil {
		m.mu.Lock()
		session.State = oldState
		session.StateReason = fmt.Sprintf("auth error: %v", err)
		m.stats.AuthFailures++
		m.mu.Unlock()

		m.emitEvent(&SessionEvent{
			Type:      EventSessionAuthFail,
			SessionID: sessionID,
			Timestamp: time.Now(),
			OldState:  StateAuthenticating,
			NewState:  oldState,
			Reason:    err.Error(),
		})

		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	m.mu.Lock()
	if result.Success {
		session.Authenticated = true
		session.SubscriberID = result.SubscriberID
		session.ISPID = result.ISPID
		session.RADIUSSessionID = result.RADIUSSessionID
		session.State = StateAddressAssign

		// Apply session attributes
		if result.SessionTimeout > 0 {
			session.SessionTimeout = result.SessionTimeout
		}
		if result.IdleTimeout > 0 {
			session.IdleTimeout = result.IdleTimeout
		}
		if result.DownloadRateBps > 0 {
			session.DownloadRateBps = result.DownloadRateBps
		}
		if result.UploadRateBps > 0 {
			session.UploadRateBps = result.UploadRateBps
		}
		if result.QoSPolicyID != "" {
			session.QoSPolicyID = result.QoSPolicyID
		}

		// Handle walled garden
		if result.WalledGarden {
			session.WalledGarden = true
			session.WalledReason = result.WalledReason
			session.State = StateWalledGarden
		}

		m.stats.AuthSuccesses++
	} else {
		session.State = oldState
		session.StateReason = result.Error
		m.stats.AuthFailures++
	}
	session.UpdatedAt = time.Now()
	m.mu.Unlock()

	eventType := EventSessionAuth
	if !result.Success {
		eventType = EventSessionAuthFail
	}

	m.emitEvent(&SessionEvent{
		Type:      eventType,
		SessionID: sessionID,
		Timestamp: time.Now(),
		OldState:  StateAuthenticating,
		NewState:  session.State,
		Details: map[string]any{
			"success":       result.Success,
			"subscriber_id": result.SubscriberID,
			"isp_id":        result.ISPID,
		},
	})

	m.logger.Info("Session authenticated",
		zap.String("session_id", sessionID),
		zap.Bool("success", result.Success),
		zap.String("subscriber_id", result.SubscriberID),
		zap.String("isp_id", result.ISPID),
	)

	return result, nil
}

// AssignAddress assigns IP addresses to a session.
func (m *Manager) AssignAddress(ctx context.Context, sessionID string, ipv4PoolID, ipv6PoolID string) error {
	m.mu.Lock()
	session, exists := m.sessions[sessionID]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("session not found: %s", sessionID)
	}
	m.mu.Unlock()

	// Allocate IPv4
	if ipv4PoolID != "" && m.allocator != nil {
		ip, mask, gateway, err := m.allocator.AllocateIPv4(ctx, session, ipv4PoolID)
		if err != nil {
			return fmt.Errorf("allocate IPv4: %w", err)
		}

		m.mu.Lock()
		session.IPv4 = ip
		session.SubnetMask = mask
		session.Gateway = gateway
		m.byIP[ip.String()] = sessionID
		m.mu.Unlock()
	}

	// Allocate IPv6
	if ipv6PoolID != "" && m.allocator != nil {
		ip, prefix, err := m.allocator.AllocateIPv6(ctx, session, ipv6PoolID)
		if err != nil {
			// IPv6 failure is not fatal
			m.logger.Warn("Failed to allocate IPv6",
				zap.String("session_id", sessionID),
				zap.Error(err),
			)
		} else {
			m.mu.Lock()
			session.IPv6 = ip
			session.IPv6Prefix = prefix
			if ip != nil {
				m.byIP[ip.String()] = sessionID
			}
			m.mu.Unlock()
		}
	}

	m.mu.Lock()
	session.State = StateEstablishing
	session.UpdatedAt = time.Now()
	m.mu.Unlock()

	m.logger.Info("Address assigned",
		zap.String("session_id", sessionID),
		zap.String("ipv4", session.IPv4.String()),
	)

	return nil
}

// ActivateSession marks a session as active.
func (m *Manager) ActivateSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	oldState := session.State
	if session.WalledGarden {
		session.State = StateWalledGarden
	} else {
		session.State = StateActive
	}
	session.UpdatedAt = time.Now()
	session.LastActivity = time.Now()

	m.emitEvent(&SessionEvent{
		Type:      EventSessionActivate,
		SessionID: sessionID,
		Timestamp: time.Now(),
		OldState:  oldState,
		NewState:  session.State,
	})

	m.logger.Info("Session activated",
		zap.String("session_id", sessionID),
		zap.String("state", string(session.State)),
	)

	return nil
}

// SetWalledGarden puts a session in walled garden state.
func (m *Manager) SetWalledGarden(sessionID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	oldState := session.State
	session.WalledGarden = true
	session.WalledReason = reason
	session.State = StateWalledGarden
	session.UpdatedAt = time.Now()

	m.emitEvent(&SessionEvent{
		Type:      EventSessionWalled,
		SessionID: sessionID,
		Timestamp: time.Now(),
		OldState:  oldState,
		NewState:  StateWalledGarden,
		Reason:    reason,
	})

	m.logger.Info("Session walled",
		zap.String("session_id", sessionID),
		zap.String("reason", reason),
	)

	return nil
}

// ClearWalledGarden removes a session from walled garden.
func (m *Manager) ClearWalledGarden(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	if !session.WalledGarden {
		return nil // Already not walled
	}

	oldState := session.State
	session.WalledGarden = false
	session.WalledReason = ""
	session.State = StateActive
	session.UpdatedAt = time.Now()

	m.emitEvent(&SessionEvent{
		Type:      EventSessionUnwalled,
		SessionID: sessionID,
		Timestamp: time.Now(),
		OldState:  oldState,
		NewState:  StateActive,
	})

	m.logger.Info("Session unwalled",
		zap.String("session_id", sessionID),
	)

	return nil
}

// TerminateSession terminates a session.
func (m *Manager) TerminateSession(ctx context.Context, sessionID string, reason TerminateReason) error {
	m.mu.Lock()
	session, exists := m.sessions[sessionID]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("session not found: %s", sessionID)
	}

	oldState := session.State
	session.State = StateTerminating
	session.StateReason = string(reason)
	session.UpdatedAt = time.Now()
	m.mu.Unlock()

	// Release IP addresses
	if session.IPv4 != nil && m.allocator != nil {
		if err := m.allocator.ReleaseIPv4(ctx, session.IPv4); err != nil {
			m.logger.Warn("Failed to release IPv4",
				zap.String("session_id", sessionID),
				zap.Error(err),
			)
		}
	}
	if session.IPv6 != nil && m.allocator != nil {
		if err := m.allocator.ReleaseIPv6(ctx, session.IPv6); err != nil {
			m.logger.Warn("Failed to release IPv6",
				zap.String("session_id", sessionID),
				zap.Error(err),
			)
		}
	}

	m.mu.Lock()
	// Remove from indexes
	if session.MAC != nil {
		delete(m.byMAC, session.MAC.String())
	}
	if session.IPv4 != nil {
		delete(m.byIP, session.IPv4.String())
	}
	if session.IPv6 != nil {
		delete(m.byIP, session.IPv6.String())
	}

	// Update stats
	m.stats.TotalBytesIn += int64(session.BytesIn)
	m.stats.TotalBytesOut += int64(session.BytesOut)
	m.stats.TotalSessionsEnded++

	// Remove session
	delete(m.sessions, sessionID)
	m.mu.Unlock()

	m.emitEvent(&SessionEvent{
		Type:      EventSessionTerminate,
		SessionID: sessionID,
		Timestamp: time.Now(),
		OldState:  oldState,
		NewState:  StateTerminated,
		Reason:    string(reason),
		Details: map[string]any{
			"bytes_in":  session.BytesIn,
			"bytes_out": session.BytesOut,
			"duration":  time.Since(session.StartTime).String(),
		},
	})

	m.logger.Info("Session terminated",
		zap.String("session_id", sessionID),
		zap.String("reason", string(reason)),
		zap.Uint64("bytes_in", session.BytesIn),
		zap.Uint64("bytes_out", session.BytesOut),
	)

	return nil
}

// UpdateActivity updates session activity and traffic stats.
func (m *Manager) UpdateActivity(sessionID string, bytesIn, bytesOut, packetsIn, packetsOut uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.LastActivity = time.Now()
	session.BytesIn += bytesIn
	session.BytesOut += bytesOut
	session.PacketsIn += packetsIn
	session.PacketsOut += packetsOut

	return nil
}

// GetSession returns a session by ID.
func (m *Manager) GetSession(sessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[sessionID]
	return session, exists
}

// GetSessionByMAC returns a session by MAC address.
func (m *Manager) GetSessionByMAC(mac net.HardwareAddr) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, exists := m.byMAC[mac.String()]
	if !exists {
		return nil, false
	}
	return m.sessions[id], true
}

// GetSessionByIP returns a session by IP address.
func (m *Manager) GetSessionByIP(ip net.IP) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, exists := m.byIP[ip.String()]
	if !exists {
		return nil, false
	}
	return m.sessions[id], true
}

// ListSessions returns all active sessions.
func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	return result
}

// ListSessionsByISP returns sessions for a specific ISP.
func (m *Manager) ListSessionsByISP(ispID string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Session
	for _, s := range m.sessions {
		if s.ISPID == ispID {
			result = append(result, s)
		}
	}
	return result
}

// Stats returns manager statistics.
func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	stats.ActiveSessions = len(m.sessions)

	// Count walled garden sessions
	for _, s := range m.sessions {
		if s.WalledGarden {
			stats.WalledGardenSessions++
		}
	}

	return stats
}

// cleanupLoop periodically cleans up expired sessions.
func (m *Manager) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanupExpiredSessions()
		}
	}
}

// cleanupExpiredSessions terminates expired sessions.
func (m *Manager) cleanupExpiredSessions() {
	m.mu.RLock()
	var toTerminate []struct {
		id     string
		reason TerminateReason
	}

	now := time.Now()
	for id, session := range m.sessions {
		// Check session timeout
		if session.SessionTimeout > 0 {
			if now.Sub(session.StartTime) > session.SessionTimeout {
				toTerminate = append(toTerminate, struct {
					id     string
					reason TerminateReason
				}{id, TerminateSessionTimeout})
				continue
			}
		}

		// Check idle timeout
		if session.IdleTimeout > 0 {
			if now.Sub(session.LastActivity) > session.IdleTimeout {
				toTerminate = append(toTerminate, struct {
					id     string
					reason TerminateReason
				}{id, TerminateIdleTimeout})
			}
		}
	}
	m.mu.RUnlock()

	// Terminate outside the lock
	for _, t := range toTerminate {
		m.TerminateSession(context.Background(), t.id, t.reason)
	}

	if len(toTerminate) > 0 {
		m.logger.Info("Cleaned up expired sessions", zap.Int("count", len(toTerminate)))
	}
}
