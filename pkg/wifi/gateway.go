// Package wifi provides WiFi Gateway Mode for standalone DHCP/subscriber management
// without the full OLT-BNG architecture. This enables deployment on standard x86
// gateway appliances for enterprise WiFi and similar use cases.
//
// Key differences from OLT-BNG mode:
//   - IP allocation happens on DHCP DISCOVER (not at RADIUS authentication time)
//   - Subscriber identity is unknown until captive portal authentication
//   - Higher cache miss rate due to new devices constantly arriving
//   - Shorter session lifetimes (minutes/hours vs days)
//   - Nexus integration is optional
package wifi

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// OperatingMode defines the BNG operating mode
type OperatingMode string

const (
	// ModeOLTBNG is the standard OLT-BNG mode with RADIUS-first allocation
	ModeOLTBNG OperatingMode = "olt_bng"
	// ModeWiFiGateway is the WiFi gateway mode with DHCP-first allocation
	ModeWiFiGateway OperatingMode = "wifi_gateway"
)

// Config holds configuration for WiFi gateway mode
type Config struct {
	// Mode is the operating mode
	Mode OperatingMode `json:"mode"`

	// AllocationTrigger defines when IP allocation happens
	// "dhcp_discover" - allocate on DHCP DISCOVER (WiFi mode)
	// "radius_auth" - allocate after RADIUS authentication (OLT-BNG mode)
	AllocationTrigger string `json:"allocation_trigger"`

	// DeallocationTrigger defines when IPs are released
	// "lease_expiry" - release when DHCP lease expires
	// "session_termination" - release when session terminates (RADIUS-driven)
	DeallocationTrigger string `json:"deallocation_trigger"`

	// LeaseDuration is the default DHCP lease duration
	LeaseDuration time.Duration `json:"lease_duration"`

	// NexusEnabled indicates whether Nexus is used for IP coordination
	NexusEnabled bool `json:"nexus_enabled"`

	// PONEnabled indicates whether PON features are active
	PONEnabled bool `json:"pon_enabled"`

	// PPPoEEnabled indicates whether PPPoE is active
	PPPoEEnabled bool `json:"pppoe_enabled"`

	// CaptivePortalEnabled indicates whether captive portal is active
	CaptivePortalEnabled bool `json:"captive_portal_enabled"`

	// CaptivePortalURL is the URL to redirect unauthenticated users to
	CaptivePortalURL string `json:"captive_portal_url,omitempty"`

	// GracePeriod is the time allowed for captive portal authentication
	// before the session is terminated
	GracePeriod time.Duration `json:"grace_period"`
}

// DefaultWiFiConfig returns default configuration for WiFi gateway mode
func DefaultWiFiConfig() Config {
	return Config{
		Mode:                 ModeWiFiGateway,
		AllocationTrigger:    "dhcp_discover",
		DeallocationTrigger:  "lease_expiry",
		LeaseDuration:        30 * time.Minute,
		NexusEnabled:         false,
		PONEnabled:           false,
		PPPoEEnabled:         false,
		CaptivePortalEnabled: true,
		GracePeriod:          5 * time.Minute,
	}
}

// DefaultOLTBNGConfig returns default configuration for OLT-BNG mode
func DefaultOLTBNGConfig() Config {
	return Config{
		Mode:                 ModeOLTBNG,
		AllocationTrigger:    "radius_auth",
		DeallocationTrigger:  "session_termination",
		LeaseDuration:        24 * time.Hour,
		NexusEnabled:         true,
		PONEnabled:           true,
		PPPoEEnabled:         true,
		CaptivePortalEnabled: false,
	}
}

// Session represents a WiFi gateway session
type Session struct {
	ID       string           `json:"id"`
	MAC      net.HardwareAddr `json:"mac"`
	IP       net.IP           `json:"ip"`
	Hostname string           `json:"hostname,omitempty"`
	PoolID   uint32           `json:"pool_id"`

	// Session state
	State         SessionState `json:"state"`
	Authenticated bool         `json:"authenticated"`
	AuthMethod    string       `json:"auth_method,omitempty"`
	UserIdentity  string       `json:"user_identity,omitempty"` // From captive portal

	// Timing
	CreatedAt       time.Time     `json:"created_at"`
	LeaseExpiry     time.Time     `json:"lease_expiry"`
	AuthenticatedAt time.Time     `json:"authenticated_at,omitempty"`
	GracePeriodEnds time.Time     `json:"grace_period_ends,omitempty"`
	LastRenewal     time.Time     `json:"last_renewal"`
	LeaseDuration   time.Duration `json:"lease_duration"`

	// Traffic stats
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`

	// Device info (if available)
	VendorClass string `json:"vendor_class,omitempty"`
	UserClass   string `json:"user_class,omitempty"`
}

// SessionState represents the state of a WiFi session
type SessionState string

const (
	// StateNew is a newly created session (DHCP DISCOVER received)
	StateNew SessionState = "new"
	// StateGracePeriod is waiting for captive portal authentication
	StateGracePeriod SessionState = "grace_period"
	// StateAuthenticated is a fully authenticated session
	StateAuthenticated SessionState = "authenticated"
	// StateActive is an active session with traffic flowing
	StateActive SessionState = "active"
	// StateExpired is an expired session
	StateExpired SessionState = "expired"
)

// Manager manages WiFi gateway sessions
type Manager struct {
	config Config
	logger *zap.Logger

	mu       sync.RWMutex
	sessions map[string]*Session // MAC string -> Session
	byIP     map[string]string   // IP string -> MAC string

	// Callbacks
	onSessionCreate func(*Session)
	onSessionAuth   func(*Session)
	onSessionExpire func(*Session)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new WiFi gateway manager
func NewManager(config Config, logger *zap.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		config:   config,
		logger:   logger,
		sessions: make(map[string]*Session),
		byIP:     make(map[string]string),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start starts the WiFi gateway manager
func (m *Manager) Start() error {
	m.logger.Info("Starting WiFi gateway manager",
		zap.String("mode", string(m.config.Mode)),
		zap.Duration("lease_duration", m.config.LeaseDuration),
	)

	// Start cleanup goroutine
	m.wg.Add(1)
	go m.cleanupLoop()

	return nil
}

// Stop stops the WiFi gateway manager
func (m *Manager) Stop() error {
	m.logger.Info("Stopping WiFi gateway manager")
	m.cancel()
	m.wg.Wait()
	return nil
}

// OnSessionCreate registers a callback for session creation
func (m *Manager) OnSessionCreate(callback func(*Session)) {
	m.onSessionCreate = callback
}

// OnSessionAuth registers a callback for session authentication
func (m *Manager) OnSessionAuth(callback func(*Session)) {
	m.onSessionAuth = callback
}

// OnSessionExpire registers a callback for session expiration
func (m *Manager) OnSessionExpire(callback func(*Session)) {
	m.onSessionExpire = callback
}

// CreateSession creates a new session for a DHCP DISCOVER
// In WiFi gateway mode, this is where IP allocation happens
func (m *Manager) CreateSession(mac net.HardwareAddr, hostname string, poolID uint32, ip net.IP) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	macStr := mac.String()
	now := time.Now()

	// Check for existing session
	if existing, ok := m.sessions[macStr]; ok {
		// Renew existing session
		existing.LeaseExpiry = now.Add(m.config.LeaseDuration)
		existing.LastRenewal = now
		m.logger.Debug("Renewed existing session",
			zap.String("mac", macStr),
			zap.Time("expiry", existing.LeaseExpiry),
		)
		return existing, nil
	}

	// Create new session
	session := &Session{
		ID:            generateSessionID(),
		MAC:           mac,
		IP:            ip,
		Hostname:      hostname,
		PoolID:        poolID,
		State:         StateNew,
		Authenticated: false,
		CreatedAt:     now,
		LeaseExpiry:   now.Add(m.config.LeaseDuration),
		LastRenewal:   now,
		LeaseDuration: m.config.LeaseDuration,
	}

	// Set grace period if captive portal is enabled
	if m.config.CaptivePortalEnabled {
		session.State = StateGracePeriod
		session.GracePeriodEnds = now.Add(m.config.GracePeriod)
	}

	m.sessions[macStr] = session
	m.byIP[ip.String()] = macStr

	m.logger.Info("Created WiFi session",
		zap.String("session_id", session.ID),
		zap.String("mac", macStr),
		zap.String("ip", ip.String()),
		zap.String("state", string(session.State)),
	)

	if m.onSessionCreate != nil {
		go m.onSessionCreate(session)
	}

	return session, nil
}

// RenewSession renews a session's lease
func (m *Manager) RenewSession(mac net.HardwareAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	macStr := mac.String()
	session, ok := m.sessions[macStr]
	if !ok {
		return fmt.Errorf("session not found for MAC %s", macStr)
	}

	now := time.Now()
	session.LeaseExpiry = now.Add(m.config.LeaseDuration)
	session.LastRenewal = now

	m.logger.Debug("Renewed session",
		zap.String("mac", macStr),
		zap.Time("expiry", session.LeaseExpiry),
	)

	return nil
}

// AuthenticateSession marks a session as authenticated (after captive portal)
func (m *Manager) AuthenticateSession(mac net.HardwareAddr, authMethod, userIdentity string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	macStr := mac.String()
	session, ok := m.sessions[macStr]
	if !ok {
		return fmt.Errorf("session not found for MAC %s", macStr)
	}

	now := time.Now()
	session.Authenticated = true
	session.AuthMethod = authMethod
	session.UserIdentity = userIdentity
	session.AuthenticatedAt = now
	session.State = StateAuthenticated

	m.logger.Info("Session authenticated",
		zap.String("session_id", session.ID),
		zap.String("mac", macStr),
		zap.String("auth_method", authMethod),
		zap.String("user_identity", userIdentity),
	)

	if m.onSessionAuth != nil {
		go m.onSessionAuth(session)
	}

	return nil
}

// ReleaseSession releases a session (DHCP RELEASE or timeout)
func (m *Manager) ReleaseSession(mac net.HardwareAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	macStr := mac.String()
	session, ok := m.sessions[macStr]
	if !ok {
		return nil // Already released
	}

	delete(m.sessions, macStr)
	if session.IP != nil {
		delete(m.byIP, session.IP.String())
	}

	m.logger.Info("Session released",
		zap.String("session_id", session.ID),
		zap.String("mac", macStr),
		zap.Uint64("bytes_in", session.BytesIn),
		zap.Uint64("bytes_out", session.BytesOut),
	)

	if m.onSessionExpire != nil {
		go m.onSessionExpire(session)
	}

	return nil
}

// GetSession returns a session by MAC address
func (m *Manager) GetSession(mac net.HardwareAddr) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[mac.String()]
	return session, ok
}

// GetSessionByIP returns a session by IP address
func (m *Manager) GetSessionByIP(ip net.IP) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	macStr, ok := m.byIP[ip.String()]
	if !ok {
		return nil, false
	}

	session, ok := m.sessions[macStr]
	return session, ok
}

// ListSessions returns all active sessions
func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		result = append(result, session)
	}
	return result
}

// UpdateTrafficStats updates traffic counters for a session
func (m *Manager) UpdateTrafficStats(mac net.HardwareAddr, bytesIn, bytesOut, packetsIn, packetsOut uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[mac.String()]
	if !ok {
		return
	}

	session.BytesIn += bytesIn
	session.BytesOut += bytesOut
	session.PacketsIn += packetsIn
	session.PacketsOut += packetsOut
}

// IsInGracePeriod checks if a session is still in its grace period
func (m *Manager) IsInGracePeriod(mac net.HardwareAddr) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[mac.String()]
	if !ok {
		return false
	}

	return session.State == StateGracePeriod && time.Now().Before(session.GracePeriodEnds)
}

// NeedsAuthentication checks if a session requires captive portal authentication
func (m *Manager) NeedsAuthentication(mac net.HardwareAddr) bool {
	if !m.config.CaptivePortalEnabled {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[mac.String()]
	if !ok {
		return true // No session = needs auth
	}

	return !session.Authenticated
}

// Stats returns WiFi gateway statistics
func (m *Manager) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := Stats{
		ActiveSessions: len(m.sessions),
	}

	now := time.Now()
	for _, session := range m.sessions {
		if session.Authenticated {
			stats.AuthenticatedSessions++
		}
		if session.State == StateGracePeriod && now.Before(session.GracePeriodEnds) {
			stats.GracePeriodSessions++
		}
		stats.TotalBytesIn += session.BytesIn
		stats.TotalBytesOut += session.BytesOut
	}

	return stats
}

// Stats holds WiFi gateway statistics
type Stats struct {
	ActiveSessions        int    `json:"active_sessions"`
	AuthenticatedSessions int    `json:"authenticated_sessions"`
	GracePeriodSessions   int    `json:"grace_period_sessions"`
	TotalBytesIn          uint64 `json:"total_bytes_in"`
	TotalBytesOut         uint64 `json:"total_bytes_out"`
}

// cleanupLoop periodically removes expired sessions
func (m *Manager) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Minute)
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

// cleanupExpiredSessions removes expired sessions
func (m *Manager) cleanupExpiredSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var expired []string

	for macStr, session := range m.sessions {
		expired_session := false

		// Check lease expiry
		if now.After(session.LeaseExpiry) {
			expired_session = true
		}

		// Check grace period expiry for unauthenticated sessions
		if session.State == StateGracePeriod && !session.Authenticated {
			if now.After(session.GracePeriodEnds) {
				expired_session = true
			}
		}

		if expired_session {
			expired = append(expired, macStr)
		}
	}

	for _, macStr := range expired {
		session := m.sessions[macStr]
		delete(m.sessions, macStr)
		if session.IP != nil {
			delete(m.byIP, session.IP.String())
		}

		m.logger.Info("Session expired",
			zap.String("session_id", session.ID),
			zap.String("mac", macStr),
			zap.String("state", string(session.State)),
			zap.Bool("authenticated", session.Authenticated),
		)

		if m.onSessionExpire != nil {
			go m.onSessionExpire(session)
		}
	}

	if len(expired) > 0 {
		m.logger.Info("Cleaned up expired sessions", zap.Int("count", len(expired)))
	}
}

// GetConfig returns the current configuration
func (m *Manager) GetConfig() Config {
	return m.config
}

// Helper function to generate a unique session ID
func generateSessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
