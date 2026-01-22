package pppoe

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SessionState represents the state of a PPPoE session
type SessionState int

const (
	StateDiscovery SessionState = iota
	StateLCPNegotiation
	StateAuthentication
	StateIPCPNegotiation
	StateEstablished
	StateTerminating
	StateClosed
)

func (s SessionState) String() string {
	switch s {
	case StateDiscovery:
		return "Discovery"
	case StateLCPNegotiation:
		return "LCP Negotiation"
	case StateAuthentication:
		return "Authentication"
	case StateIPCPNegotiation:
		return "IPCP Negotiation"
	case StateEstablished:
		return "Established"
	case StateTerminating:
		return "Terminating"
	case StateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// Session represents a PPPoE session
type Session struct {
	ID          uint16
	ClientMAC   net.HardwareAddr
	ServerMAC   net.HardwareAddr
	State       SessionState
	ServiceName string
	HostUniq    []byte
	ACCookie    []byte

	// Authentication
	Username      string
	Authenticated bool
	AuthMethod    string // "PAP" or "CHAP"

	// LCP state
	LCPIdentifier uint8
	MagicNumber   uint32
	PeerMagic     uint32
	MRU           uint16
	PeerMRU       uint16

	// IP configuration
	ClientIP     net.IP
	ServerIP     net.IP
	PrimaryDNS   net.IP
	SecondaryDNS net.IP

	// Statistics
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64

	// Timing
	CreatedAt     time.Time
	EstablishedAt time.Time
	LastActivity  time.Time

	// RADIUS
	SessionID string
	Class     []byte

	mu sync.RWMutex
}

// NewSession creates a new PPPoE session
func NewSession(id uint16, clientMAC, serverMAC net.HardwareAddr) (*Session, error) {
	// Generate magic number
	magicBytes := make([]byte, 4)
	if _, err := rand.Read(magicBytes); err != nil {
		return nil, fmt.Errorf("failed to generate magic number: %w", err)
	}
	magic := uint32(magicBytes[0])<<24 | uint32(magicBytes[1])<<16 |
		uint32(magicBytes[2])<<8 | uint32(magicBytes[3])

	// Generate session ID
	sidBytes := make([]byte, 8)
	if _, err := rand.Read(sidBytes); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	return &Session{
		ID:           id,
		ClientMAC:    clientMAC,
		ServerMAC:    serverMAC,
		State:        StateDiscovery,
		MagicNumber:  magic,
		MRU:          1492, // Default PPPoE MRU
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		SessionID:    hex.EncodeToString(sidBytes),
	}, nil
}

// UpdateActivity updates the last activity timestamp
func (s *Session) UpdateActivity() {
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

// AddBytesIn adds bytes to the input counter
func (s *Session) AddBytesIn(n uint64) {
	atomic.AddUint64(&s.BytesIn, n)
	atomic.AddUint64(&s.PacketsIn, 1)
}

// AddBytesOut adds bytes to the output counter
func (s *Session) AddBytesOut(n uint64) {
	atomic.AddUint64(&s.BytesOut, n)
	atomic.AddUint64(&s.PacketsOut, 1)
}

// SetState updates the session state
func (s *Session) SetState(state SessionState) {
	s.mu.Lock()
	s.State = state
	if state == StateEstablished {
		s.EstablishedAt = time.Now()
	}
	s.mu.Unlock()
}

// GetState returns the current session state
func (s *Session) GetState() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State
}

// IsEstablished returns true if the session is established
func (s *Session) IsEstablished() bool {
	return s.GetState() == StateEstablished
}

// Duration returns the session duration
func (s *Session) Duration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.EstablishedAt.IsZero() {
		return 0
	}
	return time.Since(s.EstablishedAt)
}

// NextLCPIdentifier returns the next LCP identifier
func (s *Session) NextLCPIdentifier() uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LCPIdentifier++
	return s.LCPIdentifier
}

// SessionManager manages PPPoE sessions
type SessionManager struct {
	sessions     map[uint16]*Session
	macToSession map[string]uint16 // MAC string -> session ID
	nextID       uint16
	mu           sync.RWMutex
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:     make(map[uint16]*Session),
		macToSession: make(map[string]uint16),
		nextID:       1,
	}
}

// CreateSession creates a new session
func (m *SessionManager) CreateSession(clientMAC, serverMAC net.HardwareAddr) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find next available session ID
	for {
		if _, exists := m.sessions[m.nextID]; !exists {
			break
		}
		m.nextID++
		if m.nextID == 0 {
			m.nextID = 1 // Skip 0
		}
	}

	session, err := NewSession(m.nextID, clientMAC, serverMAC)
	if err != nil {
		return nil, err
	}
	m.sessions[m.nextID] = session
	m.macToSession[clientMAC.String()] = m.nextID
	m.nextID++

	return session, nil
}

// GetSession returns a session by ID
func (m *SessionManager) GetSession(id uint16) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// GetSessionByMAC returns a session by client MAC
func (m *SessionManager) GetSessionByMAC(mac net.HardwareAddr) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if id, ok := m.macToSession[mac.String()]; ok {
		return m.sessions[id]
	}
	return nil
}

// RemoveSession removes a session
func (m *SessionManager) RemoveSession(id uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, ok := m.sessions[id]; ok {
		delete(m.macToSession, session.ClientMAC.String())
		delete(m.sessions, id)
	}
}

// GetAllSessions returns all sessions
func (m *SessionManager) GetAllSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// Count returns the number of active sessions
func (m *SessionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// CleanupExpired removes sessions that have been inactive
func (m *SessionManager) CleanupExpired(timeout time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	var removed int
	now := time.Now()

	for id, session := range m.sessions {
		session.mu.RLock()
		inactive := now.Sub(session.LastActivity) > timeout
		session.mu.RUnlock()

		if inactive {
			delete(m.macToSession, session.ClientMAC.String())
			delete(m.sessions, id)
			removed++
		}
	}

	return removed
}
