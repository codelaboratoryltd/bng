package ha

import (
	"sync"
)

// InMemorySessionStore is a simple in-memory implementation of SessionStore.
// It's used for HA state synchronization when a more sophisticated backing
// store isn't needed.
type InMemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState
}

// NewInMemorySessionStore creates a new in-memory session store.
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions: make(map[string]*SessionState),
	}
}

// GetSession returns a session by ID.
func (s *InMemorySessionStore) GetSession(sessionID string) (*SessionState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	return sess, ok
}

// GetAllSessions returns all active sessions.
func (s *InMemorySessionStore) GetAllSessions() []SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]SessionState, 0, len(s.sessions))
	for _, sess := range s.sessions {
		result = append(result, *sess)
	}
	return result
}

// PutSession adds or updates a session.
func (s *InMemorySessionStore) PutSession(session *SessionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.SessionID] = session
	return nil
}

// DeleteSession removes a session.
func (s *InMemorySessionStore) DeleteSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

// GetSessionCount returns the number of active sessions.
func (s *InMemorySessionStore) GetSessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
