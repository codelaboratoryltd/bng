package audit

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryStorage is an in-memory storage implementation for testing and development.
type MemoryStorage struct {
	mu     sync.RWMutex
	events map[string]*Event

	// Index by subscriber
	bySubscriber map[string][]string

	// Index by session
	bySession map[string][]string

	// Index by type
	byType map[EventType][]string

	// Index by timestamp (for range queries)
	byTime []*Event
}

// NewMemoryStorage creates a new in-memory storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		events:       make(map[string]*Event),
		bySubscriber: make(map[string][]string),
		bySession:    make(map[string][]string),
		byType:       make(map[EventType][]string),
		byTime:       make([]*Event, 0),
	}
}

// Store persists an event.
func (s *MemoryStorage) Store(ctx context.Context, event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events[event.ID] = event

	// Update indexes
	if event.SubscriberID != "" {
		s.bySubscriber[event.SubscriberID] = append(s.bySubscriber[event.SubscriberID], event.ID)
	}
	if event.SessionID != "" {
		s.bySession[event.SessionID] = append(s.bySession[event.SessionID], event.ID)
	}
	s.byType[event.Type] = append(s.byType[event.Type], event.ID)

	// Insert into time-sorted slice
	s.byTime = append(s.byTime, event)
	sort.Slice(s.byTime, func(i, j int) bool {
		return s.byTime[i].Timestamp.Before(s.byTime[j].Timestamp)
	})

	return nil
}

// StoreBatch persists multiple events.
func (s *MemoryStorage) StoreBatch(ctx context.Context, events []*Event) error {
	for _, event := range events {
		if err := s.Store(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// Query retrieves events matching criteria.
func (s *MemoryStorage) Query(ctx context.Context, query *Query) ([]*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var candidates []*Event

	// Start with time range if specified
	if !query.StartTime.IsZero() || !query.EndTime.IsZero() {
		for _, event := range s.byTime {
			if !query.StartTime.IsZero() && event.Timestamp.Before(query.StartTime) {
				continue
			}
			if !query.EndTime.IsZero() && event.Timestamp.After(query.EndTime) {
				continue
			}
			candidates = append(candidates, event)
		}
	} else {
		// No time filter, start with all events
		for _, event := range s.events {
			candidates = append(candidates, event)
		}
	}

	// Apply filters
	var results []*Event
	for _, event := range candidates {
		if s.matchesQuery(event, query) {
			results = append(results, event)
		}
	}

	// Sort by timestamp (descending by default)
	if query.Ascending {
		sort.Slice(results, func(i, j int) bool {
			return results[i].Timestamp.Before(results[j].Timestamp)
		})
	} else {
		sort.Slice(results, func(i, j int) bool {
			return results[i].Timestamp.After(results[j].Timestamp)
		})
	}

	// Apply offset and limit
	if query.Offset > 0 {
		if query.Offset >= len(results) {
			return []*Event{}, nil
		}
		results = results[query.Offset:]
	}

	if query.Limit > 0 && len(results) > query.Limit {
		results = results[:query.Limit]
	}

	return results, nil
}

// matchesQuery checks if an event matches query criteria.
func (s *MemoryStorage) matchesQuery(event *Event, query *Query) bool {
	// Type filter
	if len(query.Types) > 0 {
		found := false
		for _, t := range query.Types {
			if event.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Category filter
	if len(query.Categories) > 0 {
		found := false
		category := event.Type.Category()
		for _, c := range query.Categories {
			if category == c {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Subscriber filter
	if query.SubscriberID != "" && event.SubscriberID != query.SubscriberID {
		return false
	}

	// MAC filter
	if query.MAC != "" && (event.MAC == nil || event.MAC.String() != query.MAC) {
		return false
	}

	// IPv4 filter
	if query.IPv4 != "" && (event.IPv4 == nil || event.IPv4.String() != query.IPv4) {
		return false
	}

	// Session filter
	if query.SessionID != "" && event.SessionID != query.SessionID {
		return false
	}

	// ISP filter
	if query.ISPID != "" && event.ISPID != query.ISPID {
		return false
	}

	// Severity filter
	if event.Type.GetSeverity() < query.MinSeverity {
		return false
	}

	return true
}

// Delete removes events by ID.
func (s *MemoryStorage) Delete(ctx context.Context, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, id := range ids {
		event, exists := s.events[id]
		if !exists {
			continue
		}

		// Remove from indexes
		if event.SubscriberID != "" {
			s.removeFromIndex(s.bySubscriber, event.SubscriberID, id)
		}
		if event.SessionID != "" {
			s.removeFromIndex(s.bySession, event.SessionID, id)
		}
		s.removeFromTypeIndex(event.Type, id)

		// Remove from time index
		for i, e := range s.byTime {
			if e.ID == id {
				s.byTime = append(s.byTime[:i], s.byTime[i+1:]...)
				break
			}
		}

		delete(s.events, id)
	}

	return nil
}

// removeFromIndex removes an ID from a string index.
func (s *MemoryStorage) removeFromIndex(index map[string][]string, key, id string) {
	ids := index[key]
	for i, eid := range ids {
		if eid == id {
			index[key] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
}

// removeFromTypeIndex removes an ID from the type index.
func (s *MemoryStorage) removeFromTypeIndex(eventType EventType, id string) {
	ids := s.byType[eventType]
	for i, eid := range ids {
		if eid == id {
			s.byType[eventType] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
}

// DeleteExpired removes events past their retention.
func (s *MemoryStorage) DeleteExpired(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var expired []string

	for id, event := range s.events {
		if !event.ExpiresAt.IsZero() && event.ExpiresAt.Before(now) {
			expired = append(expired, id)
		}
	}

	// Unlock and call Delete (which will re-lock)
	s.mu.Unlock()
	err := s.Delete(ctx, expired)
	s.mu.Lock()

	return int64(len(expired)), err
}

// Close releases storage resources.
// Note: For MemoryStorage, we don't destroy data on Close() to allow
// querying after shutdown (useful for testing and graceful shutdown).
func (s *MemoryStorage) Close() error {
	// MemoryStorage has no resources to release.
	// Data is preserved for post-shutdown queries.
	return nil
}

// Clear removes all stored events and resets indexes.
// Use this to explicitly free memory when the data is no longer needed.
func (s *MemoryStorage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = make(map[string]*Event)
	s.bySubscriber = make(map[string][]string)
	s.bySession = make(map[string][]string)
	s.byType = make(map[EventType][]string)
	s.byTime = make([]*Event, 0)
}

// Count returns the number of stored events.
func (s *MemoryStorage) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// GetBySubscriber returns all events for a subscriber.
func (s *MemoryStorage) GetBySubscriber(subscriberID string) []*Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.bySubscriber[subscriberID]
	events := make([]*Event, 0, len(ids))
	for _, id := range ids {
		if event, ok := s.events[id]; ok {
			events = append(events, event)
		}
	}
	return events
}

// GetBySession returns all events for a session.
func (s *MemoryStorage) GetBySession(sessionID string) []*Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.bySession[sessionID]
	events := make([]*Event, 0, len(ids))
	for _, id := range ids {
		if event, ok := s.events[id]; ok {
			events = append(events, event)
		}
	}
	return events
}

// GetByType returns all events of a type.
func (s *MemoryStorage) GetByType(eventType EventType) []*Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.byType[eventType]
	events := make([]*Event, 0, len(ids))
	for _, id := range ids {
		if event, ok := s.events[id]; ok {
			events = append(events, event)
		}
	}
	return events
}

// Stats returns storage statistics.
func (s *MemoryStorage) Stats() MemoryStorageStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return MemoryStorageStats{
		TotalEvents: len(s.events),
		Subscribers: len(s.bySubscriber),
		Sessions:    len(s.bySession),
		EventTypes:  len(s.byType),
	}
}

// MemoryStorageStats holds memory storage statistics.
type MemoryStorageStats struct {
	TotalEvents int
	Subscribers int
	Sessions    int
	EventTypes  int
}
