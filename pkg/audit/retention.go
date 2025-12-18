package audit

import (
	"sync"
	"time"
)

// RetentionManager manages data retention policies.
type RetentionManager struct {
	mu sync.RWMutex

	// Default retention in days
	defaultDays int

	// Per-category retention
	categoryDays map[string]int

	// Per-event-type retention (overrides category)
	eventTypeDays map[EventType]int

	// Legal hold - events matching these criteria are never deleted
	legalHolds []*LegalHold
}

// LegalHold represents a legal hold that prevents deletion.
type LegalHold struct {
	ID          string
	Description string
	CreatedAt   time.Time
	ExpiresAt   time.Time

	// Matching criteria (all that are set must match)
	SubscriberIDs []string
	IPAddresses   []string
	MACAddresses  []string
	SessionIDs    []string
	EventTypes    []EventType
	StartTime     time.Time
	EndTime       time.Time
}

// RetentionPolicy defines retention for a specific scope.
type RetentionPolicy struct {
	Name        string
	Description string
	Days        int
	Categories  []string
	EventTypes  []EventType
	Priority    int // Higher priority overrides lower
}

// NewRetentionManager creates a new retention manager.
func NewRetentionManager(defaultDays int, categoryDays map[string]int) *RetentionManager {
	rm := &RetentionManager{
		defaultDays:   defaultDays,
		categoryDays:  make(map[string]int),
		eventTypeDays: make(map[EventType]int),
		legalHolds:    make([]*LegalHold, 0),
	}

	if categoryDays != nil {
		for k, v := range categoryDays {
			rm.categoryDays[k] = v
		}
	}

	return rm
}

// GetRetention returns the retention period for a category.
func (rm *RetentionManager) GetRetention(category string) int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if days, ok := rm.categoryDays[category]; ok {
		return days
	}
	return rm.defaultDays
}

// GetRetentionForEvent returns the retention period for an event type.
func (rm *RetentionManager) GetRetentionForEvent(eventType EventType) int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Check event type override first
	if days, ok := rm.eventTypeDays[eventType]; ok {
		return days
	}

	// Fall back to category
	category := eventType.Category()
	if days, ok := rm.categoryDays[category]; ok {
		return days
	}

	return rm.defaultDays
}

// SetCategoryRetention sets retention for a category.
func (rm *RetentionManager) SetCategoryRetention(category string, days int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.categoryDays[category] = days
}

// SetEventTypeRetention sets retention for an event type.
func (rm *RetentionManager) SetEventTypeRetention(eventType EventType, days int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.eventTypeDays[eventType] = days
}

// AddLegalHold adds a legal hold.
func (rm *RetentionManager) AddLegalHold(hold *LegalHold) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if hold.CreatedAt.IsZero() {
		hold.CreatedAt = time.Now()
	}

	rm.legalHolds = append(rm.legalHolds, hold)
}

// RemoveLegalHold removes a legal hold by ID.
func (rm *RetentionManager) RemoveLegalHold(id string) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, hold := range rm.legalHolds {
		if hold.ID == id {
			rm.legalHolds = append(rm.legalHolds[:i], rm.legalHolds[i+1:]...)
			return true
		}
	}
	return false
}

// GetLegalHolds returns all active legal holds.
func (rm *RetentionManager) GetLegalHolds() []*LegalHold {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Return only non-expired holds
	now := time.Now()
	active := make([]*LegalHold, 0)
	for _, hold := range rm.legalHolds {
		if hold.ExpiresAt.IsZero() || hold.ExpiresAt.After(now) {
			active = append(active, hold)
		}
	}
	return active
}

// IsUnderLegalHold checks if an event is under legal hold.
func (rm *RetentionManager) IsUnderLegalHold(event *Event) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	now := time.Now()
	for _, hold := range rm.legalHolds {
		// Check if hold is expired
		if !hold.ExpiresAt.IsZero() && hold.ExpiresAt.Before(now) {
			continue
		}

		if rm.eventMatchesHold(event, hold) {
			return true
		}
	}
	return false
}

// eventMatchesHold checks if an event matches a legal hold's criteria.
func (rm *RetentionManager) eventMatchesHold(event *Event, hold *LegalHold) bool {
	// Time range check
	if !hold.StartTime.IsZero() && event.Timestamp.Before(hold.StartTime) {
		return false
	}
	if !hold.EndTime.IsZero() && event.Timestamp.After(hold.EndTime) {
		return false
	}

	// Subscriber ID check
	if len(hold.SubscriberIDs) > 0 {
		found := false
		for _, id := range hold.SubscriberIDs {
			if event.SubscriberID == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// IP address check
	if len(hold.IPAddresses) > 0 {
		found := false
		eventIP := ""
		if event.IPv4 != nil {
			eventIP = event.IPv4.String()
		}
		for _, ip := range hold.IPAddresses {
			if eventIP == ip {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// MAC address check
	if len(hold.MACAddresses) > 0 {
		found := false
		eventMAC := ""
		if event.MAC != nil {
			eventMAC = event.MAC.String()
		}
		for _, mac := range hold.MACAddresses {
			if eventMAC == mac {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Session ID check
	if len(hold.SessionIDs) > 0 {
		found := false
		for _, id := range hold.SessionIDs {
			if event.SessionID == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Event type check
	if len(hold.EventTypes) > 0 {
		found := false
		for _, et := range hold.EventTypes {
			if event.Type == et {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// CleanupExpiredHolds removes expired legal holds.
func (rm *RetentionManager) CleanupExpiredHolds() int {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	active := make([]*LegalHold, 0)
	expired := 0

	for _, hold := range rm.legalHolds {
		if hold.ExpiresAt.IsZero() || hold.ExpiresAt.After(now) {
			active = append(active, hold)
		} else {
			expired++
		}
	}

	rm.legalHolds = active
	return expired
}

// GetPolicySummary returns a summary of retention policies.
func (rm *RetentionManager) GetPolicySummary() map[string]int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	summary := make(map[string]int)
	summary["default"] = rm.defaultDays

	for category, days := range rm.categoryDays {
		summary["category:"+category] = days
	}

	for eventType, days := range rm.eventTypeDays {
		summary["event:"+string(eventType)] = days
	}

	return summary
}

// StandardRetentionPolicies returns standard ISP retention policies.
func StandardRetentionPolicies() map[string]int {
	return map[string]int{
		// Session data - 1 year (common legal requirement)
		"session": 365,

		// NAT mappings - 90 days to 1 year (varies by jurisdiction)
		// Many countries require IP address to subscriber mapping
		"nat": 365,

		// Authentication logs - 1 year
		"auth": 365,

		// DHCP logs - shorter retention, less critical
		"dhcp": 90,

		// Admin actions - 2 years (audit trail)
		"admin": 730,

		// Policy violations - 1 year
		"policy": 365,

		// Walled garden - 90 days
		"walledgarden": 90,

		// System events - 30 days
		"system": 30,
	}
}

// LegalRetentionRequirements documents common legal requirements.
type LegalRetentionRequirements struct {
	Jurisdiction string
	Description  string
	SessionDays  int
	NATDays      int
	AuthDays     int
	Reference    string
}

// CommonLegalRequirements returns retention requirements for common jurisdictions.
func CommonLegalRequirements() []LegalRetentionRequirements {
	return []LegalRetentionRequirements{
		{
			Jurisdiction: "EU",
			Description:  "EU Data Retention (post-2014 ruling, varies by member state)",
			SessionDays:  365,
			NATDays:      365,
			AuthDays:     365,
			Reference:    "Varies by member state post Digital Rights Ireland ruling",
		},
		{
			Jurisdiction: "UK",
			Description:  "UK Investigatory Powers Act 2016",
			SessionDays:  365,
			NATDays:      365,
			AuthDays:     365,
			Reference:    "IPA 2016 - Internet Connection Records",
		},
		{
			Jurisdiction: "US",
			Description:  "US - No federal mandate, varies by state",
			SessionDays:  180,
			NATDays:      180,
			AuthDays:     180,
			Reference:    "No federal requirement, best practice",
		},
		{
			Jurisdiction: "AU",
			Description:  "Australia Telecommunications (Interception and Access) Act",
			SessionDays:  730,
			NATDays:      730,
			AuthDays:     730,
			Reference:    "Metadata Retention Scheme - 2 years",
		},
	}
}
