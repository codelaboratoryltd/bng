package audit_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/audit"
	"go.uber.org/zap"
)

func TestEventType_String(t *testing.T) {
	tests := []struct {
		eventType audit.EventType
		category  string
		severity  audit.Severity
	}{
		{audit.EventSessionStart, "session", audit.SeverityInfo},
		{audit.EventSessionStop, "session", audit.SeverityInfo},
		{audit.EventAuthSuccess, "auth", audit.SeverityInfo},
		{audit.EventAuthFailure, "auth", audit.SeverityWarning},
		{audit.EventNATMapping, "nat", audit.SeverityDebug},
		{audit.EventDHCPAck, "dhcp", audit.SeverityInfo},
		{audit.EventPolicyViolation, "policy", audit.SeverityWarning},
		{audit.EventSystemError, "system", audit.SeverityError},
	}

	for _, tt := range tests {
		if got := tt.eventType.Category(); got != tt.category {
			t.Errorf("EventType(%s).Category() = %s, want %s", tt.eventType, got, tt.category)
		}
		if got := tt.eventType.GetSeverity(); got != tt.severity {
			t.Errorf("EventType(%s).GetSeverity() = %v, want %v", tt.eventType, got, tt.severity)
		}
	}
}

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		severity audit.Severity
		expected string
	}{
		{audit.SeverityDebug, "DEBUG"},
		{audit.SeverityInfo, "INFO"},
		{audit.SeverityNotice, "NOTICE"},
		{audit.SeverityWarning, "WARNING"},
		{audit.SeverityError, "ERROR"},
		{audit.SeverityCritical, "CRITICAL"},
		{audit.SeverityAlert, "ALERT"},
		{audit.SeverityEmergency, "EMERGENCY"},
	}

	for _, tt := range tests {
		if got := tt.severity.String(); got != tt.expected {
			t.Errorf("Severity(%d).String() = %s, want %s", tt.severity, got, tt.expected)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	config := audit.DefaultConfig()

	if config.BufferSize == 0 {
		t.Error("BufferSize should not be 0")
	}

	if config.FlushInterval == 0 {
		t.Error("FlushInterval should not be 0")
	}

	if config.DefaultRetentionDays == 0 {
		t.Error("DefaultRetentionDays should not be 0")
	}

	if len(config.RetentionByCategory) == 0 {
		t.Error("RetentionByCategory should not be empty")
	}
}

func TestLogger_StartStop(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.DeviceID = "test-device"
	config.SyncWrites = true // Synchronous for testing

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	if err := auditLogger.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Allow time for goroutines
	time.Sleep(10 * time.Millisecond)

	if err := auditLogger.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Should have system start and stop events
	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventSystemStart, audit.EventSystemStop},
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(events) < 2 {
		t.Errorf("Expected at least 2 system events, got %d", len(events))
	}
}

func TestLogger_LogEvent(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.DeviceID = "test-device"
	config.SyncWrites = true // Synchronous for testing

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	if err := auditLogger.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer auditLogger.Stop()

	// Log a session event
	event := &audit.Event{
		Type:         audit.EventSessionStart,
		SubscriberID: "sub-123",
		SessionID:    "sess-456",
		MAC:          net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		IPv4:         net.ParseIP("10.0.0.100"),
		ISPID:        "ISP-A",
	}

	auditLogger.LogEvent(event)

	// Query for it
	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventSessionStart},
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	found := false
	for _, e := range events {
		if e.SessionID == "sess-456" {
			found = true
			if e.SubscriberID != "sub-123" {
				t.Errorf("SubscriberID = %s, want sub-123", e.SubscriberID)
			}
			if e.ID == "" {
				t.Error("Event should have an ID")
			}
			if e.Timestamp.IsZero() {
				t.Error("Event should have a timestamp")
			}
			if e.DeviceID != "test-device" {
				t.Errorf("DeviceID = %s, want test-device", e.DeviceID)
			}
		}
	}

	if !found {
		t.Error("Logged event not found")
	}
}

func TestLogger_LogSessionLifecycle(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.DeviceID = "test-device"
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	if err := auditLogger.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer auditLogger.Stop()

	// Log session start
	session := &audit.SessionEvent{
		Event: audit.Event{
			SubscriberID: "sub-123",
			SessionID:    "sess-789",
			IPv4:         net.ParseIP("10.0.0.50"),
		},
		ConnectionType: "IPoE",
		PONPort:        "pon1",
	}

	auditLogger.LogSessionStart(session)

	// Simulate session duration
	time.Sleep(10 * time.Millisecond)

	// Add some traffic
	session.BytesIn = 1000000
	session.BytesOut = 500000
	session.TermCause = "User-Request"

	auditLogger.LogSessionStop(session)

	// Query for session events
	events, err := storage.Query(context.Background(), &audit.Query{
		SessionID: "sess-789",
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	// Should have start and stop events
	hasStart := false
	hasStop := false
	for _, e := range events {
		if e.Type == audit.EventSessionStart {
			hasStart = true
		}
		if e.Type == audit.EventSessionStop {
			hasStop = true
			if e.BytesIn != 1000000 {
				t.Errorf("BytesIn = %d, want 1000000", e.BytesIn)
			}
		}
	}

	if !hasStart {
		t.Error("Missing session start event")
	}
	if !hasStop {
		t.Error("Missing session stop event")
	}
}

func TestLogger_Stats(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	if err := auditLogger.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer auditLogger.Stop()

	// Log some events
	for i := 0; i < 10; i++ {
		auditLogger.LogEvent(&audit.Event{
			Type: audit.EventSessionStart,
		})
	}

	stats := auditLogger.Stats()
	// Should have at least 10 + system start event
	if stats.EventsLogged < 10 {
		t.Errorf("EventsLogged = %d, want >= 10", stats.EventsLogged)
	}
}

func TestMemoryStorage_Query(t *testing.T) {
	storage := audit.NewMemoryStorage()
	ctx := context.Background()

	// Add test events
	events := []*audit.Event{
		{
			ID:           "1",
			Type:         audit.EventSessionStart,
			Timestamp:    time.Now().Add(-2 * time.Hour),
			SubscriberID: "sub-1",
			ISPID:        "ISP-A",
		},
		{
			ID:           "2",
			Type:         audit.EventSessionStop,
			Timestamp:    time.Now().Add(-1 * time.Hour),
			SubscriberID: "sub-1",
			ISPID:        "ISP-A",
		},
		{
			ID:           "3",
			Type:         audit.EventAuthSuccess,
			Timestamp:    time.Now(),
			SubscriberID: "sub-2",
			ISPID:        "ISP-B",
		},
	}

	for _, e := range events {
		storage.Store(ctx, e)
	}

	// Query by subscriber
	results, err := storage.Query(ctx, &audit.Query{
		SubscriberID: "sub-1",
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 events for sub-1, got %d", len(results))
	}

	// Query by ISP
	results, err = storage.Query(ctx, &audit.Query{
		ISPID: "ISP-B",
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 event for ISP-B, got %d", len(results))
	}

	// Query by type
	results, err = storage.Query(ctx, &audit.Query{
		Types: []audit.EventType{audit.EventSessionStart},
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 session start event, got %d", len(results))
	}

	// Query with limit
	results, err = storage.Query(ctx, &audit.Query{
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 events with limit, got %d", len(results))
	}
}

func TestMemoryStorage_Delete(t *testing.T) {
	storage := audit.NewMemoryStorage()
	ctx := context.Background()

	event := &audit.Event{
		ID:           "test-1",
		Type:         audit.EventSessionStart,
		Timestamp:    time.Now(),
		SubscriberID: "sub-1",
	}

	storage.Store(ctx, event)

	if storage.Count() != 1 {
		t.Errorf("Expected 1 event, got %d", storage.Count())
	}

	// Delete
	err := storage.Delete(ctx, []string{"test-1"})
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if storage.Count() != 0 {
		t.Errorf("Expected 0 events after delete, got %d", storage.Count())
	}
}

func TestMemoryStorage_DeleteExpired(t *testing.T) {
	storage := audit.NewMemoryStorage()
	ctx := context.Background()

	// Add expired event
	expired := &audit.Event{
		ID:        "expired-1",
		Type:      audit.EventSessionStart,
		Timestamp: time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired yesterday
	}
	storage.Store(ctx, expired)

	// Add current event
	current := &audit.Event{
		ID:        "current-1",
		Type:      audit.EventSessionStart,
		Timestamp: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Expires tomorrow
	}
	storage.Store(ctx, current)

	if storage.Count() != 2 {
		t.Errorf("Expected 2 events, got %d", storage.Count())
	}

	// Delete expired
	deleted, err := storage.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}

	if deleted != 1 {
		t.Errorf("Expected 1 deleted, got %d", deleted)
	}

	if storage.Count() != 1 {
		t.Errorf("Expected 1 event remaining, got %d", storage.Count())
	}
}

func TestRetentionManager(t *testing.T) {
	rm := audit.NewRetentionManager(90, map[string]int{
		"session": 365,
		"nat":     180,
	})

	// Test default
	if days := rm.GetRetention("unknown"); days != 90 {
		t.Errorf("Default retention = %d, want 90", days)
	}

	// Test category override
	if days := rm.GetRetention("session"); days != 365 {
		t.Errorf("Session retention = %d, want 365", days)
	}

	// Test set category
	rm.SetCategoryRetention("dhcp", 30)
	if days := rm.GetRetention("dhcp"); days != 30 {
		t.Errorf("DHCP retention = %d, want 30", days)
	}
}

func TestRetentionManager_LegalHold(t *testing.T) {
	rm := audit.NewRetentionManager(90, nil)

	// Add legal hold
	hold := &audit.LegalHold{
		ID:            "hold-1",
		Description:   "Investigation XYZ",
		SubscriberIDs: []string{"sub-123"},
		StartTime:     time.Now().Add(-24 * time.Hour),
		EndTime:       time.Now().Add(24 * time.Hour),
	}
	rm.AddLegalHold(hold)

	// Check matching event
	event := &audit.Event{
		SubscriberID: "sub-123",
		Timestamp:    time.Now(),
	}

	if !rm.IsUnderLegalHold(event) {
		t.Error("Event should be under legal hold")
	}

	// Check non-matching event
	event2 := &audit.Event{
		SubscriberID: "sub-456",
		Timestamp:    time.Now(),
	}

	if rm.IsUnderLegalHold(event2) {
		t.Error("Event should not be under legal hold")
	}

	// Remove hold
	if !rm.RemoveLegalHold("hold-1") {
		t.Error("Failed to remove legal hold")
	}

	if rm.IsUnderLegalHold(event) {
		t.Error("Event should not be under legal hold after removal")
	}
}

func TestFormatSyslog(t *testing.T) {
	event := &audit.Event{
		ID:           "test-1",
		Type:         audit.EventSessionStart,
		Timestamp:    time.Now(),
		DeviceID:     "bng-1",
		SubscriberID: "sub-123",
		SessionID:    "sess-456",
		IPv4:         net.ParseIP("10.0.0.50"),
		MAC:          net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		ISPID:        "ISP-A",
	}

	msg := audit.FormatSyslog(event)

	// Check for expected content
	expectedParts := []string{
		"device=bng-1",
		"type=SESSION_START",
		"subscriber=sub-123",
		"session=sess-456",
		"ipv4=10.0.0.50",
		"isp=ISP-A",
	}

	for _, part := range expectedParts {
		if !contains(msg, part) {
			t.Errorf("Syslog message should contain %q", part)
		}
	}
}

func TestStandardRetentionPolicies(t *testing.T) {
	policies := audit.StandardRetentionPolicies()

	if policies["session"] < 365 {
		t.Errorf("Session retention should be >= 365 days")
	}

	if policies["nat"] < 90 {
		t.Errorf("NAT retention should be >= 90 days")
	}

	if policies["admin"] < 365 {
		t.Errorf("Admin retention should be >= 365 days")
	}
}

func TestCommonLegalRequirements(t *testing.T) {
	reqs := audit.CommonLegalRequirements()

	if len(reqs) == 0 {
		t.Error("Should have legal requirements")
	}

	// Check for UK requirements (example)
	found := false
	for _, req := range reqs {
		if req.Jurisdiction == "UK" {
			found = true
			if req.SessionDays < 365 {
				t.Error("UK requires at least 1 year retention")
			}
		}
	}

	if !found {
		t.Error("Missing UK legal requirements")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
