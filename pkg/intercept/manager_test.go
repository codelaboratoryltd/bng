package intercept_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/intercept"
	"go.uber.org/zap"
)

func TestWarrantValidation(t *testing.T) {
	logger := zap.NewNop()
	config := intercept.DefaultConfig()
	config.Enabled = true

	manager := intercept.NewManager(config, logger)

	tests := []struct {
		name    string
		warrant *intercept.Warrant
		wantErr bool
	}{
		{
			name: "valid warrant with subscriber ID",
			warrant: &intercept.Warrant{
				LIID:               "TEST-001",
				Type:               intercept.WarrantIRI,
				TargetSubscriberID: "sub-123",
				ValidFrom:          time.Now().Add(-1 * time.Hour),
				ValidUntil:         time.Now().Add(24 * time.Hour),
			},
			wantErr: false,
		},
		{
			name: "valid warrant with MAC",
			warrant: &intercept.Warrant{
				LIID:       "TEST-002",
				Type:       intercept.WarrantCC,
				TargetMAC:  net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
				ValidFrom:  time.Now().Add(-1 * time.Hour),
				ValidUntil: time.Now().Add(24 * time.Hour),
			},
			wantErr: false,
		},
		{
			name: "missing LIID",
			warrant: &intercept.Warrant{
				Type:               intercept.WarrantIRI,
				TargetSubscriberID: "sub-123",
				ValidFrom:          time.Now(),
				ValidUntil:         time.Now().Add(24 * time.Hour),
			},
			wantErr: true,
		},
		{
			name: "missing type",
			warrant: &intercept.Warrant{
				LIID:               "TEST-003",
				TargetSubscriberID: "sub-123",
				ValidFrom:          time.Now(),
				ValidUntil:         time.Now().Add(24 * time.Hour),
			},
			wantErr: true,
		},
		{
			name: "missing target",
			warrant: &intercept.Warrant{
				LIID:       "TEST-004",
				Type:       intercept.WarrantIRI,
				ValidFrom:  time.Now(),
				ValidUntil: time.Now().Add(24 * time.Hour),
			},
			wantErr: true,
		},
		{
			name: "invalid time range",
			warrant: &intercept.Warrant{
				LIID:               "TEST-005",
				Type:               intercept.WarrantIRI,
				TargetSubscriberID: "sub-123",
				ValidFrom:          time.Now().Add(24 * time.Hour),
				ValidUntil:         time.Now(), // Before ValidFrom
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.AddWarrant(tt.warrant)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddWarrant() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWarrantLifecycle(t *testing.T) {
	logger := zap.NewNop()
	config := intercept.DefaultConfig()
	config.Enabled = true

	manager := intercept.NewManager(config, logger)

	// Add a warrant
	warrant := &intercept.Warrant{
		LIID:               "TEST-LC-001",
		Type:               intercept.WarrantIRICC,
		TargetSubscriberID: "sub-lifecycle",
		ValidFrom:          time.Now().Add(-1 * time.Hour),
		ValidUntil:         time.Now().Add(24 * time.Hour),
		AuthorityRef:       "COURT-2024-001",
		IssuingBody:        "Test Authority",
	}

	if err := manager.AddWarrant(warrant); err != nil {
		t.Fatalf("AddWarrant failed: %v", err)
	}

	// Verify warrant was added
	retrieved, err := manager.GetWarrant(warrant.ID)
	if err != nil {
		t.Fatalf("GetWarrant failed: %v", err)
	}

	if retrieved.LIID != "TEST-LC-001" {
		t.Errorf("LIID = %s, want TEST-LC-001", retrieved.LIID)
	}
	if retrieved.Status != intercept.WarrantStatusActive {
		t.Errorf("Status = %s, want ACTIVE", retrieved.Status)
	}

	// List warrants
	warrants := manager.ListWarrants()
	if len(warrants) != 1 {
		t.Errorf("ListWarrants returned %d, want 1", len(warrants))
	}

	// Update status
	if err := manager.UpdateWarrantStatus(warrant.ID, intercept.WarrantStatusSuspended); err != nil {
		t.Fatalf("UpdateWarrantStatus failed: %v", err)
	}

	retrieved, _ = manager.GetWarrant(warrant.ID)
	if retrieved.Status != intercept.WarrantStatusSuspended {
		t.Errorf("Status = %s, want SUSPENDED", retrieved.Status)
	}

	// Remove warrant
	if err := manager.RemoveWarrant(warrant.ID); err != nil {
		t.Fatalf("RemoveWarrant failed: %v", err)
	}

	// Verify removed
	_, err = manager.GetWarrant(warrant.ID)
	if err == nil {
		t.Error("Expected error getting removed warrant")
	}
}

func TestSessionMatching(t *testing.T) {
	logger := zap.NewNop()
	config := intercept.DefaultConfig()
	config.Enabled = true

	manager := intercept.NewManager(config, logger)

	// Add warrants for different targets
	warrantBySubscriber := &intercept.Warrant{
		LIID:               "MATCH-SUB",
		Type:               intercept.WarrantIRI,
		TargetSubscriberID: "sub-match",
		ValidFrom:          time.Now().Add(-1 * time.Hour),
		ValidUntil:         time.Now().Add(24 * time.Hour),
	}
	manager.AddWarrant(warrantBySubscriber)

	warrantByMAC := &intercept.Warrant{
		LIID:       "MATCH-MAC",
		Type:       intercept.WarrantCC,
		TargetMAC:  net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		ValidFrom:  time.Now().Add(-1 * time.Hour),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}
	manager.AddWarrant(warrantByMAC)

	warrantByIP := &intercept.Warrant{
		LIID:       "MATCH-IP",
		Type:       intercept.WarrantIRICC,
		TargetIPv4: net.ParseIP("10.0.0.100"),
		ValidFrom:  time.Now().Add(-1 * time.Hour),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}
	manager.AddWarrant(warrantByIP)

	tests := []struct {
		name         string
		subscriberID string
		mac          net.HardwareAddr
		ipv4         net.IP
		wantCount    int
		wantLIIDs    []string
	}{
		{
			name:         "match by subscriber ID",
			subscriberID: "sub-match",
			wantCount:    1,
			wantLIIDs:    []string{"MATCH-SUB"},
		},
		{
			name:      "match by MAC",
			mac:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			wantCount: 1,
			wantLIIDs: []string{"MATCH-MAC"},
		},
		{
			name:      "match by IP",
			ipv4:      net.ParseIP("10.0.0.100"),
			wantCount: 1,
			wantLIIDs: []string{"MATCH-IP"},
		},
		{
			name:      "no match",
			ipv4:      net.ParseIP("192.168.1.1"),
			wantCount: 0,
		},
		{
			name:         "multiple matches",
			subscriberID: "sub-match",
			mac:          net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			wantCount:    2,
			wantLIIDs:    []string{"MATCH-SUB", "MATCH-MAC"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := manager.MatchSession(tt.subscriberID, tt.mac, tt.ipv4, nil)

			if len(matches) != tt.wantCount {
				t.Errorf("MatchSession returned %d warrants, want %d", len(matches), tt.wantCount)
			}

			if tt.wantLIIDs != nil {
				for _, wantLIID := range tt.wantLIIDs {
					found := false
					for _, m := range matches {
						if m.LIID == wantLIID {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected LIID %s not found in matches", wantLIID)
					}
				}
			}
		})
	}
}

func TestInterceptSession(t *testing.T) {
	logger := zap.NewNop()
	config := intercept.DefaultConfig()
	config.Enabled = true

	manager := intercept.NewManager(config, logger)

	// Add a warrant
	warrant := &intercept.Warrant{
		LIID:               "SESSION-TEST",
		Type:               intercept.WarrantIRICC,
		TargetSubscriberID: "sub-session",
		ValidFrom:          time.Now().Add(-1 * time.Hour),
		ValidUntil:         time.Now().Add(24 * time.Hour),
	}
	manager.AddWarrant(warrant)

	// Start an intercept session
	mac := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	ipv4 := net.ParseIP("10.0.0.50")

	session := manager.StartInterceptSession(
		warrant,
		"sess-12345",
		"sub-session",
		mac,
		ipv4,
		nil,
	)

	if session.SessionID != "sess-12345" {
		t.Errorf("SessionID = %s, want sess-12345", session.SessionID)
	}
	if session.WarrantID != warrant.ID {
		t.Errorf("WarrantID = %s, want %s", session.WarrantID, warrant.ID)
	}

	// Verify session can be retrieved
	retrieved, exists := manager.GetSession("sess-12345")
	if !exists {
		t.Fatal("Session not found")
	}
	if retrieved.SubscriberID != "sub-session" {
		t.Errorf("SubscriberID = %s, want sub-session", retrieved.SubscriberID)
	}

	// Check stats
	stats := manager.Stats()
	if stats.ActiveInterceptions != 1 {
		t.Errorf("ActiveInterceptions = %d, want 1", stats.ActiveInterceptions)
	}

	// Stop the session
	manager.StopInterceptSession("sess-12345")

	// Verify session is removed
	_, exists = manager.GetSession("sess-12345")
	if exists {
		t.Error("Session should be removed after stop")
	}
}

func TestWarrantExpiry(t *testing.T) {
	logger := zap.NewNop()
	config := intercept.DefaultConfig()
	config.Enabled = true

	manager := intercept.NewManager(config, logger)

	// Add an already-expired warrant
	expiredWarrant := &intercept.Warrant{
		LIID:               "EXPIRED-001",
		Type:               intercept.WarrantIRI,
		TargetSubscriberID: "sub-expired",
		ValidFrom:          time.Now().Add(-48 * time.Hour),
		ValidUntil:         time.Now().Add(-24 * time.Hour), // Expired yesterday
	}
	manager.AddWarrant(expiredWarrant)

	retrieved, _ := manager.GetWarrant(expiredWarrant.ID)
	if retrieved.Status != intercept.WarrantStatusExpired {
		t.Errorf("Expired warrant status = %s, want EXPIRED", retrieved.Status)
	}

	// Matching should not return expired warrants
	matches := manager.MatchSession("sub-expired", nil, nil, nil)
	if len(matches) != 0 {
		t.Errorf("Expired warrant should not match, got %d matches", len(matches))
	}
}

func TestPendingWarrant(t *testing.T) {
	logger := zap.NewNop()
	config := intercept.DefaultConfig()
	config.Enabled = true

	manager := intercept.NewManager(config, logger)

	// Add a future warrant
	futureWarrant := &intercept.Warrant{
		LIID:               "FUTURE-001",
		Type:               intercept.WarrantIRI,
		TargetSubscriberID: "sub-future",
		ValidFrom:          time.Now().Add(24 * time.Hour), // Starts tomorrow
		ValidUntil:         time.Now().Add(48 * time.Hour),
	}
	manager.AddWarrant(futureWarrant)

	retrieved, _ := manager.GetWarrant(futureWarrant.ID)
	if retrieved.Status != intercept.WarrantStatusPending {
		t.Errorf("Future warrant status = %s, want PENDING", retrieved.Status)
	}

	// Matching should not return pending warrants
	matches := manager.MatchSession("sub-future", nil, nil, nil)
	if len(matches) != 0 {
		t.Errorf("Pending warrant should not match, got %d matches", len(matches))
	}
}

func TestWarrantTypes(t *testing.T) {
	tests := []struct {
		warrantType intercept.WarrantType
		expected    string
	}{
		{intercept.WarrantIRI, "IRI"},
		{intercept.WarrantCC, "CC"},
		{intercept.WarrantIRICC, "IRI+CC"},
	}

	for _, tt := range tests {
		if string(tt.warrantType) != tt.expected {
			t.Errorf("WarrantType = %s, want %s", tt.warrantType, tt.expected)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	config := intercept.DefaultConfig()

	if config.Enabled {
		t.Error("LI should be disabled by default")
	}
	if config.RequireTLS != true {
		t.Error("TLS should be required by default")
	}
	if config.DeliveryBufferSize == 0 {
		t.Error("DeliveryBufferSize should not be 0")
	}
	if config.RetryAttempts == 0 {
		t.Error("RetryAttempts should not be 0")
	}
}

// MockExporter is a test exporter that records deliveries.
type MockExporter struct {
	IRIRecords []*intercept.InterceptRecord
	CCRecords  []*intercept.InterceptRecord
}

func (m *MockExporter) Name() string { return "mock" }

func (m *MockExporter) DeliverIRI(ctx context.Context, record *intercept.InterceptRecord) error {
	m.IRIRecords = append(m.IRIRecords, record)
	return nil
}

func (m *MockExporter) DeliverCC(ctx context.Context, record *intercept.InterceptRecord) error {
	m.CCRecords = append(m.CCRecords, record)
	return nil
}

func (m *MockExporter) Close() error { return nil }
