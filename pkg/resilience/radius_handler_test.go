package resilience

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// mockAuthenticator implements RADIUSAuthenticator for testing.
type mockAuthenticator struct {
	authSuccess bool
	authError   error
	reachable   bool
	acctRecords []*AccountingRecord
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, mac net.HardwareAddr, username string) (*AuthResult, error) {
	if m.authError != nil {
		return nil, m.authError
	}
	return &AuthResult{
		Success:      m.authSuccess,
		SubscriberID: username,
		ISPID:        "isp-1",
	}, nil
}

func (m *mockAuthenticator) SendAccounting(ctx context.Context, record *AccountingRecord) error {
	m.acctRecords = append(m.acctRecords, record)
	return nil
}

func (m *mockAuthenticator) IsReachable(ctx context.Context) bool {
	return m.reachable
}

func TestRADIUSHandlerCacheProfile(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	handler := NewRADIUSHandler(config, logger)

	profile := &CachedProfile{
		SubscriberID:    "sub-123",
		ISPID:           "isp-1",
		QoSPolicyID:     "qos-basic",
		DownloadRateBps: 100_000_000,
		UploadRateBps:   50_000_000,
	}

	handler.CacheProfile(profile)

	// Retrieve cached profile
	retrieved, ok := handler.GetCachedProfile("sub-123")
	if !ok {
		t.Fatal("Failed to retrieve cached profile")
	}

	if retrieved.ISPID != "isp-1" {
		t.Errorf("Expected ISPID 'isp-1', got '%s'", retrieved.ISPID)
	}

	if !retrieved.CachedAt.Before(time.Now().Add(time.Second)) {
		t.Error("CachedAt should be set to approximately now")
	}
}

func TestRADIUSHandlerCacheExpiry(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	config.CachedProfileTTL = 100 * time.Millisecond
	handler := NewRADIUSHandler(config, logger)

	profile := &CachedProfile{
		SubscriberID: "sub-123",
		ISPID:        "isp-1",
	}

	handler.CacheProfile(profile)

	// Should be retrievable initially
	_, ok := handler.GetCachedProfile("sub-123")
	if !ok {
		t.Fatal("Should be able to retrieve fresh profile")
	}

	// Wait for expiry
	time.Sleep(200 * time.Millisecond)

	// Should not be retrievable after expiry
	_, ok = handler.GetCachedProfile("sub-123")
	if ok {
		t.Error("Should not retrieve expired profile")
	}
}

func TestRADIUSHandlerDegradedAuth(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	handler := NewRADIUSHandler(config, logger)

	// Cache a profile first
	profile := &CachedProfile{
		SubscriberID:    "sub-123",
		ISPID:           "isp-1",
		DownloadRateBps: 100_000_000,
	}
	handler.CacheProfile(profile)

	// Perform degraded auth
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	session, err := handler.AuthenticateDegraded(mac, "sub-123")

	if err != nil {
		t.Fatalf("Degraded auth failed: %v", err)
	}

	if session.SessionID == "" {
		t.Error("Session ID should be set")
	}

	if !session.NeedsReauth {
		t.Error("Session should need re-authentication")
	}

	if session.CachedProfile.ISPID != "isp-1" {
		t.Errorf("Expected ISPID 'isp-1', got '%s'", session.CachedProfile.ISPID)
	}
}

func TestRADIUSHandlerDegradedAuthNoProfile(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	handler := NewRADIUSHandler(config, logger)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	_, err := handler.AuthenticateDegraded(mac, "unknown-sub")

	if err == nil {
		t.Error("Expected error for unknown subscriber")
	}

	_, ok := err.(*NoCachedProfileError)
	if !ok {
		t.Errorf("Expected NoCachedProfileError, got %T", err)
	}
}

func TestRADIUSHandlerGetDegradedSessions(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	handler := NewRADIUSHandler(config, logger)

	// Cache profiles
	for i := 0; i < 3; i++ {
		handler.CacheProfile(&CachedProfile{
			SubscriberID: "sub-" + string(rune('1'+i)),
			ISPID:        "isp-1",
		})
	}

	// Perform degraded auths
	for i := 0; i < 3; i++ {
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)}
		handler.AuthenticateDegraded(mac, "sub-"+string(rune('1'+i)))
	}

	sessions := handler.GetDegradedSessions()
	if len(sessions) != 3 {
		t.Errorf("Expected 3 degraded sessions, got %d", len(sessions))
	}
}

func TestRADIUSHandlerBufferAccounting(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	config.AccountingBufferSize = 100
	handler := NewRADIUSHandler(config, logger)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.1.100")

	record := &BufferedAcctRecord{
		SessionID:    "session-1",
		MAC:          mac,
		FramedIP:     ip,
		StatusType:   1, // Start
		InputOctets:  1000,
		OutputOctets: 2000,
	}

	if err := handler.BufferAccounting(record); err != nil {
		t.Fatalf("Failed to buffer accounting: %v", err)
	}

	if handler.GetBufferedAccountingCount() != 1 {
		t.Errorf("Expected 1 buffered record, got %d", handler.GetBufferedAccountingCount())
	}
}

func TestRADIUSHandlerBufferFull(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	config.AccountingBufferSize = 5
	handler := NewRADIUSHandler(config, logger)

	// Fill buffer
	for i := 0; i < 5; i++ {
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)}
		handler.BufferAccounting(&BufferedAcctRecord{
			SessionID: "session-" + string(rune('1'+i)),
			MAC:       mac,
		})
	}

	// Try to add one more
	err := handler.BufferAccounting(&BufferedAcctRecord{
		SessionID: "session-overflow",
		MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0xFF},
	})

	if err == nil {
		t.Error("Expected error when buffer is full")
	}

	_, ok := err.(*BufferFullError)
	if !ok {
		t.Errorf("Expected BufferFullError, got %T", err)
	}
}

func TestRADIUSHandlerSyncAccounting(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	handler := NewRADIUSHandler(config, logger)

	auth := &mockAuthenticator{authSuccess: true}
	handler.SetAuthenticator(auth)

	// Buffer some records
	for i := 0; i < 5; i++ {
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)}
		handler.BufferAccounting(&BufferedAcctRecord{
			SessionID:  "session-" + string(rune('1'+i)),
			MAC:        mac,
			StatusType: 2, // Stop
		})
	}

	ctx := context.Background()
	synced := handler.SyncBufferedAccounting(ctx, 10)

	if synced != 5 {
		t.Errorf("Expected 5 synced records, got %d", synced)
	}

	if handler.GetBufferedAccountingCount() != 0 {
		t.Errorf("Expected 0 buffered records after sync, got %d", handler.GetBufferedAccountingCount())
	}

	if len(auth.acctRecords) != 5 {
		t.Errorf("Expected 5 records sent to authenticator, got %d", len(auth.acctRecords))
	}
}

func TestRADIUSHandlerProcessReauths(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	handler := NewRADIUSHandler(config, logger)

	auth := &mockAuthenticator{authSuccess: true}
	handler.SetAuthenticator(auth)

	// Cache profile and create degraded session
	handler.CacheProfile(&CachedProfile{
		SubscriberID: "sub-1",
		ISPID:        "isp-1",
	})

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	session, _ := handler.AuthenticateDegraded(mac, "sub-1")

	// Queue for re-auth
	handler.QueueReauth(session)

	if handler.GetReauthQueueLength() != 1 {
		t.Errorf("Expected 1 in reauth queue, got %d", handler.GetReauthQueueLength())
	}

	// Process re-auths
	ctx := context.Background()
	completed, failed := handler.ProcessReauths(ctx, 100)

	if completed != 1 {
		t.Errorf("Expected 1 completed, got %d", completed)
	}

	if failed != 0 {
		t.Errorf("Expected 0 failed, got %d", failed)
	}

	// Session should no longer need re-auth
	sessions := handler.GetDegradedSessions()
	for _, s := range sessions {
		if s.SessionID == session.SessionID && s.NeedsReauth {
			t.Error("Session should no longer need re-auth")
		}
	}
}

func TestRADIUSHandlerStats(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	handler := NewRADIUSHandler(config, logger)

	// Cache and create degraded session
	handler.CacheProfile(&CachedProfile{SubscriberID: "sub-1"})
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	handler.AuthenticateDegraded(mac, "sub-1")

	// Buffer accounting
	handler.BufferAccounting(&BufferedAcctRecord{
		SessionID: "session-1",
		MAC:       mac,
	})

	degradedAuths, _, _, acctBuffered, _, _ := handler.Stats()

	if degradedAuths != 1 {
		t.Errorf("Expected 1 degraded auth, got %d", degradedAuths)
	}

	if acctBuffered != 1 {
		t.Errorf("Expected 1 buffered acct, got %d", acctBuffered)
	}
}

func TestRADIUSHandlerPurgeExpiredProfiles(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultPartitionConfig()
	config.CachedProfileTTL = 100 * time.Millisecond
	handler := NewRADIUSHandler(config, logger)

	// Cache profiles
	handler.CacheProfile(&CachedProfile{SubscriberID: "sub-1"})
	handler.CacheProfile(&CachedProfile{SubscriberID: "sub-2"})

	if handler.GetCachedProfileCount() != 2 {
		t.Fatalf("Expected 2 cached profiles, got %d", handler.GetCachedProfileCount())
	}

	// Wait for expiry
	time.Sleep(200 * time.Millisecond)

	purged := handler.PurgeExpiredProfiles()
	if purged != 2 {
		t.Errorf("Expected 2 purged, got %d", purged)
	}

	if handler.GetCachedProfileCount() != 0 {
		t.Errorf("Expected 0 cached profiles after purge, got %d", handler.GetCachedProfileCount())
	}
}
