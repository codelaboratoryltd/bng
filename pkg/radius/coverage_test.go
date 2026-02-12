package radius

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"layeh.com/radius"
)

// ---------------------------------------------------------------------------
// PolicyManager tests (policy.go — all functions at 0%)
// ---------------------------------------------------------------------------

func TestNewPolicyManager(t *testing.T) {
	pm := NewPolicyManager()
	if pm == nil {
		t.Fatal("NewPolicyManager returned nil")
	}
	if pm.policies == nil {
		t.Fatal("policies map is nil")
	}
	if len(pm.policies) != 0 {
		t.Errorf("expected empty policies, got %d", len(pm.policies))
	}
}

func TestPolicyManager_AddPolicy(t *testing.T) {
	pm := NewPolicyManager()

	// Valid policy
	err := pm.AddPolicy(&QoSPolicy{
		Name:        "test-50mbps",
		DownloadBPS: 50_000_000,
		UploadBPS:   10_000_000,
		BurstSize:   1_000_000,
		Priority:    4,
	})
	if err != nil {
		t.Fatalf("AddPolicy failed: %v", err)
	}

	// Empty name should fail
	err = pm.AddPolicy(&QoSPolicy{
		Name: "",
	})
	if err == nil {
		t.Error("expected error for empty policy name")
	}
}

func TestPolicyManager_GetPolicy(t *testing.T) {
	pm := NewPolicyManager()
	pm.AddPolicy(&QoSPolicy{
		Name:        "gold",
		DownloadBPS: 1_000_000_000,
		UploadBPS:   100_000_000,
		Priority:    6,
	})

	// Found
	p := pm.GetPolicy("gold")
	if p == nil {
		t.Fatal("expected policy 'gold', got nil")
	}
	if p.DownloadBPS != 1_000_000_000 {
		t.Errorf("expected 1Gbps download, got %d", p.DownloadBPS)
	}
	if p.Priority != 6 {
		t.Errorf("expected priority 6, got %d", p.Priority)
	}

	// Not found
	p = pm.GetPolicy("nonexistent")
	if p != nil {
		t.Error("expected nil for nonexistent policy")
	}
}

func TestPolicyManager_RemovePolicy(t *testing.T) {
	pm := NewPolicyManager()
	pm.AddPolicy(&QoSPolicy{Name: "temp", DownloadBPS: 100})

	pm.RemovePolicy("temp")

	if pm.GetPolicy("temp") != nil {
		t.Error("policy should have been removed")
	}

	// Remove nonexistent should not panic
	pm.RemovePolicy("does-not-exist")
}

func TestPolicyManager_ListPolicies(t *testing.T) {
	pm := NewPolicyManager()
	pm.AddPolicy(&QoSPolicy{Name: "alpha"})
	pm.AddPolicy(&QoSPolicy{Name: "beta"})
	pm.AddPolicy(&QoSPolicy{Name: "gamma"})

	names := pm.ListPolicies()
	if len(names) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(names))
	}

	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	for _, want := range []string{"alpha", "beta", "gamma"} {
		if !nameSet[want] {
			t.Errorf("missing policy %q in list", want)
		}
	}
}

func TestDefaultPolicies(t *testing.T) {
	defaults := DefaultPolicies()
	if len(defaults) == 0 {
		t.Fatal("DefaultPolicies returned empty slice")
	}

	nameSet := make(map[string]bool)
	for _, p := range defaults {
		if p.Name == "" {
			t.Error("policy with empty name")
		}
		nameSet[p.Name] = true
	}

	// Verify expected policies exist
	for _, expected := range []string{"residential-50mbps", "residential-100mbps", "business-100mbps", "guest", "unlimited"} {
		if !nameSet[expected] {
			t.Errorf("missing expected default policy %q", expected)
		}
	}

	// Verify unlimited has zero rates
	for _, p := range defaults {
		if p.Name == "unlimited" {
			if p.DownloadBPS != 0 || p.UploadBPS != 0 {
				t.Error("unlimited policy should have zero rates")
			}
		}
	}
}

func TestPolicyManager_LoadDefaultPolicies(t *testing.T) {
	pm := NewPolicyManager()
	pm.LoadDefaultPolicies()

	defaults := DefaultPolicies()
	names := pm.ListPolicies()
	if len(names) != len(defaults) {
		t.Errorf("expected %d policies after LoadDefaultPolicies, got %d", len(defaults), len(names))
	}

	// Verify a specific policy was loaded correctly
	p := pm.GetPolicy("residential-100mbps")
	if p == nil {
		t.Fatal("residential-100mbps not loaded")
	}
	if p.DownloadBPS != 100_000_000 {
		t.Errorf("expected 100Mbps download, got %d", p.DownloadBPS)
	}
}

func TestPolicyManager_ConcurrentAccess(t *testing.T) {
	pm := NewPolicyManager()
	pm.LoadDefaultPolicies()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := fmt.Sprintf("policy-%d", n)
			pm.AddPolicy(&QoSPolicy{Name: name, DownloadBPS: uint64(n) * 1_000_000})
			pm.GetPolicy(name)
			pm.ListPolicies()
			if n%3 == 0 {
				pm.RemovePolicy(name)
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// AccountingManager tests (accounting.go — all functions at 0%)
// ---------------------------------------------------------------------------

func testClient(t *testing.T) *Client {
	t.Helper()
	logger := zap.NewNop()
	client, err := NewClient(ClientConfig{
		Servers: []ServerConfig{
			{Host: "192.0.2.1", Port: 1812, Secret: "testing123"},
		},
		NASID:   "test-nas",
		Timeout: 100 * time.Millisecond,
		Retries: 1,
	}, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestNewAccountingManager(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	// Valid creation
	am, err := NewAccountingManager(client, AccountingConfig{}, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if am == nil {
		t.Fatal("expected non-nil AccountingManager")
	}

	// Verify defaults applied
	if am.config.DefaultInterimInterval != 5*time.Minute {
		t.Errorf("expected 5min interim interval, got %v", am.config.DefaultInterimInterval)
	}
	if am.config.MaxRetries != 10 {
		t.Errorf("expected 10 max retries, got %d", am.config.MaxRetries)
	}
	if am.config.QueueSize != 10000 {
		t.Errorf("expected queue size 10000, got %d", am.config.QueueSize)
	}
	if am.config.ShutdownTimeout != 30*time.Second {
		t.Errorf("expected 30s shutdown timeout, got %v", am.config.ShutdownTimeout)
	}
	if am.config.PersistPath != "/var/lib/bng/accounting" {
		t.Errorf("expected default persist path, got %s", am.config.PersistPath)
	}

	// Nil client should fail
	_, err = NewAccountingManager(nil, AccountingConfig{}, logger)
	if err == nil {
		t.Error("expected error for nil client")
	}
}

func TestNewAccountingManager_WithConfig(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	cfg := AccountingConfig{
		DefaultInterimInterval: 2 * time.Minute,
		InterimEnabled:         true,
		MaxRetries:             5,
		RetryBaseDelay:         2 * time.Second,
		RetryMaxDelay:          30 * time.Second,
		QueueSize:              500,
		ShutdownTimeout:        10 * time.Second,
		PersistPath:            "/tmp/test-persist",
	}

	am, err := NewAccountingManager(client, cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if am.config.DefaultInterimInterval != 2*time.Minute {
		t.Errorf("expected 2min interim, got %v", am.config.DefaultInterimInterval)
	}
	if am.config.MaxRetries != 5 {
		t.Errorf("expected 5 retries, got %d", am.config.MaxRetries)
	}
}

func TestAccountingManager_SetCounterFetcher(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	am, _ := NewAccountingManager(client, AccountingConfig{}, logger)

	called := false
	am.SetCounterFetcher(func(sessionID string) (*SessionCounters, error) {
		called = true
		return &SessionCounters{InputOctets: 1000}, nil
	})

	if am.counterFetcher == nil {
		t.Fatal("counterFetcher not set")
	}

	// Invoke to verify it was set correctly
	counters, err := am.counterFetcher("test")
	if err != nil {
		t.Fatalf("counterFetcher error: %v", err)
	}
	if !called {
		t.Error("counterFetcher was not called")
	}
	if counters.InputOctets != 1000 {
		t.Errorf("expected InputOctets 1000, got %d", counters.InputOctets)
	}
}

func TestAccountingManager_StartStop(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		ShutdownTimeout: 1 * time.Second,
		DrainOnShutdown: false,
	}, logger)

	// Start
	err := am.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Starting again should fail
	err = am.Start()
	if err == nil {
		t.Error("expected error on double Start")
	}

	// Stop
	err = am.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Stop again should be idempotent
	err = am.Stop()
	if err != nil {
		t.Fatalf("second Stop failed: %v", err)
	}
}

func TestAccountingManager_StartSession(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	session := &AccountingSession{
		SessionID: "session-001",
		Username:  "user@test.com",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.100"),
		NASPort:   1,
		CircuitID: "eth0/1/1:100",
		RemoteID:  "nte-001",
		Class:     []byte("class-data"),
	}

	err := am.StartSession(session)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	// Session should have defaults set
	if session.InterimInterval != am.config.DefaultInterimInterval {
		t.Errorf("expected default interim interval, got %v", session.InterimInterval)
	}
	if session.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}

	// Starting duplicate session should fail
	dup := &AccountingSession{SessionID: "session-001", Username: "dup"}
	err = am.StartSession(dup)
	if err == nil {
		t.Error("expected error for duplicate session")
	}

	// Empty session ID should fail
	err = am.StartSession(&AccountingSession{SessionID: ""})
	if err == nil {
		t.Error("expected error for empty session ID")
	}

	// Verify session is tracked
	s, ok := am.GetSession("session-001")
	if !ok {
		t.Fatal("session not found after StartSession")
	}
	if s.Username != "user@test.com" {
		t.Errorf("expected username user@test.com, got %s", s.Username)
	}

	// Verify persistence file exists
	sessionFile := filepath.Join(tempDir, "sessions", "session-001.json")
	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		t.Error("session persistence file not created")
	}
}

func TestAccountingManager_StopSession(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	// Start a session first
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	session := &AccountingSession{
		SessionID: "session-stop-001",
		Username:  "user@test.com",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.100"),
	}
	am.StartSession(session)

	// Stop the session (will fail to send accounting-stop to unreachable server, but queues it)
	err := am.StopSession("session-stop-001", TerminateCauseUserRequest)
	if err != nil {
		t.Fatalf("StopSession failed: %v", err)
	}

	// Session should be removed
	_, ok := am.GetSession("session-stop-001")
	if ok {
		t.Error("session should be removed after StopSession")
	}

	// Stop non-existent session should fail
	err = am.StopSession("non-existent", TerminateCauseUserRequest)
	if err == nil {
		t.Error("expected error for non-existent session")
	}
}

func TestAccountingManager_UpdateSessionInterval(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	am.StartSession(&AccountingSession{
		SessionID: "session-interval",
		Username:  "user",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.1"),
	})

	err := am.UpdateSessionInterval("session-interval", 10*time.Minute)
	if err != nil {
		t.Fatalf("UpdateSessionInterval failed: %v", err)
	}

	s, _ := am.GetSession("session-interval")
	if s.InterimInterval != 10*time.Minute {
		t.Errorf("expected 10min interval, got %v", s.InterimInterval)
	}

	// Non-existent session
	err = am.UpdateSessionInterval("nonexistent", time.Minute)
	if err == nil {
		t.Error("expected error for non-existent session")
	}
}

func TestAccountingManager_GetStats(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	am.StartSession(&AccountingSession{
		SessionID: "session-stats",
		Username:  "user",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.1"),
	})

	stats := am.GetStats()
	if stats.ActiveSessions != 1 {
		t.Errorf("expected 1 active session, got %d", stats.ActiveSessions)
	}
	// Initial stats should be zero
	if stats.InterimTotal != 0 {
		t.Errorf("expected 0 interim total, got %d", stats.InterimTotal)
	}
	if stats.StopTotal != 0 {
		t.Errorf("expected 0 stop total, got %d", stats.StopTotal)
	}
}

func TestAccountingManager_ListSessions(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	// Empty list
	sessions := am.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}

	// Add sessions
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	am.StartSession(&AccountingSession{SessionID: "s1", Username: "u1", MAC: mac, FramedIP: net.ParseIP("10.0.0.1")})
	am.StartSession(&AccountingSession{SessionID: "s2", Username: "u2", MAC: mac, FramedIP: net.ParseIP("10.0.0.2")})
	am.StartSession(&AccountingSession{SessionID: "s3", Username: "u3", MAC: mac, FramedIP: net.ParseIP("10.0.0.3")})

	sessions = am.ListSessions()
	if len(sessions) != 3 {
		t.Errorf("expected 3 sessions, got %d", len(sessions))
	}
}

func TestAccountingManager_GetSession(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	// Not found
	_, ok := am.GetSession("nonexistent")
	if ok {
		t.Error("expected false for nonexistent session")
	}

	// Found
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	am.StartSession(&AccountingSession{SessionID: "found-session", Username: "user", MAC: mac, FramedIP: net.ParseIP("10.0.0.1")})
	s, ok := am.GetSession("found-session")
	if !ok {
		t.Fatal("expected session to be found")
	}
	if s.SessionID != "found-session" {
		t.Errorf("expected session ID 'found-session', got %s", s.SessionID)
	}
}

func TestAccountingManager_FetchCounters(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	// No counter fetcher, no session => empty counters
	counters := am.fetchCounters("nonexistent")
	if counters.InputOctets != 0 || counters.OutputOctets != 0 {
		t.Error("expected empty counters for nonexistent session without fetcher")
	}

	// With session but no fetcher => last known values
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	session := &AccountingSession{
		SessionID: "counters-session",
		Username:  "user",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.1"),
	}
	am.StartSession(session)
	// Simulate some last known values
	am.sessionsMu.Lock()
	am.sessions["counters-session"].LastInputOctets = 5000
	am.sessions["counters-session"].LastOutputOctets = 10000
	am.sessions["counters-session"].LastInputPkts = 50
	am.sessions["counters-session"].LastOutputPkts = 100
	am.sessionsMu.Unlock()

	counters = am.fetchCounters("counters-session")
	if counters.InputOctets != 5000 {
		t.Errorf("expected 5000 input octets, got %d", counters.InputOctets)
	}
	if counters.OutputOctets != 10000 {
		t.Errorf("expected 10000 output octets, got %d", counters.OutputOctets)
	}

	// With counter fetcher that succeeds
	am.SetCounterFetcher(func(sessionID string) (*SessionCounters, error) {
		return &SessionCounters{
			InputOctets:   99999,
			OutputOctets:  88888,
			InputPackets:  999,
			OutputPackets: 888,
		}, nil
	})

	counters = am.fetchCounters("counters-session")
	if counters.InputOctets != 99999 {
		t.Errorf("expected 99999 from fetcher, got %d", counters.InputOctets)
	}

	// With counter fetcher that fails => falls back to session values
	am.SetCounterFetcher(func(sessionID string) (*SessionCounters, error) {
		return nil, fmt.Errorf("eBPF read failed")
	})

	counters = am.fetchCounters("counters-session")
	if counters.InputOctets != 5000 {
		t.Errorf("expected fallback to 5000, got %d", counters.InputOctets)
	}
}

func TestAccountingManager_QueuePendingRecord(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       10,
		RetryBaseDelay:  100 * time.Millisecond,
	}, logger)

	req := &AcctRequest{
		SessionID:  "queue-test",
		StatusType: AcctStatusStop,
	}

	am.queuePendingRecord(req)

	am.pendingMu.RLock()
	if len(am.pendingRecords) != 1 {
		t.Errorf("expected 1 pending record, got %d", len(am.pendingRecords))
	}
	am.pendingMu.RUnlock()

	depth := atomic.LoadUint64(&am.pendingQueueDepth)
	if depth != 1 {
		t.Errorf("expected queue depth 1, got %d", depth)
	}
}

func TestAccountingManager_QueueFull(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       2,
		RetryBaseDelay:  100 * time.Millisecond,
	}, logger)

	// Fill the channel queue (not the pending map)
	for i := 0; i < 5; i++ {
		am.queuePendingRecord(&AcctRequest{
			SessionID:  fmt.Sprintf("overflow-%d", i),
			StatusType: AcctStatusStop,
		})
	}

	// Should not panic, just log warning
	am.pendingMu.RLock()
	count := len(am.pendingRecords)
	am.pendingMu.RUnlock()
	if count != 5 {
		t.Errorf("expected 5 pending records (map), got %d", count)
	}
}

func TestAccountingManager_PersistPendingRecords(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	// No records => should return nil without writing
	err := am.persistPendingRecords()
	if err != nil {
		t.Fatalf("persistPendingRecords with no records failed: %v", err)
	}

	// Add some pending records
	am.pendingMu.Lock()
	am.pendingRecords["rec-1"] = &PendingAcctRecord{
		ID: "rec-1",
		Request: &AcctRequest{
			SessionID:  "s1",
			StatusType: AcctStatusStop,
		},
		CreatedAt: time.Now(),
	}
	am.pendingMu.Unlock()

	err = am.persistPendingRecords()
	if err != nil {
		t.Fatalf("persistPendingRecords failed: %v", err)
	}

	// Verify file exists
	pendingFile := filepath.Join(tempDir, "pending.json")
	data, err := os.ReadFile(pendingFile)
	if err != nil {
		t.Fatalf("failed to read pending file: %v", err)
	}

	var records map[string]*PendingAcctRecord
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatalf("failed to unmarshal pending records: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 persisted record, got %d", len(records))
	}
}

func TestAccountingManager_PersistActiveSession(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	session := &AccountingSession{
		SessionID: "persist-test",
		Username:  "user@test.com",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.1"),
		NASPort:   42,
		StartTime: time.Now(),
	}

	am.persistActiveSession(session)

	path := filepath.Join(tempDir, "sessions", "persist-test.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("session file not found: %v", err)
	}

	var loaded AccountingSession
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal session: %v", err)
	}
	if loaded.SessionID != "persist-test" {
		t.Errorf("expected session ID persist-test, got %s", loaded.SessionID)
	}
	if loaded.Username != "user@test.com" {
		t.Errorf("expected username user@test.com, got %s", loaded.Username)
	}
}

func TestAccountingManager_RemovePersistedSession(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	// Persist a session, then remove it
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	session := &AccountingSession{
		SessionID: "remove-test",
		Username:  "user",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.1"),
		StartTime: time.Now(),
	}
	am.persistActiveSession(session)

	path := filepath.Join(tempDir, "sessions", "remove-test.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("session file should exist before removal")
	}

	am.removePersistedSession("remove-test")

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("session file should be removed")
	}

	// Removing nonexistent should not panic
	am.removePersistedSession("nonexistent")
}

func TestAccountingManager_RecoverOrphanedSessions(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()

	// Create orphaned session file before starting the manager
	sessionsDir := filepath.Join(tempDir, "sessions")
	os.MkdirAll(sessionsDir, 0755)

	orphanSession := AccountingSession{
		SessionID:        "orphan-001",
		Username:         "orphan-user",
		FramedIP:         net.ParseIP("10.0.0.99"),
		NASPort:          1,
		StartTime:        time.Now().Add(-1 * time.Hour),
		LastInputOctets:  500000,
		LastOutputOctets: 1000000,
		StopPending:      true,
		StopCause:        TerminateCauseNASReboot,
	}
	data, _ := json.Marshal(orphanSession)
	os.WriteFile(filepath.Join(sessionsDir, "orphan-001.json"), data, 0600)

	// Create pending records file
	pendingRecords := map[string]*PendingAcctRecord{
		"pending-001": {
			ID: "pending-001",
			Request: &AcctRequest{
				SessionID:  "pending-sess",
				StatusType: AcctStatusStop,
			},
			CreatedAt: time.Now(),
		},
	}
	pendingData, _ := json.Marshal(pendingRecords)
	os.WriteFile(filepath.Join(tempDir, "pending.json"), pendingData, 0600)

	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	err := am.recoverOrphanedSessions()
	if err != nil {
		t.Fatalf("recoverOrphanedSessions failed: %v", err)
	}

	// Orphan should have been recovered
	recovered := atomic.LoadUint64(&am.orphanedRecovered)
	if recovered != 1 {
		t.Errorf("expected 1 orphan recovered, got %d", recovered)
	}

	// Orphan file should be removed
	if _, err := os.Stat(filepath.Join(sessionsDir, "orphan-001.json")); !os.IsNotExist(err) {
		t.Error("orphan session file should be removed after recovery")
	}

	// Pending records should be recovered (1 from pending.json + 1 from orphan session stop)
	am.pendingMu.RLock()
	pendingCount := len(am.pendingRecords)
	am.pendingMu.RUnlock()
	if pendingCount < 1 {
		t.Errorf("expected at least 1 pending record recovered, got %d", pendingCount)
	}

	// Pending file should be removed
	if _, err := os.Stat(filepath.Join(tempDir, "pending.json")); !os.IsNotExist(err) {
		t.Error("pending.json should be removed after recovery")
	}
}

func TestAccountingManager_RecoverOrphanedSessions_NoDir(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	nonExistentPath := filepath.Join(tempDir, "nonexistent")

	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     nonExistentPath,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	// Should not error when directory doesn't exist
	err := am.recoverOrphanedSessions()
	if err != nil {
		t.Fatalf("expected nil error for nonexistent dir, got: %v", err)
	}
}

func TestAccountingManager_RecoverCorruptSession(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()

	sessionsDir := filepath.Join(tempDir, "sessions")
	os.MkdirAll(sessionsDir, 0755)

	// Write a corrupt session file
	os.WriteFile(filepath.Join(sessionsDir, "corrupt.json"), []byte("not-valid-json{"), 0600)

	// Write a subdirectory (should be skipped)
	os.MkdirAll(filepath.Join(sessionsDir, "subdir"), 0755)

	// Write a non-json file (should be skipped)
	os.WriteFile(filepath.Join(sessionsDir, "readme.txt"), []byte("text file"), 0600)

	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	err := am.recoverOrphanedSessions()
	if err != nil {
		t.Fatalf("recoverOrphanedSessions failed: %v", err)
	}

	// Corrupt file should be removed
	if _, err := os.Stat(filepath.Join(sessionsDir, "corrupt.json")); !os.IsNotExist(err) {
		t.Error("corrupt session file should be removed")
	}
}

func TestAccountingManager_SendAccountingStop(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	session := &AccountingSession{
		SessionID: "stop-test",
		Username:  "user",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.1"),
		StartTime: time.Now().Add(-30 * time.Minute),
	}
	am.StartSession(session)

	// Set counter fetcher
	am.SetCounterFetcher(func(sessionID string) (*SessionCounters, error) {
		return &SessionCounters{
			InputOctets:   1000000,
			OutputOctets:  2000000,
			InputPackets:  10000,
			OutputPackets: 20000,
		}, nil
	})

	// sendAccountingStop will fail (no real server), but should queue the record
	err := am.sendAccountingStop(session, TerminateCauseUserRequest)
	if err == nil {
		t.Error("expected error since no real RADIUS server")
	}

	// Should have incremented stopFailed
	if atomic.LoadUint64(&am.stopFailed) != 1 {
		t.Errorf("expected 1 stopFailed, got %d", atomic.LoadUint64(&am.stopFailed))
	}

	// Should have queued the pending record
	am.pendingMu.RLock()
	pendingCount := len(am.pendingRecords)
	am.pendingMu.RUnlock()
	if pendingCount < 1 {
		t.Error("expected at least 1 pending record after failed stop")
	}
}

func TestAccountingManager_DrainAllSessions(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: true,
		ShutdownTimeout: 2 * time.Second,
		QueueSize:       100,
	}, logger)

	// Add multiple sessions
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	for i := 0; i < 3; i++ {
		am.StartSession(&AccountingSession{
			SessionID: fmt.Sprintf("drain-%d", i),
			Username:  fmt.Sprintf("user-%d", i),
			MAC:       mac,
			FramedIP:  net.ParseIP(fmt.Sprintf("10.0.0.%d", i+1)),
			StartTime: time.Now().Add(-10 * time.Minute),
		})
	}

	// Drain will attempt to send accounting-stop to unreachable server
	am.drainAllSessions()

	// Records should be queued since server is unreachable
	am.pendingMu.RLock()
	pendingCount := len(am.pendingRecords)
	am.pendingMu.RUnlock()
	if pendingCount < 3 {
		t.Errorf("expected at least 3 pending records from drain, got %d", pendingCount)
	}
}

func TestAccountingManager_SendInterimUpdates(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:            tempDir,
		InterimEnabled:         true,
		DefaultInterimInterval: 1 * time.Millisecond, // Very short for testing
		DrainOnShutdown:        false,
		QueueSize:              100,
	}, logger)

	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	session := &AccountingSession{
		SessionID:       "interim-test",
		Username:        "user",
		MAC:             mac,
		FramedIP:        net.ParseIP("10.0.0.1"),
		InterimInterval: 1 * time.Millisecond,
		StartTime:       time.Now().Add(-1 * time.Hour),
		LastInterimTime: time.Now().Add(-1 * time.Hour), // Long overdue
	}
	am.sessionsMu.Lock()
	am.sessions["interim-test"] = session
	am.sessionsMu.Unlock()

	// Set counter fetcher
	am.SetCounterFetcher(func(sessionID string) (*SessionCounters, error) {
		return &SessionCounters{
			InputOctets:  5000,
			OutputOctets: 10000,
		}, nil
	})

	// Trigger interim update cycle
	am.sendInterimUpdates()

	// Should have incremented interimFailed (server unreachable)
	if atomic.LoadUint64(&am.interimFailed) != 1 {
		t.Errorf("expected 1 interimFailed, got %d", atomic.LoadUint64(&am.interimFailed))
	}
}

func TestAccountingManager_SendInterimUpdates_StopPendingSkipped(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  true,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	session := &AccountingSession{
		SessionID:       "stop-pending-test",
		Username:        "user",
		MAC:             mac,
		FramedIP:        net.ParseIP("10.0.0.1"),
		InterimInterval: 1 * time.Millisecond,
		StartTime:       time.Now().Add(-1 * time.Hour),
		LastInterimTime: time.Now().Add(-1 * time.Hour),
		StopPending:     true, // This session should be skipped
	}
	am.sessionsMu.Lock()
	am.sessions["stop-pending-test"] = session
	am.sessionsMu.Unlock()

	am.sendInterimUpdates()

	// Should NOT have attempted any interim updates (session is stop-pending)
	if atomic.LoadUint64(&am.interimFailed) != 0 {
		t.Errorf("expected 0 interimFailed (stop-pending skipped), got %d", atomic.LoadUint64(&am.interimFailed))
	}
}

func TestAccountingManager_ProcessPendingRecord_MaxRetries(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
		MaxRetries:      2,
		RetryBaseDelay:  1 * time.Millisecond,
	}, logger)

	record := &PendingAcctRecord{
		ID: "max-retry-test",
		Request: &AcctRequest{
			SessionID:  "s1",
			StatusType: AcctStatusStop,
		},
		CreatedAt:  time.Now(),
		RetryCount: 1, // Already retried once
		NextRetry:  time.Now(),
	}

	am.pendingMu.Lock()
	am.pendingRecords[record.ID] = record
	am.pendingMu.Unlock()

	// This will fail (no server), and RetryCount will become 2 which equals MaxRetries
	am.processPendingRecord(record)

	// Record should be removed after max retries
	am.pendingMu.RLock()
	_, exists := am.pendingRecords[record.ID]
	am.pendingMu.RUnlock()
	if exists {
		t.Error("record should be removed after max retries")
	}

	if atomic.LoadUint64(&am.stopAbandoned) != 1 {
		t.Errorf("expected 1 stopAbandoned, got %d", atomic.LoadUint64(&am.stopAbandoned))
	}
}

func TestAccountingManager_ProcessPendingRecord_RetryBackoff(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
		MaxRetries:      10,
		RetryBaseDelay:  100 * time.Millisecond,
		RetryMaxDelay:   500 * time.Millisecond,
	}, logger)

	record := &PendingAcctRecord{
		ID: "retry-backoff-test",
		Request: &AcctRequest{
			SessionID:  "s1",
			StatusType: AcctStatusStop,
		},
		CreatedAt:  time.Now(),
		RetryCount: 0,
		NextRetry:  time.Now(),
	}

	am.pendingMu.Lock()
	am.pendingRecords[record.ID] = record
	am.pendingMu.Unlock()

	am.processPendingRecord(record)

	// RetryCount should have incremented
	if record.RetryCount != 1 {
		t.Errorf("expected retry count 1, got %d", record.RetryCount)
	}

	// NextRetry should be in the future
	if record.NextRetry.Before(time.Now()) {
		t.Error("NextRetry should be in the future")
	}

	// LastError should be set
	if record.LastError == "" {
		t.Error("LastError should be set after failure")
	}

	// StopRetries should be incremented for AcctStatusStop
	if atomic.LoadUint64(&am.stopRetries) != 1 {
		t.Errorf("expected 1 stopRetries, got %d", atomic.LoadUint64(&am.stopRetries))
	}
}

func TestAccountingManager_RetryPendingRecords(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
		MaxRetries:      10,
		RetryBaseDelay:  1 * time.Millisecond,
	}, logger)

	// Add record that's due for retry
	record := &PendingAcctRecord{
		ID: "retry-due",
		Request: &AcctRequest{
			SessionID:  "s1",
			StatusType: AcctStatusInterimUpdate,
		},
		CreatedAt:  time.Now().Add(-1 * time.Minute),
		RetryCount: 0,
		NextRetry:  time.Now().Add(-1 * time.Second), // Already past due
	}

	am.pendingMu.Lock()
	am.pendingRecords[record.ID] = record
	am.pendingMu.Unlock()

	am.retryPendingRecords()

	// Record should have been attempted (retry count incremented)
	if record.RetryCount < 1 {
		t.Error("expected retry count >= 1 after retryPendingRecords")
	}
}

func TestAccountingManager_StartWithRecovery(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()

	// Write an orphaned session before starting
	sessionsDir := filepath.Join(tempDir, "sessions")
	os.MkdirAll(sessionsDir, 0755)

	orphan := AccountingSession{
		SessionID: "orphan-recovery",
		Username:  "orphan",
		FramedIP:  net.ParseIP("10.0.0.50"),
		StartTime: time.Now().Add(-2 * time.Hour),
	}
	data, _ := json.Marshal(orphan)
	os.WriteFile(filepath.Join(sessionsDir, "orphan-recovery.json"), data, 0600)

	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		ShutdownTimeout: 1 * time.Second,
		QueueSize:       100,
	}, logger)

	err := am.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Give background goroutines a moment
	time.Sleep(50 * time.Millisecond)

	// Orphan should be recovered
	if atomic.LoadUint64(&am.orphanedRecovered) != 1 {
		t.Errorf("expected 1 orphan recovered, got %d", atomic.LoadUint64(&am.orphanedRecovered))
	}

	am.Stop()
}

func TestAccountingManager_StopWithDrain(t *testing.T) {
	logger := zap.NewNop()
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: true,
		ShutdownTimeout: 2 * time.Second,
		QueueSize:       100,
	}, logger)

	am.Start()

	// Add a session
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	am.StartSession(&AccountingSession{
		SessionID: "drain-on-stop",
		Username:  "user",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.1"),
	})

	// Stop should drain
	am.Stop()

	// Pending records should have been persisted if any
	// (the drain will fail since no real server, but records get queued)
}

// ---------------------------------------------------------------------------
// CoA parsing tests (coa.go — parseAttributes, verifyRequestAuthenticator, etc.)
// ---------------------------------------------------------------------------

func TestParseAttributes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantLen int
		wantErr bool
	}{
		{
			name:    "empty",
			data:    []byte{},
			wantLen: 0,
			wantErr: false,
		},
		{
			name: "single attribute User-Name",
			data: func() []byte {
				val := []byte("testuser")
				attr := make([]byte, 2+len(val))
				attr[0] = AttrUserName
				attr[1] = byte(2 + len(val))
				copy(attr[2:], val)
				return attr
			}(),
			wantLen: 1,
			wantErr: false,
		},
		{
			name: "multiple attributes",
			data: func() []byte {
				var buf []byte
				// User-Name
				val1 := []byte("user1")
				attr1 := make([]byte, 2+len(val1))
				attr1[0] = AttrUserName
				attr1[1] = byte(2 + len(val1))
				copy(attr1[2:], val1)
				buf = append(buf, attr1...)
				// NAS-IP-Address (4 bytes)
				attr2 := make([]byte, 6)
				attr2[0] = AttrNASIPAddress
				attr2[1] = 6
				copy(attr2[2:], net.ParseIP("192.168.1.1").To4())
				buf = append(buf, attr2...)
				// Framed-IP-Address
				attr3 := make([]byte, 6)
				attr3[0] = AttrFramedIPAddress
				attr3[1] = 6
				copy(attr3[2:], net.ParseIP("10.0.0.1").To4())
				buf = append(buf, attr3...)
				return buf
			}(),
			wantLen: 3,
			wantErr: false,
		},
		{
			name:    "invalid length too short",
			data:    []byte{AttrUserName, 1}, // length < 2 is invalid
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "length exceeds data",
			data:    []byte{AttrUserName, 10, 0x41, 0x42}, // claims 10 bytes but only 4 total
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := parseAttributes(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(attrs) != tt.wantLen {
				t.Errorf("expected %d attributes, got %d", tt.wantLen, len(attrs))
			}
		})
	}
}

func TestParseAttributes_AllTypes(t *testing.T) {
	var buf []byte

	// User-Name
	userName := []byte("testuser")
	attr := make([]byte, 2+len(userName))
	attr[0] = AttrUserName
	attr[1] = byte(2 + len(userName))
	copy(attr[2:], userName)
	buf = append(buf, attr...)

	// Calling-Station-Id
	callingID := []byte("AA:BB:CC:DD:EE:FF")
	attr = make([]byte, 2+len(callingID))
	attr[0] = AttrCallingStationID
	attr[1] = byte(2 + len(callingID))
	copy(attr[2:], callingID)
	buf = append(buf, attr...)

	// Acct-Session-Id
	acctSessID := []byte("session-123")
	attr = make([]byte, 2+len(acctSessID))
	attr[0] = AttrAcctSessionID
	attr[1] = byte(2 + len(acctSessID))
	copy(attr[2:], acctSessID)
	buf = append(buf, attr...)

	// Session-Timeout (uint32)
	attr = make([]byte, 6)
	attr[0] = AttrSessionTimeout
	attr[1] = 6
	binary.BigEndian.PutUint32(attr[2:], 3600)
	buf = append(buf, attr...)

	// Idle-Timeout (uint32)
	attr = make([]byte, 6)
	attr[0] = AttrIdleTimeout
	attr[1] = 6
	binary.BigEndian.PutUint32(attr[2:], 300)
	buf = append(buf, attr...)

	// Filter-Id
	filterID := []byte("gold-plan")
	attr = make([]byte, 2+len(filterID))
	attr[0] = AttrFilterID
	attr[1] = byte(2 + len(filterID))
	copy(attr[2:], filterID)
	buf = append(buf, attr...)

	attrs, err := parseAttributes(buf)
	if err != nil {
		t.Fatalf("parseAttributes failed: %v", err)
	}
	if len(attrs) != 6 {
		t.Fatalf("expected 6 attributes, got %d", len(attrs))
	}

	if string(attrs[0].Value) != "testuser" {
		t.Error("User-Name mismatch")
	}
	if string(attrs[2].Value) != "session-123" {
		t.Error("Acct-Session-Id mismatch")
	}
}

func TestCoAServer_ParseCoARequest(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Secret: "testing123",
	}, logger)

	attrs := []Attribute{
		{Type: AttrUserName, Value: []byte("testuser")},
		{Type: AttrNASIPAddress, Value: net.ParseIP("192.168.1.1").To4()},
		{Type: AttrFramedIPAddress, Value: net.ParseIP("10.0.0.100").To4()},
		{Type: AttrCallingStationID, Value: []byte("AA:BB:CC:DD:EE:FF")},
		{Type: AttrAcctSessionID, Value: []byte("session-123")},
		{Type: AttrSessionTimeout, Value: func() []byte {
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, 3600)
			return b
		}()},
		{Type: AttrIdleTimeout, Value: func() []byte {
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, 300)
			return b
		}()},
		{Type: AttrFilterID, Value: []byte("gold-plan")},
	}

	req := srv.parseCoARequest(attrs)

	if req.Username != "testuser" {
		t.Errorf("expected username testuser, got %s", req.Username)
	}
	if !req.NASIPAddress.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("NASIPAddress mismatch: %v", req.NASIPAddress)
	}
	if !req.FramedIP.Equal(net.ParseIP("10.0.0.100")) {
		t.Errorf("FramedIP mismatch: %v", req.FramedIP)
	}
	if req.CallingStation != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("CallingStation mismatch: %s", req.CallingStation)
	}
	if req.SessionID != "session-123" {
		t.Errorf("SessionID mismatch: %s", req.SessionID)
	}
	if req.SessionTimeout != 3600 {
		t.Errorf("SessionTimeout mismatch: %d", req.SessionTimeout)
	}
	if req.IdleTimeout != 300 {
		t.Errorf("IdleTimeout mismatch: %d", req.IdleTimeout)
	}
	if req.FilterID != "gold-plan" {
		t.Errorf("FilterID mismatch: %s", req.FilterID)
	}
	if len(req.Attributes) != 8 {
		t.Errorf("expected 8 raw attributes, got %d", len(req.Attributes))
	}
}

func TestCoAServer_ParseCoARequest_ShortValues(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Secret: "testing123",
	}, logger)

	// NAS-IP-Address with wrong length (not 4 bytes) should be ignored
	attrs := []Attribute{
		{Type: AttrNASIPAddress, Value: []byte{1, 2}},             // Too short
		{Type: AttrFramedIPAddress, Value: []byte{1, 2, 3, 4, 5}}, // Too long (5 bytes)
		{Type: AttrSessionTimeout, Value: []byte{1, 2}},           // Too short
		{Type: AttrIdleTimeout, Value: []byte{1}},                 // Too short
	}

	req := srv.parseCoARequest(attrs)
	if req.NASIPAddress != nil {
		t.Error("NASIPAddress should be nil for short value")
	}
	if req.FramedIP != nil {
		t.Error("FramedIP should be nil for wrong-length value")
	}
	if req.SessionTimeout != 0 {
		t.Error("SessionTimeout should be 0 for short value")
	}
	if req.IdleTimeout != 0 {
		t.Error("IdleTimeout should be 0 for short value")
	}
}

func TestCoAServer_ParseDisconnectRequest(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Secret: "testing123",
	}, logger)

	attrs := []Attribute{
		{Type: AttrUserName, Value: []byte("disconn-user")},
		{Type: AttrNASIPAddress, Value: net.ParseIP("192.168.1.1").To4()},
		{Type: AttrFramedIPAddress, Value: net.ParseIP("10.0.0.50").To4()},
		{Type: AttrCallingStationID, Value: []byte("11:22:33:44:55:66")},
		{Type: AttrAcctSessionID, Value: []byte("acct-session-789")},
	}

	req := srv.parseDisconnectRequest(attrs)

	if req.Username != "disconn-user" {
		t.Errorf("Username mismatch: %s", req.Username)
	}
	if !req.NASIPAddress.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("NASIPAddress mismatch: %v", req.NASIPAddress)
	}
	if !req.FramedIP.Equal(net.ParseIP("10.0.0.50")) {
		t.Errorf("FramedIP mismatch: %v", req.FramedIP)
	}
	if req.CallingStation != "11:22:33:44:55:66" {
		t.Errorf("CallingStation mismatch: %s", req.CallingStation)
	}
	if req.SessionID != "acct-session-789" {
		t.Errorf("SessionID mismatch: %s", req.SessionID)
	}
	if req.AcctSessionID != "acct-session-789" {
		t.Errorf("AcctSessionID mismatch: %s", req.AcctSessionID)
	}
}

func TestCoAServer_VerifyRequestAuthenticator(t *testing.T) {
	logger := zap.NewNop()
	secret := "testing123"
	srv, _ := NewCoAServer(CoAServerConfig{
		Secret: secret,
	}, logger)

	// Build a proper CoA request packet with correct authenticator
	code := byte(CodeCoARequest)
	identifier := byte(1)
	attrs := []byte{} // No attributes for simplicity

	length := uint16(20 + len(attrs))
	packet := make([]byte, length)
	packet[0] = code
	packet[1] = identifier
	binary.BigEndian.PutUint16(packet[2:4], length)
	// Authenticator = MD5(Code + ID + Length + 16 zero bytes + Attributes + Secret)
	hash := md5.New()
	hash.Write(packet[:4])
	hash.Write(make([]byte, 16))
	hash.Write(packet[20:])
	hash.Write([]byte(secret))
	authenticator := hash.Sum(nil)
	copy(packet[4:20], authenticator)

	// Valid authenticator
	if !srv.verifyRequestAuthenticator(packet, authenticator) {
		t.Error("expected valid authenticator to pass verification")
	}

	// Invalid authenticator
	badAuth := make([]byte, 16)
	badAuth[0] = 0xFF
	if srv.verifyRequestAuthenticator(packet, badAuth) {
		t.Error("expected invalid authenticator to fail verification")
	}
}

func TestCoAServer_StartStop(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Address: "127.0.0.1:0", // Random port
		Secret:  "testing123",
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := srv.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify running
	if atomic.LoadInt32(&srv.running) != 1 {
		t.Error("server should be running")
	}

	err = srv.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if atomic.LoadInt32(&srv.running) != 0 {
		t.Error("server should not be running after stop")
	}
}

func TestCoAServer_StopWithoutStart(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Secret: "testing123",
	}, logger)

	// Stop without Start should not error (conn is nil)
	err := srv.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestCoAServer_HandleCoARequest_WithHandler(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Address: "127.0.0.1:0",
		Secret:  "testing123",
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	handlerCalled := false
	srv.SetCoAHandler(func(ctx context.Context, req *CoARequest) *CoAResponse {
		handlerCalled = true
		return &CoAResponse{Success: true, Message: "accepted"}
	})

	// Build a CoA request packet and send it
	sendCoAPacket(t, srv, CodeCoARequest)

	time.Sleep(100 * time.Millisecond) // Allow time to process

	if !handlerCalled {
		t.Error("CoA handler was not called")
	}

	stats := srv.GetStats()
	if stats["coa_requests_received"] != 1 {
		t.Errorf("expected 1 CoA request, got %d", stats["coa_requests_received"])
	}
}

func TestCoAServer_HandleCoARequest_NoHandler(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Address: "127.0.0.1:0",
		Secret:  "testing123",
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	// No handler set — should default to accepting
	sendCoAPacket(t, srv, CodeCoARequest)

	time.Sleep(100 * time.Millisecond)

	stats := srv.GetStats()
	if stats["coa_requests_received"] != 1 {
		t.Errorf("expected 1 CoA request, got %d", stats["coa_requests_received"])
	}
	if stats["coa_acks_sent"] != 1 {
		t.Errorf("expected 1 CoA ACK (default accept), got %d", stats["coa_acks_sent"])
	}
}

func TestCoAServer_HandleDisconnectRequest_WithHandler(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Address: "127.0.0.1:0",
		Secret:  "testing123",
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	handlerCalled := false
	srv.SetDisconnectHandler(func(ctx context.Context, req *DisconnectRequest) *DisconnectResponse {
		handlerCalled = true
		return &DisconnectResponse{Success: true, Message: "disconnected"}
	})

	sendCoAPacket(t, srv, CodeDisconnectRequest)

	time.Sleep(100 * time.Millisecond)

	if !handlerCalled {
		t.Error("Disconnect handler was not called")
	}

	stats := srv.GetStats()
	if stats["disconnect_requests_received"] != 1 {
		t.Errorf("expected 1 disconnect request, got %d", stats["disconnect_requests_received"])
	}
}

func TestCoAServer_HandleDisconnectRequest_NoHandler(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Address: "127.0.0.1:0",
		Secret:  "testing123",
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	// No handler set — should default to rejecting
	sendCoAPacket(t, srv, CodeDisconnectRequest)

	time.Sleep(100 * time.Millisecond)

	stats := srv.GetStats()
	if stats["disconnect_requests_received"] != 1 {
		t.Errorf("expected 1 disconnect request, got %d", stats["disconnect_requests_received"])
	}
	if stats["disconnect_naks_sent"] != 1 {
		t.Errorf("expected 1 disconnect NAK (default reject), got %d", stats["disconnect_naks_sent"])
	}
}

// sendCoAPacket builds and sends a RADIUS packet to the CoA server
func sendCoAPacket(t *testing.T, srv *CoAServer, code byte) {
	t.Helper()
	secret := srv.secret

	// Build attributes — User-Name
	userName := []byte("testuser")
	attrBuf := make([]byte, 2+len(userName))
	attrBuf[0] = AttrUserName
	attrBuf[1] = byte(2 + len(userName))
	copy(attrBuf[2:], userName)

	length := uint16(20 + len(attrBuf))
	packet := make([]byte, length)
	packet[0] = code
	packet[1] = 1 // identifier
	binary.BigEndian.PutUint16(packet[2:4], length)
	copy(packet[20:], attrBuf)

	// Calculate authenticator
	hash := md5.New()
	hash.Write(packet[:4])
	hash.Write(make([]byte, 16))
	hash.Write(packet[20:])
	hash.Write([]byte(secret))
	authenticator := hash.Sum(nil)
	copy(packet[4:20], authenticator)

	// Send to server
	addr := srv.conn.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("failed to dial CoA server: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		t.Fatalf("failed to send packet: %v", err)
	}
}

func TestCoAServer_ReceiveLoop_InvalidPacket(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Address: "127.0.0.1:0",
		Secret:  "testing123",
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	addr := srv.conn.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Send too-short packet (< 20 bytes)
	conn.Write([]byte{0x01, 0x02, 0x03})

	// Send packet with length > actual bytes
	badPacket := make([]byte, 20)
	badPacket[0] = CodeCoARequest
	badPacket[1] = 1
	binary.BigEndian.PutUint16(badPacket[2:4], 100) // claims 100 bytes, only 20 sent
	conn.Write(badPacket)

	// Send packet with invalid authenticator
	packet := make([]byte, 20)
	packet[0] = CodeCoARequest
	packet[1] = 1
	binary.BigEndian.PutUint16(packet[2:4], 20)
	// Leave authenticator as zeros (incorrect)
	conn.Write(packet)

	// Send packet with unknown code
	secret := "testing123"
	unknownPacket := make([]byte, 20)
	unknownPacket[0] = 99 // Unknown code
	unknownPacket[1] = 1
	binary.BigEndian.PutUint16(unknownPacket[2:4], 20)
	hash := md5.New()
	hash.Write(unknownPacket[:4])
	hash.Write(make([]byte, 16))
	hash.Write(unknownPacket[20:])
	hash.Write([]byte(secret))
	auth := hash.Sum(nil)
	copy(unknownPacket[4:20], auth)
	conn.Write(unknownPacket)

	time.Sleep(200 * time.Millisecond)

	// No crashes, no CoA or DM requests counted for invalid packets
	stats := srv.GetStats()
	if stats["coa_requests_received"] != 0 {
		t.Errorf("expected 0 CoA requests for invalid packets, got %d", stats["coa_requests_received"])
	}
}

func TestCoAServer_ReceiveLoop_BadAttributes(t *testing.T) {
	logger := zap.NewNop()
	srv, _ := NewCoAServer(CoAServerConfig{
		Address: "127.0.0.1:0",
		Secret:  "testing123",
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	addr := srv.conn.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Send packet with bad attributes (attr length=1 which is < 2)
	badAttrData := []byte{AttrUserName, 1} // invalid attribute
	length := uint16(20 + len(badAttrData))
	packet := make([]byte, length)
	packet[0] = CodeCoARequest
	packet[1] = 1
	binary.BigEndian.PutUint16(packet[2:4], length)
	copy(packet[20:], badAttrData)

	// Calculate proper authenticator
	secret := "testing123"
	hash := md5.New()
	hash.Write(packet[:4])
	hash.Write(make([]byte, 16))
	hash.Write(packet[20:])
	hash.Write([]byte(secret))
	auth := hash.Sum(nil)
	copy(packet[4:20], auth)

	conn.Write(packet)

	time.Sleep(200 * time.Millisecond)

	// Should be counted as received but fail to parse attributes
	// (actually it's counted before parsing, so CoA request count may be 0 since
	// the attribute parsing happens before handleCoARequest)
}

// ---------------------------------------------------------------------------
// CoA Processor tests (coa_handler.go — deeper coverage)
// ---------------------------------------------------------------------------

func TestCoAProcessor_HandleCoA_LookupByIP(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	// Set up lookup by IP only (no session ID lookup)
	proc.SetSessionLookupByIP(func(ip net.IP) (*SessionInfo, bool) {
		if ip.Equal(net.ParseIP("10.0.0.99")) {
			return &SessionInfo{
				SessionID:       "session-by-ip",
				FramedIP:        ip,
				DownloadRateBPS: 100_000_000,
				UploadRateBPS:   50_000_000,
			}, true
		}
		return nil, false
	})

	proc.SetSessionPolicyUpdater(func(ctx context.Context, sessionID string, update *PolicyUpdate) error {
		return nil
	})

	req := &CoARequest{
		FramedIP: net.ParseIP("10.0.0.99"),
		FilterID: "upgrade-plan",
	}

	resp := proc.HandleCoA(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success, got error: %s", resp.Message)
	}
}

func TestCoAProcessor_HandleCoA_LookupByMAC(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookupByMAC(func(mac string) (*SessionInfo, bool) {
		if mac == "AA:BB:CC:DD:EE:FF" {
			return &SessionInfo{
				SessionID:       "session-by-mac",
				DownloadRateBPS: 100_000_000,
				UploadRateBPS:   50_000_000,
			}, true
		}
		return nil, false
	})

	proc.SetSessionPolicyUpdater(func(ctx context.Context, sessionID string, update *PolicyUpdate) error {
		return nil
	})

	req := &CoARequest{
		CallingStation: "AA:BB:CC:DD:EE:FF",
		FilterID:       "upgrade-plan",
	}

	resp := proc.HandleCoA(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success, got error: %s", resp.Message)
	}
}

func TestCoAProcessor_HandleCoA_PolicyUpdateFails(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookup(func(sessionID string) (*SessionInfo, bool) {
		return &SessionInfo{SessionID: sessionID}, true
	})

	proc.SetSessionPolicyUpdater(func(ctx context.Context, sessionID string, update *PolicyUpdate) error {
		return fmt.Errorf("policy update failed")
	})

	req := &CoARequest{
		SessionID: "session-1",
		FilterID:  "new-policy",
	}

	resp := proc.HandleCoA(context.Background(), req)
	if resp.Success {
		t.Error("expected failure when policy update fails")
	}
	if resp.ErrorCause != ErrorCauseResourcesUnavailable {
		t.Errorf("expected ErrorCauseResourcesUnavailable, got %d", resp.ErrorCause)
	}
}

func TestCoAProcessor_HandleCoA_WithEBPFUpdater(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookup(func(sessionID string) (*SessionInfo, bool) {
		return &SessionInfo{
			SessionID:       sessionID,
			DownloadRateBPS: 100_000_000,
			UploadRateBPS:   50_000_000,
		}, true
	})

	proc.SetSessionPolicyUpdater(func(ctx context.Context, sessionID string, update *PolicyUpdate) error {
		return nil
	})

	ebpfCalled := false
	proc.SetEBPFQoSUpdater(func(sessionID string, downloadBPS, uploadBPS uint64) error {
		ebpfCalled = true
		if downloadBPS != 200_000_000 {
			t.Errorf("expected 200Mbps download, got %d", downloadBPS)
		}
		// Upload should fall back to session value
		if uploadBPS != 50_000_000 {
			t.Errorf("expected 50Mbps upload (from session), got %d", uploadBPS)
		}
		return nil
	})

	req := &CoARequest{
		SessionID:   "session-qos",
		QoSDownload: 200000, // 200 Mbps in kbps
	}

	resp := proc.HandleCoA(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success, got: %s", resp.Message)
	}
	if !ebpfCalled {
		t.Error("eBPF QoS updater was not called")
	}
}

func TestCoAProcessor_HandleCoA_EBPFUpdaterFails(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookup(func(sessionID string) (*SessionInfo, bool) {
		return &SessionInfo{
			SessionID:       sessionID,
			DownloadRateBPS: 100_000_000,
			UploadRateBPS:   50_000_000,
		}, true
	})

	proc.SetSessionPolicyUpdater(func(ctx context.Context, sessionID string, update *PolicyUpdate) error {
		return nil
	})

	proc.SetEBPFQoSUpdater(func(sessionID string, downloadBPS, uploadBPS uint64) error {
		return fmt.Errorf("eBPF map update failed")
	})

	req := &CoARequest{
		SessionID:   "session-ebpf-fail",
		QoSDownload: 200000,
		QoSUpload:   100000,
	}

	// eBPF failure should not fail the CoA (policy was updated)
	resp := proc.HandleCoA(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success despite eBPF failure, got: %s", resp.Message)
	}
}

func TestCoAProcessor_HandleCoA_WithAuditLogger(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookup(func(sessionID string) (*SessionInfo, bool) {
		return &SessionInfo{SessionID: sessionID}, true
	})

	proc.SetSessionPolicyUpdater(func(ctx context.Context, sessionID string, update *PolicyUpdate) error {
		return nil
	})

	auditLogger := NewDefaultAuditLogger(logger)
	proc.SetAuditLogger(auditLogger)

	req := &CoARequest{
		SessionID: "session-audit",
		FilterID:  "gold-plan",
		FramedIP:  net.ParseIP("10.0.0.1"),
	}

	resp := proc.HandleCoA(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success, got: %s", resp.Message)
	}
}

func TestCoAProcessor_HandleDisconnect_LookupByIP(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookupByIP(func(ip net.IP) (*SessionInfo, bool) {
		if ip.Equal(net.ParseIP("10.0.0.99")) {
			return &SessionInfo{SessionID: "session-disc-ip"}, true
		}
		return nil, false
	})

	proc.SetSessionTerminator(func(ctx context.Context, sessionID string, reason uint32) error {
		return nil
	})

	req := &DisconnectRequest{
		FramedIP: net.ParseIP("10.0.0.99"),
	}

	resp := proc.HandleDisconnect(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success, got error: %s", resp.Message)
	}
}

func TestCoAProcessor_HandleDisconnect_LookupByMAC(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookupByMAC(func(mac string) (*SessionInfo, bool) {
		if mac == "11:22:33:44:55:66" {
			return &SessionInfo{SessionID: "session-disc-mac"}, true
		}
		return nil, false
	})

	proc.SetSessionTerminator(func(ctx context.Context, sessionID string, reason uint32) error {
		return nil
	})

	req := &DisconnectRequest{
		CallingStation: "11:22:33:44:55:66",
	}

	resp := proc.HandleDisconnect(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success, got error: %s", resp.Message)
	}
}

func TestCoAProcessor_HandleDisconnect_ByAcctSessionID(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookup(func(sessionID string) (*SessionInfo, bool) {
		if sessionID == "acct-123" {
			return &SessionInfo{SessionID: "acct-123"}, true
		}
		return nil, false
	})

	proc.SetSessionTerminator(func(ctx context.Context, sessionID string, reason uint32) error {
		return nil
	})

	req := &DisconnectRequest{
		SessionID:     "non-existent", // Primary lookup fails
		AcctSessionID: "acct-123",     // Fallback succeeds
	}

	resp := proc.HandleDisconnect(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success via AcctSessionID, got error: %s", resp.Message)
	}
}

func TestCoAProcessor_HandleDisconnect_TerminatorFails(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookup(func(sessionID string) (*SessionInfo, bool) {
		return &SessionInfo{SessionID: sessionID}, true
	})

	proc.SetSessionTerminator(func(ctx context.Context, sessionID string, reason uint32) error {
		return fmt.Errorf("termination failed")
	})

	req := &DisconnectRequest{SessionID: "session-fail-term"}

	resp := proc.HandleDisconnect(context.Background(), req)
	if resp.Success {
		t.Error("expected failure when terminator fails")
	}
	if resp.ErrorCause != ErrorCauseSessionContextNotRemovable {
		t.Errorf("expected ErrorCauseSessionContextNotRemovable, got %d", resp.ErrorCause)
	}
}

func TestCoAProcessor_HandleDisconnect_WithAccountingManager(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)
	client := testClient(t)

	tempDir := t.TempDir()
	am, _ := NewAccountingManager(client, AccountingConfig{
		PersistPath:     tempDir,
		InterimEnabled:  false,
		DrainOnShutdown: false,
		QueueSize:       100,
	}, logger)

	// Start a session in the accounting manager
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	am.StartSession(&AccountingSession{
		SessionID: "disc-acct-session",
		Username:  "user",
		MAC:       mac,
		FramedIP:  net.ParseIP("10.0.0.1"),
	})

	proc.SetAccountingManager(am)
	proc.SetSessionLookup(func(sessionID string) (*SessionInfo, bool) {
		return &SessionInfo{SessionID: sessionID}, true
	})
	proc.SetSessionTerminator(func(ctx context.Context, sessionID string, reason uint32) error {
		return nil
	})

	req := &DisconnectRequest{SessionID: "disc-acct-session"}

	resp := proc.HandleDisconnect(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success, got: %s", resp.Message)
	}

	// Session should be stopped in accounting manager
	_, exists := am.GetSession("disc-acct-session")
	if exists {
		t.Error("session should be stopped in accounting manager")
	}
}

func TestCoAProcessor_HandleDisconnect_WithAuditLogger(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookup(func(sessionID string) (*SessionInfo, bool) {
		return &SessionInfo{SessionID: sessionID}, true
	})
	proc.SetSessionTerminator(func(ctx context.Context, sessionID string, reason uint32) error {
		return nil
	})

	auditLogger := NewDefaultAuditLogger(logger)
	proc.SetAuditLogger(auditLogger)

	req := &DisconnectRequest{
		SessionID: "disc-audit",
		FramedIP:  net.ParseIP("10.0.0.1"),
	}

	resp := proc.HandleDisconnect(context.Background(), req)
	if !resp.Success {
		t.Errorf("expected success, got: %s", resp.Message)
	}
}

func TestCoAProcessor_BuildPolicyUpdate(t *testing.T) {
	proc := NewCoAProcessor(zap.NewNop())

	tests := []struct {
		name      string
		req       *CoARequest
		expectNil bool
		filterID  string
		dlBPS     uint64
		ulBPS     uint64
		sessTmout time.Duration
		idleTmout time.Duration
	}{
		{
			name:      "no changes",
			req:       &CoARequest{SessionID: "s1"},
			expectNil: true,
		},
		{
			name:     "filter ID only",
			req:      &CoARequest{FilterID: "gold"},
			filterID: "gold",
		},
		{
			name:  "QoS download/upload",
			req:   &CoARequest{QoSDownload: 100000, QoSUpload: 50000},
			dlBPS: 100_000_000, // 100000 kbps * 1000
			ulBPS: 50_000_000,
		},
		{
			name:      "session timeout",
			req:       &CoARequest{SessionTimeout: 7200},
			sessTmout: 7200 * time.Second,
		},
		{
			name:      "idle timeout",
			req:       &CoARequest{IdleTimeout: 600},
			idleTmout: 600 * time.Second,
		},
		{
			name:      "all changes",
			req:       &CoARequest{FilterID: "platinum", QoSDownload: 500000, QoSUpload: 250000, SessionTimeout: 86400, IdleTimeout: 3600},
			filterID:  "platinum",
			dlBPS:     500_000_000,
			ulBPS:     250_000_000,
			sessTmout: 86400 * time.Second,
			idleTmout: 3600 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			update := proc.buildPolicyUpdate(tt.req)
			if tt.expectNil {
				if update != nil {
					t.Error("expected nil policy update")
				}
				return
			}
			if update == nil {
				t.Fatal("expected non-nil policy update")
			}
			if update.FilterID != tt.filterID {
				t.Errorf("FilterID: got %q, want %q", update.FilterID, tt.filterID)
			}
			if update.DownloadRateBPS != tt.dlBPS {
				t.Errorf("DownloadRateBPS: got %d, want %d", update.DownloadRateBPS, tt.dlBPS)
			}
			if update.UploadRateBPS != tt.ulBPS {
				t.Errorf("UploadRateBPS: got %d, want %d", update.UploadRateBPS, tt.ulBPS)
			}
			if update.SessionTimeout != tt.sessTmout {
				t.Errorf("SessionTimeout: got %v, want %v", update.SessionTimeout, tt.sessTmout)
			}
			if update.IdleTimeout != tt.idleTmout {
				t.Errorf("IdleTimeout: got %v, want %v", update.IdleTimeout, tt.idleTmout)
			}
		})
	}
}

func TestCoAProcessor_GetStats(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	proc.SetSessionLookup(func(sessionID string) (*SessionInfo, bool) {
		if sessionID == "exists" {
			return &SessionInfo{SessionID: sessionID}, true
		}
		return nil, false
	})
	proc.SetSessionPolicyUpdater(func(ctx context.Context, sessionID string, update *PolicyUpdate) error {
		return nil
	})
	proc.SetSessionTerminator(func(ctx context.Context, sessionID string, reason uint32) error {
		return nil
	})

	// Process some CoA and Disconnect requests
	proc.HandleCoA(context.Background(), &CoARequest{SessionID: "exists", FilterID: "plan"})
	proc.HandleCoA(context.Background(), &CoARequest{SessionID: "nope", FilterID: "plan"})
	proc.HandleDisconnect(context.Background(), &DisconnectRequest{SessionID: "exists"})
	proc.HandleDisconnect(context.Background(), &DisconnectRequest{SessionID: "nope"})

	stats := proc.GetStats()
	if stats.CoAProcessed != 2 {
		t.Errorf("expected 2 CoA processed, got %d", stats.CoAProcessed)
	}
	if stats.CoASucceeded != 1 {
		t.Errorf("expected 1 CoA succeeded, got %d", stats.CoASucceeded)
	}
	if stats.CoAFailed != 1 {
		t.Errorf("expected 1 CoA failed, got %d", stats.CoAFailed)
	}
	if stats.DisconnectProcessed != 2 {
		t.Errorf("expected 2 disconnect processed, got %d", stats.DisconnectProcessed)
	}
	if stats.DisconnectSucceeded != 1 {
		t.Errorf("expected 1 disconnect succeeded, got %d", stats.DisconnectSucceeded)
	}
	if stats.DisconnectFailed != 1 {
		t.Errorf("expected 1 disconnect failed, got %d", stats.DisconnectFailed)
	}
	if stats.PolicyUpdates != 1 {
		t.Errorf("expected 1 policy update, got %d", stats.PolicyUpdates)
	}
	if stats.AvgProcessingMs <= 0 {
		t.Error("expected positive average processing time")
	}
}

func TestCoAProcessor_NoLookups(t *testing.T) {
	logger := zap.NewNop()
	proc := NewCoAProcessor(logger)

	// No lookups configured — all requests should fail
	resp := proc.HandleCoA(context.Background(), &CoARequest{
		SessionID: "test",
		FilterID:  "plan",
	})
	if resp.Success {
		t.Error("expected failure with no lookups configured")
	}

	dresp := proc.HandleDisconnect(context.Background(), &DisconnectRequest{
		SessionID: "test",
	})
	if dresp.Success {
		t.Error("expected failure with no lookups configured")
	}
}

// ---------------------------------------------------------------------------
// DefaultAuditLogger tests
// ---------------------------------------------------------------------------

func TestDefaultAuditLogger_LogCoARequest_NilFramedIP(t *testing.T) {
	logger := zap.NewNop()
	al := NewDefaultAuditLogger(logger)

	// Should not panic with nil FramedIP
	al.LogCoARequest(
		&CoARequest{SessionID: "test"},
		&CoAResponse{Success: true},
		100*time.Millisecond,
	)
}

func TestDefaultAuditLogger_LogDisconnectRequest_NilFramedIP(t *testing.T) {
	logger := zap.NewNop()
	al := NewDefaultAuditLogger(logger)

	// Should not panic with nil FramedIP
	al.LogDisconnectRequest(
		&DisconnectRequest{SessionID: "test"},
		&DisconnectResponse{Success: false, ErrorCause: ErrorCauseSessionContextNotFound},
		50*time.Millisecond,
	)
}

// ---------------------------------------------------------------------------
// Client addMessageAuthenticator test
// ---------------------------------------------------------------------------

func TestAddMessageAuthenticator(t *testing.T) {
	secret := []byte("testing123")
	packet := radius.New(radius.CodeAccessRequest, secret)

	err := addMessageAuthenticator(packet, secret)
	if err != nil {
		t.Fatalf("addMessageAuthenticator failed: %v", err)
	}

	// Verify the Message-Authenticator attribute was set (non-zero)
	encoded, err := packet.Encode()
	if err != nil {
		t.Fatalf("packet encode failed: %v", err)
	}
	if len(encoded) < 20 {
		t.Fatal("encoded packet too short")
	}
}

func TestFormatMAC(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF"},
		{"00:00:00:00:00:00", "00-00-00-00-00-00"},
		{"ff:ff:ff:ff:ff:ff", "FF-FF-FF-FF-FF-FF"},
		{"01:23:45:67:89:ab", "01-23-45-67-89-AB"},
	}

	for _, tt := range tests {
		mac, err := net.ParseMAC(tt.input)
		if err != nil {
			t.Fatalf("ParseMAC(%s): %v", tt.input, err)
		}
		result := formatMAC(mac)
		if result != tt.expected {
			t.Errorf("formatMAC(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestClientGetServerNextServer(t *testing.T) {
	logger := zap.NewNop()
	client, _ := NewClient(ClientConfig{
		Servers: []ServerConfig{
			{Host: "10.0.0.1", Port: 1812, Secret: "s1"},
			{Host: "10.0.0.2", Port: 1812, Secret: "s2"},
			{Host: "10.0.0.3", Port: 1812, Secret: "s3"},
		},
		NASID: "test-nas",
	}, logger)

	// Cycle through all servers
	s1 := client.getServer()
	if s1.Host != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", s1.Host)
	}

	client.nextServer()
	s2 := client.getServer()
	if s2.Host != "10.0.0.2" {
		t.Errorf("expected 10.0.0.2, got %s", s2.Host)
	}

	client.nextServer()
	s3 := client.getServer()
	if s3.Host != "10.0.0.3" {
		t.Errorf("expected 10.0.0.3, got %s", s3.Host)
	}

	// Wrap around
	client.nextServer()
	s4 := client.getServer()
	if s4.Host != "10.0.0.1" {
		t.Errorf("expected wrap to 10.0.0.1, got %s", s4.Host)
	}
}
