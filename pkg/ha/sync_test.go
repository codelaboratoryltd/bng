package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// mockSessionStore implements SessionStore for testing.
type mockSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*SessionState),
	}
}

func (m *mockSessionStore) GetSession(sessionID string) (*SessionState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	return s, ok
}

func (m *mockSessionStore) GetAllSessions() []SessionState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]SessionState, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, *s)
	}
	return result
}

func (m *mockSessionStore) PutSession(session *SessionState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.SessionID] = session
	return nil
}

func (m *mockSessionStore) DeleteSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionID)
	return nil
}

func (m *mockSessionStore) GetSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func TestSyncMessage_Encode_Decode(t *testing.T) {
	original := &SyncMessage{
		Type: SyncTypeAdd,
		Sessions: []SessionState{
			{
				SessionID:    "sess-001",
				SubscriberID: "sub-001",
				MAC:          "00:11:22:33:44:55",
				IP:           "10.0.0.100",
				VLAN:         100,
				QoSProfile:   "premium",
				CreatedAt:    time.Now().Truncate(time.Second),
			},
		},
		Timestamp:   time.Now().Truncate(time.Second),
		SequenceNum: 42,
		NodeID:      "bng-001",
	}

	// Encode
	data, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	// Decode
	decoded, err := DecodeSyncMessage(data)
	if err != nil {
		t.Fatalf("DecodeSyncMessage() error = %v", err)
	}

	// Verify
	if decoded.Type != original.Type {
		t.Errorf("Type = %v, want %v", decoded.Type, original.Type)
	}
	if decoded.SequenceNum != original.SequenceNum {
		t.Errorf("SequenceNum = %v, want %v", decoded.SequenceNum, original.SequenceNum)
	}
	if decoded.NodeID != original.NodeID {
		t.Errorf("NodeID = %v, want %v", decoded.NodeID, original.NodeID)
	}
	if len(decoded.Sessions) != 1 {
		t.Fatalf("len(Sessions) = %v, want 1", len(decoded.Sessions))
	}
	if decoded.Sessions[0].SessionID != original.Sessions[0].SessionID {
		t.Errorf("SessionID = %v, want %v", decoded.Sessions[0].SessionID, original.Sessions[0].SessionID)
	}
}

func TestHASyncer_ActiveHandleGetSessions(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	// Add some test sessions
	store.PutSession(&SessionState{
		SessionID:    "sess-001",
		SubscriberID: "sub-001",
		MAC:          "00:11:22:33:44:55",
		IP:           "10.0.0.100",
		VLAN:         100,
		CreatedAt:    time.Now(),
	})
	store.PutSession(&SessionState{
		SessionID:    "sess-002",
		SubscriberID: "sub-002",
		MAC:          "00:11:22:33:44:66",
		IP:           "10.0.0.101",
		VLAN:         100,
		CreatedAt:    time.Now(),
	})

	config := DefaultSyncConfig()
	config.NodeID = "bng-active"
	config.Role = RoleActive

	syncer := NewHASyncer(config, store, logger)

	// Create test request
	req := httptest.NewRequest("GET", "/ha/sessions", nil)
	w := httptest.NewRecorder()

	syncer.handleGetSessions(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Status = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	var msg SyncMessage
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if msg.Type != SyncTypeFull {
		t.Errorf("Type = %v, want %v", msg.Type, SyncTypeFull)
	}
	if len(msg.Sessions) != 2 {
		t.Errorf("len(Sessions) = %v, want 2", len(msg.Sessions))
	}
	if msg.NodeID != "bng-active" {
		t.Errorf("NodeID = %v, want bng-active", msg.NodeID)
	}
}

func TestHASyncer_ActiveHandleHealth(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-active"
	config.Role = RoleActive

	syncer := NewHASyncer(config, store, logger)

	req := httptest.NewRequest("GET", "/ha/health", nil)
	w := httptest.NewRecorder()

	syncer.handleHealth(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Status = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if health["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", health["status"])
	}
	if health["node_id"] != "bng-active" {
		t.Errorf("node_id = %v, want bng-active", health["node_id"])
	}
}

func TestHASyncer_PushChange(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-active"
	config.Role = RoleActive

	syncer := NewHASyncer(config, store, logger)

	session := &SessionState{
		SessionID:    "sess-001",
		SubscriberID: "sub-001",
		MAC:          "00:11:22:33:44:55",
		IP:           "10.0.0.100",
	}

	// Push a change
	err := syncer.PushChange(SyncTypeAdd, session)
	if err != nil {
		t.Fatalf("PushChange() error = %v", err)
	}

	// Verify change is queued
	select {
	case msg := <-syncer.pendingChanges:
		if msg.Type != SyncTypeAdd {
			t.Errorf("Type = %v, want %v", msg.Type, SyncTypeAdd)
		}
		if len(msg.Sessions) != 1 {
			t.Errorf("len(Sessions) = %v, want 1", len(msg.Sessions))
		}
		if msg.Sessions[0].SessionID != "sess-001" {
			t.Errorf("SessionID = %v, want sess-001", msg.Sessions[0].SessionID)
		}
	default:
		t.Error("Expected change to be queued")
	}
}

func TestHASyncer_PushChange_StandbyError(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-standby"
	config.Role = RoleStandby
	config.Partner = &PartnerInfo{
		NodeID:   "bng-active",
		Endpoint: "127.0.0.1:9000",
	}

	syncer := NewHASyncer(config, store, logger)

	session := &SessionState{
		SessionID: "sess-001",
	}

	err := syncer.PushChange(SyncTypeAdd, session)
	if err == nil {
		t.Error("Expected error when calling PushChange on standby")
	}
}

func TestHASyncer_Integration_FullSync(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create active node
	activeStore := newMockSessionStore()
	activeStore.PutSession(&SessionState{
		SessionID:       "sess-001",
		SubscriberID:    "sub-001",
		MAC:             "00:11:22:33:44:55",
		IP:              "10.0.0.100",
		VLAN:            100,
		QoSProfile:      "premium",
		DownloadRateBps: 100_000_000,
		UploadRateBps:   50_000_000,
		SessionType:     "ipoe",
		CreatedAt:       time.Now(),
		State:           "active",
	})
	activeStore.PutSession(&SessionState{
		SessionID:       "sess-002",
		SubscriberID:    "sub-002",
		MAC:             "00:11:22:33:44:66",
		IP:              "10.0.0.101",
		VLAN:            100,
		QoSProfile:      "basic",
		DownloadRateBps: 50_000_000,
		UploadRateBps:   25_000_000,
		SessionType:     "ipoe",
		CreatedAt:       time.Now(),
		State:           "active",
	})

	activeConfig := DefaultSyncConfig()
	activeConfig.NodeID = "bng-active"
	activeConfig.Role = RoleActive
	activeConfig.ListenAddr = "127.0.0.1:0" // Random port

	activeSyncer := NewHASyncer(activeConfig, activeStore, logger)

	if err := activeSyncer.Start(); err != nil {
		t.Fatalf("Active Start() error = %v", err)
	}
	defer activeSyncer.Stop()

	// Get the actual port
	time.Sleep(100 * time.Millisecond) // Wait for server to start

	// Create a test server that wraps the active syncer's handlers
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ha/sessions":
			activeSyncer.handleGetSessions(w, r)
		case "/ha/health":
			activeSyncer.handleHealth(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// Create standby node
	standbyStore := newMockSessionStore()

	standbyConfig := DefaultSyncConfig()
	standbyConfig.NodeID = "bng-standby"
	standbyConfig.Role = RoleStandby
	standbyConfig.Partner = &PartnerInfo{
		NodeID:   "bng-active",
		Endpoint: ts.Listener.Addr().String(),
	}
	standbyConfig.ReconnectInterval = 100 * time.Millisecond

	standbySyncer := NewHASyncer(standbyConfig, standbyStore, logger)

	// Perform full sync
	err := standbySyncer.performFullSync()
	if err != nil {
		t.Fatalf("performFullSync() error = %v", err)
	}

	// Verify sessions were synced
	if standbyStore.GetSessionCount() != 2 {
		t.Errorf("Standby session count = %v, want 2", standbyStore.GetSessionCount())
	}

	sess1, ok := standbyStore.GetSession("sess-001")
	if !ok {
		t.Error("Expected to find sess-001")
	} else {
		if sess1.MAC != "00:11:22:33:44:55" {
			t.Errorf("sess-001 MAC = %v, want 00:11:22:33:44:55", sess1.MAC)
		}
		if sess1.IP != "10.0.0.100" {
			t.Errorf("sess-001 IP = %v, want 10.0.0.100", sess1.IP)
		}
	}

	sess2, ok := standbyStore.GetSession("sess-002")
	if !ok {
		t.Error("Expected to find sess-002")
	} else {
		if sess2.MAC != "00:11:22:33:44:66" {
			t.Errorf("sess-002 MAC = %v, want 00:11:22:33:44:66", sess2.MAC)
		}
	}

	// Verify stats
	stats := standbySyncer.Stats()
	if stats.SessionsSynced != 2 {
		t.Errorf("SessionsSynced = %v, want 2", stats.SessionsSynced)
	}
	if stats.MessagesReceived != 1 {
		t.Errorf("MessagesReceived = %v, want 1", stats.MessagesReceived)
	}
}

func TestHASyncer_HandleSSEData(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-standby"
	config.Role = RoleStandby
	config.Partner = &PartnerInfo{
		NodeID:   "bng-active",
		Endpoint: "127.0.0.1:9000",
	}

	syncer := NewHASyncer(config, store, logger)

	// Test add
	addMsg := &SyncMessage{
		Type: SyncTypeAdd,
		Sessions: []SessionState{
			{
				SessionID: "sess-001",
				MAC:       "00:11:22:33:44:55",
				IP:        "10.0.0.100",
			},
		},
		NodeID: "bng-active",
	}
	data, _ := addMsg.Encode()
	if err := syncer.handleSSEData(data); err != nil {
		t.Fatalf("handleSSEData(add) error = %v", err)
	}

	if store.GetSessionCount() != 1 {
		t.Errorf("Session count = %v, want 1", store.GetSessionCount())
	}

	// Test update
	updateMsg := &SyncMessage{
		Type: SyncTypeUpdate,
		Sessions: []SessionState{
			{
				SessionID: "sess-001",
				MAC:       "00:11:22:33:44:55",
				IP:        "10.0.0.200", // Changed IP
			},
		},
		NodeID: "bng-active",
	}
	data, _ = updateMsg.Encode()
	if err := syncer.handleSSEData(data); err != nil {
		t.Fatalf("handleSSEData(update) error = %v", err)
	}

	sess, ok := store.GetSession("sess-001")
	if !ok {
		t.Fatal("Expected to find sess-001")
	}
	if sess.IP != "10.0.0.200" {
		t.Errorf("IP = %v, want 10.0.0.200", sess.IP)
	}

	// Test delete
	deleteMsg := &SyncMessage{
		Type: SyncTypeDelete,
		Sessions: []SessionState{
			{SessionID: "sess-001"},
		},
		NodeID: "bng-active",
	}
	data, _ = deleteMsg.Encode()
	if err := syncer.handleSSEData(data); err != nil {
		t.Fatalf("handleSSEData(delete) error = %v", err)
	}

	if store.GetSessionCount() != 0 {
		t.Errorf("Session count = %v, want 0", store.GetSessionCount())
	}
}

func TestHASyncer_HandleSSEData_Heartbeat(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-standby"
	config.Role = RoleStandby
	config.Partner = &PartnerInfo{
		NodeID:   "bng-active",
		Endpoint: "127.0.0.1:9000",
	}

	syncer := NewHASyncer(config, store, logger)

	heartbeatMsg := &SyncMessage{
		Type:      SyncTypeHeartbeat,
		Timestamp: time.Now(),
		NodeID:    "bng-active",
	}
	data, _ := heartbeatMsg.Encode()

	err := syncer.handleSSEData(data)
	if err != nil {
		t.Fatalf("handleSSEData(heartbeat) error = %v", err)
	}

	// Heartbeat should not affect session count
	if store.GetSessionCount() != 0 {
		t.Errorf("Session count = %v, want 0", store.GetSessionCount())
	}

	stats := syncer.Stats()
	if stats.MessagesReceived != 1 {
		t.Errorf("MessagesReceived = %v, want 1", stats.MessagesReceived)
	}
}

func TestHASyncer_GetReceivedSessions(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-standby"
	config.Role = RoleStandby
	config.Partner = &PartnerInfo{
		NodeID:   "bng-active",
		Endpoint: "127.0.0.1:9000",
	}

	syncer := NewHASyncer(config, store, logger)

	// Simulate receiving sessions
	addMsg := &SyncMessage{
		Type: SyncTypeAdd,
		Sessions: []SessionState{
			{SessionID: "sess-001", MAC: "00:11:22:33:44:55"},
			{SessionID: "sess-002", MAC: "00:11:22:33:44:66"},
		},
		NodeID: "bng-active",
	}
	data, _ := addMsg.Encode()
	syncer.handleSSEData(data)

	// Test GetReceivedSession
	sess, ok := syncer.GetReceivedSession("sess-001")
	if !ok {
		t.Error("Expected to find sess-001")
	}
	if sess.MAC != "00:11:22:33:44:55" {
		t.Errorf("MAC = %v, want 00:11:22:33:44:55", sess.MAC)
	}

	_, ok = syncer.GetReceivedSession("sess-999")
	if ok {
		t.Error("Did not expect to find sess-999")
	}

	// Test GetAllReceivedSessions
	allSessions := syncer.GetAllReceivedSessions()
	if len(allSessions) != 2 {
		t.Errorf("len(allSessions) = %v, want 2", len(allSessions))
	}
}

func TestHASyncer_Stats(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-test"
	config.Role = RoleActive

	syncer := NewHASyncer(config, store, logger)

	stats := syncer.Stats()
	if stats.SessionsSynced != 0 {
		t.Errorf("Initial SessionsSynced = %v, want 0", stats.SessionsSynced)
	}
	if stats.MessagesReceived != 0 {
		t.Errorf("Initial MessagesReceived = %v, want 0", stats.MessagesReceived)
	}

	// Add a session to store
	store.PutSession(&SessionState{SessionID: "sess-001"})

	stats = syncer.Stats()
	if stats.SessionsSynced != 1 {
		t.Errorf("SessionsSynced = %v, want 1", stats.SessionsSynced)
	}
}

func TestHASyncer_StartStop_Active(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-active"
	config.Role = RoleActive
	config.ListenAddr = "127.0.0.1:0"
	config.HeartbeatInterval = 50 * time.Millisecond

	syncer := NewHASyncer(config, store, logger)

	if err := syncer.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Give time for goroutines to start
	time.Sleep(100 * time.Millisecond)

	if err := syncer.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestHASyncer_StartStop_StandbyNoPartner(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-standby"
	config.Role = RoleStandby
	// No partner configured

	syncer := NewHASyncer(config, store, logger)

	err := syncer.Start()
	if err == nil {
		t.Error("Expected error when starting standby without partner")
		syncer.Stop()
	}
}

func TestDefaultSyncConfig(t *testing.T) {
	config := DefaultSyncConfig()

	if config.ReconnectInterval != 5*time.Second {
		t.Errorf("ReconnectInterval = %v, want 5s", config.ReconnectInterval)
	}
	if config.HeartbeatInterval != 10*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 10s", config.HeartbeatInterval)
	}
	if config.FullSyncInterval != 5*time.Minute {
		t.Errorf("FullSyncInterval = %v, want 5m", config.FullSyncInterval)
	}
	if config.ConnectTimeout != 10*time.Second {
		t.Errorf("ConnectTimeout = %v, want 10s", config.ConnectTimeout)
	}
	if config.RequestTimeout != 30*time.Second {
		t.Errorf("RequestTimeout = %v, want 30s", config.RequestTimeout)
	}
}

func TestRole_Constants(t *testing.T) {
	if RoleActive != "active" {
		t.Errorf("RoleActive = %v, want active", RoleActive)
	}
	if RoleStandby != "standby" {
		t.Errorf("RoleStandby = %v, want standby", RoleStandby)
	}
	if RoleUnknown != "unknown" {
		t.Errorf("RoleUnknown = %v, want unknown", RoleUnknown)
	}
}

func TestSyncMessageType_Constants(t *testing.T) {
	types := []struct {
		got  SyncMessageType
		want string
	}{
		{SyncTypeFull, "full"},
		{SyncTypeAdd, "add"},
		{SyncTypeUpdate, "update"},
		{SyncTypeDelete, "delete"},
		{SyncTypeHeartbeat, "heartbeat"},
		{SyncTypeFullRequest, "full_request"},
	}

	for _, tt := range types {
		if string(tt.got) != tt.want {
			t.Errorf("SyncMessageType = %v, want %v", tt.got, tt.want)
		}
	}
}

func TestHASyncer_BroadcastLoop_WithClient(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-active"
	config.Role = RoleActive
	config.HeartbeatInterval = 50 * time.Millisecond

	syncer := NewHASyncer(config, store, logger)

	// Add a mock client
	clientChan := make(chan *SyncMessage, 10)
	syncer.sseClientsMu.Lock()
	syncer.sseClients["test-client"] = clientChan
	syncer.sseClientsMu.Unlock()

	// Start broadcast loop
	ctx, cancel := context.WithCancel(context.Background())
	syncer.ctx = ctx
	syncer.cancel = cancel

	syncer.wg.Add(1)
	go syncer.broadcastLoop()

	// Push a change
	session := &SessionState{
		SessionID: "sess-001",
		MAC:       "00:11:22:33:44:55",
	}
	syncer.pendingChanges <- &SyncMessage{
		Type:     SyncTypeAdd,
		Sessions: []SessionState{*session},
		NodeID:   "bng-active",
	}

	// Wait for message
	select {
	case msg := <-clientChan:
		if msg.Type != SyncTypeAdd {
			t.Errorf("Type = %v, want add", msg.Type)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timed out waiting for broadcast message")
	}

	// Wait for heartbeat
	select {
	case msg := <-clientChan:
		if msg.Type != SyncTypeHeartbeat {
			t.Errorf("Type = %v, want heartbeat", msg.Type)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timed out waiting for heartbeat")
	}

	cancel()
	time.Sleep(100 * time.Millisecond)
}

func TestHASyncer_MethodNotAllowed(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-active"
	config.Role = RoleActive

	syncer := NewHASyncer(config, store, logger)

	// Test POST to GET endpoint
	req := httptest.NewRequest("POST", "/ha/sessions", nil)
	w := httptest.NewRecorder()
	syncer.handleGetSessions(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusMethodNotAllowed)
	}

	// Test POST to stream endpoint
	req = httptest.NewRequest("POST", "/ha/sessions/stream", nil)
	w = httptest.NewRecorder()
	syncer.handleSessionStream(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHASyncer_IsConnected(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-test"
	config.Role = RoleActive

	syncer := NewHASyncer(config, store, logger)

	// Initially not connected
	if syncer.IsConnected() {
		t.Error("Expected IsConnected() = false initially")
	}

	// Simulate connection
	syncer.mu.Lock()
	syncer.connected = true
	syncer.mu.Unlock()

	if !syncer.IsConnected() {
		t.Error("Expected IsConnected() = true after setting connected")
	}
}

func TestHASyncer_RecordError(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockSessionStore()

	config := DefaultSyncConfig()
	config.NodeID = "bng-test"
	config.Role = RoleActive

	syncer := NewHASyncer(config, store, logger)

	testErr := "test error message"
	syncer.recordError(fmt.Errorf("%s", testErr))

	stats := syncer.Stats()
	if stats.LastError != testErr {
		t.Errorf("LastError = %v, want %v", stats.LastError, testErr)
	}
	if stats.LastErrorTime.IsZero() {
		t.Error("Expected LastErrorTime to be set")
	}
}

func TestSessionState_AllFields(t *testing.T) {
	now := time.Now()
	session := SessionState{
		SessionID:       "sess-001",
		SubscriberID:    "sub-001",
		MAC:             "00:11:22:33:44:55",
		IP:              "10.0.0.100",
		IPv6:            "2001:db8::100",
		Gateway:         "10.0.0.1",
		VLAN:            100,
		STag:            200,
		CTag:            300,
		QoSProfile:      "premium",
		DownloadRateBps: 100_000_000,
		UploadRateBps:   50_000_000,
		SessionType:     "ipoe",
		ISPID:           "isp-001",
		Username:        "user@isp.com",
		CreatedAt:       now,
		LastActivity:    now,
		State:           "active",
		WalledGarden:    false,
		BytesIn:         1000,
		BytesOut:        2000,
	}

	// Encode and decode to verify all fields
	msg := &SyncMessage{
		Type:     SyncTypeAdd,
		Sessions: []SessionState{session},
	}
	data, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded, err := DecodeSyncMessage(data)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	got := decoded.Sessions[0]
	if got.SessionID != session.SessionID {
		t.Errorf("SessionID mismatch")
	}
	if got.SubscriberID != session.SubscriberID {
		t.Errorf("SubscriberID mismatch")
	}
	if got.MAC != session.MAC {
		t.Errorf("MAC mismatch")
	}
	if got.IP != session.IP {
		t.Errorf("IP mismatch")
	}
	if got.IPv6 != session.IPv6 {
		t.Errorf("IPv6 mismatch")
	}
	if got.Gateway != session.Gateway {
		t.Errorf("Gateway mismatch")
	}
	if got.VLAN != session.VLAN {
		t.Errorf("VLAN mismatch")
	}
	if got.STag != session.STag {
		t.Errorf("STag mismatch")
	}
	if got.CTag != session.CTag {
		t.Errorf("CTag mismatch")
	}
	if got.QoSProfile != session.QoSProfile {
		t.Errorf("QoSProfile mismatch")
	}
	if got.DownloadRateBps != session.DownloadRateBps {
		t.Errorf("DownloadRateBps mismatch")
	}
	if got.UploadRateBps != session.UploadRateBps {
		t.Errorf("UploadRateBps mismatch")
	}
	if got.SessionType != session.SessionType {
		t.Errorf("SessionType mismatch")
	}
	if got.ISPID != session.ISPID {
		t.Errorf("ISPID mismatch")
	}
	if got.Username != session.Username {
		t.Errorf("Username mismatch")
	}
	if got.State != session.State {
		t.Errorf("State mismatch")
	}
	if got.WalledGarden != session.WalledGarden {
		t.Errorf("WalledGarden mismatch")
	}
	if got.BytesIn != session.BytesIn {
		t.Errorf("BytesIn mismatch")
	}
	if got.BytesOut != session.BytesOut {
		t.Errorf("BytesOut mismatch")
	}
}
