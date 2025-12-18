package subscriber

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// mockAuth implements Authenticator for testing.
type mockAuth struct {
	result *AuthResult
	err    error
}

func (m *mockAuth) Authenticate(ctx context.Context, req *SessionRequest) (*AuthResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

// mockAllocator implements AddressAllocator for testing.
type mockAllocator struct {
	ipv4      net.IP
	mask      net.IPMask
	gateway   net.IP
	ipv6      net.IP
	prefix    *net.IPNet
	released4 []net.IP
	released6 []net.IP
}

func (m *mockAllocator) AllocateIPv4(ctx context.Context, session *Session, poolID string) (net.IP, net.IPMask, net.IP, error) {
	return m.ipv4, m.mask, m.gateway, nil
}

func (m *mockAllocator) AllocateIPv6(ctx context.Context, session *Session, poolID string) (net.IP, *net.IPNet, error) {
	return m.ipv6, m.prefix, nil
}

func (m *mockAllocator) ReleaseIPv4(ctx context.Context, ip net.IP) error {
	m.released4 = append(m.released4, ip)
	return nil
}

func (m *mockAllocator) ReleaseIPv6(ctx context.Context, ip net.IP) error {
	m.released6 = append(m.released6, ip)
	return nil
}

func newTestManager(t *testing.T) (*Manager, *mockAuth, *mockAllocator) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	config := DefaultManagerConfig()
	config.CleanupInterval = 50 * time.Millisecond

	auth := &mockAuth{
		result: &AuthResult{
			Success:         true,
			SubscriberID:    "sub-123",
			ISPID:           "isp-1",
			RADIUSSessionID: "rad-abc",
			DownloadRateBps: 100_000_000,
			UploadRateBps:   50_000_000,
		},
	}

	allocator := &mockAllocator{
		ipv4:    net.ParseIP("10.0.0.50"),
		mask:    net.CIDRMask(24, 32),
		gateway: net.ParseIP("10.0.0.1"),
		ipv6:    net.ParseIP("2001:db8::50"),
		prefix:  &net.IPNet{IP: net.ParseIP("2001:db8:1::"), Mask: net.CIDRMask(64, 128)},
	}

	return NewManager(config, auth, allocator, logger), auth, allocator
}

func TestManager_StartStop(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestManager_CreateSession(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	req := &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	}

	session, err := mgr.CreateSession(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if session.ID == "" {
		t.Error("Expected session ID to be set")
	}
	if session.State != StateInit {
		t.Errorf("State = %v, want init", session.State)
	}
	if session.MAC.String() != mac.String() {
		t.Errorf("MAC = %v, want %v", session.MAC, mac)
	}

	// Verify lookup works
	retrieved, ok := mgr.GetSession(session.ID)
	if !ok {
		t.Error("Expected to find session by ID")
	}
	if retrieved.ID != session.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, session.ID)
	}

	// Verify MAC lookup
	retrieved, ok = mgr.GetSessionByMAC(mac)
	if !ok {
		t.Error("Expected to find session by MAC")
	}
	if retrieved.ID != session.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, session.ID)
	}

	// Verify duplicate MAC rejected
	_, err = mgr.CreateSession(context.Background(), req)
	if err == nil {
		t.Error("Expected error for duplicate MAC")
	}
}

func TestManager_Authenticate(t *testing.T) {
	mgr, auth, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	req := &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	}

	session, _ := mgr.CreateSession(context.Background(), req)

	// Authenticate
	result, err := mgr.Authenticate(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if !result.Success {
		t.Error("Expected auth success")
	}
	if result.SubscriberID != "sub-123" {
		t.Errorf("SubscriberID = %v, want sub-123", result.SubscriberID)
	}

	// Verify session updated
	session, _ = mgr.GetSession(session.ID)
	if !session.Authenticated {
		t.Error("Expected session to be authenticated")
	}
	if session.SubscriberID != "sub-123" {
		t.Errorf("SubscriberID = %v, want sub-123", session.SubscriberID)
	}
	if session.State != StateAddressAssign {
		t.Errorf("State = %v, want address_assign", session.State)
	}

	// Test auth failure
	auth.result = &AuthResult{
		Success: false,
		Error:   "invalid credentials",
	}

	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	session2, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:   mac2,
		NTEID: "nte-002",
		Type:  SessionTypeIPoE,
	})

	result, err = mgr.Authenticate(context.Background(), session2.ID)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.Success {
		t.Error("Expected auth failure")
	}
}

func TestManager_AssignAddress(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	req := &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	}

	session, _ := mgr.CreateSession(context.Background(), req)
	mgr.Authenticate(context.Background(), session.ID)

	// Assign address
	err := mgr.AssignAddress(context.Background(), session.ID, "pool-1", "pool-v6")
	if err != nil {
		t.Fatalf("AssignAddress() error = %v", err)
	}

	// Verify addresses
	session, _ = mgr.GetSession(session.ID)
	if session.IPv4.String() != "10.0.0.50" {
		t.Errorf("IPv4 = %v, want 10.0.0.50", session.IPv4)
	}
	if session.IPv6.String() != "2001:db8::50" {
		t.Errorf("IPv6 = %v, want 2001:db8::50", session.IPv6)
	}
	if session.State != StateEstablishing {
		t.Errorf("State = %v, want establishing", session.State)
	}

	// Verify IP lookup
	found, ok := mgr.GetSessionByIP(net.ParseIP("10.0.0.50"))
	if !ok {
		t.Error("Expected to find session by IP")
	}
	if found.ID != session.ID {
		t.Errorf("ID = %v, want %v", found.ID, session.ID)
	}
}

func TestManager_ActivateSession(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	req := &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	}

	session, _ := mgr.CreateSession(context.Background(), req)
	mgr.Authenticate(context.Background(), session.ID)
	mgr.AssignAddress(context.Background(), session.ID, "pool-1", "")

	// Activate
	err := mgr.ActivateSession(session.ID)
	if err != nil {
		t.Fatalf("ActivateSession() error = %v", err)
	}

	session, _ = mgr.GetSession(session.ID)
	if session.State != StateActive {
		t.Errorf("State = %v, want active", session.State)
	}
}

func TestManager_WalledGarden(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	req := &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	}

	session, _ := mgr.CreateSession(context.Background(), req)
	mgr.Authenticate(context.Background(), session.ID)
	mgr.AssignAddress(context.Background(), session.ID, "pool-1", "")
	mgr.ActivateSession(session.ID)

	// Put in walled garden
	err := mgr.SetWalledGarden(session.ID, "payment due")
	if err != nil {
		t.Fatalf("SetWalledGarden() error = %v", err)
	}

	session, _ = mgr.GetSession(session.ID)
	if !session.WalledGarden {
		t.Error("Expected WalledGarden = true")
	}
	if session.WalledReason != "payment due" {
		t.Errorf("WalledReason = %v, want 'payment due'", session.WalledReason)
	}
	if session.State != StateWalledGarden {
		t.Errorf("State = %v, want walled_garden", session.State)
	}

	// Clear walled garden
	err = mgr.ClearWalledGarden(session.ID)
	if err != nil {
		t.Fatalf("ClearWalledGarden() error = %v", err)
	}

	session, _ = mgr.GetSession(session.ID)
	if session.WalledGarden {
		t.Error("Expected WalledGarden = false")
	}
	if session.State != StateActive {
		t.Errorf("State = %v, want active", session.State)
	}
}

func TestManager_TerminateSession(t *testing.T) {
	mgr, _, allocator := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	req := &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	}

	session, _ := mgr.CreateSession(context.Background(), req)
	mgr.Authenticate(context.Background(), session.ID)
	mgr.AssignAddress(context.Background(), session.ID, "pool-1", "pool-v6")
	mgr.ActivateSession(session.ID)

	sessionID := session.ID

	// Update some traffic
	mgr.UpdateActivity(sessionID, 1000, 2000, 10, 20)

	// Terminate
	err := mgr.TerminateSession(context.Background(), sessionID, TerminateUserRequest)
	if err != nil {
		t.Fatalf("TerminateSession() error = %v", err)
	}

	// Verify session is gone
	_, ok := mgr.GetSession(sessionID)
	if ok {
		t.Error("Expected session to be removed")
	}

	// Verify MAC lookup is gone
	_, ok = mgr.GetSessionByMAC(mac)
	if ok {
		t.Error("Expected MAC index to be removed")
	}

	// Verify IPs were released
	if len(allocator.released4) != 1 {
		t.Errorf("Expected 1 IPv4 release, got %d", len(allocator.released4))
	}
	if len(allocator.released6) != 1 {
		t.Errorf("Expected 1 IPv6 release, got %d", len(allocator.released6))
	}

	// Verify stats
	stats := mgr.Stats()
	if stats.TotalSessionsEnded != 1 {
		t.Errorf("TotalSessionsEnded = %d, want 1", stats.TotalSessionsEnded)
	}
	if stats.TotalBytesIn != 1000 {
		t.Errorf("TotalBytesIn = %d, want 1000", stats.TotalBytesIn)
	}
}

func TestManager_UpdateActivity(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	req := &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	}

	session, _ := mgr.CreateSession(context.Background(), req)

	// Update activity
	err := mgr.UpdateActivity(session.ID, 1000, 2000, 10, 20)
	if err != nil {
		t.Fatalf("UpdateActivity() error = %v", err)
	}

	session, _ = mgr.GetSession(session.ID)
	if session.BytesIn != 1000 {
		t.Errorf("BytesIn = %d, want 1000", session.BytesIn)
	}
	if session.BytesOut != 2000 {
		t.Errorf("BytesOut = %d, want 2000", session.BytesOut)
	}
	if session.PacketsIn != 10 {
		t.Errorf("PacketsIn = %d, want 10", session.PacketsIn)
	}
	if session.PacketsOut != 20 {
		t.Errorf("PacketsOut = %d, want 20", session.PacketsOut)
	}

	// Accumulates
	mgr.UpdateActivity(session.ID, 500, 500, 5, 5)
	session, _ = mgr.GetSession(session.ID)
	if session.BytesIn != 1500 {
		t.Errorf("BytesIn = %d, want 1500", session.BytesIn)
	}
}

func TestManager_SessionCleanup(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultManagerConfig()
	config.CleanupInterval = 50 * time.Millisecond
	config.DefaultIdleTimeout = 10 * time.Millisecond

	auth := &mockAuth{
		result: &AuthResult{Success: true, SubscriberID: "sub-1"},
	}
	allocator := &mockAllocator{
		ipv4:    net.ParseIP("10.0.0.50"),
		mask:    net.CIDRMask(24, 32),
		gateway: net.ParseIP("10.0.0.1"),
	}

	mgr := NewManager(config, auth, allocator, logger)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	})
	mgr.Authenticate(context.Background(), session.ID)
	mgr.ActivateSession(session.ID)

	// Wait for idle timeout
	time.Sleep(20 * time.Millisecond)

	// Start manager to run cleanup
	mgr.Start()
	defer mgr.Stop()

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	// Verify session was cleaned up
	sessions := mgr.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions after cleanup, got %d", len(sessions))
	}
}

func TestManager_ListSessions(t *testing.T) {
	mgr, auth, _ := newTestManager(t)

	// Create multiple sessions
	for i := 0; i < 3; i++ {
		mac, _ := net.ParseMAC("00:11:22:33:44:5" + string(rune('0'+i)))
		auth.result = &AuthResult{
			Success:      true,
			SubscriberID: "sub-" + string(rune('0'+i)),
			ISPID:        "isp-1",
		}
		if i == 2 {
			auth.result.ISPID = "isp-2" // Different ISP
		}

		session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
			MAC:   mac,
			NTEID: "nte-00" + string(rune('0'+i)),
			Type:  SessionTypeIPoE,
		})
		mgr.Authenticate(context.Background(), session.ID)
	}

	// List all
	sessions := mgr.ListSessions()
	if len(sessions) != 3 {
		t.Errorf("ListSessions() = %d, want 3", len(sessions))
	}

	// List by ISP
	sessions = mgr.ListSessionsByISP("isp-1")
	if len(sessions) != 2 {
		t.Errorf("ListSessionsByISP(isp-1) = %d, want 2", len(sessions))
	}

	sessions = mgr.ListSessionsByISP("isp-2")
	if len(sessions) != 1 {
		t.Errorf("ListSessionsByISP(isp-2) = %d, want 1", len(sessions))
	}
}

func TestManager_Stats(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Initial stats
	stats := mgr.Stats()
	if stats.ActiveSessions != 0 {
		t.Errorf("ActiveSessions = %d, want 0", stats.ActiveSessions)
	}

	// Create session
	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	})

	stats = mgr.Stats()
	if stats.ActiveSessions != 1 {
		t.Errorf("ActiveSessions = %d, want 1", stats.ActiveSessions)
	}
	if stats.TotalSessionsCreated != 1 {
		t.Errorf("TotalSessionsCreated = %d, want 1", stats.TotalSessionsCreated)
	}

	// Authenticate
	mgr.Authenticate(context.Background(), session.ID)
	stats = mgr.Stats()
	if stats.AuthSuccesses != 1 {
		t.Errorf("AuthSuccesses = %d, want 1", stats.AuthSuccesses)
	}

	// Set walled garden
	mgr.SetWalledGarden(session.ID, "test")
	stats = mgr.Stats()
	if stats.WalledGardenSessions != 1 {
		t.Errorf("WalledGardenSessions = %d, want 1", stats.WalledGardenSessions)
	}
}

func TestManager_EventHandler(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	var events []*SessionEvent
	mgr.OnEvent(func(event *SessionEvent) {
		events = append(events, event)
	})

	// Create session - should emit event
	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:   mac,
		NTEID: "nte-001",
		Type:  SessionTypeIPoE,
	})

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].Type != EventSessionCreate {
		t.Errorf("Event type = %v, want session_create", events[0].Type)
	}

	// Authenticate - should emit event
	mgr.Authenticate(context.Background(), session.ID)
	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}
	if events[1].Type != EventSessionAuth {
		t.Errorf("Event type = %v, want session_auth", events[1].Type)
	}

	// Activate - should emit event
	mgr.ActivateSession(session.ID)
	if len(events) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(events))
	}
	if events[2].Type != EventSessionActivate {
		t.Errorf("Event type = %v, want session_activate", events[2].Type)
	}
}

func TestManager_MaxSessions(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultManagerConfig()
	config.MaxSessions = 2

	auth := &mockAuth{result: &AuthResult{Success: true}}
	mgr := NewManager(config, auth, nil, logger)

	// Create max sessions
	for i := 0; i < 2; i++ {
		mac, _ := net.ParseMAC("00:11:22:33:44:5" + string(rune('0'+i)))
		_, err := mgr.CreateSession(context.Background(), &SessionRequest{
			MAC:   mac,
			NTEID: "nte-00" + string(rune('0'+i)),
			Type:  SessionTypeIPoE,
		})
		if err != nil {
			t.Fatalf("CreateSession() error = %v", err)
		}
	}

	// Next should fail
	mac, _ := net.ParseMAC("00:11:22:33:44:59")
	_, err := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:   mac,
		NTEID: "nte-009",
		Type:  SessionTypeIPoE,
	})
	if err == nil {
		t.Error("Expected max sessions error")
	}
}
