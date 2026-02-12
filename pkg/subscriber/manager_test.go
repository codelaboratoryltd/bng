package subscriber

import (
	"context"
	"fmt"
	"net"
	"sync"
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
	ipv4        net.IP
	mask        net.IPMask
	gateway     net.IP
	ipv6        net.IP
	prefix      *net.IPNet
	released4   []net.IP
	released6   []net.IP
	ipv4Err     error
	ipv6Err     error
	release4Err error
	release6Err error
}

func (m *mockAllocator) AllocateIPv4(ctx context.Context, session *Session, poolID string) (net.IP, net.IPMask, net.IP, error) {
	if m.ipv4Err != nil {
		return nil, nil, nil, m.ipv4Err
	}
	return m.ipv4, m.mask, m.gateway, nil
}

func (m *mockAllocator) AllocateIPv6(ctx context.Context, session *Session, poolID string) (net.IP, *net.IPNet, error) {
	if m.ipv6Err != nil {
		return nil, nil, m.ipv6Err
	}
	return m.ipv6, m.prefix, nil
}

func (m *mockAllocator) ReleaseIPv4(ctx context.Context, ip net.IP) error {
	m.released4 = append(m.released4, ip)
	return m.release4Err
}

func (m *mockAllocator) ReleaseIPv6(ctx context.Context, ip net.IP) error {
	m.released6 = append(m.released6, ip)
	return m.release6Err
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

// === New tests for Issue #78: error paths, concurrent access, edge cases ===

// Test Authenticate with error from authenticator
func TestManager_AuthenticateError(t *testing.T) {
	mgr, auth, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})

	// Set auth to return an error
	auth.err = fmt.Errorf("radius timeout")

	_, err := mgr.Authenticate(context.Background(), session.ID)
	if err == nil {
		t.Error("Expected authentication error")
	}

	// Session state should revert to init (the old state)
	s, ok := mgr.GetSession(session.ID)
	if !ok {
		t.Fatal("Session should still exist after auth error")
	}
	if s.State != StateInit {
		t.Errorf("State = %v, want init (reverted)", s.State)
	}

	// Stats should reflect failure
	stats := mgr.Stats()
	if stats.AuthFailures != 1 {
		t.Errorf("AuthFailures = %d, want 1", stats.AuthFailures)
	}
}

// Test Authenticate for nonexistent session
func TestManager_AuthenticateNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	_, err := mgr.Authenticate(context.Background(), "nonexistent-id")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

// Test Authenticate with walled garden result
func TestManager_AuthenticateWalledGarden(t *testing.T) {
	mgr, auth, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})

	auth.result = &AuthResult{
		Success:      true,
		SubscriberID: "sub-walled",
		ISPID:        "isp-1",
		WalledGarden: true,
		WalledReason: "overdue payment",
	}

	result, err := mgr.Authenticate(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !result.Success {
		t.Error("Expected auth success")
	}

	s, _ := mgr.GetSession(session.ID)
	if s.State != StateWalledGarden {
		t.Errorf("State = %v, want walled_garden", s.State)
	}
	if !s.WalledGarden {
		t.Error("Expected WalledGarden = true")
	}
	if s.WalledReason != "overdue payment" {
		t.Errorf("WalledReason = %v, want 'overdue payment'", s.WalledReason)
	}
}

// Test Authenticate applies all session attributes
func TestManager_AuthenticateAttributes(t *testing.T) {
	mgr, auth, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})

	auth.result = &AuthResult{
		Success:         true,
		SubscriberID:    "sub-attrs",
		ISPID:           "isp-1",
		RADIUSSessionID: "rad-123",
		SessionTimeout:  2 * time.Hour,
		IdleTimeout:     15 * time.Minute,
		DownloadRateBps: 200_000_000,
		UploadRateBps:   100_000_000,
		QoSPolicyID:     "qos-gold",
	}

	mgr.Authenticate(context.Background(), session.ID)

	s, _ := mgr.GetSession(session.ID)
	if s.SessionTimeout != 2*time.Hour {
		t.Errorf("SessionTimeout = %v, want 2h", s.SessionTimeout)
	}
	if s.IdleTimeout != 15*time.Minute {
		t.Errorf("IdleTimeout = %v, want 15m", s.IdleTimeout)
	}
	if s.DownloadRateBps != 200_000_000 {
		t.Errorf("DownloadRateBps = %d, want 200000000", s.DownloadRateBps)
	}
	if s.UploadRateBps != 100_000_000 {
		t.Errorf("UploadRateBps = %d, want 100000000", s.UploadRateBps)
	}
	if s.QoSPolicyID != "qos-gold" {
		t.Errorf("QoSPolicyID = %v, want qos-gold", s.QoSPolicyID)
	}
	if s.RADIUSSessionID != "rad-123" {
		t.Errorf("RADIUSSessionID = %v, want rad-123", s.RADIUSSessionID)
	}
}

// Test CreateSession stores metadata (CircuitID, RemoteID, Hostname)
func TestManager_CreateSessionMetadata(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, err := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:       mac,
		Type:      SessionTypeIPoE,
		CircuitID: "eth 0/1/1:100",
		RemoteID:  "remote-001",
		Hostname:  "subscriber-host",
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if session.Metadata["circuit_id"] != "eth 0/1/1:100" {
		t.Errorf("circuit_id = %v, want 'eth 0/1/1:100'", session.Metadata["circuit_id"])
	}
	if session.Metadata["remote_id"] != "remote-001" {
		t.Errorf("remote_id = %v, want 'remote-001'", session.Metadata["remote_id"])
	}
	if session.Metadata["hostname"] != "subscriber-host" {
		t.Errorf("hostname = %v, want 'subscriber-host'", session.Metadata["hostname"])
	}
}

// Test CreateSession without optional metadata
func TestManager_CreateSessionNoMetadata(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, err := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if _, exists := session.Metadata["circuit_id"]; exists {
		t.Error("circuit_id should not be set when empty")
	}
	if _, exists := session.Metadata["remote_id"]; exists {
		t.Error("remote_id should not be set when empty")
	}
	if _, exists := session.Metadata["hostname"]; exists {
		t.Error("hostname should not be set when empty")
	}
}

// Test CreateSession with PPPoE type
func TestManager_CreateSessionPPPoE(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, err := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:      mac,
		Type:     SessionTypePPPoE,
		Username: "user@isp.com",
		STag:     100,
		CTag:     200,
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if session.Type != SessionTypePPPoE {
		t.Errorf("Type = %v, want pppoe", session.Type)
	}
	if session.Username != "user@isp.com" {
		t.Errorf("Username = %v, want user@isp.com", session.Username)
	}
	if session.STag != 100 {
		t.Errorf("STag = %d, want 100", session.STag)
	}
	if session.CTag != 200 {
		t.Errorf("CTag = %d, want 200", session.CTag)
	}
}

// Test ActivateSession with walled garden flag
func TestManager_ActivateSessionWalledGarden(t *testing.T) {
	mgr, auth, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	auth.result = &AuthResult{
		Success:      true,
		SubscriberID: "sub-1",
		WalledGarden: true,
		WalledReason: "payment",
	}

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})
	mgr.Authenticate(context.Background(), session.ID)
	mgr.AssignAddress(context.Background(), session.ID, "pool-1", "")

	// Activate a session that has WalledGarden flag
	err := mgr.ActivateSession(session.ID)
	if err != nil {
		t.Fatalf("ActivateSession() error = %v", err)
	}

	s, _ := mgr.GetSession(session.ID)
	if s.State != StateWalledGarden {
		t.Errorf("State = %v, want walled_garden (WalledGarden flag)", s.State)
	}
}

// Test ActivateSession for nonexistent session
func TestManager_ActivateSessionNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	err := mgr.ActivateSession("nonexistent-id")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

// Test SetWalledGarden for nonexistent session
func TestManager_SetWalledGardenNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	err := mgr.SetWalledGarden("nonexistent-id", "test")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

// Test ClearWalledGarden for nonexistent session
func TestManager_ClearWalledGardenNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	err := mgr.ClearWalledGarden("nonexistent-id")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

// Test ClearWalledGarden on session that is NOT walled (no-op)
func TestManager_ClearWalledGardenAlreadyClear(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})

	// Clear without setting walled garden first
	err := mgr.ClearWalledGarden(session.ID)
	if err != nil {
		t.Fatalf("ClearWalledGarden() should succeed as no-op: %v", err)
	}

	s, _ := mgr.GetSession(session.ID)
	if s.WalledGarden {
		t.Error("Expected WalledGarden = false")
	}
}

// Test TerminateSession for nonexistent session
func TestManager_TerminateSessionNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	err := mgr.TerminateSession(context.Background(), "nonexistent-id", TerminateAdminReset)
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

// Test TerminateSession without IP allocation (no allocator release needed)
func TestManager_TerminateSessionNoIPs(t *testing.T) {
	mgr, _, allocator := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})

	err := mgr.TerminateSession(context.Background(), session.ID, TerminateAdminReset)
	if err != nil {
		t.Fatalf("TerminateSession() error = %v", err)
	}

	// No IPs should have been released
	if len(allocator.released4) != 0 {
		t.Errorf("Expected 0 IPv4 releases, got %d", len(allocator.released4))
	}
	if len(allocator.released6) != 0 {
		t.Errorf("Expected 0 IPv6 releases, got %d", len(allocator.released6))
	}
}

// Test AssignAddress for nonexistent session
func TestManager_AssignAddressNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	err := mgr.AssignAddress(context.Background(), "nonexistent-id", "pool-1", "")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

// Test AssignAddress with nil allocator (IPv4 only pool ID given)
func TestManager_AssignAddressNilAllocator(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultManagerConfig()
	auth := &mockAuth{result: &AuthResult{Success: true, SubscriberID: "sub-1"}}

	// Manager with nil allocator
	mgr := NewManager(config, auth, nil, logger)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})
	mgr.Authenticate(context.Background(), session.ID)

	// AssignAddress with pool IDs but nil allocator should not crash
	err := mgr.AssignAddress(context.Background(), session.ID, "pool-1", "pool-v6")
	if err != nil {
		t.Fatalf("AssignAddress() with nil allocator should not error: %v", err)
	}

	// State should be establishing even without allocation
	s, _ := mgr.GetSession(session.ID)
	if s.State != StateEstablishing {
		t.Errorf("State = %v, want establishing", s.State)
	}
}

// Test UpdateActivity for nonexistent session
func TestManager_UpdateActivityNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	err := mgr.UpdateActivity("nonexistent-id", 100, 200, 1, 2)
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

// Test GetSession for nonexistent session
func TestManager_GetSessionNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	_, ok := mgr.GetSession("nonexistent-id")
	if ok {
		t.Error("Expected not found for nonexistent session")
	}
}

// Test GetSessionByMAC for nonexistent MAC
func TestManager_GetSessionByMACNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	_, ok := mgr.GetSessionByMAC(mac)
	if ok {
		t.Error("Expected not found for nonexistent MAC")
	}
}

// Test GetSessionByIP for nonexistent IP
func TestManager_GetSessionByIPNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	_, ok := mgr.GetSessionByIP(net.ParseIP("192.168.99.99"))
	if ok {
		t.Error("Expected not found for nonexistent IP")
	}
}

// Test ListSessionsByISP with no matching ISP
func TestManager_ListSessionsByISPEmpty(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})

	sessions := mgr.ListSessionsByISP("nonexistent-isp")
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions for nonexistent ISP, got %d", len(sessions))
	}
}

// Test concurrent session creation
func TestManager_ConcurrentCreate(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mac := net.HardwareAddr{
				byte(idx >> 8), byte(idx),
				0x33, 0x44, 0x55, byte(idx),
			}
			_, err := mgr.CreateSession(context.Background(), &SessionRequest{
				MAC:  mac,
				Type: SessionTypeIPoE,
			})
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	errCount := 0
	for range errors {
		errCount++
	}

	sessions := mgr.ListSessions()
	if len(sessions)+errCount != 50 {
		t.Errorf("sessions(%d) + errors(%d) != 50", len(sessions), errCount)
	}
}

// Test concurrent session operations (create, lookup, terminate)
func TestManager_ConcurrentOperations(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	// Create some sessions first
	ids := make([]string, 10)
	for i := 0; i < 10; i++ {
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, byte(i >> 8), byte(i)}
		session, err := mgr.CreateSession(context.Background(), &SessionRequest{
			MAC:  mac,
			Type: SessionTypeIPoE,
		})
		if err != nil {
			t.Fatalf("CreateSession() error = %v", err)
		}
		ids[i] = session.ID
	}

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mgr.ListSessions()
			_ = mgr.Stats()
		}()
	}

	// Concurrent lookups
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mgr.GetSession(ids[idx])
		}(i)
	}

	// Concurrent activity updates
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mgr.UpdateActivity(ids[idx], 100, 200, 1, 2)
		}(i)
	}

	wg.Wait()

	// Verify all sessions still exist
	sessions := mgr.ListSessions()
	if len(sessions) != 10 {
		t.Errorf("Expected 10 sessions, got %d", len(sessions))
	}
}

// Test session timeout cleanup
func TestManager_SessionTimeoutCleanup(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultManagerConfig()
	config.CleanupInterval = 50 * time.Millisecond
	config.DefaultSessionTimeout = 10 * time.Millisecond
	config.DefaultIdleTimeout = 0 // Disable idle timeout

	auth := &mockAuth{result: &AuthResult{Success: true, SubscriberID: "sub-1"}}
	allocator := &mockAllocator{
		ipv4:    net.ParseIP("10.0.0.50"),
		mask:    net.CIDRMask(24, 32),
		gateway: net.ParseIP("10.0.0.1"),
	}

	mgr := NewManager(config, auth, allocator, logger)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})
	mgr.Authenticate(context.Background(), session.ID)
	mgr.ActivateSession(session.ID)

	// Wait for session timeout
	time.Sleep(20 * time.Millisecond)

	mgr.Start()
	defer mgr.Stop()

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	sessions := mgr.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions after session timeout, got %d", len(sessions))
	}
}

// Test DefaultManagerConfig values
func TestDefaultManagerConfig(t *testing.T) {
	config := DefaultManagerConfig()

	if config.CleanupInterval != 30*time.Second {
		t.Errorf("CleanupInterval = %v, want 30s", config.CleanupInterval)
	}
	if config.DefaultSessionTimeout != 24*time.Hour {
		t.Errorf("DefaultSessionTimeout = %v, want 24h", config.DefaultSessionTimeout)
	}
	if config.DefaultIdleTimeout != 30*time.Minute {
		t.Errorf("DefaultIdleTimeout = %v, want 30m", config.DefaultIdleTimeout)
	}
	if config.AuthTimeout != 30*time.Second {
		t.Errorf("AuthTimeout = %v, want 30s", config.AuthTimeout)
	}
	if config.MaxAuthAttempts != 3 {
		t.Errorf("MaxAuthAttempts = %d, want 3", config.MaxAuthAttempts)
	}
	if config.MaxSessions != 100000 {
		t.Errorf("MaxSessions = %d, want 100000", config.MaxSessions)
	}
	if config.DefaultDownloadRateBps != 100_000_000 {
		t.Errorf("DefaultDownloadRateBps = %d, want 100000000", config.DefaultDownloadRateBps)
	}
	if config.DefaultUploadRateBps != 50_000_000 {
		t.Errorf("DefaultUploadRateBps = %d, want 50000000", config.DefaultUploadRateBps)
	}
}

// Test OnEvent with multiple handlers
func TestManager_MultipleEventHandlers(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	count1 := 0
	count2 := 0
	mgr.OnEvent(func(event *SessionEvent) { count1++ })
	mgr.OnEvent(func(event *SessionEvent) { count2++ })

	mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})

	if count1 != 1 {
		t.Errorf("handler1 count = %d, want 1", count1)
	}
	if count2 != 1 {
		t.Errorf("handler2 count = %d, want 1", count2)
	}
}

// Test TerminateSession with nil allocator
func TestManager_TerminateSessionNilAllocator(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultManagerConfig()
	auth := &mockAuth{result: &AuthResult{Success: true, SubscriberID: "sub-1"}}

	mgr := NewManager(config, auth, nil, logger)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})

	// Manually set IPs on session to test nil allocator path during terminate
	mgr.mu.Lock()
	session.IPv4 = net.ParseIP("10.0.0.50")
	session.IPv6 = net.ParseIP("2001:db8::50")
	mgr.mu.Unlock()

	// Should not panic with nil allocator
	err := mgr.TerminateSession(context.Background(), session.ID, TerminateAdminReset)
	if err != nil {
		t.Fatalf("TerminateSession() with nil allocator error = %v", err)
	}
}

// Test full lifecycle: create -> auth -> address -> activate -> update -> walled -> unwalled -> terminate
func TestManager_FullLifecycle(t *testing.T) {
	mgr, auth, allocator := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	var events []SessionEventType
	mgr.OnEvent(func(event *SessionEvent) {
		events = append(events, event.Type)
	})

	// 1. Create
	session, err := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:       mac,
		Type:      SessionTypeIPoE,
		CircuitID: "eth 0/1/1:100",
		RemoteID:  "olt-001",
		Hostname:  "cpe-001",
		STag:      100,
		CTag:      200,
	})
	if err != nil {
		t.Fatalf("CreateSession error: %v", err)
	}

	auth.result = &AuthResult{
		Success:         true,
		SubscriberID:    "sub-lifecycle",
		ISPID:           "isp-lifecycle",
		RADIUSSessionID: "rad-lifecycle",
		SessionTimeout:  4 * time.Hour,
		IdleTimeout:     1 * time.Hour,
		DownloadRateBps: 50_000_000,
		UploadRateBps:   25_000_000,
		QoSPolicyID:     "gold",
	}

	// 2. Authenticate
	result, err := mgr.Authenticate(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if !result.Success {
		t.Fatal("Expected auth success")
	}

	// 3. Assign address
	err = mgr.AssignAddress(context.Background(), session.ID, "pool-v4", "pool-v6")
	if err != nil {
		t.Fatalf("AssignAddress error: %v", err)
	}

	// 4. Activate
	err = mgr.ActivateSession(session.ID)
	if err != nil {
		t.Fatalf("ActivateSession error: %v", err)
	}

	s, _ := mgr.GetSession(session.ID)
	if s.State != StateActive {
		t.Errorf("State = %v, want active", s.State)
	}

	// 5. Update activity
	mgr.UpdateActivity(session.ID, 5000, 10000, 50, 100)

	// 6. Walled garden
	mgr.SetWalledGarden(session.ID, "overdue")
	s, _ = mgr.GetSession(session.ID)
	if s.State != StateWalledGarden {
		t.Errorf("State = %v, want walled_garden", s.State)
	}

	// 7. Unwalled
	mgr.ClearWalledGarden(session.ID)
	s, _ = mgr.GetSession(session.ID)
	if s.State != StateActive {
		t.Errorf("State = %v, want active", s.State)
	}

	// 8. Terminate
	err = mgr.TerminateSession(context.Background(), session.ID, TerminateUserRequest)
	if err != nil {
		t.Fatalf("TerminateSession error: %v", err)
	}

	_, ok := mgr.GetSession(session.ID)
	if ok {
		t.Error("Session should be gone after terminate")
	}

	// Verify IP releases
	if len(allocator.released4) != 1 {
		t.Errorf("Expected 1 IPv4 release, got %d", len(allocator.released4))
	}
	if len(allocator.released6) != 1 {
		t.Errorf("Expected 1 IPv6 release, got %d", len(allocator.released6))
	}

	// Verify event sequence
	expectedEvents := []SessionEventType{
		EventSessionCreate,
		EventSessionAuth,
		EventSessionActivate,
		EventSessionWalled,
		EventSessionUnwalled,
		EventSessionTerminate,
	}
	if len(events) != len(expectedEvents) {
		t.Fatalf("Expected %d events, got %d: %v", len(expectedEvents), len(events), events)
	}
	for i, expected := range expectedEvents {
		if events[i] != expected {
			t.Errorf("Event[%d] = %v, want %v", i, events[i], expected)
		}
	}

	// Verify stats
	stats := mgr.Stats()
	if stats.TotalSessionsCreated != 1 {
		t.Errorf("TotalSessionsCreated = %d, want 1", stats.TotalSessionsCreated)
	}
	if stats.TotalSessionsEnded != 1 {
		t.Errorf("TotalSessionsEnded = %d, want 1", stats.TotalSessionsEnded)
	}
	if stats.AuthSuccesses != 1 {
		t.Errorf("AuthSuccesses = %d, want 1", stats.AuthSuccesses)
	}
	if stats.TotalBytesIn != 5000 {
		t.Errorf("TotalBytesIn = %d, want 5000", stats.TotalBytesIn)
	}
	if stats.TotalBytesOut != 10000 {
		t.Errorf("TotalBytesOut = %d, want 10000", stats.TotalBytesOut)
	}
}

// Test AssignAddress with IPv4 allocation failure
func TestManager_AssignAddressIPv4Failure(t *testing.T) {
	mgr, auth, allocator := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	auth.result = &AuthResult{Success: true, SubscriberID: "sub-1"}
	allocator.ipv4Err = fmt.Errorf("pool exhausted")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})
	mgr.Authenticate(context.Background(), session.ID)

	err := mgr.AssignAddress(context.Background(), session.ID, "pool-1", "")
	if err == nil {
		t.Error("Expected IPv4 allocation error")
	}
}

// Test AssignAddress with IPv6 allocation failure (non-fatal)
func TestManager_AssignAddressIPv6Failure(t *testing.T) {
	mgr, auth, allocator := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	auth.result = &AuthResult{Success: true, SubscriberID: "sub-1"}
	allocator.ipv6Err = fmt.Errorf("no IPv6 pools available")

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})
	mgr.Authenticate(context.Background(), session.ID)

	// IPv6 failure should not be fatal
	err := mgr.AssignAddress(context.Background(), session.ID, "pool-v4", "pool-v6")
	if err != nil {
		t.Fatalf("AssignAddress() should succeed despite IPv6 failure: %v", err)
	}

	s, _ := mgr.GetSession(session.ID)
	if s.IPv4.String() != "10.0.0.50" {
		t.Errorf("IPv4 = %v, want 10.0.0.50", s.IPv4)
	}
	if s.IPv6 != nil {
		t.Errorf("IPv6 = %v, want nil (allocation failed)", s.IPv6)
	}
	if s.State != StateEstablishing {
		t.Errorf("State = %v, want establishing", s.State)
	}
}

// Test TerminateSession with IP release errors (should still succeed)
func TestManager_TerminateSessionReleaseErrors(t *testing.T) {
	mgr, auth, allocator := newTestManager(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	auth.result = &AuthResult{Success: true, SubscriberID: "sub-1"}

	session, _ := mgr.CreateSession(context.Background(), &SessionRequest{
		MAC:  mac,
		Type: SessionTypeIPoE,
	})
	mgr.Authenticate(context.Background(), session.ID)
	mgr.AssignAddress(context.Background(), session.ID, "pool-v4", "pool-v6")
	mgr.ActivateSession(session.ID)

	// Set release to fail
	allocator.release4Err = fmt.Errorf("release failed")
	allocator.release6Err = fmt.Errorf("release failed")

	// Terminate should still succeed even if release fails
	err := mgr.TerminateSession(context.Background(), session.ID, TerminateAdminReset)
	if err != nil {
		t.Fatalf("TerminateSession() should succeed despite release errors: %v", err)
	}

	_, ok := mgr.GetSession(session.ID)
	if ok {
		t.Error("Session should be removed after terminate")
	}
}
