package wifi

import (
	"fmt"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestManager_CreateSession(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	config.LeaseDuration = 5 * time.Minute
	config.GracePeriod = 1 * time.Minute

	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := net.ParseIP("10.0.1.100")

	session, err := mgr.CreateSession(mac, "test-host", 1, ip)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if session == nil {
		t.Fatal("CreateSession() returned nil session")
	}

	if session.State != StateGracePeriod {
		t.Errorf("State = %v, want %v", session.State, StateGracePeriod)
	}

	if !session.IP.Equal(ip) {
		t.Errorf("IP = %v, want %v", session.IP, ip)
	}

	if session.Hostname != "test-host" {
		t.Errorf("Hostname = %v, want test-host", session.Hostname)
	}
}

func TestManager_GetSession(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := net.ParseIP("10.0.1.100")

	_, _ = mgr.CreateSession(mac, "test", 1, ip)

	// Get by MAC
	session, ok := mgr.GetSession(mac)
	if !ok {
		t.Error("GetSession() returned false, expected true")
	}
	if session == nil {
		t.Error("GetSession() returned nil session")
	}

	// Get by IP
	session, ok = mgr.GetSessionByIP(ip)
	if !ok {
		t.Error("GetSessionByIP() returned false, expected true")
	}
	if session == nil {
		t.Error("GetSessionByIP() returned nil session")
	}

	// Non-existent
	_, ok = mgr.GetSession(net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if ok {
		t.Error("GetSession() for non-existent should return false")
	}
}

func TestManager_AuthenticateSession(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := net.ParseIP("10.0.1.100")

	_, _ = mgr.CreateSession(mac, "test", 1, ip)

	// Authenticate
	err := mgr.AuthenticateSession(mac, "captive_portal", "user@example.com")
	if err != nil {
		t.Fatalf("AuthenticateSession() error = %v", err)
	}

	session, _ := mgr.GetSession(mac)
	if !session.Authenticated {
		t.Error("Session should be authenticated")
	}
	if session.State != StateAuthenticated {
		t.Errorf("State = %v, want %v", session.State, StateAuthenticated)
	}
	if session.UserIdentity != "user@example.com" {
		t.Errorf("UserIdentity = %v, want user@example.com", session.UserIdentity)
	}
}

func TestManager_RenewSession(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	config.LeaseDuration = 10 * time.Minute
	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := net.ParseIP("10.0.1.100")

	session, _ := mgr.CreateSession(mac, "test", 1, ip)
	originalExpiry := session.LeaseExpiry

	// Wait a bit and renew
	time.Sleep(10 * time.Millisecond)

	err := mgr.RenewSession(mac)
	if err != nil {
		t.Fatalf("RenewSession() error = %v", err)
	}

	session, _ = mgr.GetSession(mac)
	if !session.LeaseExpiry.After(originalExpiry) {
		t.Error("LeaseExpiry should be extended after renewal")
	}
}

func TestManager_ReleaseSession(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := net.ParseIP("10.0.1.100")

	_, _ = mgr.CreateSession(mac, "test", 1, ip)

	// Release
	err := mgr.ReleaseSession(mac)
	if err != nil {
		t.Fatalf("ReleaseSession() error = %v", err)
	}

	// Should be gone
	_, ok := mgr.GetSession(mac)
	if ok {
		t.Error("Session should be removed after release")
	}

	_, ok = mgr.GetSessionByIP(ip)
	if ok {
		t.Error("IP mapping should be removed after release")
	}
}

func TestManager_NeedsAuthentication(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	config.CaptivePortalEnabled = true
	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := net.ParseIP("10.0.1.100")

	// No session = needs auth
	if !mgr.NeedsAuthentication(mac) {
		t.Error("Should need authentication with no session")
	}

	_, _ = mgr.CreateSession(mac, "test", 1, ip)

	// New session = needs auth
	if !mgr.NeedsAuthentication(mac) {
		t.Error("Should need authentication for new session")
	}

	_ = mgr.AuthenticateSession(mac, "captive_portal", "user@example.com")

	// Authenticated = no auth needed
	if mgr.NeedsAuthentication(mac) {
		t.Error("Should not need authentication after auth")
	}
}

func TestManager_NeedsAuthentication_Disabled(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	config.CaptivePortalEnabled = false
	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	// With captive portal disabled, never needs auth
	if mgr.NeedsAuthentication(mac) {
		t.Error("Should not need authentication when captive portal is disabled")
	}
}

func TestManager_Stats(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	// Create a few sessions
	for i := 0; i < 3; i++ {
		mac := net.HardwareAddr{0x00, byte(i), 0x22, 0x33, 0x44, 0x55}
		ip := net.ParseIP(fmt.Sprintf("10.0.1.%d", 100+i))
		_, _ = mgr.CreateSession(mac, "test", 1, ip)
	}

	// Authenticate one
	_ = mgr.AuthenticateSession(net.HardwareAddr{0x00, 0x00, 0x22, 0x33, 0x44, 0x55}, "test", "user")

	stats := mgr.Stats()
	if stats.ActiveSessions != 3 {
		t.Errorf("ActiveSessions = %d, want 3", stats.ActiveSessions)
	}
	if stats.AuthenticatedSessions != 1 {
		t.Errorf("AuthenticatedSessions = %d, want 1", stats.AuthenticatedSessions)
	}
}

func TestManager_UpdateTrafficStats(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := net.ParseIP("10.0.1.100")

	_, _ = mgr.CreateSession(mac, "test", 1, ip)

	mgr.UpdateTrafficStats(mac, 1000, 2000, 10, 20)
	mgr.UpdateTrafficStats(mac, 500, 500, 5, 5)

	session, _ := mgr.GetSession(mac)
	if session.BytesIn != 1500 {
		t.Errorf("BytesIn = %d, want 1500", session.BytesIn)
	}
	if session.BytesOut != 2500 {
		t.Errorf("BytesOut = %d, want 2500", session.BytesOut)
	}
}

func TestDefaultConfigs(t *testing.T) {
	wifiConfig := DefaultWiFiConfig()
	if wifiConfig.Mode != ModeWiFiGateway {
		t.Errorf("WiFi Mode = %v, want %v", wifiConfig.Mode, ModeWiFiGateway)
	}
	if wifiConfig.AllocationTrigger != "dhcp_discover" {
		t.Errorf("WiFi AllocationTrigger = %v, want dhcp_discover", wifiConfig.AllocationTrigger)
	}

	oltConfig := DefaultOLTBNGConfig()
	if oltConfig.Mode != ModeOLTBNG {
		t.Errorf("OLT Mode = %v, want %v", oltConfig.Mode, ModeOLTBNG)
	}
	if oltConfig.AllocationTrigger != "radius_auth" {
		t.Errorf("OLT AllocationTrigger = %v, want radius_auth", oltConfig.AllocationTrigger)
	}
}

func TestManager_SessionRenewalOnCreate(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultWiFiConfig()
	mgr := NewManager(config, logger)
	_ = mgr.Start()
	defer mgr.Stop()

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := net.ParseIP("10.0.1.100")

	// First create
	session1, _ := mgr.CreateSession(mac, "test", 1, ip)
	id1 := session1.ID

	// Second create with same MAC should renew, not create new
	session2, _ := mgr.CreateSession(mac, "test", 1, ip)

	if session2.ID != id1 {
		t.Error("Second CreateSession should return same session (renewal)")
	}
}
