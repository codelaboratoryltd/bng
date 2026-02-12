package radius

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNewClientAdditional(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		cfg         ClientConfig
		expectError bool
	}{
		{
			name: "valid configuration",
			cfg: ClientConfig{
				Servers: []ServerConfig{
					{Host: "127.0.0.1", Port: 1812, Secret: "testing123"},
				},
				NASID:   "test-nas",
				Timeout: 0, // Use default
				Retries: 0, // Use default
			},
			expectError: false,
		},
		{
			name: "multiple servers",
			cfg: ClientConfig{
				Servers: []ServerConfig{
					{Host: "127.0.0.1", Port: 1812, Secret: "testing123"},
					{Host: "127.0.0.2", Port: 1812, Secret: "testing123"},
				},
				NASID: "test-nas",
			},
			expectError: false,
		},
		{
			name: "no servers",
			cfg: ClientConfig{
				Servers: []ServerConfig{},
				NASID:   "test-nas",
			},
			expectError: true,
		},
		{
			name: "no NAS-ID",
			cfg: ClientConfig{
				Servers: []ServerConfig{
					{Host: "127.0.0.1", Port: 1812, Secret: "testing123"},
				},
				NASID: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.cfg, logger)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if client == nil {
					t.Error("expected non-nil client")
				}
			}
		})
	}
}

func TestClientDefaultsAdditional(t *testing.T) {
	logger := zap.NewNop()
	cfg := ClientConfig{
		Servers: []ServerConfig{
			{Host: "127.0.0.1", Port: 1812, Secret: "testing123"},
		},
		NASID: "test-nas",
	}

	client, err := NewClient(cfg, logger)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Check defaults
	if client.timeout.Seconds() != 3 {
		t.Errorf("expected default timeout 3s, got %v", client.timeout)
	}

	if client.retries != 3 {
		t.Errorf("expected default retries 3, got %d", client.retries)
	}
}

func TestFormatMACAdditional(t *testing.T) {
	tests := []struct {
		mac      string
		expected string
	}{
		{"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF"},
		{"00:00:00:00:00:00", "00-00-00-00-00-00"},
		{"ff:ff:ff:ff:ff:ff", "FF-FF-FF-FF-FF-FF"},
		{"01:23:45:67:89:ab", "01-23-45-67-89-AB"},
	}

	for _, tt := range tests {
		mac, err := net.ParseMAC(tt.mac)
		if err != nil {
			t.Fatalf("failed to parse MAC %s: %v", tt.mac, err)
		}

		result := formatMAC(mac)
		if result != tt.expected {
			t.Errorf("formatMAC(%s) = %s, want %s", tt.mac, result, tt.expected)
		}
	}
}

func TestServerConfigStructAdditional(t *testing.T) {
	cfg := ServerConfig{
		Host:   "192.168.1.100",
		Port:   1812,
		Secret: "secret123",
	}

	if cfg.Host != "192.168.1.100" {
		t.Errorf("expected Host 192.168.1.100, got %s", cfg.Host)
	}

	if cfg.Port != 1812 {
		t.Errorf("expected Port 1812, got %d", cfg.Port)
	}

	if cfg.Secret != "secret123" {
		t.Errorf("expected Secret secret123, got %s", cfg.Secret)
	}
}

func TestAuthRequestStructAdditional(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	req := &AuthRequest{
		Username:    "user@example.com",
		Password:    "password123",
		MAC:         mac,
		CircuitID:   "eth0/1/1:100",
		RemoteID:    "remote-1",
		NASPort:     1,
		NASPortType: 15, // Ethernet
		CalledID:    "called-station",
		CallingID:   "calling-station",
	}

	if req.Username != "user@example.com" {
		t.Error("Username mismatch")
	}

	if req.NASPortType != 15 {
		t.Errorf("expected NASPortType 15, got %d", req.NASPortType)
	}
}

func TestAuthResponseStructAdditional(t *testing.T) {
	resp := &AuthResponse{
		Accepted:       true,
		RejectReason:   "",
		SessionTimeout: 3600,
		IdleTimeout:    300,
		FramedIP:       net.ParseIP("10.0.0.100"),
		FramedPool:     "residential",
		FilterID:       "100mbps-policy",
		Class:          []byte("session-class"),
		DownloadBPS:    104857600, // 100 Mbps
		UploadBPS:      20971520,  // 20 Mbps
		Attributes:     map[string]interface{}{"custom": "value"},
	}

	if !resp.Accepted {
		t.Error("expected Accepted to be true")
	}

	if resp.SessionTimeout != 3600 {
		t.Errorf("expected SessionTimeout 3600, got %d", resp.SessionTimeout)
	}

	if resp.FilterID != "100mbps-policy" {
		t.Errorf("expected FilterID 100mbps-policy, got %s", resp.FilterID)
	}
}

func TestAcctRequestStructAdditional(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	req := &AcctRequest{
		SessionID:      "session-123",
		Username:       "user@example.com",
		MAC:            mac,
		FramedIP:       net.ParseIP("10.0.0.100"),
		StatusType:     AcctStatusStart,
		InputOctets:    1000000,
		OutputOctets:   5000000,
		InputPackets:   1000,
		OutputPackets:  5000,
		SessionTime:    3600,
		TerminateCause: TerminateCauseUserRequest,
		Class:          []byte("class"),
		NASPort:        1,
		CircuitID:      "circuit-1",
		RemoteID:       "remote-1",
	}

	if req.SessionID != "session-123" {
		t.Error("SessionID mismatch")
	}

	if req.StatusType != AcctStatusStart {
		t.Error("StatusType should be Start")
	}
}

func TestAcctStatusTypeConstantsAdditional(t *testing.T) {
	tests := []struct {
		name     string
		value    AcctStatusType
		expected uint32
	}{
		{"AcctStatusStart", AcctStatusStart, 1},
		{"AcctStatusStop", AcctStatusStop, 2},
		{"AcctStatusInterimUpdate", AcctStatusInterimUpdate, 3},
		{"AcctStatusAccountingOn", AcctStatusAccountingOn, 7},
		{"AcctStatusAccountingOff", AcctStatusAccountingOff, 8},
	}

	for _, tt := range tests {
		if uint32(tt.value) != tt.expected {
			t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.expected)
		}
	}
}

func TestTerminateCauseConstantsAdditional(t *testing.T) {
	causes := []struct {
		name     string
		value    int
		expected int
	}{
		{"TerminateCauseUserRequest", TerminateCauseUserRequest, 1},
		{"TerminateCauseLostCarrier", TerminateCauseLostCarrier, 2},
		{"TerminateCauseLostService", TerminateCauseLostService, 3},
		{"TerminateCauseIdleTimeout", TerminateCauseIdleTimeout, 4},
		{"TerminateCauseSessionTimeout", TerminateCauseSessionTimeout, 5},
		{"TerminateCauseAdminReset", TerminateCauseAdminReset, 6},
		{"TerminateCauseAdminReboot", TerminateCauseAdminReboot, 7},
		{"TerminateCausePortError", TerminateCausePortError, 8},
		{"TerminateCauseNASError", TerminateCauseNASError, 9},
		{"TerminateCauseNASRequest", TerminateCauseNASRequest, 10},
		{"TerminateCauseNASReboot", TerminateCauseNASReboot, 11},
		{"TerminateCausePortUnneeded", TerminateCausePortUnneeded, 12},
		{"TerminateCausePortPreempted", TerminateCausePortPreempted, 13},
		{"TerminateCausePortSuspended", TerminateCausePortSuspended, 14},
		{"TerminateCauseServiceUnavail", TerminateCauseServiceUnavail, 15},
		{"TerminateCauseCallback", TerminateCauseCallback, 16},
		{"TerminateCauseUserError", TerminateCauseUserError, 17},
		{"TerminateCauseHostRequest", TerminateCauseHostRequest, 18},
	}

	for _, tt := range causes {
		if tt.value != tt.expected {
			t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.expected)
		}
	}
}

func TestClientGetServerAdditional(t *testing.T) {
	logger := zap.NewNop()
	cfg := ClientConfig{
		Servers: []ServerConfig{
			{Host: "192.168.1.1", Port: 1812, Secret: "secret1"},
			{Host: "192.168.1.2", Port: 1812, Secret: "secret2"},
		},
		NASID: "test-nas",
	}

	client, _ := NewClient(cfg, logger)

	// First server should be returned initially
	server := client.getServer()
	if server.Host != "192.168.1.1" {
		t.Errorf("expected first server 192.168.1.1, got %s", server.Host)
	}
}

func TestClientNextServerAdditional(t *testing.T) {
	logger := zap.NewNop()
	cfg := ClientConfig{
		Servers: []ServerConfig{
			{Host: "192.168.1.1", Port: 1812, Secret: "secret1"},
			{Host: "192.168.1.2", Port: 1812, Secret: "secret2"},
		},
		NASID: "test-nas",
	}

	client, _ := NewClient(cfg, logger)

	// Get first server
	server1 := client.getServer()
	if server1.Host != "192.168.1.1" {
		t.Errorf("expected first server 192.168.1.1, got %s", server1.Host)
	}

	// Advance to next server
	client.nextServer()

	// Get second server
	server2 := client.getServer()
	if server2.Host != "192.168.1.2" {
		t.Errorf("expected second server 192.168.1.2, got %s", server2.Host)
	}

	// Advance again - should wrap around
	client.nextServer()

	server3 := client.getServer()
	if server3.Host != "192.168.1.1" {
		t.Errorf("expected first server again, got %s", server3.Host)
	}
}

func TestClientConfigStructAdditional(t *testing.T) {
	cfg := ClientConfig{
		Servers: []ServerConfig{
			{Host: "192.168.1.1", Port: 1812, Secret: "secret"},
		},
		NASID:   "test-nas",
		Timeout: 5000000000, // 5 seconds
		Retries: 5,
	}

	if len(cfg.Servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(cfg.Servers))
	}

	if cfg.NASID != "test-nas" {
		t.Error("NASID mismatch")
	}

	if cfg.Retries != 5 {
		t.Errorf("expected Retries 5, got %d", cfg.Retries)
	}
}

func TestAuthResponseAttributesMapAdditional(t *testing.T) {
	resp := &AuthResponse{
		Accepted:   true,
		Attributes: make(map[string]interface{}),
	}

	resp.Attributes["custom-attr"] = "custom-value"
	resp.Attributes["numeric-attr"] = 42

	if resp.Attributes["custom-attr"] != "custom-value" {
		t.Error("string attribute mismatch")
	}

	if resp.Attributes["numeric-attr"] != 42 {
		t.Error("numeric attribute mismatch")
	}
}

func TestAcctRequestOctetCountersAdditional(t *testing.T) {
	req := &AcctRequest{
		SessionID:    "session-1",
		InputOctets:  uint64(5) << 32, // More than 4GB
		OutputOctets: uint64(10) << 32,
	}

	// Verify gigaword calculation would be correct
	inputGigawords := req.InputOctets >> 32
	if inputGigawords != 5 {
		t.Errorf("expected 5 input gigawords, got %d", inputGigawords)
	}

	outputGigawords := req.OutputOctets >> 32
	if outputGigawords != 10 {
		t.Errorf("expected 10 output gigawords, got %d", outputGigawords)
	}
}

func TestAuthResponseRejectReasonAdditional(t *testing.T) {
	resp := &AuthResponse{
		Accepted:     false,
		RejectReason: "Invalid credentials",
	}

	if resp.Accepted {
		t.Error("expected Accepted to be false")
	}

	if resp.RejectReason != "Invalid credentials" {
		t.Errorf("expected reject reason 'Invalid credentials', got %s", resp.RejectReason)
	}
}

func TestAuthResponseFramedIPAdditional(t *testing.T) {
	ip := net.ParseIP("10.0.0.100")
	resp := &AuthResponse{
		Accepted: true,
		FramedIP: ip,
	}

	if !resp.FramedIP.Equal(ip) {
		t.Error("FramedIP mismatch")
	}
}

func TestAuthResponseClassAdditional(t *testing.T) {
	classData := []byte("session-class-data")
	resp := &AuthResponse{
		Accepted: true,
		Class:    classData,
	}

	if string(resp.Class) != string(classData) {
		t.Error("Class data mismatch")
	}
}

// Issue #91: Test rate limiting configuration defaults
func TestRateLimitDefaults(t *testing.T) {
	logger := zap.NewNop()
	cfg := ClientConfig{
		Servers: []ServerConfig{
			{Host: "127.0.0.1", Port: 1812, Secret: "testing123"},
		},
		NASID: "test-nas",
	}

	client, err := NewClient(cfg, logger)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if len(client.limiters) != 1 {
		t.Fatalf("expected 1 limiter, got %d", len(client.limiters))
	}

	// Default should be 1000 req/s with burst 100
	limiter := client.limiters[0]
	if limiter.Limit() != 1000 {
		t.Errorf("expected default rate 1000, got %v", limiter.Limit())
	}
	if limiter.Burst() != 100 {
		t.Errorf("expected default burst 100, got %d", limiter.Burst())
	}
}

// Issue #91: Test custom rate limit configuration
func TestRateLimitCustomConfig(t *testing.T) {
	logger := zap.NewNop()
	cfg := ClientConfig{
		Servers: []ServerConfig{
			{Host: "127.0.0.1", Port: 1812, Secret: "testing123"},
			{Host: "127.0.0.2", Port: 1812, Secret: "testing456"},
		},
		NASID: "test-nas",
		RateLimit: RateLimitConfig{
			RequestsPerSecond: 500,
			BurstSize:         50,
		},
	}

	client, err := NewClient(cfg, logger)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if len(client.limiters) != 2 {
		t.Fatalf("expected 2 limiters, got %d", len(client.limiters))
	}

	for i, lim := range client.limiters {
		if lim.Limit() != 500 {
			t.Errorf("limiter[%d] rate = %v, want 500", i, lim.Limit())
		}
		if lim.Burst() != 50 {
			t.Errorf("limiter[%d] burst = %d, want 50", i, lim.Burst())
		}
	}
}

// Issue #91: Test rate limiting blocks on canceled context
func TestRateLimitCancelledContext(t *testing.T) {
	logger := zap.NewNop()
	cfg := ClientConfig{
		Servers: []ServerConfig{
			{Host: "127.0.0.1", Port: 1812, Secret: "testing123"},
		},
		NASID: "test-nas",
		RateLimit: RateLimitConfig{
			RequestsPerSecond: 1, // Very low rate
			BurstSize:         1, // Minimal burst
		},
	}

	client, err := NewClient(cfg, logger)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Consume the single burst token
	ctx := context.Background()
	if err := client.waitRateLimit(ctx); err != nil {
		t.Fatalf("first waitRateLimit should succeed: %v", err)
	}

	// Second call with an already-canceled context should fail
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	err = client.waitRateLimit(canceledCtx)
	if err == nil {
		t.Error("waitRateLimit with canceled context should return error")
	}
}

// Issue #91: Test rate limiting allows burst
func TestRateLimitBurst(t *testing.T) {
	logger := zap.NewNop()
	cfg := ClientConfig{
		Servers: []ServerConfig{
			{Host: "127.0.0.1", Port: 1812, Secret: "testing123"},
		},
		NASID: "test-nas",
		RateLimit: RateLimitConfig{
			RequestsPerSecond: 10,
			BurstSize:         5,
		},
	}

	client, err := NewClient(cfg, logger)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Should be able to consume burst tokens without delay
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := client.waitRateLimit(ctx); err != nil {
			t.Fatalf("waitRateLimit burst call %d failed: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	// Burst of 5 should complete nearly instantly (well under 1s)
	if elapsed > 500*time.Millisecond {
		t.Errorf("burst of 5 took %v, expected near-instant", elapsed)
	}
}

// Issue #91: Test RateLimitConfig struct
func TestRateLimitConfigStruct(t *testing.T) {
	cfg := RateLimitConfig{
		RequestsPerSecond: 2000,
		BurstSize:         200,
	}

	if cfg.RequestsPerSecond != 2000 {
		t.Errorf("RequestsPerSecond = %f, want 2000", cfg.RequestsPerSecond)
	}
	if cfg.BurstSize != 200 {
		t.Errorf("BurstSize = %d, want 200", cfg.BurstSize)
	}
}
