//go:build linux

package ztp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewBootstrapClient(t *testing.T) {
	tests := []struct {
		name    string
		cfg     BootstrapConfig
		wantErr bool
	}{
		{
			name:    "empty nexus URL",
			cfg:     BootstrapConfig{},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: BootstrapConfig{
				NexusURL: "http://localhost:9000",
			},
			wantErr: false,
		},
		{
			name: "with all options",
			cfg: BootstrapConfig{
				NexusURL:       "http://localhost:9000",
				Interface:      "eth0",
				Serial:         "TEST-SERIAL-001",
				InitialBackoff: 1 * time.Second,
				MaxBackoff:     30 * time.Second,
				MaxRetries:     5,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewBootstrapClient(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBootstrapClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewBootstrapClient() returned nil client")
			}
		})
	}
}

func TestBootstrapClient_Register(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse *BootstrapResponse
		serverStatus   int
		wantErr        bool
	}{
		{
			name: "configured device",
			serverResponse: &BootstrapResponse{
				NodeID:  "node-abc123",
				Status:  "configured",
				SiteID:  "site-london-1",
				Role:    "active",
				Message: "Device configured successfully",
				Pools: []PoolAssignment{
					{PoolID: "pool-1", CIDR: "10.0.0.0/24"},
				},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
		},
		{
			name: "pending device",
			serverResponse: &BootstrapResponse{
				NodeID:     "node-abc123",
				Status:     "pending",
				RetryAfter: 30,
				Message:    "Device registered, awaiting configuration",
			},
			serverStatus: http.StatusCreated,
			wantErr:      false,
		},
		{
			name:         "server error",
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
		},
		{
			name:         "bad request",
			serverStatus: http.StatusBadRequest,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/bootstrap" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Errorf("unexpected method: %s", r.Method)
				}

				// Verify request body
				var req BootstrapRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("failed to decode request: %v", err)
				}

				w.WriteHeader(tt.serverStatus)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client, err := NewBootstrapClient(BootstrapConfig{
				NexusURL: server.URL,
				Serial:   "TEST-SERIAL",
			})
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			req := &BootstrapRequest{
				Serial: "TEST-SERIAL",
				MAC:    "00:11:22:33:44:55",
			}

			resp, err := client.register(ctx, req)
			if (err != nil) != tt.wantErr {
				t.Errorf("register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.serverResponse != nil {
				if resp.NodeID != tt.serverResponse.NodeID {
					t.Errorf("NodeID = %v, want %v", resp.NodeID, tt.serverResponse.NodeID)
				}
				if resp.Status != tt.serverResponse.Status {
					t.Errorf("Status = %v, want %v", resp.Status, tt.serverResponse.Status)
				}
			}
		})
	}
}

func TestBootstrapClient_BootstrapOnce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := BootstrapResponse{
			NodeID:     "node-test123",
			Status:     "pending",
			RetryAfter: 30,
			Message:    "Awaiting configuration",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewBootstrapClient(BootstrapConfig{
		NexusURL: server.URL,
		Serial:   "BOOTSTRAP-TEST",
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	resp, err := client.BootstrapOnce(ctx)
	if err != nil {
		t.Fatalf("BootstrapOnce() error = %v", err)
	}

	if resp.Status != "pending" {
		t.Errorf("Status = %v, want pending", resp.Status)
	}
	if resp.RetryAfter != 30 {
		t.Errorf("RetryAfter = %v, want 30", resp.RetryAfter)
	}
}

func TestBootstrapClient_RegisterAndWait(t *testing.T) {
	// Track number of requests
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)

		var resp BootstrapResponse
		if count < 3 {
			// First 2 requests return pending
			resp = BootstrapResponse{
				NodeID:     "node-wait-test",
				Status:     "pending",
				RetryAfter: 1, // Short retry for test
				Message:    "Awaiting configuration",
			}
		} else {
			// Third request returns configured
			resp = BootstrapResponse{
				NodeID:  "node-wait-test",
				Status:  "configured",
				SiteID:  "site-test",
				Role:    "active",
				Message: "Device configured",
				Pools: []PoolAssignment{
					{PoolID: "pool-1", CIDR: "10.0.0.0/24"},
				},
			}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewBootstrapClient(BootstrapConfig{
		NexusURL:       server.URL,
		Serial:         "WAIT-TEST",
		InitialBackoff: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info := &SystemInfo{
		Serial: "WAIT-TEST",
		MAC:    "00:11:22:33:44:55",
	}

	config, err := client.registerAndWait(ctx, info)
	if err != nil {
		t.Fatalf("registerAndWait() error = %v", err)
	}

	if config.NodeID != "node-wait-test" {
		t.Errorf("NodeID = %v, want node-wait-test", config.NodeID)
	}
	if config.SiteID != "site-test" {
		t.Errorf("SiteID = %v, want site-test", config.SiteID)
	}
	if config.Role != "active" {
		t.Errorf("Role = %v, want active", config.Role)
	}

	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("requestCount = %v, want 3", requestCount)
	}
}

func TestBootstrapClient_MaxRetries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return pending
		resp := BootstrapResponse{
			NodeID:     "node-retry-test",
			Status:     "pending",
			RetryAfter: 1,
			Message:    "Awaiting configuration",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewBootstrapClient(BootstrapConfig{
		NexusURL:       server.URL,
		Serial:         "RETRY-TEST",
		MaxRetries:     3,
		InitialBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	info := &SystemInfo{
		Serial: "RETRY-TEST",
		MAC:    "00:11:22:33:44:55",
	}

	_, err = client.registerAndWait(ctx, info)
	if err == nil {
		t.Error("registerAndWait() should have failed after max retries")
	}
}

func TestBootstrapClient_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return pending
		resp := BootstrapResponse{
			NodeID:     "node-cancel-test",
			Status:     "pending",
			RetryAfter: 60, // Long retry
			Message:    "Awaiting configuration",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewBootstrapClient(BootstrapConfig{
		NexusURL: server.URL,
		Serial:   "CANCEL-TEST",
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	info := &SystemInfo{
		Serial: "CANCEL-TEST",
		MAC:    "00:11:22:33:44:55",
	}

	_, err = client.registerAndWait(ctx, info)
	if err == nil {
		t.Error("registerAndWait() should have failed due to context cancellation")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestBootstrapClient_Healthcheck(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "healthy",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "unhealthy",
			statusCode: http.StatusServiceUnavailable,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client, err := NewBootstrapClient(BootstrapConfig{
				NexusURL: server.URL,
			})
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			err = client.Healthcheck(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Healthcheck() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFindPrimaryMAC(t *testing.T) {
	// This test may be flaky depending on the system's network interfaces
	mac, err := findPrimaryMAC()
	if err != nil {
		// Not an error in CI where there may be no physical interfaces
		t.Skipf("findPrimaryMAC() failed (may be expected in CI): %v", err)
	}

	if mac == "" {
		t.Error("findPrimaryMAC() returned empty MAC")
	}

	// Verify MAC format (XX:XX:XX:XX:XX:XX)
	if len(mac) != 17 {
		t.Errorf("MAC format unexpected: %s", mac)
	}
}

func TestDetectSerial(t *testing.T) {
	// This test may be flaky depending on the system
	serial, err := detectSerial()
	if err != nil {
		// Not an error in CI/containers where DMI info may not be available
		t.Skipf("detectSerial() failed (may be expected in CI): %v", err)
	}

	if serial == "" {
		t.Error("detectSerial() returned empty serial")
	}
}

func TestBootstrapResponse_JSON(t *testing.T) {
	resp := BootstrapResponse{
		NodeID:  "node-123",
		Status:  "configured",
		SiteID:  "site-london",
		Role:    "active",
		Partner: &PartnerInfo{NodeID: "node-456", Status: "online"},
		Pools:   []PoolAssignment{{PoolID: "pool-1", CIDR: "10.0.0.0/24", Subnets: []string{"10.0.0.0/26"}}},
		Cluster: &ClusterInfo{Peers: []string{"nexus-1:9000", "nexus-2:9000"}},
		Message: "Device configured successfully",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var decoded BootstrapResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.NodeID != resp.NodeID {
		t.Errorf("NodeID = %v, want %v", decoded.NodeID, resp.NodeID)
	}
	if decoded.Partner == nil || decoded.Partner.NodeID != resp.Partner.NodeID {
		t.Error("Partner not preserved")
	}
	if len(decoded.Pools) != 1 || decoded.Pools[0].PoolID != "pool-1" {
		t.Error("Pools not preserved")
	}
	if decoded.Cluster == nil || len(decoded.Cluster.Peers) != 2 {
		t.Error("Cluster not preserved")
	}
}
