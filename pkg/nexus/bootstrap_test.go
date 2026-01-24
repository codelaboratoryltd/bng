package nexus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewBootstrapClient(t *testing.T) {
	config := BootstrapClientConfig{
		NexusURL: "http://nexus.example.com:9000",
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Model:    "TestOLT-1600",
		Firmware: "5.15.0",
	}

	client := NewBootstrapClient(config)

	require.NotNil(t, client)
	assert.Equal(t, "http://nexus.example.com:9000", client.baseURL)
	assert.Equal(t, "TEST-SERIAL-001", client.serial)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", client.mac)
	assert.Equal(t, "TestOLT-1600", client.model)
	assert.Equal(t, "5.15.0", client.firmware)
	assert.NotNil(t, client.httpClient)
	assert.NotNil(t, client.logger)
}

func TestNewBootstrapClient_WithCustomHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 60 * time.Second}

	config := BootstrapClientConfig{
		NexusURL:   "http://nexus.example.com:9000",
		Serial:     "TEST-SERIAL-001",
		MAC:        "aa:bb:cc:dd:ee:ff",
		HTTPClient: customClient,
	}

	client := NewBootstrapClient(config)

	assert.Equal(t, customClient, client.httpClient)
}

func TestNewBootstrapClient_WithLogger(t *testing.T) {
	logger := zap.NewNop()

	config := BootstrapClientConfig{
		NexusURL: "http://nexus.example.com:9000",
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Logger:   logger,
	}

	client := NewBootstrapClient(config)

	assert.Equal(t, logger, client.logger)
}

func TestBootstrapClient_BootstrapOnce_Configured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bootstrap", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req BootstrapRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "TEST-SERIAL-001", req.Serial)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", req.MAC)
		assert.Equal(t, "TestOLT-1600", req.Model)
		assert.Equal(t, "5.15.0", req.Firmware)

		resp := BootstrapResponse{
			NodeID: "node-001",
			Status: "configured",
			SiteID: "site-london-01",
			Role:   "primary",
			Partner: &PartnerInfo{
				NodeID:   "node-002",
				Endpoint: "192.168.1.2:8080",
			},
			Pools: []PoolInfo{
				{
					ID:      "pool-1",
					CIDR:    "10.0.0.0/24",
					Gateway: "10.0.0.1",
					DNS:     []string{"8.8.8.8", "8.8.4.4"},
				},
			},
			Message: "Device configured successfully",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Model:    "TestOLT-1600",
		Firmware: "5.15.0",
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.BootstrapOnce(ctx)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "node-001", resp.NodeID)
	assert.Equal(t, "configured", resp.Status)
	assert.Equal(t, "site-london-01", resp.SiteID)
	assert.Equal(t, "primary", resp.Role)
	require.NotNil(t, resp.Partner)
	assert.Equal(t, "node-002", resp.Partner.NodeID)
	assert.Equal(t, "192.168.1.2:8080", resp.Partner.Endpoint)
	require.Len(t, resp.Pools, 1)
	assert.Equal(t, "10.0.0.0/24", resp.Pools[0].CIDR)
}

func TestBootstrapClient_BootstrapOnce_Pending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := BootstrapResponse{
			NodeID:     "node-001",
			Status:     "pending",
			RetryAfter: 30,
			Message:    "Device registered, awaiting site assignment",
		}

		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.BootstrapOnce(ctx)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "pending", resp.Status)
	assert.Equal(t, "node-001", resp.NodeID)
	assert.Equal(t, 30, resp.RetryAfter)
	assert.True(t, resp.IsPending())
	assert.False(t, resp.IsConfigured())
}

func TestBootstrapClient_Bootstrap_PendingThenConfigured(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)

		if count < 3 {
			// First two requests return pending
			resp := BootstrapResponse{
				NodeID:     "node-001",
				Status:     "pending",
				RetryAfter: 1, // Short retry for testing
				Message:    "Awaiting site assignment",
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Third request returns configured
		resp := BootstrapResponse{
			NodeID: "node-001",
			Status: "configured",
			SiteID: "site-london-01",
			Role:   "primary",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Logger:   zap.NewNop(),
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.Bootstrap(ctx)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "configured", resp.Status)
	assert.Equal(t, "site-london-01", resp.SiteID)
	assert.Equal(t, int32(3), atomic.LoadInt32(&requestCount))
}

func TestBootstrapClient_Bootstrap_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := BootstrapResponse{
			NodeID:     "node-001",
			Status:     "pending",
			RetryAfter: 60, // Long retry
			Message:    "Awaiting site assignment",
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Logger:   zap.NewNop(),
	}

	client := NewBootstrapClient(config)

	// Cancel after a short time
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	resp, err := client.Bootstrap(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestBootstrapClient_Bootstrap_Rejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := BootstrapResponse{
			Status:  "rejected",
			Message: "Device serial not in allowlist",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "UNKNOWN-SERIAL",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Logger:   zap.NewNop(),
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.Bootstrap(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "rejected")
	assert.Contains(t, err.Error(), "not in allowlist")
}

func TestBootstrapClient_BootstrapOnce_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.BootstrapOnce(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "500")
}

func TestBootstrapClient_BootstrapOnce_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid credentials"))
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.BootstrapOnce(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestBootstrapClient_BootstrapOnce_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("device not authorized"))
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.BootstrapOnce(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "device not authorized")
}

func TestBootstrapClient_BootstrapOnce_BadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing required field: serial"))
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		MAC:      "aa:bb:cc:dd:ee:ff",
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.BootstrapOnce(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid request")
}

func TestBootstrapClient_BootstrapOnce_ServiceUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("service temporarily unavailable"))
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.BootstrapOnce(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "service unavailable")
}

func TestBootstrapClient_BootstrapOnce_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.BootstrapOnce(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestBootstrapClient_Bootstrap_DefaultRetryAfter(t *testing.T) {
	// This test verifies that the default retry behavior is used when RetryAfter=0.
	// We don't actually wait the full 60 seconds - we verify the first pending response
	// and then cancel the context.

	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		// Always return pending with no retry_after (should use default of 60s)
		resp := BootstrapResponse{
			NodeID:     "node-001",
			Status:     "pending",
			RetryAfter: 0, // Should trigger default of 60s
			Message:    "Awaiting site assignment",
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := BootstrapClientConfig{
		NexusURL: server.URL,
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Logger:   zap.NewNop(),
	}

	client := NewBootstrapClient(config)

	// Cancel quickly to avoid waiting the full 60 second default
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	resp, err := client.Bootstrap(ctx)

	// Should timeout because default retry is 60s and we only wait 100ms
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	// Verify at least one request was made
	assert.GreaterOrEqual(t, atomic.LoadInt32(&requestCount), int32(1))
}

func TestBootstrapResponse_IsPending(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"pending status", "pending", true},
		{"configured status", "configured", false},
		{"rejected status", "rejected", false},
		{"empty status", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &BootstrapResponse{Status: tt.status}
			assert.Equal(t, tt.expected, resp.IsPending())
		})
	}
}

func TestBootstrapResponse_IsConfigured(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"configured status", "configured", true},
		{"pending status", "pending", false},
		{"rejected status", "rejected", false},
		{"empty status", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &BootstrapResponse{Status: tt.status}
			assert.Equal(t, tt.expected, resp.IsConfigured())
		})
	}
}

func TestBootstrapResponse_HasHAPartner(t *testing.T) {
	tests := []struct {
		name     string
		partner  *PartnerInfo
		expected bool
	}{
		{
			"with partner",
			&PartnerInfo{NodeID: "node-002", Endpoint: "192.168.1.2:8080"},
			true,
		},
		{
			"nil partner",
			nil,
			false,
		},
		{
			"empty partner NodeID",
			&PartnerInfo{NodeID: "", Endpoint: "192.168.1.2:8080"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &BootstrapResponse{Partner: tt.partner}
			assert.Equal(t, tt.expected, resp.HasHAPartner())
		})
	}
}

func TestBootstrapResponse_IsPrimary(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		expected bool
	}{
		{"primary role", "primary", true},
		{"standby role", "standby", false},
		{"empty role", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &BootstrapResponse{Role: tt.role}
			assert.Equal(t, tt.expected, resp.IsPrimary())
		})
	}
}

func TestBootstrapResponse_IsStandby(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		expected bool
	}{
		{"standby role", "standby", true},
		{"primary role", "primary", false},
		{"empty role", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &BootstrapResponse{Role: tt.role}
			assert.Equal(t, tt.expected, resp.IsStandby())
		})
	}
}

func TestBootstrapRequest_JSON(t *testing.T) {
	req := BootstrapRequest{
		Serial:    "TEST-123",
		MAC:       "aa:bb:cc:dd:ee:ff",
		Model:     "TestOLT-1600",
		Firmware:  "5.15.0",
		PublicKey: "ssh-rsa AAAA...",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded BootstrapRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Serial, decoded.Serial)
	assert.Equal(t, req.MAC, decoded.MAC)
	assert.Equal(t, req.Model, decoded.Model)
	assert.Equal(t, req.Firmware, decoded.Firmware)
	assert.Equal(t, req.PublicKey, decoded.PublicKey)
}

func TestBootstrapResponse_JSON(t *testing.T) {
	resp := BootstrapResponse{
		NodeID: "node-001",
		Status: "configured",
		SiteID: "site-london-01",
		Role:   "primary",
		Partner: &PartnerInfo{
			NodeID:   "node-002",
			Endpoint: "192.168.1.2:8080",
		},
		Pools: []PoolInfo{
			{
				ID:      "pool-1",
				CIDR:    "10.0.0.0/24",
				Gateway: "10.0.0.1",
				DNS:     []string{"8.8.8.8", "8.8.4.4"},
			},
		},
		RetryAfter: 30,
		Message:    "Welcome",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded BootstrapResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "node-001", decoded.NodeID)
	assert.Equal(t, "configured", decoded.Status)
	assert.Equal(t, "site-london-01", decoded.SiteID)
	assert.Equal(t, "primary", decoded.Role)
	require.NotNil(t, decoded.Partner)
	assert.Equal(t, "node-002", decoded.Partner.NodeID)
	require.Len(t, decoded.Pools, 1)
	assert.Equal(t, "10.0.0.0/24", decoded.Pools[0].CIDR)
}

func TestBootstrapClient_BootstrapOnce_ConnectionError(t *testing.T) {
	config := BootstrapClientConfig{
		NexusURL: "http://localhost:99999", // Non-existent port
		Serial:   "TEST-SERIAL-001",
		MAC:      "aa:bb:cc:dd:ee:ff",
	}

	client := NewBootstrapClient(config)
	ctx := context.Background()

	resp, err := client.BootstrapOnce(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "HTTP request failed")
}
