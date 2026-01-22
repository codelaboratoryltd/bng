package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDefaultBootstrapConfig(t *testing.T) {
	config := DefaultBootstrapConfig()

	assert.Equal(t, "eth0", config.ZTPInterface)
	assert.Equal(t, 30*time.Second, config.RetryInterval)
	assert.Equal(t, 0, config.MaxRetries) // 0 = infinite
	assert.Empty(t, config.NexusServerURL)
	assert.False(t, config.ZTPEnabled)
}

func TestNewBootstrap(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultBootstrapConfig()
	config.NexusServerURL = "http://nexus.example.com:9000"

	bootstrap, err := NewBootstrap(config, logger)
	require.NoError(t, err)
	require.NotNil(t, bootstrap)
	assert.Equal(t, config, bootstrap.config)
	assert.NotNil(t, bootstrap.logger)
	assert.NotNil(t, bootstrap.client)
}

func TestState_String(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateBootstrap, "bootstrap"},
		{StateConnected, "connected"},
		{StatePartitioned, "partitioned"},
		{StateRecovering, "recovering"},
		{State(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestBootstrap_Register_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/devices/register", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req RegistrationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.NotEmpty(t, req.Serial)

		resp := RegistrationResponse{
			Status:   "approved",
			DeviceID: "olt-test-001",
			Message:  "Device registered successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zap.NewNop()
	config := BootstrapConfig{
		NexusServerURL: server.URL,
		SerialOverride: "TEST-SERIAL-001",
		RetryInterval:  100 * time.Millisecond,
		MaxRetries:     3,
	}

	bootstrap, err := NewBootstrap(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := bootstrap.Register(ctx)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "approved", resp.Status)
	assert.Equal(t, "olt-test-001", resp.DeviceID)
}

func TestBootstrap_Register_Pending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := RegistrationResponse{
			Status:  "pending",
			Message: "Awaiting administrator approval",
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zap.NewNop()
	config := BootstrapConfig{
		NexusServerURL: server.URL,
		SerialOverride: "TEST-SERIAL-001",
	}

	bootstrap, err := NewBootstrap(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := bootstrap.Register(ctx)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "pending", resp.Status)
}

func TestBootstrap_Register_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	logger := zap.NewNop()
	config := BootstrapConfig{
		NexusServerURL: server.URL,
		SerialOverride: "TEST-SERIAL-001",
	}

	bootstrap, err := NewBootstrap(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := bootstrap.Register(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "500")
}

func TestBootstrap_RegisterWithRetry_MaxRetries(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	logger := zap.NewNop()
	config := BootstrapConfig{
		NexusServerURL: server.URL,
		SerialOverride: "TEST-SERIAL-001",
		RetryInterval:  10 * time.Millisecond,
		MaxRetries:     3,
	}

	bootstrap, err := NewBootstrap(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := bootstrap.RegisterWithRetry(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "max registration attempts")
	assert.Equal(t, 3, attempts)
}

func TestBootstrap_RegisterWithRetry_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := RegistrationResponse{
			Status:  "pending",
			Message: "Awaiting approval",
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zap.NewNop()
	config := BootstrapConfig{
		NexusServerURL: server.URL,
		SerialOverride: "TEST-SERIAL-001",
		RetryInterval:  1 * time.Second,
		MaxRetries:     0,
	}

	bootstrap, bootstrapErr := NewBootstrap(config, logger)
	require.NoError(t, bootstrapErr)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	resp, err := bootstrap.RegisterWithRetry(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestBootstrap_RegisterWithRetry_Rejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := RegistrationResponse{
			Status:  "rejected",
			Message: "Device not authorized",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zap.NewNop()
	config := BootstrapConfig{
		NexusServerURL: server.URL,
		SerialOverride: "TEST-SERIAL-001",
		RetryInterval:  10 * time.Millisecond,
		MaxRetries:     3,
	}

	bootstrap, err := NewBootstrap(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := bootstrap.RegisterWithRetry(ctx)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "rejected")
}

func TestBootstrap_DiscoverNexusURL_ZTPDisabled(t *testing.T) {
	logger := zap.NewNop()

	config := BootstrapConfig{
		ZTPEnabled:     false,
		NexusServerURL: "http://configured.nexus.com:9000",
	}

	bootstrap, err := NewBootstrap(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	url, err := bootstrap.DiscoverNexusURL(ctx)

	require.NoError(t, err)
	assert.Equal(t, "http://configured.nexus.com:9000", url)
}

func TestBootstrap_DiscoverNexusURL_ZTPDisabledNoURL(t *testing.T) {
	logger := zap.NewNop()

	config := BootstrapConfig{
		ZTPEnabled:     false,
		NexusServerURL: "",
	}

	bootstrap, bootstrapErr := NewBootstrap(config, logger)
	require.NoError(t, bootstrapErr)

	ctx := context.Background()
	url, err := bootstrap.DiscoverNexusURL(ctx)

	assert.Error(t, err)
	assert.Empty(t, url)
	assert.Contains(t, err.Error(), "ZTP not enabled")
}

func TestDeviceInfo_JSON(t *testing.T) {
	info := DeviceInfo{
		Serial:       "TEST-123",
		MAC:          "aa:bb:cc:dd:ee:ff",
		Model:        "TestOLT-1600",
		Firmware:     "5.15.0",
		AgentVersion: "1.0.0",
		Capabilities: []string{"gpon", "10g-uplink", "ebpf"},
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var decoded DeviceInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, info.Serial, decoded.Serial)
	assert.Equal(t, info.MAC, decoded.MAC)
	assert.Equal(t, info.Model, decoded.Model)
	assert.Equal(t, info.Firmware, decoded.Firmware)
	assert.Equal(t, info.Capabilities, decoded.Capabilities)
}

func TestRegistrationRequest_JSON(t *testing.T) {
	req := RegistrationRequest{
		DeviceInfo: DeviceInfo{
			Serial:       "TEST-123",
			MAC:          "aa:bb:cc:dd:ee:ff",
			Model:        "TestOLT",
			AgentVersion: "1.0.0",
			Capabilities: []string{"ebpf"},
		},
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded RegistrationRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Serial, decoded.Serial)
	assert.Equal(t, req.Timestamp.UTC(), decoded.Timestamp.UTC())
}

func TestRegistrationResponse_JSON(t *testing.T) {
	resp := RegistrationResponse{
		Status:     "approved",
		DeviceID:   "olt-001",
		CLSetPeers: []string{"peer1:9000", "peer2:9000"},
		Message:    "Welcome",
		Config: &DeviceConfig{
			DeviceID: "olt-001",
			NetCoID:  "netco-1",
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded RegistrationResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "approved", decoded.Status)
	assert.Equal(t, "olt-001", decoded.DeviceID)
	assert.Len(t, decoded.CLSetPeers, 2)
	require.NotNil(t, decoded.Config)
	assert.Equal(t, "netco-1", decoded.Config.NetCoID)
}
