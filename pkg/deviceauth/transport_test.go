package deviceauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestAuthenticatedTransport(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create a PSK authenticator for testing
	auth, err := NewPSKAuthenticator(&PSKConfig{
		Key: "test-transport-key",
	}, logger, WithDeviceID("transport-test-device"))
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create a test server that captures headers
	var capturedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create authenticated transport
	transport := &AuthenticatedTransport{
		Base:          http.DefaultTransport,
		Authenticator: auth,
	}

	// Create client with authenticated transport
	client := &http.Client{Transport: transport}

	// Make a request
	req, err := http.NewRequest("GET", server.URL+"/test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Custom-Header", "custom-value")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()

	// Verify authentication headers were added
	if capturedHeaders.Get("X-Device-ID") != "transport-test-device" {
		t.Errorf("Expected X-Device-ID header, got '%s'", capturedHeaders.Get("X-Device-ID"))
	}

	if capturedHeaders.Get("X-Auth-Mode") != "psk" {
		t.Errorf("Expected X-Auth-Mode header 'psk', got '%s'", capturedHeaders.Get("X-Auth-Mode"))
	}

	if capturedHeaders.Get(PSKTimestampHeader) == "" {
		t.Error("Expected timestamp header to be present")
	}

	if capturedHeaders.Get(PSKSignatureHeader) == "" {
		t.Error("Expected signature header to be present")
	}

	// Original headers should still be present
	if capturedHeaders.Get("Custom-Header") != "custom-value" {
		t.Errorf("Expected Custom-Header to be preserved, got '%s'", capturedHeaders.Get("Custom-Header"))
	}
}

func TestNewAuthenticatedClient(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create authenticator
	auth, err := NewPSKAuthenticator(&PSKConfig{
		Key: "client-test-key-123",
	}, logger, WithDeviceID("client-test-device"))
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create authenticated client
	client := NewAuthenticatedClient(auth)
	if client == nil {
		t.Fatal("Client should not be nil")
	}

	// Verify transport is authenticated
	transport, ok := client.Transport.(*AuthenticatedTransport)
	if !ok {
		t.Fatal("Client transport should be AuthenticatedTransport")
	}

	if transport.Authenticator != auth {
		t.Error("Transport should use provided authenticator")
	}
}

func TestWrapHTTPClient(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create original client with custom settings
	originalClient := &http.Client{
		Timeout: 5 * 1000000000, // 5 seconds
	}

	// Create authenticator
	auth, err := NewPSKAuthenticator(&PSKConfig{
		Key: "wrap-test-key-1234",
	}, logger, WithDeviceID("wrap-test-device"))
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Wrap the client
	wrappedClient := WrapHTTPClient(originalClient, auth)

	// Verify timeout is preserved
	if wrappedClient.Timeout != originalClient.Timeout {
		t.Error("Wrapped client should preserve timeout")
	}

	// Verify transport is authenticated
	transport, ok := wrappedClient.Transport.(*AuthenticatedTransport)
	if !ok {
		t.Fatal("Wrapped client transport should be AuthenticatedTransport")
	}

	if transport.Authenticator != auth {
		t.Error("Transport should use provided authenticator")
	}
}

func TestAuthenticatedRoundTripper(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create authenticator
	auth, err := NewNoneAuthenticator(logger, WithDeviceID("rt-test-device"))
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create round tripper
	rt := AuthenticatedRoundTripper(http.DefaultTransport, auth)

	// Verify it's the right type
	authRT, ok := rt.(*AuthenticatedTransport)
	if !ok {
		t.Fatal("RoundTripper should be AuthenticatedTransport")
	}

	if authRT.Base != http.DefaultTransport {
		t.Error("Base transport should be preserved")
	}

	if authRT.Authenticator != auth {
		t.Error("Authenticator should be preserved")
	}
}

func TestTransportWithNilAuthenticator(t *testing.T) {
	// Test that transport works even with nil authenticator
	transport := &AuthenticatedTransport{
		Base:          http.DefaultTransport,
		Authenticator: nil,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No auth headers should be added
		if r.Header.Get("X-Device-ID") != "" {
			t.Error("X-Device-ID should not be present with nil authenticator")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{Transport: transport}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()
}
