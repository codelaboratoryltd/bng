package nexus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
)

const mockBaseURL = "http://nexus-test"

// setupMockAllocator creates an HTTPAllocator with httpmock activated.
// Call t.Cleanup is registered automatically to deactivate httpmock.
func setupMockAllocator(t *testing.T) *HTTPAllocator {
	t.Helper()
	allocator := NewHTTPAllocator(mockBaseURL)
	httpmock.ActivateNonDefault(allocator.httpClient)
	t.Cleanup(httpmock.DeactivateAndReset)
	return allocator
}

// registerPoolResponder registers a standard pool GET responder.
func registerPoolResponder(poolID, cidr string, prefix int) {
	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/pools/"+poolID,
		httpmock.NewJsonResponderOrPanic(http.StatusOK, PoolResponse{
			ID:     poolID,
			CIDR:   cidr,
			Prefix: prefix,
		}))
}

func TestNewHTTPAllocator(t *testing.T) {
	allocator := NewHTTPAllocator("http://localhost:9000")
	if allocator == nil {
		t.Fatal("expected non-nil allocator")
	}

	if allocator.baseURL != "http://localhost:9000" {
		t.Errorf("expected baseURL http://localhost:9000, got %s", allocator.baseURL)
	}

	if allocator.httpClient == nil {
		t.Error("expected non-nil http client")
	}

	if allocator.pools == nil {
		t.Error("expected non-nil pools map")
	}
}

func TestHTTPAllocatorAllocateIPv4(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("test-pool", "10.0.0.0/24", 24)
	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
		httpmock.NewJsonResponderOrPanic(http.StatusCreated, AllocationResponse{
			PoolID:       "test-pool",
			SubscriberID: "aa:bb:cc:dd:ee:ff",
			IP:           "10.0.0.100",
			Timestamp:    time.Now(),
		}))

	ctx := context.Background()
	ip, mask, gateway, err := allocator.AllocateIPv4(ctx, "aa:bb:cc:dd:ee:ff", "test-pool")
	if err != nil {
		t.Fatalf("AllocateIPv4 failed: %v", err)
	}

	if ip == nil {
		t.Fatal("expected non-nil IP")
	}
	if ip.String() != "10.0.0.100" {
		t.Errorf("expected IP 10.0.0.100, got %s", ip.String())
	}
	if mask == nil {
		t.Fatal("expected non-nil mask")
	}
	if gateway == nil {
		t.Fatal("expected non-nil gateway")
	}
}

func TestHTTPAllocatorAllocateIPv4Conflict(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("test-pool", "10.0.0.0/24", 24)
	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
		httpmock.NewStringResponder(http.StatusConflict, ""))
	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/aa:bb:cc:dd:ee:ff",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, AllocationResponse{
			PoolID:       "test-pool",
			SubscriberID: "aa:bb:cc:dd:ee:ff",
			IP:           "10.0.0.50",
			Timestamp:    time.Now(),
		}))

	ctx := context.Background()
	ip, _, _, err := allocator.AllocateIPv4(ctx, "aa:bb:cc:dd:ee:ff", "test-pool")
	if err != nil {
		t.Fatalf("AllocateIPv4 failed: %v", err)
	}
	if ip.String() != "10.0.0.50" {
		t.Errorf("expected existing IP 10.0.0.50, got %s", ip.String())
	}
}

func TestHTTPAllocatorLookupIPv4(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("test-pool", "10.0.0.0/24", 24)
	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/existing-sub",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, AllocationResponse{
			PoolID:       "test-pool",
			SubscriberID: "existing-sub",
			IP:           "10.0.0.42",
			Timestamp:    time.Now(),
		}))
	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/new-sub",
		httpmock.NewStringResponder(http.StatusNotFound, ""))

	ctx := context.Background()

	// Test existing allocation
	ip, _, _, err := allocator.LookupIPv4(ctx, "existing-sub", "test-pool")
	if err != nil {
		t.Fatalf("LookupIPv4 for existing sub failed: %v", err)
	}
	if ip.String() != "10.0.0.42" {
		t.Errorf("expected IP 10.0.0.42, got %s", ip.String())
	}

	// Test non-existing allocation
	_, _, _, err = allocator.LookupIPv4(ctx, "new-sub", "test-pool")
	if !errors.Is(err, ErrNoAllocation) {
		t.Errorf("expected ErrNoAllocation, got %v", err)
	}
}

func TestHTTPAllocatorReleaseIPv4(t *testing.T) {
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("DELETE", mockBaseURL+"/api/v1/allocations/sub-123",
		httpmock.NewStringResponder(http.StatusNoContent, ""))

	err := allocator.ReleaseIPv4(context.Background(), "sub-123")
	if err != nil {
		t.Errorf("ReleaseIPv4 failed: %v", err)
	}
}

func TestHTTPAllocatorCreatePool(t *testing.T) {
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/pools",
		httpmock.NewStringResponder(http.StatusCreated, ""))

	err := allocator.CreatePool(context.Background(), "new-pool", "192.168.0.0/24", 24)
	if err != nil {
		t.Errorf("CreatePool failed: %v", err)
	}
}

func TestHTTPAllocatorGetAllocation(t *testing.T) {
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/sub-123",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, AllocationResponse{
			PoolID:       "pool-1",
			SubscriberID: "sub-123",
			IP:           "10.0.0.10",
			Timestamp:    time.Now(),
		}))
	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/not-found",
		httpmock.NewStringResponder(http.StatusNotFound, ""))

	ctx := context.Background()

	// Test existing allocation
	alloc, err := allocator.GetAllocation(ctx, "sub-123")
	if err != nil {
		t.Fatalf("GetAllocation failed: %v", err)
	}
	if alloc.IP != "10.0.0.10" {
		t.Errorf("expected IP 10.0.0.10, got %s", alloc.IP)
	}

	// Test non-existing allocation
	_, err = allocator.GetAllocation(ctx, "not-found")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestHTTPAllocatorHealthCheck(t *testing.T) {
	// Test successful health check
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("GET", mockBaseURL+"/health",
		httpmock.NewStringResponder(http.StatusOK, ""))

	err := allocator.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("HealthCheck for healthy server failed: %v", err)
	}

	// Test unhealthy server
	httpmock.Reset()
	httpmock.RegisterResponder("GET", mockBaseURL+"/health",
		httpmock.NewStringResponder(http.StatusServiceUnavailable, ""))

	err = allocator.HealthCheck(context.Background())
	if err == nil {
		t.Error("HealthCheck for unhealthy server should fail")
	}
}

func TestHTTPAllocatorAllocateIPv6(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("pool-1", "2001:db8::/32", 48)
	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
		httpmock.NewJsonResponderOrPanic(http.StatusCreated, AllocationResponse{
			PoolID:       "pool-1",
			SubscriberID: "sub-123",
			IP:           "2001:db8:1::",
			Prefix:       48,
			Timestamp:    time.Now(),
		}))

	ctx := context.Background()
	ip, prefix, err := allocator.AllocateIPv6(ctx, "sub-123", "pool-1")
	if err != nil {
		t.Fatalf("AllocateIPv6 failed: %v", err)
	}
	if ip == nil {
		t.Error("expected non-nil IP")
	}
	if prefix == nil {
		t.Error("expected non-nil prefix")
	}
}

func TestHTTPAllocatorReleaseIPv6Stub(t *testing.T) {
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("DELETE", mockBaseURL+"/api/v1/allocations/sub-123",
		httpmock.NewStringResponder(http.StatusNoContent, ""))

	err := allocator.ReleaseIPv6(context.Background(), "sub-123")
	if err != nil {
		t.Errorf("ReleaseIPv6 should not return error: %v", err)
	}
}

func TestHTTPAllocatorPoolCaching(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("cached-pool", "10.0.0.0/24", 24)
	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
		httpmock.NewJsonResponderOrPanic(http.StatusCreated, AllocationResponse{IP: "10.0.0.1"}))

	ctx := context.Background()

	// First call should fetch pool info
	_, _, _, err := allocator.AllocateIPv4(ctx, "sub-1", "cached-pool")
	if err != nil {
		t.Fatalf("first AllocateIPv4 failed: %v", err)
	}

	// Second call should use cached pool info
	_, _, _, err = allocator.AllocateIPv4(ctx, "sub-2", "cached-pool")
	if err != nil {
		t.Fatalf("second AllocateIPv4 failed: %v", err)
	}

	// Pool should only be fetched once (cached after first call)
	info := httpmock.GetCallCountInfo()
	poolCalls := info["GET "+mockBaseURL+"/api/v1/pools/cached-pool"]
	if poolCalls != 1 {
		t.Errorf("expected pool to be fetched once, got %d calls", poolCalls)
	}
}

func TestPoolInfoStruct(t *testing.T) {
	info := &PoolInfo{
		ID:      "test-pool",
		CIDR:    "10.0.0.0/24",
		Gateway: net.ParseIP("10.0.0.1"),
		Mask:    net.IPMask{255, 255, 255, 0},
	}

	if info.ID != "test-pool" {
		t.Errorf("expected ID test-pool, got %s", info.ID)
	}
	if info.CIDR != "10.0.0.0/24" {
		t.Errorf("expected CIDR 10.0.0.0/24, got %s", info.CIDR)
	}
}

func TestAllocationRequestStruct(t *testing.T) {
	req := AllocationRequest{
		PoolID:       "pool-1",
		SubscriberID: "sub-123",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded AllocationRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.PoolID != req.PoolID {
		t.Errorf("PoolID mismatch")
	}
	if decoded.SubscriberID != req.SubscriberID {
		t.Errorf("SubscriberID mismatch")
	}
}

func TestErrNoAllocation(t *testing.T) {
	if ErrNoAllocation == nil {
		t.Error("ErrNoAllocation should not be nil")
	}
	if ErrNoAllocation.Error() != "no allocation found" {
		t.Errorf("unexpected error message: %s", ErrNoAllocation.Error())
	}
}

func TestHTTPAllocatorIPv6Conflict(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("test-pool-v6", "2001:db8::/64", 64)
	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
		httpmock.NewStringResponder(http.StatusConflict, ""))
	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/sub-v6",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, AllocationResponse{
			PoolID:       "test-pool-v6",
			SubscriberID: "sub-v6",
			IP:           "2001:db8::1",
			Prefix:       64,
			Timestamp:    time.Now(),
		}))

	ctx := context.Background()
	ip, prefix, err := allocator.AllocateIPv6(ctx, "sub-v6", "test-pool-v6")
	if err != nil {
		t.Fatalf("IPv6 conflict handling failed: %v", err)
	}
	if ip.String() != "2001:db8::1" {
		t.Errorf("expected existing IP 2001:db8::1, got %s", ip.String())
	}
	if prefix == nil {
		t.Fatal("expected non-nil prefix")
	}
}

func TestHTTPAllocatorHTTPErrorScenarios(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		expectedError string
	}{
		{"400 Bad Request", http.StatusBadRequest, "allocation failed with status 400"},
		{"500 Internal Server Error", http.StatusInternalServerError, "allocation failed with status 500"},
		{"Rate limit 429", http.StatusTooManyRequests, "allocation failed with status 429"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocator := setupMockAllocator(t)

			registerPoolResponder("test", "10.0.0.0/24", 24)
			httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
				httpmock.NewStringResponder(tt.statusCode, ""))

			_, _, _, err := allocator.AllocateIPv4(context.Background(), "sub-123", "test")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.expectedError {
				t.Errorf("expected error %q, got %q", tt.expectedError, err.Error())
			}
		})
	}
}

// TestHTTPAllocatorNetworkErrors uses httptest.NewServer because it tests
// real network timeouts that require actual TCP connections.
func TestHTTPAllocatorNetworkErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		if r.URL.Path == "/api/v1/pools/test" {
			json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	allocator.httpClient.Timeout = 10 * time.Millisecond
	ctx := context.Background()

	_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "test")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("expected request failed error, got: %v", err)
	}
}

// TestHTTPAllocatorContextCancellation uses httptest.NewServer because httpmock
// transport doesn't propagate context cancellation the same way as real HTTP.
func TestHTTPAllocatorContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		if r.URL.Path == "/api/v1/pools/test" {
			json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	allocator.httpClient.Timeout = 1 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "test")
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context canceled error, got: %v", err)
	}
}

// TestHTTPAllocatorContextDeadline uses httptest.NewServer because it tests
// real deadline expiration during an active HTTP request.
func TestHTTPAllocatorContextDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		if r.URL.Path == "/api/v1/pools/test" {
			json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "test")
	if err == nil {
		t.Fatal("expected context deadline exceeded error")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("expected context deadline exceeded error, got: %v", err)
	}
}

func TestHTTPAllocatorMalformedJSONResponse(t *testing.T) {
	tests := []struct {
		name        string
		expectError string
		poolResp    func(req *http.Request) (*http.Response, error)
		allocResp   func(req *http.Request) (*http.Response, error)
	}{
		{
			name:        "invalid JSON",
			expectError: "decode response",
			poolResp: func(req *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, `{"id":"test","cidr":"10.0.0.0/24","prefix":24`), nil // Missing }
			},
			allocResp: nil,
		},
		{
			name:        "empty response body",
			expectError: "decode response",
			poolResp: func(req *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, ""), nil
			},
			allocResp: nil,
		},
		{
			name:        "invalid IP address",
			expectError: "invalid IP in response",
			poolResp:    nil, // Use standard pool responder
			allocResp: func(req *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(http.StatusOK, AllocationResponse{
					PoolID:       "test",
					SubscriberID: "sub-123",
					IP:           "invalid-ip",
					Timestamp:    time.Now(),
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocator := setupMockAllocator(t)

			if tt.poolResp != nil {
				httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/pools/test", tt.poolResp)
			} else {
				registerPoolResponder("test", "10.0.0.0/24", 24)
			}
			if tt.allocResp != nil {
				httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations", tt.allocResp)
			}

			_, _, _, err := allocator.AllocateIPv4(context.Background(), "sub-123", "test")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("expected error containing %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

func TestHTTPAllocatorInvalidCIDR(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		expectErr string
	}{
		{"invalid CIDR format", "not-a-cidr", "invalid CIDR"},
		{"invalid IP in CIDR", "999.999.999.999/24", "invalid CIDR"},
		{"missing CIDR prefix", "10.0.0.0", "invalid CIDR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocator := setupMockAllocator(t)

			httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/pools/test-pool",
				httpmock.NewJsonResponderOrPanic(http.StatusOK, PoolResponse{
					ID:     "test-pool",
					CIDR:   tt.cidr,
					Prefix: 24,
				}))

			_, _, _, err := allocator.AllocateIPv4(context.Background(), "sub-123", "test-pool")
			if err == nil {
				t.Fatal("expected error for invalid CIDR")
			}
			if !strings.Contains(err.Error(), tt.expectErr) {
				t.Errorf("expected error containing %q, got %q", tt.expectErr, err.Error())
			}
		})
	}
}

func TestHTTPAllocatorIPv4InvalidCIDRForIPv6Pool(t *testing.T) {
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/pools/v6-pool",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, PoolResponse{
			ID:     "v6-pool",
			CIDR:   "2001:db8::/64",
			Prefix: 64,
		}))

	_, _, _, err := allocator.AllocateIPv4(context.Background(), "sub-123", "v6-pool")
	if err == nil {
		t.Fatal("expected error for IPv6 CIDR in IPv4 allocation")
	}
	if !strings.Contains(err.Error(), "To4") {
		t.Logf("got expected error: %v", err)
	}
}

func TestHTTPAllocatorEmptySubscriberID(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("test", "10.0.0.0/24", 24)

	ctx := context.Background()

	_, _, _, err := allocator.AllocateIPv4(ctx, "", "test")
	if err == nil {
		t.Fatal("expected error for empty subscriber ID")
	}

	_, _, _, err = allocator.AllocateIPv4(ctx, "   ", "test")
	if err == nil {
		t.Fatal("expected error for whitespace-only subscriber ID")
	}
}

func TestHTTPAllocatorInvalidPoolID(t *testing.T) {
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/pools/non-existent-pool",
		httpmock.NewStringResponder(http.StatusNotFound, ""))

	_, _, _, err := allocator.AllocateIPv4(context.Background(), "sub-123", "non-existent-pool")
	if err == nil {
		t.Fatal("expected error for non-existent pool")
	}
	if !strings.Contains(err.Error(), "pool not found") {
		t.Errorf("expected pool not found error, got %q", err.Error())
	}
}

func TestHTTPAllocatorGetExistingAllocationIPv4Errors(t *testing.T) {
	tests := []struct {
		name        string
		allocResp   httpmock.Responder
		expectError string
	}{
		{
			name:        "not found after conflict",
			allocResp:   httpmock.NewStringResponder(http.StatusNotFound, ""),
			expectError: "get allocation failed with status 404",
		},
		{
			name:        "server error after conflict",
			allocResp:   httpmock.NewStringResponder(http.StatusInternalServerError, ""),
			expectError: "get allocation failed with status 500",
		},
		{
			name: "invalid JSON in existing allocation",
			allocResp: func(req *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, `{"invalid": "json"`), nil
			},
			expectError: "decode response",
		},
		{
			name: "malformed IP in existing allocation",
			allocResp: func(req *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(http.StatusOK, AllocationResponse{
					PoolID:       "pool-1",
					SubscriberID: "sub-123",
					IP:           "invalid!.ip.123",
					Timestamp:    time.Now(),
				})
			},
			expectError: "invalid IP in response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocator := setupMockAllocator(t)

			registerPoolResponder("test", "10.0.0.0/24", 24)
			httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
				httpmock.NewStringResponder(http.StatusConflict, ""))
			httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/sub-123", tt.allocResp)

			_, _, _, err := allocator.AllocateIPv4(context.Background(), "sub-123", "test")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("expected error containing %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

func TestHTTPAllocatorLookupIPv4Errors(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("test", "10.0.0.0/24", 24)
	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/sub-123",
		httpmock.NewStringResponder(http.StatusInternalServerError, ""))

	_, _, _, err := allocator.LookupIPv4(context.Background(), "sub-123", "test")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "lookup failed with status 500") {
		t.Errorf("expected 500 error, got %q", err.Error())
	}
}

func TestHTTPAllocatorReleaseIPv4Errors(t *testing.T) {
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("DELETE", mockBaseURL+"/api/v1/allocations/concurrent-sub",
		httpmock.NewStringResponder(http.StatusConflict, ""))
	httpmock.RegisterResponder("DELETE", mockBaseURL+"/api/v1/allocations/server-error",
		httpmock.NewStringResponder(http.StatusInternalServerError, ""))

	tests := []struct {
		name        string
		subscriber  string
		expectError string
	}{
		{"conflict error", "concurrent-sub", "release failed with status 409"},
		{"server error", "server-error", "release failed with status 500"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := allocator.ReleaseIPv4(context.Background(), tt.subscriber)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("expected error containing %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

func TestHTTPAllocatorCreatePoolErrors(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		expectError string
	}{
		{"bad request", http.StatusBadRequest, "create pool failed with status 400"},
		{"server error", http.StatusInternalServerError, "create pool failed with status 500"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocator := setupMockAllocator(t)

			httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/pools",
				httpmock.NewStringResponder(tt.statusCode, ""))

			err := allocator.CreatePool(context.Background(), "new-pool", "192.168.1.0/24", 24)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("expected error containing %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

func TestHTTPAllocatorGetAllocationErrors(t *testing.T) {
	tests := []struct {
		name        string
		responder   httpmock.Responder
		expectError string
	}{
		{
			name:        "server error",
			responder:   httpmock.NewStringResponder(http.StatusInternalServerError, ""),
			expectError: "get allocation failed with status 500",
		},
		{
			name: "invalid JSON",
			responder: func(req *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, `{"invalid": "json"`), nil
			},
			expectError: "decode response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocator := setupMockAllocator(t)

			httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/sub-123", tt.responder)

			_, err := allocator.GetAllocation(context.Background(), "sub-123")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("expected error containing %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

func TestHTTPAllocatorHealthCheckErrors(t *testing.T) {
	t.Run("server error", func(t *testing.T) {
		allocator := setupMockAllocator(t)

		httpmock.RegisterResponder("GET", mockBaseURL+"/health",
			httpmock.NewStringResponder(http.StatusInternalServerError, ""))

		err := allocator.HealthCheck(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "health check failed with status 500") {
			t.Errorf("expected 500 error, got %q", err.Error())
		}
	})

	// Timeout test needs a real server for actual network delay
	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		allocator := NewHTTPAllocator(server.URL)
		allocator.httpClient.Timeout = 10 * time.Millisecond

		err := allocator.HealthCheck(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "context deadline exceeded") && !strings.Contains(err.Error(), "request failed") {
			t.Errorf("expected timeout error, got %q", err.Error())
		}
	})
}

func TestHTTPAllocatorIPv6WithPrefixFallback(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("test-pool", "2001:db8:1::/64", 64)
	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, AllocationResponse{
			PoolID:       "test-pool",
			SubscriberID: "sub-123",
			IP:           "2001:db8:1::100",
			Prefix:       0, // Missing prefix — should fallback to pool prefix
			Timestamp:    time.Now(),
		}))

	ip, prefix, err := allocator.AllocateIPv6(context.Background(), "sub-123", "test-pool")
	if err != nil {
		t.Fatalf("IPv6 allocation failed: %v", err)
	}
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}
	if prefix == nil {
		t.Fatal("expected non-nil prefix")
	}
	ones, _ := prefix.Mask.Size()
	if ones != 64 {
		t.Errorf("expected prefix /64, got /%d", ones)
	}
}

func TestHTTPAllocatorIPv6ConflictWithFallback(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("test-pool", "2001:db8:1::/56", 56)
	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
		httpmock.NewStringResponder(http.StatusConflict, ""))
	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/allocations/sub-123",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, AllocationResponse{
			PoolID:       "test-pool",
			SubscriberID: "sub-123",
			IP:           "2001:db8:1::50",
			Prefix:       0, // No prefix — should fallback
			Timestamp:    time.Now(),
		}))

	ip, prefix, err := allocator.AllocateIPv6(context.Background(), "sub-123", "test-pool")
	if err != nil {
		t.Fatalf("IPv6 conflict handling failed: %v", err)
	}
	if ip.String() != "2001:db8:1::50" {
		t.Errorf("expected IP 2001:db8:1::50, got %s", ip.String())
	}
	if prefix == nil {
		t.Fatal("expected non-nil prefix")
	}
	ones, _ := prefix.Mask.Size()
	if ones != 56 {
		t.Errorf("expected fallback prefix /56, got /%d", ones)
	}
}

func TestHTTPAllocatorInvalidJSONInPoolRequest(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("test", "10.0.0.0/24", 24)
	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, AllocationResponse{
			PoolID:       "test",
			SubscriberID: "sub-123",
			IP:           "10.0.0.100",
			Timestamp:    time.Now(),
		}))

	ip, _, _, err := allocator.AllocateIPv4(context.Background(), "sub-123", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip.String() != "10.0.0.100" {
		t.Errorf("expected IP 10.0.0.100, got %s", ip.String())
	}
}

func TestHTTPAllocatorConcurrentPoolAccess(t *testing.T) {
	allocator := setupMockAllocator(t)

	registerPoolResponder("concurrent-pool", "10.0.0.0/24", 24)
	httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
		httpmock.NewJsonResponderOrPanic(http.StatusCreated, AllocationResponse{IP: "10.0.0.1"}))

	ctx := context.Background()

	done := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		go func(id int) {
			_, _, _, err := allocator.AllocateIPv4(ctx, fmt.Sprintf("sub-%d", id), "concurrent-pool")
			if err != nil {
				t.Errorf("concurrent allocation failed: %v", err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 5; i++ {
		<-done
	}

	info := httpmock.GetCallCountInfo()
	poolCalls := info["GET "+mockBaseURL+"/api/v1/pools/concurrent-pool"]
	if poolCalls < 1 || poolCalls > 5 {
		t.Errorf("expected pool to be fetched between 1-5 times, got %d calls", poolCalls)
	}
}

func TestHTTPAllocatorIPv4GatewayForDifferentSubnetSizes(t *testing.T) {
	tests := []struct {
		name       string
		cidr       string
		expectedGW string
	}{
		{"/24 subnet", "192.168.1.0/24", "192.168.1.1"},
		{"/16 subnet", "172.16.0.0/16", "172.16.0.1"},
		{"/8 subnet", "10.0.0.0/8", "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocator := setupMockAllocator(t)

			registerPoolResponder("test", tt.cidr, 24)
			httpmock.RegisterResponder("POST", mockBaseURL+"/api/v1/allocations",
				httpmock.NewJsonResponderOrPanic(http.StatusOK, AllocationResponse{
					PoolID:       "test",
					SubscriberID: "sub-123",
					IP:           strings.Split(tt.cidr, "/")[0],
					Timestamp:    time.Now(),
				}))

			_, _, gateway, err := allocator.AllocateIPv4(context.Background(), "sub-123", "test")
			if err != nil {
				t.Fatalf("allocation failed: %v", err)
			}
			if gateway.String() != tt.expectedGW {
				t.Errorf("expected gateway %s, got %s", tt.expectedGW, gateway.String())
			}
		})
	}
}

func TestHTTPAllocatorMalformedCIDRInPool(t *testing.T) {
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/pools/malformed-pool",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, PoolResponse{
			ID:     "malformed-pool",
			CIDR:   "not-a-valid-cidr",
			Prefix: 24,
		}))

	_, _, _, err := allocator.AllocateIPv4(context.Background(), "sub-123", "malformed-pool")
	if err == nil {
		t.Fatal("expected error for malformed CIDR")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("expected invalid CIDR error, got %q", err.Error())
	}
}

func TestHTTPAllocatorEmptyCIDR(t *testing.T) {
	allocator := setupMockAllocator(t)

	httpmock.RegisterResponder("GET", mockBaseURL+"/api/v1/pools/empty-cidr-pool",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, PoolResponse{
			ID:     "empty-cidr-pool",
			CIDR:   "",
			Prefix: 24,
		}))

	_, _, _, err := allocator.AllocateIPv4(context.Background(), "sub-123", "empty-cidr-pool")
	if err == nil {
		t.Fatal("expected error for empty CIDR")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("expected invalid CIDR error, got %q", err.Error())
	}
}
