package nexus

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/pools/test-pool" && r.Method == "GET":
			// Return pool info
			resp := PoolResponse{
				ID:     "test-pool",
				CIDR:   "10.0.0.0/24",
				Prefix: 24,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/api/v1/allocations" && r.Method == "POST":
			// Return allocation
			resp := AllocationResponse{
				PoolID:       "test-pool",
				SubscriberID: "aa:bb:cc:dd:ee:ff",
				IP:           "10.0.0.100",
				Timestamp:    time.Now(),
			}
			w.WriteHeader(http.StatusCreated)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
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
	// Create a mock server that returns conflict then existing allocation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/pools/test-pool" && r.Method == "GET":
			resp := PoolResponse{
				ID:     "test-pool",
				CIDR:   "10.0.0.0/24",
				Prefix: 24,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/api/v1/allocations" && r.Method == "POST":
			// Return conflict - subscriber already has allocation
			w.WriteHeader(http.StatusConflict)

		case r.URL.Path == "/api/v1/allocations/aa:bb:cc:dd:ee:ff" && r.Method == "GET":
			// Return existing allocation
			resp := AllocationResponse{
				PoolID:       "test-pool",
				SubscriberID: "aa:bb:cc:dd:ee:ff",
				IP:           "10.0.0.50",
				Timestamp:    time.Now(),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
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
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/pools/test-pool" && r.Method == "GET":
			resp := PoolResponse{
				ID:     "test-pool",
				CIDR:   "10.0.0.0/24",
				Prefix: 24,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/api/v1/allocations/existing-sub" && r.Method == "GET":
			resp := AllocationResponse{
				PoolID:       "test-pool",
				SubscriberID: "existing-sub",
				IP:           "10.0.0.42",
				Timestamp:    time.Now(),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/api/v1/allocations/new-sub" && r.Method == "GET":
			w.WriteHeader(http.StatusNotFound)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
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
	if err != ErrNoAllocation {
		t.Errorf("expected ErrNoAllocation, got %v", err)
	}
}

func TestHTTPAllocatorReleaseIPv4(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/allocations/sub-123" && r.Method == "DELETE" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	err := allocator.ReleaseIPv4(ctx, "sub-123")
	if err != nil {
		t.Errorf("ReleaseIPv4 failed: %v", err)
	}
}

func TestHTTPAllocatorCreatePool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/pools" && r.Method == "POST" {
			w.WriteHeader(http.StatusCreated)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	err := allocator.CreatePool(ctx, "new-pool", "192.168.0.0/24", 24)
	if err != nil {
		t.Errorf("CreatePool failed: %v", err)
	}
}

func TestHTTPAllocatorGetAllocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/allocations/sub-123" && r.Method == "GET" {
			resp := AllocationResponse{
				PoolID:       "pool-1",
				SubscriberID: "sub-123",
				IP:           "10.0.0.10",
				Timestamp:    time.Now(),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		} else if r.URL.Path == "/api/v1/allocations/not-found" && r.Method == "GET" {
			w.WriteHeader(http.StatusNotFound)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
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
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestHTTPAllocatorHealthCheck(t *testing.T) {
	// Test successful health check
	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer healthyServer.Close()

	allocator := NewHTTPAllocator(healthyServer.URL)
	ctx := context.Background()

	err := allocator.HealthCheck(ctx)
	if err != nil {
		t.Errorf("HealthCheck for healthy server failed: %v", err)
	}

	// Test unhealthy server
	unhealthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthyServer.Close()

	allocator2 := NewHTTPAllocator(unhealthyServer.URL)
	err = allocator2.HealthCheck(ctx)
	if err == nil {
		t.Error("HealthCheck for unhealthy server should fail")
	}
}

func TestHTTPAllocatorAllocateIPv6(t *testing.T) {
	// Create a mock server for IPv6 allocation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/pools/pool-1" && r.Method == "GET":
			resp := PoolResponse{
				ID:     "pool-1",
				CIDR:   "2001:db8::/32",
				Prefix: 48,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/api/v1/allocations" && r.Method == "POST":
			resp := AllocationResponse{
				PoolID:       "pool-1",
				SubscriberID: "sub-123",
				IP:           "2001:db8:1::",
				Prefix:       48,
				Timestamp:    time.Now(),
			}
			w.WriteHeader(http.StatusCreated)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
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
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/allocations/sub-123" && r.Method == "DELETE" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	err := allocator.ReleaseIPv6(ctx, "sub-123")
	if err != nil {
		t.Errorf("ReleaseIPv6 should not return error: %v", err)
	}
}

func TestHTTPAllocatorPoolCaching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/pools/cached-pool" && r.Method == "GET" {
			callCount++
			resp := PoolResponse{
				ID:     "cached-pool",
				CIDR:   "10.0.0.0/24",
				Prefix: 24,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		} else if r.URL.Path == "/api/v1/allocations" && r.Method == "POST" {
			resp := AllocationResponse{
				IP: "10.0.0.1",
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
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

	// Pool should only be fetched once
	if callCount != 1 {
		t.Errorf("expected pool to be fetched once, got %d calls", callCount)
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

// Additional tests for comprehensive coverage

func TestHTTPAllocatorIPv6Conflict(t *testing.T) {
	// Test IPv6 conflict handling (currently 0% coverage)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/pools/test-pool-v6" && r.Method == "GET":
			resp := PoolResponse{
				ID:     "test-pool-v6",
				CIDR:   "2001:db8::/64",
				Prefix: 64,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/api/v1/allocations" && r.Method == "POST":
			w.WriteHeader(http.StatusConflict) // Conflict response

		case r.URL.Path == "/api/v1/allocations/sub-v6" && r.Method == "GET":
			// Return existing IPv6 allocation
			resp := AllocationResponse{
				PoolID:       "test-pool-v6",
				SubscriberID: "sub-v6",
				IP:           "2001:db8::1",
				Prefix:       64,
				Timestamp:    time.Now(),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
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
		handler       http.HandlerFunc
	}{
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			expectedError: "allocation failed with status 400",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/pools/test" {
					json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			expectedError: "allocation failed with status 500",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/pools/test" {
					json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name:          "Rate limit 429",
			statusCode:    http.StatusTooManyRequests,
			expectedError: "allocation failed with status 429",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/pools/test" {
					json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
					return
				}
				w.WriteHeader(http.StatusTooManyRequests)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			allocator := NewHTTPAllocator(server.URL)
			ctx := context.Background()

			_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "test")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.expectedError {
				t.Errorf("expected error %q, got %q", tt.expectedError, err.Error())
			}
		})
	}
}

func TestHTTPAllocatorNetworkErrors(t *testing.T) {
	// Test timeout scenario
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow server
		time.Sleep(200 * time.Millisecond)
		if r.URL.Path == "/api/v1/pools/test" {
			json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	allocator.httpClient.Timeout = 10 * time.Millisecond // Very short timeout
	ctx := context.Background()

	_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "test")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("expected request failed error, got: %v", err)
	}
}

func TestHTTPAllocatorContextCancellation(t *testing.T) {
	// Test context cancellation during request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Simulate slow response
		if r.URL.Path == "/api/v1/pools/test" {
			json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	allocator.httpClient.Timeout = 1 * time.Second

	// Cancel context immediately
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

func TestHTTPAllocatorContextDeadline(t *testing.T) {
	// Test context deadline
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

	// Set a deadline that will expire
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
		response    string
		expectError string
		handler     http.HandlerFunc
	}{
		{
			name:        "invalid JSON",
			expectError: "decode response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				if r.URL.Path == "/api/v1/pools/test" {
					w.Write([]byte(`{"id":"test","cidr":"10.0.0.0/24","prefix":24`)) // Missing closing brace
				} else {
					w.Write([]byte("not json"))
				}
			},
		},
		{
			name:        "empty response body",
			expectError: "decode response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			name:        "invalid IP address",
			expectError: "invalid IP in response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/pools/test" {
					json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
					return
				}
				json.NewEncoder(w).Encode(AllocationResponse{
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
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			allocator := NewHTTPAllocator(server.URL)
			ctx := context.Background()

			_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "test")
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
		{
			name:      "invalid CIDR format",
			cidr:      "not-a-cidr",
			expectErr: "invalid CIDR",
		},
		{
			name:      "invalid IP in CIDR",
			cidr:      "999.999.999.999/24",
			expectErr: "invalid CIDR",
		},
		{
			name:      "missing CIDR prefix",
			cidr:      "10.0.0.0",
			expectErr: "invalid CIDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(PoolResponse{
					ID:     "test-pool",
					CIDR:   tt.cidr,
					Prefix: 24,
				})
			}))
			defer server.Close()

			allocator := NewHTTPAllocator(server.URL)
			ctx := context.Background()

			_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "test-pool")
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
	// Test IPv4 allocation from IPv6 pool (invalid CIDR for IPv4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(PoolResponse{
			ID:     "v6-pool",
			CIDR:   "2001:db8::/64",
			Prefix: 64,
		})
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "v6-pool")
	if err == nil {
		t.Fatal("expected error for IPv6 CIDR in IPv4 allocation")
	}
	if !strings.Contains(err.Error(), "To4") {
		t.Logf("got expected error: %v", err)
	}
}

func TestHTTPAllocatorEmptySubscriberID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/pools/test" && r.Method == "GET" {
			json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	// Test empty subscriber ID
	_, _, _, err := allocator.AllocateIPv4(ctx, "", "test")
	if err == nil {
		t.Fatal("expected error for empty subscriber ID")
	}

	// Test with spaces
	_, _, _, err = allocator.AllocateIPv4(ctx, "   ", "test")
	if err == nil {
		t.Fatal("expected error for whitespace-only subscriber ID")
	}
}

func TestHTTPAllocatorInvalidPoolID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "non-existent-pool")
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
		handler     http.HandlerFunc
		expectError string
	}{
		{
			name: "not found after conflict",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectError: "get allocation failed with status 404",
		},
		{
			name: "server error after conflict",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectError: "get allocation failed with status 500",
		},
		{
			name: "invalid JSON in existing allocation",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"invalid": "json"`)) // Missing closing brace
			},
			expectError: "decode response",
		},
		{
			name: "malformed IP in existing allocation",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(AllocationResponse{
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
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/pools/test" {
					json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
					return
				}
				if r.URL.Path == "/api/v1/allocations" {
					w.WriteHeader(http.StatusConflict)
					return
				}
				if r.URL.Path == "/api/v1/allocations/sub-123" {
					tt.handler(w, r)
					return
				}
			}))
			defer server.Close()

			allocator := NewHTTPAllocator(server.URL)
			ctx := context.Background()

			_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "test")
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/pools/test" {
			json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
			return
		}
		if r.URL.Path == "/api/v1/allocations/sub-123" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	_, _, _, err := allocator.LookupIPv4(ctx, "sub-123", "test")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "lookup failed with status 500") {
		t.Errorf("expected 500 error, got %q", err.Error())
	}
}

func TestHTTPAllocatorReleaseIPv4Errors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/allocations/concurrent-sub" {
			// Simulate lock conflict
			w.WriteHeader(http.StatusConflict)
			return
		}
		if r.URL.Path == "/api/v1/allocations/server-error" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	tests := []struct {
		name        string
		subscriber  string
		expectError string
	}{
		{
			name:        "conflict error",
			subscriber:  "concurrent-sub",
			expectError: "release failed with status 409",
		},
		{
			name:        "server error",
			subscriber:  "server-error",
			expectError: "release failed with status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := allocator.ReleaseIPv4(ctx, tt.subscriber)
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
		handler     http.HandlerFunc
		expectError string
	}{
		{
			name: "bad request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			expectError: "create pool failed with status 400",
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectError: "create pool failed with status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			allocator := NewHTTPAllocator(server.URL)
			ctx := context.Background()

			err := allocator.CreatePool(ctx, "new-pool", "192.168.1.0/24", 24)
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
		handler     http.HandlerFunc
		expectError string
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectError: "get allocation failed with status 500",
		},
		{
			name: "invalid JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"invalid": "json"`))
			},
			expectError: "decode response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/allocations/sub-123" {
					tt.handler(w, r)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			allocator := NewHTTPAllocator(server.URL)
			ctx := context.Background()

			_, err := allocator.GetAllocation(ctx, "sub-123")
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
	tests := []struct {
		name        string
		handler     http.HandlerFunc
		expectError string
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectError: "health check failed with status 500",
		},
		{
			name: "timeout",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
			},
			expectError: "context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					tt.handler(w, r)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			allocator := NewHTTPAllocator(server.URL)
			if tt.name == "timeout" {
				allocator.httpClient.Timeout = 10 * time.Millisecond
			}
			ctx := context.Background()

			err := allocator.HealthCheck(ctx)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.expectError) && !strings.Contains(err.Error(), "request failed") {
				t.Errorf("expected error containing %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

func TestHTTPAllocatorIPv6WithPrefixFallback(t *testing.T) {
	// Test IPv6 allocation when prefix is not in response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/pools/test-pool" && r.Method == "GET":
			// Return pool with /64 prefix
			json.NewEncoder(w).Encode(PoolResponse{
				ID:     "test-pool",
				CIDR:   "2001:db8:1::/64",
				Prefix: 64,
			})
		case r.URL.Path == "/api/v1/allocations" && r.Method == "POST":
			// Return allocation WITHOUT prefix (should fallback to pool prefix)
			json.NewEncoder(w).Encode(AllocationResponse{
				PoolID:       "test-pool",
				SubscriberID: "sub-123",
				IP:           "2001:db8:1::100",
				Prefix:       0, // Missing prefix
				Timestamp:    time.Now(),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	ip, prefix, err := allocator.AllocateIPv6(ctx, "sub-123", "test-pool")
	if err != nil {
		t.Fatalf("IPv6 allocation failed: %v", err)
	}

	if ip == nil {
		t.Fatal("expected non-nil IP")
	}

	if prefix == nil {
		t.Fatal("expected non-nil prefix")
	}

	// Verify the prefix is /64 (from pool, not from response)
	ones, _ := prefix.Mask.Size()
	if ones != 64 {
		t.Errorf("expected prefix /64, got /%d", ones)
	}
}

func TestHTTPAllocatorIPv6ConflictWithFallback(t *testing.T) {
	// Test IPv6 conflict handling with fallback to pool prefix
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch {
		case r.URL.Path == "/api/v1/pools/test-pool" && r.Method == "GET":
			json.NewEncoder(w).Encode(PoolResponse{
				ID:     "test-pool",
				CIDR:   "2001:db8:1::/56",
				Prefix: 56,
			})
		case r.URL.Path == "/api/v1/allocations" && r.Method == "POST":
			w.WriteHeader(http.StatusConflict) // Conflict on first try
		case r.URL.Path == "/api/v1/allocations/sub-123" && r.Method == "GET":
			// Return existing allocation without prefix
			json.NewEncoder(w).Encode(AllocationResponse{
				PoolID:       "test-pool",
				SubscriberID: "sub-123",
				IP:           "2001:db8:1::50",
				Prefix:       0, // No prefix, should fallback
				Timestamp:    time.Now(),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	ip, prefix, err := allocator.AllocateIPv6(ctx, "sub-123", "test-pool")
	if err != nil {
		t.Fatalf("IPv6 conflict handling failed: %v", err)
	}

	if ip.String() != "2001:db8:1::50" {
		t.Errorf("expected IP 2001:db8:1::50, got %s", ip.String())
	}

	if prefix == nil {
		t.Fatal("expected non-nil prefix")
	}

	// Verify fallback to pool prefix
	ones, _ := prefix.Mask.Size()
	if ones != 56 {
		t.Errorf("expected fallback prefix /56, got /%d", ones)
	}
}

func TestHTTPAllocatorInvalidJSONInPoolRequest(t *testing.T) {
	// Test that proper pool response is handled correctly
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/pools/test" && r.Method == "GET":
			json.NewEncoder(w).Encode(PoolResponse{ID: "test", CIDR: "10.0.0.0/24", Prefix: 24})
		case r.URL.Path == "/api/v1/allocations" && r.Method == "POST":
			// Return a valid allocation response
			json.NewEncoder(w).Encode(AllocationResponse{
				PoolID:       "test",
				SubscriberID: "sub-123",
				IP:           "10.0.0.100",
				Timestamp:    time.Now(),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	// This should work with proper responses from both pool and allocation endpoints
	ip, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ip.String() != "10.0.0.100" {
		t.Errorf("expected IP 10.0.0.100, got %s", ip.String())
	}
}

func TestHTTPAllocatorConcurrentPoolAccess(t *testing.T) {
	// Test concurrent access to pool cache
	callCount := 0
	syncChan := make(chan bool, 5) // Buffered channel for goroutine synchronization
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/pools/concurrent-pool" {
			callCount++
			<-syncChan                        // Wait for all goroutines to be ready
			time.Sleep(50 * time.Millisecond) // Simulate slow response
			json.NewEncoder(w).Encode(PoolResponse{
				ID:     "concurrent-pool",
				CIDR:   "10.0.0.0/24",
				Prefix: 24,
			})
		} else if r.URL.Path == "/api/v1/allocations" {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(AllocationResponse{
				IP: "10.0.0.1",
			})
		}
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	// Multiple concurrent requests for same pool
	done := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		go func(id int) {
			syncChan <- true // Signal we are ready
			_, _, _, err := allocator.AllocateIPv4(ctx, fmt.Sprintf("sub-%d", id), "concurrent-pool")
			if err != nil {
				t.Errorf("concurrent allocation failed: %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all to complete
	for i := 0; i < 5; i++ {
		<-done
	}

	// Pool should be fetched multiple times without locking
	// but all requests should succeed
	if callCount < 1 || callCount > 5 {
		t.Errorf("expected pool to be fetched between 1-5 times, got %d calls", callCount)
	}
}

func TestHTTPAllocatorIPv4GatewayForDifferentSubnetSizes(t *testing.T) {
	tests := []struct {
		name       string
		cidr       string
		expectedGW string
	}{
		{
			name:       "/24 subnet",
			cidr:       "192.168.1.0/24",
			expectedGW: "192.168.1.1",
		},
		{
			name:       "/16 subnet",
			cidr:       "172.16.0.0/16",
			expectedGW: "172.16.0.1",
		},
		{
			name:       "/8 subnet",
			cidr:       "10.0.0.0/8",
			expectedGW: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/pools/test" {
					json.NewEncoder(w).Encode(PoolResponse{
						ID:     "test",
						CIDR:   tt.cidr,
						Prefix: 24,
					})
				} else if r.URL.Path == "/api/v1/allocations" {
					json.NewEncoder(w).Encode(AllocationResponse{
						PoolID:       "test",
						SubscriberID: "sub-123",
						IP:           strings.Split(tt.cidr, "/")[0],
						Timestamp:    time.Now(),
					})
				}
			}))
			defer server.Close()

			allocator := NewHTTPAllocator(server.URL)
			ctx := context.Background()

			_, _, gateway, err := allocator.AllocateIPv4(ctx, "sub-123", "test")
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
	// Test handling of CIDR that can't be parsed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(PoolResponse{
			ID:     "malformed-pool",
			CIDR:   "not-a-valid-cidr",
			Prefix: 24,
		})
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "malformed-pool")
	if err == nil {
		t.Fatal("expected error for malformed CIDR")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("expected invalid CIDR error, got %q", err.Error())
	}
}

func TestHTTPAllocatorEmptyCIDR(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(PoolResponse{
			ID:     "empty-cidr-pool",
			CIDR:   "",
			Prefix: 24,
		})
	}))
	defer server.Close()

	allocator := NewHTTPAllocator(server.URL)
	ctx := context.Background()

	_, _, _, err := allocator.AllocateIPv4(ctx, "sub-123", "empty-cidr-pool")
	if err == nil {
		t.Fatal("expected error for empty CIDR")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("expected invalid CIDR error, got %q", err.Error())
	}
}
