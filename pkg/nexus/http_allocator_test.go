package nexus

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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
