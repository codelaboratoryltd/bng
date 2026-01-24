package nexus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// HTTPAllocator provides IP allocation by calling an external Nexus server.
// This implements the same interface used by subscriber.Manager.
type HTTPAllocator struct {
	baseURL    string
	httpClient *http.Client

	// Pool cache for gateway/mask information
	pools map[string]*PoolInfo
}

// PoolInfo caches pool configuration from Nexus.
type PoolInfo struct {
	ID      string
	CIDR    string
	Gateway net.IP
	Mask    net.IPMask
}

// AllocationRequest is the request body for creating an allocation.
type AllocationRequest struct {
	PoolID       string `json:"pool_id"`
	SubscriberID string `json:"subscriber_id"`
}

// AllocationResponse is the response from allocation endpoints.
type AllocationResponse struct {
	PoolID       string    `json:"pool_id"`
	SubscriberID string    `json:"subscriber_id"`
	IP           string    `json:"ip"`
	Timestamp    time.Time `json:"timestamp"`
}

// PoolResponse is the response from pool endpoints.
type PoolResponse struct {
	ID     string `json:"id"`
	CIDR   string `json:"cidr"`
	Prefix int    `json:"prefix"`
}

// PoolsListResponse is the response from listing pools.
type PoolsListResponse struct {
	Pools []PoolResponse `json:"pools"`
	Count int            `json:"count"`
}

// NewHTTPAllocator creates a new HTTP-based IP allocator.
func NewHTTPAllocator(nexusURL string) *HTTPAllocator {
	return &HTTPAllocator{
		baseURL: nexusURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		pools: make(map[string]*PoolInfo),
	}
}

// AllocateIPv4 allocates an IPv4 address from the specified pool via Nexus API.
func (h *HTTPAllocator) AllocateIPv4(ctx context.Context, subscriberID, poolID string) (net.IP, net.IPMask, net.IP, error) {
	// Ensure we have pool info cached
	poolInfo, err := h.getPoolInfo(ctx, poolID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get pool info: %w", err)
	}

	// Create allocation request
	req := AllocationRequest{
		PoolID:       poolID,
		SubscriberID: subscriberID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal request: %w", err)
	}

	// Call Nexus API
	url := h.baseURL + "/api/v1/allocations"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		// Subscriber already has an allocation, fetch it
		return h.getExistingAllocation(ctx, subscriberID, poolInfo)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("allocation failed with status %d", resp.StatusCode)
	}

	var allocResp AllocationResponse
	if err := json.NewDecoder(resp.Body).Decode(&allocResp); err != nil {
		return nil, nil, nil, fmt.Errorf("decode response: %w", err)
	}

	ip := net.ParseIP(allocResp.IP)
	if ip == nil {
		return nil, nil, nil, fmt.Errorf("invalid IP in response: %s", allocResp.IP)
	}

	return ip, poolInfo.Mask, poolInfo.Gateway, nil
}

// getExistingAllocation fetches an existing allocation for a subscriber.
func (h *HTTPAllocator) getExistingAllocation(ctx context.Context, subscriberID string, poolInfo *PoolInfo) (net.IP, net.IPMask, net.IP, error) {
	url := h.baseURL + "/api/v1/allocations/" + subscriberID
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("get allocation failed with status %d", resp.StatusCode)
	}

	var allocResp AllocationResponse
	if err := json.NewDecoder(resp.Body).Decode(&allocResp); err != nil {
		return nil, nil, nil, fmt.Errorf("decode response: %w", err)
	}

	ip := net.ParseIP(allocResp.IP)
	if ip == nil {
		return nil, nil, nil, fmt.Errorf("invalid IP in response: %s", allocResp.IP)
	}

	return ip, poolInfo.Mask, poolInfo.Gateway, nil
}

// LookupIPv4 checks if a subscriber has an existing allocation without creating one.
// Returns the IP if found, or ErrNoAllocation if the subscriber has no allocation.
// This is used for walled garden mode: lookup first, only assign local IP if not found.
func (h *HTTPAllocator) LookupIPv4(ctx context.Context, subscriberID, poolID string) (net.IP, net.IPMask, net.IP, error) {
	// Ensure we have pool info cached
	poolInfo, err := h.getPoolInfo(ctx, poolID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get pool info: %w", err)
	}

	// Try to get existing allocation (GET, not POST)
	url := h.baseURL + "/api/v1/allocations/" + subscriberID
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// No allocation exists - subscriber is not activated
		return nil, nil, nil, ErrNoAllocation
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("lookup failed with status %d", resp.StatusCode)
	}

	var allocResp AllocationResponse
	if err := json.NewDecoder(resp.Body).Decode(&allocResp); err != nil {
		return nil, nil, nil, fmt.Errorf("decode response: %w", err)
	}

	ip := net.ParseIP(allocResp.IP)
	if ip == nil {
		return nil, nil, nil, fmt.Errorf("invalid IP in response: %s", allocResp.IP)
	}

	return ip, poolInfo.Mask, poolInfo.Gateway, nil
}

// ErrNoAllocation is returned when a subscriber has no allocation in Nexus.
var ErrNoAllocation = fmt.Errorf("no allocation found")

// AllocateIPv6 allocates an IPv6 address (stub - returns nil for now).
func (h *HTTPAllocator) AllocateIPv6(ctx context.Context, subscriberID, poolID string) (net.IP, *net.IPNet, error) {
	// IPv6 allocation not implemented yet
	return nil, nil, nil
}

// ReleaseIPv4 releases an IPv4 address allocation.
func (h *HTTPAllocator) ReleaseIPv4(ctx context.Context, subscriberID string) error {
	url := h.baseURL + "/api/v1/allocations/" + subscriberID
	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("release failed with status %d", resp.StatusCode)
	}

	return nil
}

// ReleaseIPv6 releases an IPv6 address (stub).
func (h *HTTPAllocator) ReleaseIPv6(ctx context.Context, ip net.IP) error {
	return nil
}

// getPoolInfo fetches and caches pool information from Nexus.
func (h *HTTPAllocator) getPoolInfo(ctx context.Context, poolID string) (*PoolInfo, error) {
	// Check cache first
	if info, ok := h.pools[poolID]; ok {
		return info, nil
	}

	// Fetch from Nexus
	url := h.baseURL + "/api/v1/pools/" + poolID
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pool not found: %s", poolID)
	}

	var poolResp PoolResponse
	if err := json.NewDecoder(resp.Body).Decode(&poolResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Parse CIDR
	_, ipNet, err := net.ParseCIDR(poolResp.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", poolResp.CIDR)
	}

	// Default gateway is first usable IP in the network
	gateway := make(net.IP, 4)
	copy(gateway, ipNet.IP.To4())
	gateway[3]++ // First usable IP

	info := &PoolInfo{
		ID:      poolResp.ID,
		CIDR:    poolResp.CIDR,
		Gateway: gateway,
		Mask:    ipNet.Mask,
	}

	// Cache the info
	h.pools[poolID] = info

	return info, nil
}

// CreatePool creates a new pool in Nexus.
func (h *HTTPAllocator) CreatePool(ctx context.Context, id, cidr string, prefix int) error {
	req := map[string]interface{}{
		"id":     id,
		"cidr":   cidr,
		"prefix": prefix,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := h.baseURL + "/api/v1/pools"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		return fmt.Errorf("create pool failed with status %d", resp.StatusCode)
	}

	return nil
}

// GetAllocation fetches an existing allocation for a subscriber.
func (h *HTTPAllocator) GetAllocation(ctx context.Context, subscriberID string) (*AllocationResponse, error) {
	url := h.baseURL + "/api/v1/allocations/" + subscriberID
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get allocation failed with status %d", resp.StatusCode)
	}

	var allocResp AllocationResponse
	if err := json.NewDecoder(resp.Body).Decode(&allocResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &allocResp, nil
}

// HealthCheck verifies connectivity to the Nexus server.
func (h *HTTPAllocator) HealthCheck(ctx context.Context) error {
	url := h.baseURL + "/health"
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status %d", resp.StatusCode)
	}

	return nil
}
