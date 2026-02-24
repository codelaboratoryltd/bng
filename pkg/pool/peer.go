// Package pool provides distributed IP allocation for BNG.
package pool

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// PeerPool provides distributed IP allocation across multiple BNG peers.
// Uses Rendezvous hashing (HRW) to determine which peer owns a given subscriber,
// minimizing key redistribution when peers join/leave.
type PeerPool struct {
	mu sync.RWMutex

	nodeID      string       // This node's ID
	peers       []string     // List of peer addresses (including self)
	peerNodes   []string     // Sorted list of node IDs for consistent hashing
	localPool   *LocalPool   // Local allocation pool
	httpClient  *http.Client // For forwarding requests to peers
	logger      *zap.Logger
	listenAddr  string        // Address for peer API server
	poolNetwork *net.IPNet    // Pool network CIDR
	gateway     net.IP        // Pool gateway
	dnsServers  []net.IP      // DNS servers
	leaseTime   time.Duration // DHCP lease time

	// Health checking
	healthMu          sync.RWMutex
	peerHealthMap     map[string]*peerHealth // nodeID -> health state
	healthCancel      context.CancelFunc
	healthInterval    time.Duration
	healthThreshold   int // consecutive failures before marking unhealthy
	healthCheckClient *http.Client
}

// peerHealth tracks health state for a single peer.
type peerHealth struct {
	healthy             bool
	consecutiveFailures int
}

// LocalPool manages local IP allocations for subscribers owned by this node.
type LocalPool struct {
	mu          sync.Mutex
	network     *net.IPNet
	allocations map[string]net.IP // subscriberID -> IP
	ipToSub     map[string]string // IP -> subscriberID (reverse index)
	available   []net.IP          // Available IPs
}

// PeerPoolConfig configures a peer pool.
type PeerPoolConfig struct {
	NodeID     string
	Peers      []string
	Network    string // CIDR notation
	Gateway    string
	DNSServers []string
	LeaseTime  time.Duration
	ListenAddr string
	Logger     *zap.Logger
}

// AllocationRequest is the request body for peer allocation.
type AllocationRequest struct {
	SubscriberID string `json:"subscriber_id"`
	MAC          string `json:"mac,omitempty"`
}

// AllocationResponse is the response from peer allocation.
type AllocationResponse struct {
	IP           string `json:"ip"`
	SubscriberID string `json:"subscriber_id"`
	NodeID       string `json:"node_id"` // Node that owns this allocation
	Gateway      string `json:"gateway,omitempty"`
	DNS          string `json:"dns,omitempty"`
	LeaseTime    int    `json:"lease_time,omitempty"` // seconds
}

// NewPeerPool creates a new distributed peer pool.
func NewPeerPool(cfg PeerPoolConfig) (*PeerPool, error) {
	_, network, err := net.ParseCIDR(cfg.Network)
	if err != nil {
		return nil, fmt.Errorf("invalid network CIDR: %w", err)
	}

	gateway := net.ParseIP(cfg.Gateway)
	if gateway == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", cfg.Gateway)
	}

	var dnsServers []net.IP
	for _, dns := range cfg.DNSServers {
		ip := net.ParseIP(dns)
		if ip == nil {
			return nil, fmt.Errorf("invalid DNS server: %s", dns)
		}
		dnsServers = append(dnsServers, ip)
	}

	// Ensure peers list includes this node
	allPeers := cfg.Peers
	nodeFound := false
	for _, p := range allPeers {
		if p == cfg.NodeID {
			nodeFound = true
			break
		}
	}
	if !nodeFound {
		allPeers = append(allPeers, cfg.NodeID)
	}

	// Sort peers for consistent hashing
	sort.Strings(allPeers)

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	// Initialize peer health map — all peers start healthy.
	healthMap := make(map[string]*peerHealth, len(allPeers))
	for _, id := range allPeers {
		healthMap[id] = &peerHealth{healthy: true}
	}

	pool := &PeerPool{
		nodeID:      cfg.NodeID,
		peers:       cfg.Peers,
		peerNodes:   allPeers,
		poolNetwork: network,
		gateway:     gateway,
		dnsServers:  dnsServers,
		leaseTime:   cfg.LeaseTime,
		listenAddr:  cfg.ListenAddr,
		logger:      logger,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		peerHealthMap:   healthMap,
		healthInterval:  10 * time.Second,
		healthThreshold: 3,
		healthCheckClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	// Initialize local pool
	pool.localPool = newLocalPool(network, gateway)

	return pool, nil
}

// newLocalPool creates a new local allocation pool.
func newLocalPool(network *net.IPNet, gateway net.IP) *LocalPool {
	pool := &LocalPool{
		network:     network,
		allocations: make(map[string]net.IP),
		ipToSub:     make(map[string]string),
	}

	// Generate available IPs
	pool.available = generateAvailableIPs(network, gateway)

	return pool
}

// generateAvailableIPs generates the list of available IPs in the network.
func generateAvailableIPs(network *net.IPNet, gateway net.IP) []net.IP {
	var ips []net.IP

	networkIP := network.IP.To4()
	if networkIP == nil {
		return ips
	}

	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	numHosts := (1 << hostBits) - 2 // Exclude network and broadcast

	if numHosts <= 0 {
		return ips
	}

	baseInt := binary.BigEndian.Uint32(networkIP)

	for i := 1; i <= numHosts; i++ {
		ipInt := baseInt + uint32(i)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipInt)

		// Skip gateway
		if ip.Equal(gateway) {
			continue
		}

		ips = append(ips, ip)
	}

	return ips
}

// GetOwner returns the node ID that owns a given subscriber.
func (p *PeerPool) GetOwner(subscriberID string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return rendezvousHash(subscriberID, p.peerNodes)
}

// IsLocalOwner checks if this node owns the given subscriber.
func (p *PeerPool) IsLocalOwner(subscriberID string) bool {
	return p.GetOwner(subscriberID) == p.nodeID
}

// Allocate allocates an IP for a subscriber.
// If this node owns the subscriber, allocates locally.
// Otherwise, forwards the request to the owning peer.
// Unhealthy peers are skipped — the next healthy peer in hash order is tried.
func (p *PeerPool) Allocate(ctx context.Context, subscriberID string, mac net.HardwareAddr) (*AllocationResponse, error) {
	owner := p.getHealthyOwner(subscriberID)

	if owner == p.nodeID {
		// We own this subscriber, allocate locally
		return p.allocateLocal(subscriberID)
	}

	// Forward to owning peer
	return p.forwardAllocation(ctx, owner, subscriberID, mac)
}

// getHealthyOwner returns the highest-ranked healthy peer for a subscriber.
// Falls back through the rendezvous hash ranking, skipping unhealthy peers.
// If all remote peers are unhealthy, falls back to local allocation.
func (p *PeerPool) getHealthyOwner(subscriberID string) string {
	p.mu.RLock()
	nodes := p.peerNodes
	p.mu.RUnlock()

	ranked := rendezvousRanked(subscriberID, nodes)

	p.healthMu.RLock()
	defer p.healthMu.RUnlock()

	for _, node := range ranked {
		// Local node is always considered healthy.
		if node == p.nodeID {
			return node
		}
		h, ok := p.peerHealthMap[node]
		if !ok || h.healthy {
			return node
		}
	}

	// All remote peers unhealthy — fall back to local.
	return p.nodeID
}

// allocateLocal allocates an IP from the local pool.
func (p *PeerPool) allocateLocal(subscriberID string) (*AllocationResponse, error) {
	p.localPool.mu.Lock()
	defer p.localPool.mu.Unlock()

	// Check if already allocated
	if ip, exists := p.localPool.allocations[subscriberID]; exists {
		return p.makeResponse(ip, subscriberID), nil
	}

	// Allocate new IP
	if len(p.localPool.available) == 0 {
		return nil, fmt.Errorf("pool exhausted")
	}

	ip := p.localPool.available[0]
	p.localPool.available = p.localPool.available[1:]
	p.localPool.allocations[subscriberID] = ip
	p.localPool.ipToSub[ip.String()] = subscriberID

	p.logger.Info("Allocated IP locally",
		zap.String("subscriber", subscriberID),
		zap.String("ip", ip.String()),
	)

	return p.makeResponse(ip, subscriberID), nil
}

// makeResponse creates an allocation response.
func (p *PeerPool) makeResponse(ip net.IP, subscriberID string) *AllocationResponse {
	var dnsStr string
	if len(p.dnsServers) > 0 {
		dnsStr = p.dnsServers[0].String()
	}

	return &AllocationResponse{
		IP:           ip.String(),
		SubscriberID: subscriberID,
		NodeID:       p.nodeID,
		Gateway:      p.gateway.String(),
		DNS:          dnsStr,
		LeaseTime:    int(p.leaseTime.Seconds()),
	}
}

// forwardAllocation forwards an allocation request to the owning peer.
func (p *PeerPool) forwardAllocation(ctx context.Context, owner, subscriberID string, mac net.HardwareAddr) (*AllocationResponse, error) {
	// Find peer address for owner
	peerAddr := p.getPeerAddr(owner)
	if peerAddr == "" {
		return nil, fmt.Errorf("no address for peer %s", owner)
	}

	req := AllocationRequest{
		SubscriberID: subscriberID,
	}
	if mac != nil {
		req.MAC = mac.String()
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf("http://%s/pool/allocate", peerAddr)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("forward to peer %s: %w", owner, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("peer %s returned status %d", owner, resp.StatusCode)
	}

	var allocResp AllocationResponse
	if err := json.NewDecoder(resp.Body).Decode(&allocResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	p.logger.Info("Forwarded allocation to peer",
		zap.String("subscriber", subscriberID),
		zap.String("peer", owner),
		zap.String("ip", allocResp.IP),
	)

	return &allocResp, nil
}

// getPeerAddr returns the address for a peer node ID.
// This is a simple implementation that assumes node ID == address.
// In production, you'd have a separate mapping.
func (p *PeerPool) getPeerAddr(nodeID string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, peer := range p.peers {
		// Simple matching - in production you'd have better mapping
		if peer == nodeID || peer == nodeID+":8081" {
			return peer
		}
	}

	// Assume nodeID is the address
	return nodeID
}

// Release releases an IP allocation.
func (p *PeerPool) Release(ctx context.Context, subscriberID string) error {
	owner := p.getHealthyOwner(subscriberID)

	if owner == p.nodeID {
		return p.releaseLocal(subscriberID)
	}

	// Forward to owning peer
	return p.forwardRelease(ctx, owner, subscriberID)
}

// releaseLocal releases a local allocation.
func (p *PeerPool) releaseLocal(subscriberID string) error {
	p.localPool.mu.Lock()
	defer p.localPool.mu.Unlock()

	ip, exists := p.localPool.allocations[subscriberID]
	if !exists {
		return nil // Already released
	}

	delete(p.localPool.allocations, subscriberID)
	delete(p.localPool.ipToSub, ip.String())
	p.localPool.available = append(p.localPool.available, ip)

	p.logger.Info("Released IP locally",
		zap.String("subscriber", subscriberID),
		zap.String("ip", ip.String()),
	)

	return nil
}

// forwardRelease forwards a release request to the owning peer.
func (p *PeerPool) forwardRelease(ctx context.Context, owner, subscriberID string) error {
	peerAddr := p.getPeerAddr(owner)
	if peerAddr == "" {
		return fmt.Errorf("no address for peer %s", owner)
	}

	url := fmt.Sprintf("http://%s/pool/release/%s", peerAddr, subscriberID)
	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("forward to peer %s: %w", owner, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("peer %s returned status %d", owner, resp.StatusCode)
	}

	return nil
}

// Get returns the allocation for a subscriber.
func (p *PeerPool) Get(subscriberID string) (*AllocationResponse, bool) {
	owner := p.GetOwner(subscriberID)

	if owner == p.nodeID {
		p.localPool.mu.Lock()
		defer p.localPool.mu.Unlock()

		ip, exists := p.localPool.allocations[subscriberID]
		if !exists {
			return nil, false
		}
		return p.makeResponse(ip, subscriberID), true
	}

	// For remote allocations, we don't have the data locally
	// The caller should forward to the owning peer
	return nil, false
}

// Stats returns pool statistics.
func (p *PeerPool) Stats() PoolStats {
	p.localPool.mu.Lock()
	defer p.localPool.mu.Unlock()

	return PoolStats{
		NodeID:    p.nodeID,
		Allocated: len(p.localPool.allocations),
		Available: len(p.localPool.available),
		Total:     len(p.localPool.allocations) + len(p.localPool.available),
		PeerCount: len(p.peerNodes),
	}
}

// PoolStats represents pool statistics.
type PoolStats struct {
	NodeID    string `json:"node_id"`
	Allocated int    `json:"allocated"`
	Available int    `json:"available"`
	Total     int    `json:"total"`
	PeerCount int    `json:"peer_count"`
}

// AddPeer adds a new peer to the pool.
func (p *PeerPool) AddPeer(peerID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if already exists
	for _, id := range p.peerNodes {
		if id == peerID {
			return
		}
	}

	p.peerNodes = append(p.peerNodes, peerID)
	sort.Strings(p.peerNodes)

	p.logger.Info("Added peer", zap.String("peer", peerID))
}

// RemovePeer removes a peer from the pool.
func (p *PeerPool) RemovePeer(peerID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, id := range p.peerNodes {
		if id == peerID {
			p.peerNodes = append(p.peerNodes[:i], p.peerNodes[i+1:]...)
			break
		}
	}

	p.logger.Info("Removed peer", zap.String("peer", peerID))
}

// --- Health checking ---

// Start begins the background health check loop for remote peers.
func (p *PeerPool) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	p.healthCancel = cancel
	go p.healthCheckLoop(ctx)
	p.logger.Info("Peer health checking started",
		zap.Duration("interval", p.healthInterval),
		zap.Int("threshold", p.healthThreshold),
	)
}

// Stop stops the background health check loop.
func (p *PeerPool) Stop() {
	if p.healthCancel != nil {
		p.healthCancel()
	}
}

// healthCheckLoop periodically checks the health of all remote peers.
func (p *PeerPool) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(p.healthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.mu.RLock()
			nodes := make([]string, len(p.peerNodes))
			copy(nodes, p.peerNodes)
			p.mu.RUnlock()

			for _, nodeID := range nodes {
				if nodeID == p.nodeID {
					continue // Skip self
				}
				p.checkPeer(ctx, nodeID)
			}
		}
	}
}

// checkPeer performs a health check against a single peer and updates its state.
func (p *PeerPool) checkPeer(ctx context.Context, nodeID string) {
	peerAddr := p.getPeerAddr(nodeID)
	if peerAddr == "" {
		return
	}

	url := fmt.Sprintf("http://%s/pool/status", peerAddr)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}

	resp, err := p.healthCheckClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}

	healthy := err == nil && resp.StatusCode == http.StatusOK

	p.healthMu.Lock()
	defer p.healthMu.Unlock()

	h, ok := p.peerHealthMap[nodeID]
	if !ok {
		h = &peerHealth{healthy: true}
		p.peerHealthMap[nodeID] = h
	}

	if healthy {
		if !h.healthy {
			p.logger.Info("Peer recovered",
				zap.String("peer", nodeID),
				zap.Int("previous_failures", h.consecutiveFailures),
			)
		}
		h.consecutiveFailures = 0
		h.healthy = true
		return
	}

	h.consecutiveFailures++
	if h.healthy && h.consecutiveFailures >= p.healthThreshold {
		h.healthy = false
		p.logger.Warn("Peer marked unhealthy",
			zap.String("peer", nodeID),
			zap.Int("consecutive_failures", h.consecutiveFailures),
		)
	}
}

// IsPeerHealthy returns whether a given peer is considered healthy.
func (p *PeerPool) IsPeerHealthy(nodeID string) bool {
	if nodeID == p.nodeID {
		return true
	}
	p.healthMu.RLock()
	defer p.healthMu.RUnlock()
	h, ok := p.peerHealthMap[nodeID]
	if !ok {
		return true // Unknown peers assumed healthy
	}
	return h.healthy
}

// --- HTTP API for peer communication ---

// RegisterHandlers registers the peer pool HTTP handlers.
func (p *PeerPool) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/pool/allocate", p.handleAllocate)
	mux.HandleFunc("/pool/release/", p.handleRelease)
	mux.HandleFunc("/pool/status", p.handleStatus)
	mux.HandleFunc("/pool/get/", p.handleGet)
}

func (p *PeerPool) handleAllocate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AllocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// This endpoint is only called for local allocations
	// (requests are forwarded by the source node)
	resp, err := p.allocateLocal(req.SubscriberID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (p *PeerPool) handleRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract subscriber ID from path: /pool/release/{subscriber_id}
	subscriberID := r.URL.Path[len("/pool/release/"):]
	if subscriberID == "" {
		http.Error(w, "subscriber_id required", http.StatusBadRequest)
		return
	}

	if err := p.releaseLocal(subscriberID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (p *PeerPool) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := p.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (p *PeerPool) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract subscriber ID from path: /pool/get/{subscriber_id}
	subscriberID := r.URL.Path[len("/pool/get/"):]
	if subscriberID == "" {
		http.Error(w, "subscriber_id required", http.StatusBadRequest)
		return
	}

	resp, exists := p.Get(subscriberID)
	if !exists {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// --- Rendezvous Hash implementation ---

// rendezvousHash implements Highest Random Weight (HRW) hashing.
// Returns the node with the highest hash score for the given key.
func rendezvousHash(key string, nodes []string) string {
	if len(nodes) == 0 {
		return ""
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	var bestNode string
	var bestHash uint64

	keyHash := hashString(key)

	for _, node := range nodes {
		hash := hashCombine(keyHash, node)
		if hash > bestHash {
			bestHash = hash
			bestNode = node
		}
	}

	return bestNode
}

// rendezvousRanked returns all nodes ranked by hash score (highest first).
// Used for fallback when the primary owner is unhealthy.
func rendezvousRanked(key string, nodes []string) []string {
	if len(nodes) <= 1 {
		return nodes
	}

	type scored struct {
		node  string
		score uint64
	}

	keyHash := hashString(key)
	scores := make([]scored, len(nodes))
	for i, node := range nodes {
		scores[i] = scored{node: node, score: hashCombine(keyHash, node)}
	}

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})

	ranked := make([]string, len(scores))
	for i, s := range scores {
		ranked[i] = s.node
	}
	return ranked
}

// hashString converts a string to uint64 using FNV-1a.
func hashString(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// hashCombine creates a combined hash score for Rendezvous hashing.
func hashCombine(keyHash uint64, nodeName string) uint64 {
	nodeHash := hashString(nodeName)
	combined := keyHash ^ nodeHash

	// Wang's 64-bit hash mixer
	combined = (^combined) + (combined << 21)
	combined = combined ^ (combined >> 24)
	combined = (combined + (combined << 3)) + (combined << 8)
	combined = combined ^ (combined >> 14)
	combined = (combined + (combined << 2)) + (combined << 4)
	combined = combined ^ (combined >> 28)
	combined = combined + (combined << 31)

	return combined
}
