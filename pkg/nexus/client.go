package nexus

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/deviceauth"
)

// ClientConfig contains configuration for the Nexus client.
type ClientConfig struct {
	// DeviceID is this device's unique identifier.
	DeviceID string

	// CLSetURL is the URL of the CLSet cluster (for future use).
	CLSetURL string

	// HeartbeatInterval is how often to send heartbeats.
	HeartbeatInterval time.Duration

	// SyncInterval is how often to sync state.
	SyncInterval time.Duration

	// Auth contains device authentication configuration.
	// If set, the client will use authenticated transport for API calls.
	Auth *deviceauth.Config

	// Authenticator is an optional pre-configured authenticator.
	// If set, this takes precedence over Auth config.
	Authenticator deviceauth.Authenticator
}

// DefaultClientConfig returns sensible defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		HeartbeatInterval: 30 * time.Second,
		SyncInterval:      5 * time.Second,
	}
}

// Client is the main Nexus client that manages distributed state.
type Client struct {
	config ClientConfig
	logger *zap.Logger
	store  Store

	// Typed stores for different entity types
	Subscribers *TypedStore[Subscriber]
	NTEs        *TypedStore[NTE]
	ISPs        *TypedStore[ISPConfig]
	Pools       *TypedStore[IPPool]
	Devices     *TypedStore[Device]

	// Local caches for fast access
	mu              sync.RWMutex
	subscriberCache map[string]*Subscriber
	nteCache        map[string]*NTE
	ispCache        map[string]*ISPConfig

	// Callbacks for state changes
	onSubscriberChange func(id string, sub *Subscriber, deleted bool)
	onNTEChange        func(id string, nte *NTE, deleted bool)
	onISPChange        func(id string, isp *ISPConfig, deleted bool)

	// HTTP client for API calls (with authentication if configured)
	httpClient    *http.Client
	authenticator deviceauth.Authenticator

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewClient creates a new Nexus client.
func NewClient(config ClientConfig, store Store, logger *zap.Logger) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	c := &Client{
		config:          config,
		logger:          logger,
		store:           store,
		subscriberCache: make(map[string]*Subscriber),
		nteCache:        make(map[string]*NTE),
		ispCache:        make(map[string]*ISPConfig),
		ctx:             ctx,
		cancel:          cancel,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
	}

	// Create typed stores with appropriate prefixes
	c.Subscribers = NewTypedStore[Subscriber](store, "/subscriber")
	c.NTEs = NewTypedStore[NTE](store, "/nte")
	c.ISPs = NewTypedStore[ISPConfig](store, "/isp")
	c.Pools = NewTypedStore[IPPool](store, "/pool")
	c.Devices = NewTypedStore[Device](store, "/device")

	// Set up authenticator if provided directly
	if config.Authenticator != nil {
		c.authenticator = config.Authenticator
		c.httpClient = deviceauth.NewAuthenticatedClient(c.authenticator)
		logger.Info("Nexus client using pre-configured authenticator",
			zap.String("mode", string(c.authenticator.Mode())),
		)
	} else if config.Auth != nil && config.Auth.Mode != deviceauth.AuthModeNone {
		// Create authenticator from config
		auth, err := deviceauth.NewAuthenticator(*config.Auth, logger)
		if err != nil {
			logger.Error("Failed to create authenticator, continuing without auth",
				zap.Error(err),
			)
		} else {
			c.authenticator = auth
			c.httpClient = deviceauth.NewAuthenticatedClient(auth)
			logger.Info("Nexus client authentication initialized",
				zap.String("mode", string(auth.Mode())),
			)
		}
	}

	return c
}

// NewClientWithAuth creates a new Nexus client with a pre-configured authenticator.
func NewClientWithAuth(config ClientConfig, store Store, auth deviceauth.Authenticator, logger *zap.Logger) *Client {
	config.Authenticator = auth
	return NewClient(config, store, logger)
}

// Authenticator returns the client's authenticator (if any).
func (c *Client) Authenticator() deviceauth.Authenticator {
	return c.authenticator
}

// HTTPClient returns the HTTP client (with authentication if configured).
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// Start begins the client's background operations.
func (c *Client) Start() error {
	c.logger.Info("Starting Nexus client",
		zap.String("device_id", c.config.DeviceID),
	)

	// Set up watchers for remote changes
	c.setupWatchers()

	// Load initial state into caches
	if err := c.loadInitialState(); err != nil {
		return fmt.Errorf("load initial state: %w", err)
	}

	// Start background sync
	c.wg.Add(1)
	go c.syncLoop()

	c.logger.Info("Nexus client started")
	return nil
}

// Stop shuts down the client.
func (c *Client) Stop() error {
	c.logger.Info("Stopping Nexus client")
	c.cancel()
	c.wg.Wait()

	// Close authenticator if we own it
	if c.authenticator != nil && c.config.Auth != nil {
		if err := c.authenticator.Close(); err != nil {
			c.logger.Warn("Failed to close authenticator", zap.Error(err))
		}
	}

	return c.store.Close()
}

// setupWatchers registers callbacks for store changes.
func (c *Client) setupWatchers() {
	// Watch for subscriber changes
	c.Subscribers.Watch(func(id string, sub *Subscriber, deleted bool) {
		c.mu.Lock()
		if deleted {
			delete(c.subscriberCache, id)
		} else if sub != nil {
			c.subscriberCache[id] = sub
		}
		c.mu.Unlock()

		if c.onSubscriberChange != nil {
			c.onSubscriberChange(id, sub, deleted)
		}
	})

	// Watch for NTE changes
	c.NTEs.Watch(func(id string, nte *NTE, deleted bool) {
		c.mu.Lock()
		if deleted {
			delete(c.nteCache, id)
		} else if nte != nil {
			c.nteCache[id] = nte
		}
		c.mu.Unlock()

		if c.onNTEChange != nil {
			c.onNTEChange(id, nte, deleted)
		}
	})

	// Watch for ISP changes
	c.ISPs.Watch(func(id string, isp *ISPConfig, deleted bool) {
		c.mu.Lock()
		if deleted {
			delete(c.ispCache, id)
		} else if isp != nil {
			c.ispCache[id] = isp
		}
		c.mu.Unlock()

		if c.onISPChange != nil {
			c.onISPChange(id, isp, deleted)
		}
	})
}

// loadInitialState loads all state into local caches.
func (c *Client) loadInitialState() error {
	ctx := context.Background()

	// Load subscribers
	subs, err := c.Subscribers.List(ctx)
	if err != nil {
		return fmt.Errorf("list subscribers: %w", err)
	}
	c.mu.Lock()
	for _, sub := range subs {
		c.subscriberCache[sub.ID] = sub
	}
	c.mu.Unlock()
	c.logger.Info("Loaded subscribers", zap.Int("count", len(subs)))

	// Load NTEs
	ntes, err := c.NTEs.List(ctx)
	if err != nil {
		return fmt.Errorf("list NTEs: %w", err)
	}
	c.mu.Lock()
	for _, nte := range ntes {
		c.nteCache[nte.ID] = nte
	}
	c.mu.Unlock()
	c.logger.Info("Loaded NTEs", zap.Int("count", len(ntes)))

	// Load ISPs
	isps, err := c.ISPs.List(ctx)
	if err != nil {
		return fmt.Errorf("list ISPs: %w", err)
	}
	c.mu.Lock()
	for _, isp := range isps {
		c.ispCache[isp.ID] = isp
	}
	c.mu.Unlock()
	c.logger.Info("Loaded ISPs", zap.Int("count", len(isps)))

	return nil
}

// syncLoop periodically syncs state and sends heartbeats.
func (c *Client) syncLoop() {
	defer c.wg.Done()

	heartbeatTicker := time.NewTicker(c.config.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-heartbeatTicker.C:
			c.sendHeartbeat()
		}
	}
}

// sendHeartbeat updates the device's last-seen timestamp.
func (c *Client) sendHeartbeat() {
	ctx := context.Background()

	device, err := c.Devices.Get(ctx, c.config.DeviceID)
	if err != nil {
		c.logger.Warn("Failed to get device for heartbeat", zap.Error(err))
		return
	}

	device.LastSeen = time.Now().UTC()
	if err := c.Devices.Put(ctx, c.config.DeviceID, device); err != nil {
		c.logger.Warn("Failed to send heartbeat", zap.Error(err))
	}
}

// OnSubscriberChange registers a callback for subscriber changes.
func (c *Client) OnSubscriberChange(callback func(id string, sub *Subscriber, deleted bool)) {
	c.onSubscriberChange = callback
}

// OnNTEChange registers a callback for NTE changes.
func (c *Client) OnNTEChange(callback func(id string, nte *NTE, deleted bool)) {
	c.onNTEChange = callback
}

// OnISPChange registers a callback for ISP changes.
func (c *Client) OnISPChange(callback func(id string, isp *ISPConfig, deleted bool)) {
	c.onISPChange = callback
}

// GetSubscriber returns a subscriber from the cache.
func (c *Client) GetSubscriber(id string) (*Subscriber, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sub, ok := c.subscriberCache[id]
	return sub, ok
}

// GetSubscriberByNTE returns a subscriber by NTE ID.
func (c *Client) GetSubscriberByNTE(nteID string) (*Subscriber, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, sub := range c.subscriberCache {
		if sub.NTEID == nteID {
			return sub, true
		}
	}
	return nil, false
}

// GetNTE returns an NTE from the cache.
func (c *Client) GetNTE(id string) (*NTE, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	nte, ok := c.nteCache[id]
	return nte, ok
}

// GetNTEBySerial returns an NTE by serial number.
func (c *Client) GetNTEBySerial(serial string) (*NTE, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, nte := range c.nteCache {
		if nte.SerialNumber == serial {
			return nte, true
		}
	}
	return nil, false
}

// GetISP returns an ISP config from the cache.
func (c *Client) GetISP(id string) (*ISPConfig, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	isp, ok := c.ispCache[id]
	return isp, ok
}

// ListSubscribers returns all subscribers from the cache.
func (c *Client) ListSubscribers() []*Subscriber {
	c.mu.RLock()
	defer c.mu.RUnlock()
	subs := make([]*Subscriber, 0, len(c.subscriberCache))
	for _, sub := range c.subscriberCache {
		subs = append(subs, sub)
	}
	return subs
}

// ListSubscribersByDevice returns subscribers for a specific device.
func (c *Client) ListSubscribersByDevice(deviceID string) []*Subscriber {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var subs []*Subscriber
	for _, sub := range c.subscriberCache {
		if sub.DeviceID == deviceID {
			subs = append(subs, sub)
		}
	}
	return subs
}

// ListNTEs returns all NTEs from the cache.
func (c *Client) ListNTEs() []*NTE {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ntes := make([]*NTE, 0, len(c.nteCache))
	for _, nte := range c.nteCache {
		ntes = append(ntes, nte)
	}
	return ntes
}

// ListNTEsByDevice returns NTEs for a specific device.
func (c *Client) ListNTEsByDevice(deviceID string) []*NTE {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var ntes []*NTE
	for _, nte := range c.nteCache {
		if nte.DeviceID == deviceID {
			ntes = append(ntes, nte)
		}
	}
	return ntes
}

// ListISPs returns all ISPs from the cache.
func (c *Client) ListISPs() []*ISPConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	isps := make([]*ISPConfig, 0, len(c.ispCache))
	for _, isp := range c.ispCache {
		isps = append(isps, isp)
	}
	return isps
}

// SaveSubscriber saves a subscriber to the store.
func (c *Client) SaveSubscriber(ctx context.Context, sub *Subscriber) error {
	sub.UpdatedAt = time.Now().UTC()
	return c.Subscribers.Put(ctx, sub.ID, sub)
}

// SaveNTE saves an NTE to the store.
func (c *Client) SaveNTE(ctx context.Context, nte *NTE) error {
	nte.LastSeen = time.Now().UTC()
	return c.NTEs.Put(ctx, nte.ID, nte)
}

// SaveISP saves an ISP config to the store.
func (c *Client) SaveISP(ctx context.Context, isp *ISPConfig) error {
	return c.ISPs.Put(ctx, isp.ID, isp)
}

// DeleteSubscriber removes a subscriber from the store.
func (c *Client) DeleteSubscriber(ctx context.Context, id string) error {
	return c.Subscribers.Delete(ctx, id)
}

// DeleteNTE removes an NTE from the store.
func (c *Client) DeleteNTE(ctx context.Context, id string) error {
	return c.NTEs.Delete(ctx, id)
}

// === IP Allocation Methods ===

// GetSubscriberByMAC looks up a subscriber by their MAC address.
// MAC is stored as NTE serial or can be derived from NTE.
func (c *Client) GetSubscriberByMAC(mac string) (*Subscriber, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// First try to find NTE by MAC (some systems store MAC as serial)
	for _, nte := range c.nteCache {
		// MAC might be stored as serial or in a MAC field
		if nte.SerialNumber == mac {
			// Found NTE, now find subscriber
			for _, sub := range c.subscriberCache {
				if sub.NTEID == nte.ID {
					return sub, true
				}
			}
		}
	}

	// Direct lookup in subscriber cache by ID (if MAC is used as ID)
	if sub, ok := c.subscriberCache[mac]; ok {
		return sub, true
	}

	return nil, false
}

// AllocateIPForSubscriber allocates an IP address for a subscriber.
// If the subscriber already has an IP, it returns that IP.
// Otherwise, it allocates from the subscriber's assigned pool.
func (c *Client) AllocateIPForSubscriber(ctx context.Context, subscriberID string) (string, error) {
	// Get subscriber
	sub, ok := c.GetSubscriber(subscriberID)
	if !ok {
		return "", fmt.Errorf("subscriber %s not found", subscriberID)
	}

	// If already has IP, return it
	if sub.IPv4Addr != "" {
		return sub.IPv4Addr, nil
	}

	// Get pool for this subscriber
	poolID := sub.IPv4Pool
	if poolID == "" {
		// Try to get default pool from ISP config
		if isp, ok := c.GetISP(sub.ISPID); ok && len(isp.IPv4Pools) > 0 {
			poolID = isp.IPv4Pools[0]
		}
	}

	if poolID == "" {
		return "", fmt.Errorf("no IPv4 pool configured for subscriber %s", subscriberID)
	}

	// Get pool
	pool, err := c.Pools.Get(ctx, poolID)
	if err != nil {
		return "", fmt.Errorf("get pool %s: %w", poolID, err)
	}

	// Allocate IP from pool using deterministic hash
	ip, err := c.allocateFromPool(ctx, pool, subscriberID)
	if err != nil {
		return "", fmt.Errorf("allocate from pool: %w", err)
	}

	// Update subscriber with allocated IP
	sub.IPv4Addr = ip
	sub.IPv4Pool = poolID
	sub.UpdatedAt = time.Now().UTC()

	if err := c.SaveSubscriber(ctx, sub); err != nil {
		return "", fmt.Errorf("save subscriber: %w", err)
	}

	c.logger.Info("Allocated IP for subscriber",
		zap.String("subscriber_id", subscriberID),
		zap.String("ip", ip),
		zap.String("pool", poolID),
	)

	return ip, nil
}

// allocateFromPool allocates an IP from a pool using deterministic hashing.
// This ensures the same subscriber always gets the same IP (hashring-like behavior).
func (c *Client) allocateFromPool(ctx context.Context, pool *IPPool, subscriberID string) (string, error) {
	// Parse CIDR
	baseIP, ipNet, err := parseIPNet(pool.CIDR)
	if err != nil {
		return "", fmt.Errorf("parse CIDR %s: %w", pool.CIDR, err)
	}

	// Calculate host range
	ones, bits := ipNet.Size()
	hostBits := bits - ones
	numHosts := (1 << hostBits) - 2 // Exclude network and broadcast

	if numHosts <= 0 {
		return "", fmt.Errorf("pool %s has no usable addresses", pool.ID)
	}

	// Hash subscriber ID to get deterministic offset
	hash := hashString(subscriberID)
	offset := int(hash%uint64(numHosts)) + 1 // +1 to skip network address

	// Calculate IP
	ip := make([]byte, 4)
	copy(ip, baseIP)

	// Add offset to base IP
	ip[3] += byte(offset & 0xFF)
	ip[2] += byte((offset >> 8) & 0xFF)
	ip[1] += byte((offset >> 16) & 0xFF)
	ip[0] += byte((offset >> 24) & 0xFF)

	return formatIP(ip), nil
}

// LookupSubscriberIP looks up the pre-allocated IP for a subscriber.
// This is the read-only operation used by DHCP.
func (c *Client) LookupSubscriberIP(subscriberID string) (string, bool) {
	sub, ok := c.GetSubscriber(subscriberID)
	if !ok {
		return "", false
	}
	if sub.IPv4Addr == "" {
		return "", false
	}
	return sub.IPv4Addr, true
}

// GetSubscriberPool returns the pool configuration for a subscriber's IP.
func (c *Client) GetSubscriberPool(ctx context.Context, subscriberID string) (*IPPool, error) {
	sub, ok := c.GetSubscriber(subscriberID)
	if !ok {
		return nil, fmt.Errorf("subscriber %s not found", subscriberID)
	}

	if sub.IPv4Pool == "" {
		return nil, fmt.Errorf("subscriber %s has no pool assigned", subscriberID)
	}

	return c.Pools.Get(ctx, sub.IPv4Pool)
}

// ReleaseSubscriberIP releases a subscriber's IP allocation.
func (c *Client) ReleaseSubscriberIP(ctx context.Context, subscriberID string) error {
	sub, ok := c.GetSubscriber(subscriberID)
	if !ok {
		return fmt.Errorf("subscriber %s not found", subscriberID)
	}

	if sub.IPv4Addr == "" {
		return nil // Already released
	}

	c.logger.Info("Releasing IP for subscriber",
		zap.String("subscriber_id", subscriberID),
		zap.String("ip", sub.IPv4Addr),
	)

	sub.IPv4Addr = ""
	sub.UpdatedAt = time.Now().UTC()

	return c.SaveSubscriber(ctx, sub)
}

// Helper functions

func parseIPNet(cidr string) ([]byte, *ipNet, error) {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			ip := parseIPv4(cidr[:i])
			if ip == nil {
				return nil, nil, fmt.Errorf("invalid IP in CIDR")
			}
			prefix := 0
			for j := i + 1; j < len(cidr); j++ {
				prefix = prefix*10 + int(cidr[j]-'0')
			}
			mask := make([]byte, 4)
			for k := 0; k < prefix; k++ {
				mask[k/8] |= 1 << (7 - k%8)
			}
			return ip, &ipNet{IP: ip, Mask: mask}, nil
		}
	}
	return nil, nil, fmt.Errorf("invalid CIDR format")
}

type ipNet struct {
	IP   []byte
	Mask []byte
}

func (n *ipNet) Size() (ones int, bits int) {
	bits = 32
	for _, b := range n.Mask {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) != 0 {
				ones++
			}
		}
	}
	return ones, bits
}

func parseIPv4(s string) []byte {
	ip := make([]byte, 4)
	idx := 0
	val := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if idx >= 4 || val > 255 {
				return nil
			}
			ip[idx] = byte(val)
			idx++
			val = 0
		} else if s[i] >= '0' && s[i] <= '9' {
			val = val*10 + int(s[i]-'0')
		} else {
			return nil
		}
	}
	if idx != 4 {
		return nil
	}
	return ip
}

func formatIP(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func hashString(s string) uint64 {
	// FNV-1a hash
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
