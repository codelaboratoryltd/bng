package nexus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
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
	}

	// Create typed stores with appropriate prefixes
	c.Subscribers = NewTypedStore[Subscriber](store, "/subscriber")
	c.NTEs = NewTypedStore[NTE](store, "/nte")
	c.ISPs = NewTypedStore[ISPConfig](store, "/isp")
	c.Pools = NewTypedStore[IPPool](store, "/pool")
	c.Devices = NewTypedStore[Device](store, "/device")

	return c
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
