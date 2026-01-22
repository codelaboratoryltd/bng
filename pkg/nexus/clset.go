package nexus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CLSetConfig configures a CLSet-backed store.
type CLSetConfig struct {
	// PeerID is the unique identifier for this node in the cluster
	PeerID string

	// Namespace isolates this store's data from other CRDT users
	Namespace string

	// BootstrapPeers are the initial peers to connect to
	BootstrapPeers []string

	// SyncInterval is how often to sync with peers
	SyncInterval time.Duration

	// PeerTTL is how long a peer is considered active without heartbeat
	PeerTTL time.Duration

	// Logger for logging
	Logger *zap.Logger
}

// DefaultCLSetConfig returns sensible defaults for CLSet configuration.
func DefaultCLSetConfig() CLSetConfig {
	return CLSetConfig{
		Namespace:    "nexus",
		SyncInterval: 5 * time.Second,
		PeerTTL:      30 * time.Second,
	}
}

// CLSetStore implements Store using CLSet CRDT for distributed state.
// This provides eventual consistency across Nexus cluster nodes.
type CLSetStore struct {
	config   CLSetConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	data     map[string][]byte
	watchers map[string][]WatchCallback
	peers    map[string]peerInfo
	closed   bool
	stopSync chan struct{}

	// Hooks for CLSet integration (set when CLSet library is available)
	onInsert func(key string, value []byte)
	onUpdate func(key string, value []byte)
	onDelete func(key string)
}

// peerInfo tracks information about a cluster peer.
type peerInfo struct {
	ID       string
	Addr     string
	LastSeen time.Time
	Active   bool
}

// NewCLSetStore creates a new CLSet-backed store.
// Currently uses an in-memory implementation with sync stub.
// When CLSet library is available, this will use actual CRDT operations.
func NewCLSetStore(cfg CLSetConfig) (*CLSetStore, error) {
	if cfg.PeerID == "" {
		return nil, fmt.Errorf("peer ID required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	// Apply defaults
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 5 * time.Second
	}
	if cfg.PeerTTL == 0 {
		cfg.PeerTTL = 30 * time.Second
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "nexus"
	}

	store := &CLSetStore{
		config:   cfg,
		logger:   logger,
		data:     make(map[string][]byte),
		watchers: make(map[string][]WatchCallback),
		peers:    make(map[string]peerInfo),
		stopSync: make(chan struct{}),
	}

	// Register self as a peer
	store.peers[cfg.PeerID] = peerInfo{
		ID:       cfg.PeerID,
		LastSeen: time.Now(),
		Active:   true,
	}

	// Start sync goroutine
	go store.syncLoop()

	logger.Info("CLSet store initialized",
		zap.String("peer_id", cfg.PeerID),
		zap.String("namespace", cfg.Namespace),
		zap.Int("bootstrap_peers", len(cfg.BootstrapPeers)),
	)

	return store, nil
}

// Get retrieves a value by key.
func (c *CLSetStore) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, fmt.Errorf("store closed")
	}

	fullKey := c.namespaceKey(key)
	if data, ok := c.data[fullKey]; ok {
		return data, nil
	}
	return nil, ErrNotFound
}

// Put stores a value at the given key.
func (c *CLSetStore) Put(ctx context.Context, key string, value []byte) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("store closed")
	}

	fullKey := c.namespaceKey(key)
	isUpdate := c.data[fullKey] != nil
	c.data[fullKey] = value
	c.mu.Unlock()

	// Trigger hooks for CLSet sync
	if isUpdate && c.onUpdate != nil {
		c.onUpdate(fullKey, value)
	} else if c.onInsert != nil {
		c.onInsert(fullKey, value)
	}

	// Notify local watchers
	c.notifyWatchers(key, value, false)

	return nil
}

// Delete removes a value at the given key.
func (c *CLSetStore) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("store closed")
	}

	fullKey := c.namespaceKey(key)
	delete(c.data, fullKey)
	c.mu.Unlock()

	// Trigger hook for CLSet sync
	if c.onDelete != nil {
		c.onDelete(fullKey)
	}

	// Notify local watchers
	c.notifyWatchers(key, nil, true)

	return nil
}

// Query returns all key-value pairs matching the prefix.
func (c *CLSetStore) Query(ctx context.Context, prefix string) ([]KeyValue, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, fmt.Errorf("store closed")
	}

	fullPrefix := c.namespaceKey(prefix)
	var results []KeyValue
	for key, value := range c.data {
		if strings.HasPrefix(key, fullPrefix) {
			// Return key without namespace prefix
			userKey := c.stripNamespace(key)
			results = append(results, KeyValue{Key: userKey, Value: value})
		}
	}
	return results, nil
}

// Watch registers a callback for changes matching the prefix.
func (c *CLSetStore) Watch(prefix string, callback WatchCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.watchers[prefix] = append(c.watchers[prefix], callback)
}

// Close shuts down the store.
func (c *CLSetStore) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.stopSync)

	c.logger.Info("CLSet store closed")
	return nil
}

// namespaceKey adds the namespace prefix to a key.
func (c *CLSetStore) namespaceKey(key string) string {
	return c.config.Namespace + "/" + key
}

// stripNamespace removes the namespace prefix from a key.
func (c *CLSetStore) stripNamespace(key string) string {
	prefix := c.config.Namespace + "/"
	if strings.HasPrefix(key, prefix) {
		return key[len(prefix):]
	}
	return key
}

// notifyWatchers calls all matching watchers.
func (c *CLSetStore) notifyWatchers(key string, value []byte, deleted bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for prefix, callbacks := range c.watchers {
		if strings.HasPrefix(key, prefix) {
			for _, cb := range callbacks {
				go cb(key, value, deleted)
			}
		}
	}
}

// syncLoop periodically syncs with peers.
func (c *CLSetStore) syncLoop() {
	ticker := time.NewTicker(c.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.syncWithPeers()
			c.pruneInactivePeers()
		case <-c.stopSync:
			return
		}
	}
}

// syncWithPeers syncs state with cluster peers.
// This is a stub that will be replaced with actual CLSet P2P sync.
func (c *CLSetStore) syncWithPeers() {
	// TODO: Implement actual CLSet P2P sync when library is available
	// For now, this is a no-op placeholder
	//
	// When CLSet is integrated:
	// 1. Get delta from CLSet CRDT
	// 2. Push delta to connected peers via libp2p gossip
	// 3. Receive and merge deltas from peers
	// 4. Apply merged state to local store
}

// pruneInactivePeers removes peers that haven't been seen recently.
func (c *CLSetStore) pruneInactivePeers() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for id, peer := range c.peers {
		if id == c.config.PeerID {
			// Don't prune self
			continue
		}
		if now.Sub(peer.LastSeen) > c.config.PeerTTL {
			peer.Active = false
			c.peers[id] = peer
			c.logger.Debug("Peer marked inactive",
				zap.String("peer_id", id),
				zap.Duration("last_seen_ago", now.Sub(peer.LastSeen)),
			)
		}
	}
}

// GetPeers returns the current cluster peers.
func (c *CLSetStore) GetPeers() []peerInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	peers := make([]peerInfo, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p)
	}
	return peers
}

// GetActivePeers returns only active cluster peers.
func (c *CLSetStore) GetActivePeers() []peerInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	peers := make([]peerInfo, 0, len(c.peers))
	for _, p := range c.peers {
		if p.Active {
			peers = append(peers, p)
		}
	}
	return peers
}

// PeerCount returns the number of known peers.
func (c *CLSetStore) PeerCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.peers)
}

// ActivePeerCount returns the number of active peers.
func (c *CLSetStore) ActivePeerCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, p := range c.peers {
		if p.Active {
			count++
		}
	}
	return count
}

// SetInsertHook sets a callback for insert operations (for CLSet integration).
func (c *CLSetStore) SetInsertHook(hook func(key string, value []byte)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onInsert = hook
}

// SetUpdateHook sets a callback for update operations (for CLSet integration).
func (c *CLSetStore) SetUpdateHook(hook func(key string, value []byte)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onUpdate = hook
}

// SetDeleteHook sets a callback for delete operations (for CLSet integration).
func (c *CLSetStore) SetDeleteHook(hook func(key string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onDelete = hook
}

// ApplyRemoteChange applies a change received from a remote peer.
// This is called by the CLSet sync mechanism when changes are received.
func (c *CLSetStore) ApplyRemoteChange(key string, value []byte, deleted bool) {
	c.mu.Lock()
	if deleted {
		delete(c.data, key)
	} else {
		c.data[key] = value
	}
	c.mu.Unlock()

	// Notify watchers about remote change
	userKey := c.stripNamespace(key)
	c.notifyWatchers(userKey, value, deleted)

	c.logger.Debug("Applied remote change",
		zap.String("key", key),
		zap.Bool("deleted", deleted),
	)
}

// RegisterPeer registers a new peer in the cluster.
func (c *CLSetStore) RegisterPeer(id, addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.peers[id] = peerInfo{
		ID:       id,
		Addr:     addr,
		LastSeen: time.Now(),
		Active:   true,
	}

	c.logger.Info("Peer registered",
		zap.String("peer_id", id),
		zap.String("addr", addr),
	)
}

// UpdatePeerHeartbeat updates the last seen time for a peer.
func (c *CLSetStore) UpdatePeerHeartbeat(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if peer, exists := c.peers[id]; exists {
		peer.LastSeen = time.Now()
		peer.Active = true
		c.peers[id] = peer
	}
}

// StoreBackend identifies the store backend type.
type StoreBackend string

const (
	// BackendMemory uses in-memory storage (development/testing).
	BackendMemory StoreBackend = "memory"

	// BackendCLSet uses CLSet CRDT for distributed storage.
	BackendCLSet StoreBackend = "clset"
)

// StoreConfig configures the store backend.
type StoreConfig struct {
	Backend StoreBackend
	CLSet   CLSetConfig
}

// NewStore creates a Store based on configuration.
func NewStore(cfg StoreConfig) (Store, error) {
	switch cfg.Backend {
	case BackendMemory, "":
		return NewMemoryStore(), nil
	case BackendCLSet:
		return NewCLSetStore(cfg.CLSet)
	default:
		return nil, fmt.Errorf("unknown store backend: %s", cfg.Backend)
	}
}
