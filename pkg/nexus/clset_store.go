package nexus

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// StoreMode determines how the store participates in the cluster.
type StoreMode string

const (
	// StoreModeMemory is a local-only in-memory store (dev/testing).
	StoreModeMemory StoreMode = "memory"

	// StoreModeAuthoritative joins the CLSet hashring as a full participant.
	// Can read/write locally, changes sync via CRDT gossip.
	// Use for: OLT-BNG with partition resilience requirements.
	StoreModeAuthoritative StoreMode = "authoritative"

	// StoreModeReplica caches locally but proxies writes to central nexus.
	// Can read from cache, writes go to remote.
	// Use for: WiFi gateways, simpler deployments.
	StoreModeReplica StoreMode = "replica"
)

// CLSetConfig configures the distributed store.
type CLSetConfig struct {
	// Mode determines participation level
	Mode StoreMode

	// NodeID is this node's unique identifier in the cluster
	NodeID string

	// --- Authoritative mode settings ---

	// ListenAddr is the libp2p listen address (e.g., "/ip4/0.0.0.0/tcp/9000")
	ListenAddr string

	// BootstrapPeers are initial peers to connect to
	BootstrapPeers []string

	// DataDir is where to persist CRDT state (empty = in-memory)
	DataDir string

	// SyncInterval is how often to sync with peers
	SyncInterval time.Duration

	// --- Replica mode settings ---

	// NexusURL is the central nexus server URL (for replica mode)
	NexusURL string

	// CacheTTL is how long to cache reads before refreshing
	CacheTTL time.Duration
}

// DefaultCLSetConfig returns sensible defaults.
func DefaultCLSetConfig() CLSetConfig {
	return CLSetConfig{
		Mode:         StoreModeMemory,
		SyncInterval: 5 * time.Second,
		CacheTTL:     30 * time.Second,
	}
}

// CLSetStore implements Store with distributed state support.
// Supports three modes: memory (local), authoritative (hashring), replica (client).
type CLSetStore struct {
	config CLSetConfig
	mode   StoreMode

	// Local cache (used by all modes)
	mu    sync.RWMutex
	cache map[string]cacheEntry

	// Watchers
	watchersMu sync.RWMutex
	watchers   map[string][]WatchCallback

	// Mode-specific backends
	authoritative authoritativeBackend // For authoritative mode
	replica       replicaBackend       // For replica mode

	ctx    context.Context
	cancel context.CancelFunc
}

type cacheEntry struct {
	value     []byte
	expiresAt time.Time
}

// authoritativeBackend is the interface for CLSet hashring participation.
// This will be implemented by wrapping go-ds-crdt.
type authoritativeBackend interface {
	// Get retrieves from local CRDT state
	Get(ctx context.Context, key string) ([]byte, error)

	// Put writes to local CRDT (syncs to peers via gossip)
	Put(ctx context.Context, key string, value []byte) error

	// Delete removes from local CRDT
	Delete(ctx context.Context, key string) error

	// Query returns all matching keys from local CRDT
	Query(ctx context.Context, prefix string) ([]KeyValue, error)

	// Subscribe registers for CRDT change notifications
	Subscribe(prefix string, callback func(key string, value []byte, deleted bool))

	// Members returns current cluster members
	Members() []ClusterMember

	// Close shuts down the CRDT node
	Close() error
}

// replicaBackend is the interface for proxying to central nexus.
type replicaBackend interface {
	// Get fetches from remote nexus
	Get(ctx context.Context, key string) ([]byte, error)

	// Put writes to remote nexus
	Put(ctx context.Context, key string, value []byte) error

	// Delete removes from remote nexus
	Delete(ctx context.Context, key string) error

	// Query fetches matching keys from remote nexus
	Query(ctx context.Context, prefix string) ([]KeyValue, error)

	// Subscribe opens a watch stream to remote nexus
	Subscribe(prefix string, callback func(key string, value []byte, deleted bool)) error

	// Close shuts down the connection
	Close() error
}

// ClusterMember represents a node in the CLSet cluster.
type ClusterMember struct {
	NodeID   string
	Addr     string
	LastSeen time.Time
	IsLeader bool     // For pools this node is authoritative for
	Pools    []string // Pool IDs this node is authoritative for
	Metadata map[string]string
}

// NewCLSetStore creates a new distributed store.
func NewCLSetStore(config CLSetConfig) (*CLSetStore, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := &CLSetStore{
		config:   config,
		mode:     config.Mode,
		cache:    make(map[string]cacheEntry),
		watchers: make(map[string][]WatchCallback),
		ctx:      ctx,
		cancel:   cancel,
	}

	switch config.Mode {
	case StoreModeMemory:
		// No backend needed, just use cache

	case StoreModeAuthoritative:
		backend, err := newAuthoritativeBackend(config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("create authoritative backend: %w", err)
		}
		s.authoritative = backend

	case StoreModeReplica:
		backend, err := newReplicaBackend(config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("create replica backend: %w", err)
		}
		s.replica = backend

	default:
		cancel()
		return nil, fmt.Errorf("unknown store mode: %s", config.Mode)
	}

	return s, nil
}

// Get retrieves a value by key.
func (s *CLSetStore) Get(ctx context.Context, key string) ([]byte, error) {
	// Check cache first (for replica mode, respects TTL)
	if s.mode == StoreModeReplica {
		if entry, ok := s.getCached(key); ok {
			return entry, nil
		}
	}

	switch s.mode {
	case StoreModeMemory:
		s.mu.RLock()
		entry, ok := s.cache[key]
		s.mu.RUnlock()
		if !ok {
			return nil, ErrNotFound
		}
		return entry.value, nil

	case StoreModeAuthoritative:
		return s.authoritative.Get(ctx, key)

	case StoreModeReplica:
		value, err := s.replica.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		// Cache the result
		s.setCache(key, value)
		return value, nil
	}

	return nil, ErrNotFound
}

// Put stores a value at the given key.
func (s *CLSetStore) Put(ctx context.Context, key string, value []byte) error {
	switch s.mode {
	case StoreModeMemory:
		s.mu.Lock()
		s.cache[key] = cacheEntry{value: value}
		s.mu.Unlock()
		s.notifyWatchers(key, value, false)
		return nil

	case StoreModeAuthoritative:
		// Write to local CRDT, syncs via gossip
		if err := s.authoritative.Put(ctx, key, value); err != nil {
			return err
		}
		// Watchers notified via CRDT subscription
		return nil

	case StoreModeReplica:
		// Proxy to remote nexus
		if err := s.replica.Put(ctx, key, value); err != nil {
			return err
		}
		// Update local cache
		s.setCache(key, value)
		s.notifyWatchers(key, value, false)
		return nil
	}

	return fmt.Errorf("unknown mode")
}

// Delete removes a value at the given key.
func (s *CLSetStore) Delete(ctx context.Context, key string) error {
	switch s.mode {
	case StoreModeMemory:
		s.mu.Lock()
		delete(s.cache, key)
		s.mu.Unlock()
		s.notifyWatchers(key, nil, true)
		return nil

	case StoreModeAuthoritative:
		return s.authoritative.Delete(ctx, key)

	case StoreModeReplica:
		if err := s.replica.Delete(ctx, key); err != nil {
			return err
		}
		s.invalidateCache(key)
		s.notifyWatchers(key, nil, true)
		return nil
	}

	return fmt.Errorf("unknown mode")
}

// Query returns all key-value pairs matching the prefix.
func (s *CLSetStore) Query(ctx context.Context, prefix string) ([]KeyValue, error) {
	switch s.mode {
	case StoreModeMemory:
		s.mu.RLock()
		defer s.mu.RUnlock()
		var results []KeyValue
		for key, entry := range s.cache {
			if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
				results = append(results, KeyValue{Key: key, Value: entry.value})
			}
		}
		return results, nil

	case StoreModeAuthoritative:
		return s.authoritative.Query(ctx, prefix)

	case StoreModeReplica:
		return s.replica.Query(ctx, prefix)
	}

	return nil, fmt.Errorf("unknown mode")
}

// Watch registers a callback for changes matching the prefix.
func (s *CLSetStore) Watch(prefix string, callback WatchCallback) {
	s.watchersMu.Lock()
	s.watchers[prefix] = append(s.watchers[prefix], callback)
	s.watchersMu.Unlock()

	// For authoritative/replica modes, also subscribe to backend
	switch s.mode {
	case StoreModeAuthoritative:
		s.authoritative.Subscribe(prefix, callback)
	case StoreModeReplica:
		s.replica.Subscribe(prefix, callback)
	}
}

// Close shuts down the store.
func (s *CLSetStore) Close() error {
	s.cancel()

	switch s.mode {
	case StoreModeAuthoritative:
		if s.authoritative != nil {
			return s.authoritative.Close()
		}
	case StoreModeReplica:
		if s.replica != nil {
			return s.replica.Close()
		}
	}

	return nil
}

// Members returns current cluster members (authoritative mode only).
func (s *CLSetStore) Members() []ClusterMember {
	if s.mode == StoreModeAuthoritative && s.authoritative != nil {
		return s.authoritative.Members()
	}
	return nil
}

// Mode returns the current store mode.
func (s *CLSetStore) Mode() StoreMode {
	return s.mode
}

// --- Cache helpers ---

func (s *CLSetStore) getCached(key string) ([]byte, bool) {
	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()

	if !ok {
		return nil, false
	}

	// Check TTL
	if s.config.CacheTTL > 0 && time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.value, true
}

func (s *CLSetStore) setCache(key string, value []byte) {
	s.mu.Lock()
	s.cache[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(s.config.CacheTTL),
	}
	s.mu.Unlock()
}

func (s *CLSetStore) invalidateCache(key string) {
	s.mu.Lock()
	delete(s.cache, key)
	s.mu.Unlock()
}

func (s *CLSetStore) notifyWatchers(key string, value []byte, deleted bool) {
	s.watchersMu.RLock()
	defer s.watchersMu.RUnlock()

	for prefix, callbacks := range s.watchers {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			for _, cb := range callbacks {
				go cb(key, value, deleted)
			}
		}
	}
}

// --- Backend stubs (to be implemented) ---

func newAuthoritativeBackend(config CLSetConfig) (authoritativeBackend, error) {
	// TODO: Implement using go-ds-crdt + libp2p
	// This will:
	// 1. Create libp2p host with config.ListenAddr
	// 2. Connect to config.BootstrapPeers
	// 3. Create go-ds-crdt datastore with gossip pubsub
	// 4. Set up membership tracking
	return nil, fmt.Errorf("authoritative backend not yet implemented")
}

func newReplicaBackend(config CLSetConfig) (replicaBackend, error) {
	// TODO: Implement using gRPC client to nexus
	// This will:
	// 1. Connect to config.NexusURL
	// 2. Implement Get/Put/Delete/Query via gRPC
	// 3. Open Watch stream for subscriptions
	return nil, fmt.Errorf("replica backend not yet implemented")
}
