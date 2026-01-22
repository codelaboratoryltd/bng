package nexus

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// StoreMode determines how the store participates in the cluster.
// This mirrors the nexus role system: "read", "write", "core".
type StoreMode string

const (
	// StoreModeMemory is a local-only in-memory store (dev/testing).
	StoreModeMemory StoreMode = "memory"

	// StoreModeWrite joins CLSet gossip AND the hashring (nexus role="write").
	// - Joins libp2p gossip (receives/sends CRDT updates)
	// - Joins hashring (owns pool ranges, can allocate locally)
	// - Reads: local (from CRDT state)
	// - Writes: local (syncs via gossip)
	// - Partition behavior: full read/write capability
	//
	// REQUIRED for: Lease mode (WiFi) - must allocate new IPs during partitions.
	// RECOMMENDED for: OLT-BNG - partition resilience for allocation at RADIUS time.
	StoreModeWrite StoreMode = "write"

	// StoreModeRead joins CLSet gossip but NOT the hashring (nexus role="read").
	// - Joins libp2p gossip (receives CRDT updates in real-time)
	// - Does NOT join hashring (owns no pools)
	// - Reads: local (from CRDT state, always up-to-date via gossip)
	// - Writes: returns ErrReadOnlyNode (must proxy to write node)
	// - Partition behavior: reads work, writes fail
	//
	// SUFFICIENT for: Session mode (OLT-BNG) where renewals are read-only
	//                 and new sessions need RADIUS anyway.
	// NOT SUFFICIENT for: Lease mode (WiFi) - new devices need local allocation.
	StoreModeRead StoreMode = "read"
)

// ErrReadOnlyNode is returned when a write operation is attempted on a read-only node.
var ErrReadOnlyNode = fmt.Errorf("operation not allowed on read-only node")

// CLSetConfig configures the distributed store.
type CLSetConfig struct {
	// Mode determines participation level: "memory", "read", or "write"
	Mode StoreMode

	// NodeID is this node's unique identifier in the cluster
	NodeID string

	// NodeName identifies this node type (e.g., "BNG", "Nexus")
	// Used for filtering in membership updates
	NodeName string

	// Topic is the pubsub topic for CRDT sync
	Topic string

	// ListenAddr is the libp2p listen address (e.g., "/ip4/0.0.0.0/tcp/9000")
	ListenAddr string

	// BootstrapPeers are initial peers to connect to
	BootstrapPeers []string

	// DataDir is where to persist CRDT state (empty = in-memory badger)
	DataDir string

	// RebroadcastInterval is how often to rebroadcast CRDT state
	RebroadcastInterval time.Duration
}

// DefaultCLSetConfig returns sensible defaults.
func DefaultCLSetConfig() CLSetConfig {
	return CLSetConfig{
		Mode:                StoreModeMemory,
		NodeName:            "BNG",
		Topic:               "bng-state",
		RebroadcastInterval: 5 * time.Second,
	}
}

// CLSetStore implements Store with distributed state support.
// Supports three modes: memory (local), read (gossip, no hashring), write (gossip + hashring).
//
// Architecture matches nexus/internal/state:
// - All non-memory modes use libp2p gossip for CRDT sync
// - "read" nodes receive updates but return ErrReadOnlyNode on writes
// - "write" nodes join the hashring and can allocate locally
type CLSetStore struct {
	config CLSetConfig
	mode   StoreMode

	// Local cache (used by memory mode only)
	mu    sync.RWMutex
	cache map[string]cacheEntry

	// Watchers
	watchersMu sync.RWMutex
	watchers   map[string][]WatchCallback

	// CRDT backend (used by read and write modes)
	// Both modes use the same backend - the difference is:
	// - read: returns ErrReadOnlyNode on Put/Delete
	// - write: joins hashring, allows local writes
	crdt crdtBackend

	ctx    context.Context
	cancel context.CancelFunc
}

type cacheEntry struct {
	value     []byte
	expiresAt time.Time
}

// crdtBackend is the interface for CLSet/CRDT participation.
// Wraps go-ds-crdt with libp2p gossip, similar to nexus/internal/state.
type crdtBackend interface {
	// Get retrieves from local CRDT state (always local, synced via gossip)
	Get(ctx context.Context, key string) ([]byte, error)

	// Put writes to local CRDT (syncs to peers via gossip)
	// Only allowed on write nodes; read nodes should check mode first
	Put(ctx context.Context, key string, value []byte) error

	// Delete removes from local CRDT
	Delete(ctx context.Context, key string) error

	// Query returns all matching keys from local CRDT state
	Query(ctx context.Context, prefix string) ([]KeyValue, error)

	// Subscribe registers for CRDT change notifications (PutHook/DeleteHook)
	Subscribe(prefix string, callback func(key string, value []byte, deleted bool))

	// Members returns current cluster members from CRDT membership
	Members() []ClusterMember

	// Close performs graceful shutdown of the CRDT node
	Close() error
}

// ClusterMember represents a node in the CLSet cluster.
// Mirrors nexus/internal/store.NodeMember.
type ClusterMember struct {
	NodeID     string
	BestBefore time.Time         // When this node's membership expires
	Role       string            // "read" or "write"
	Metadata   map[string]string // Arbitrary metadata (name, version, etc.)
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

	case StoreModeRead, StoreModeWrite:
		// Both read and write modes use the same CRDT backend
		// The difference is enforced at the Store level (read returns ErrReadOnlyNode)
		backend, err := newCRDTBackend(config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("create CRDT backend: %w", err)
		}
		s.crdt = backend

	default:
		cancel()
		return nil, fmt.Errorf("unknown store mode: %s", config.Mode)
	}

	return s, nil
}

// Get retrieves a value by key.
func (s *CLSetStore) Get(ctx context.Context, key string) ([]byte, error) {
	switch s.mode {
	case StoreModeMemory:
		s.mu.RLock()
		entry, ok := s.cache[key]
		s.mu.RUnlock()
		if !ok {
			return nil, ErrNotFound
		}
		return entry.value, nil

	case StoreModeRead, StoreModeWrite:
		// Both modes read from local CRDT state (synced via gossip)
		return s.crdt.Get(ctx, key)
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

	case StoreModeRead:
		// Read-only nodes cannot write
		return ErrReadOnlyNode

	case StoreModeWrite:
		// Write to local CRDT, syncs via gossip
		if err := s.crdt.Put(ctx, key, value); err != nil {
			return err
		}
		// Watchers notified via CRDT PutHook
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

	case StoreModeRead:
		// Read-only nodes cannot delete
		return ErrReadOnlyNode

	case StoreModeWrite:
		// Delete from local CRDT, syncs via gossip
		return s.crdt.Delete(ctx, key)
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

	case StoreModeRead, StoreModeWrite:
		// Both modes read from local CRDT state
		return s.crdt.Query(ctx, prefix)
	}

	return nil, fmt.Errorf("unknown mode")
}

// Watch registers a callback for changes matching the prefix.
func (s *CLSetStore) Watch(prefix string, callback WatchCallback) {
	s.watchersMu.Lock()
	s.watchers[prefix] = append(s.watchers[prefix], callback)
	s.watchersMu.Unlock()

	// For CRDT modes, subscribe to backend (receives via PutHook/DeleteHook)
	switch s.mode {
	case StoreModeRead, StoreModeWrite:
		s.crdt.Subscribe(prefix, callback)
	}
}

// Close shuts down the store.
func (s *CLSetStore) Close() error {
	s.cancel()

	switch s.mode {
	case StoreModeRead, StoreModeWrite:
		if s.crdt != nil {
			return s.crdt.Close()
		}
	}

	return nil
}

// Members returns current cluster members.
func (s *CLSetStore) Members() []ClusterMember {
	if s.crdt != nil {
		return s.crdt.Members()
	}
	return nil
}

// IsWriteNode returns true if this node can perform writes.
func (s *CLSetStore) IsWriteNode() bool {
	return s.mode == StoreModeWrite
}

// Mode returns the current store mode.
func (s *CLSetStore) Mode() StoreMode {
	return s.mode
}

// notifyWatchers calls all matching watchers (used by memory mode).
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

// --- CRDT Backend (to be implemented) ---

// newCRDTBackend creates a CRDT backend using go-ds-crdt + libp2p.
// This mirrors the implementation in nexus/internal/state/state.go.
func newCRDTBackend(config CLSetConfig) (crdtBackend, error) {
	// TODO: Implement using go-ds-crdt + libp2p
	//
	// Implementation steps (see nexus/internal/state/state.go for reference):
	//
	// 1. Generate or load private key for libp2p identity
	//
	// 2. Create libp2p host:
	//    listen, _ := multiaddr.NewMultiaddr(config.ListenAddr)
	//    h, dht, _ := ipfslite.SetupLibp2p(ctx, privKey, nil, []multiaddr.Multiaddr{listen}, datastore, ...)
	//
	// 3. Create GossipSub pubsub:
	//    ps, _ := libpubsub.NewGossipSub(ctx, h)
	//
	// 4. Create CRDT broadcaster:
	//    pubsubBC, _ := crdt.NewPubSubBroadcaster(ctx, ps, config.Topic)
	//
	// 5. Create CRDT datastore with hooks:
	//    opts := crdt.DefaultOptions()
	//    opts.RebroadcastInterval = config.RebroadcastInterval
	//    opts.PutHook = func(k ds.Key, v []byte) { /* notify watchers */ }
	//    opts.DeleteHook = func(k ds.Key) { /* notify watchers */ }
	//    opts.MembershipHook = func(members map[string]*pb.Participant) { /* track members */ }
	//    crdtDatastore, _ := crdt.New(h, datastore, blockstore, namespace, dag, pubsubBC, opts)
	//
	// 6. Set node metadata:
	//    crdtDatastore.UpdateMeta(ctx, map[string]string{
	//        "name": config.NodeName,
	//        "role": string(config.Mode),  // "read" or "write"
	//    })
	//
	// 7. Bootstrap to peers:
	//    for _, addr := range config.BootstrapPeers { h.Connect(ctx, peerInfo) }
	//
	// Key difference from nexus:
	// - Nexus manages hashring internally for IP allocation
	// - BNG just needs the CRDT store, hashring is handled by DistributedAllocator
	//
	return nil, fmt.Errorf("CRDT backend not yet implemented - see nexus/internal/state/state.go for reference")
}
