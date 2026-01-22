package nexus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	clset "example.com/clset"
	ds "github.com/ipfs/go-datastore"
	dsquery "github.com/ipfs/go-datastore/query"
	badgerds "github.com/ipfs/go-ds-badger4"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/multiformats/go-multiaddr"
)

const (
	// DefaultPeerTTL is how long a peer is considered active without updates.
	DefaultPeerTTL = 30 * time.Second

	// DefaultPeriodicSyncInterval is how often to sync with all peers.
	DefaultPeriodicSyncInterval = 5 * time.Second

	// DefaultScheduledSyncInterval is how often to check for sync candidates.
	DefaultScheduledSyncInterval = 5 * time.Second
)

// clsetBackendImpl implements crdtBackend using CLSet + libp2p.
type clsetBackendImpl struct {
	config CLSetConfig

	// libp2p host
	host host.Host

	// Datastore (Badger-backed)
	datastore ds.Batching

	// CLSet CRDT
	crdt *clset.CRDT

	// P2P sync peer
	p2pSync *clset.Peer

	// Membership tracking (from CLSet gossip)
	membersMu sync.RWMutex
	members   map[string]*ClusterMember

	// Watchers for key changes
	watchersMu sync.RWMutex
	watchers   map[string][]func(key string, value []byte, deleted bool)

	ctx    context.Context
	cancel context.CancelFunc
}

// newCRDTBackend creates a CLSet backend using libp2p gossip.
func newCRDTBackend(config CLSetConfig) (crdtBackend, error) {
	ctx, cancel := context.WithCancel(context.Background())

	impl := &clsetBackendImpl{
		config:   config,
		members:  make(map[string]*ClusterMember),
		watchers: make(map[string][]func(key string, value []byte, deleted bool)),
		ctx:      ctx,
		cancel:   cancel,
	}

	var err error

	// 1. Create or load private key
	privKey, err := impl.getOrCreatePrivateKey()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("get private key: %w", err)
	}

	// 2. Create datastore (Badger-backed)
	impl.datastore, err = impl.createDatastore()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create datastore: %w", err)
	}

	// 3. Create libp2p host
	impl.host, err = impl.createHost(privKey)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}

	// 4. Create CLSet CRDT with hooks
	impl.crdt = clset.New(
		impl.host.ID().String(),
		impl.datastore,
		clset.WithInsertHook(func(key string, val []byte, meta clset.CRDTKeyMeta) {
			impl.notifyWatchers(key, val, false)
		}),
		clset.WithUpdateHook(func(key string, oldVal []byte, oldMeta clset.CRDTKeyMeta, newVal []byte, newMeta clset.CRDTKeyMeta) {
			impl.notifyWatchers(key, newVal, false)
		}),
		clset.WithDeleteHook(func(key string, oldVal []byte, oldMeta clset.CRDTKeyMeta) {
			impl.notifyWatchers(key, nil, true)
		}),
		clset.WithMembershipHook(impl.handleMembershipUpdate),
		clset.WithPeerTTL(DefaultPeerTTL),
	)

	// 5. Set node metadata
	if err := impl.crdt.UpdateMeta(ctx, map[string]string{
		"name": config.NodeName,
		"role": string(config.Mode),
	}); err != nil {
		cancel()
		return nil, fmt.Errorf("set metadata: %w", err)
	}

	// Ensure local peer appears in membership immediately
	impl.crdt.AddSelfToPeerMetadata()

	// 6. Create P2P sync peer
	impl.p2pSync, err = clset.NewPeer(
		impl.crdt,
		ctx,
		impl.host,
		clset.WithPeriodicSyncInterval(DefaultPeriodicSyncInterval),
		clset.WithScheduledSyncInterval(DefaultScheduledSyncInterval),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create P2P sync: %w", err)
	}

	// 7. Bootstrap to peers
	impl.bootstrapPeers()

	return impl, nil
}

// getOrCreatePrivateKey generates or loads a private key.
func (c *clsetBackendImpl) getOrCreatePrivateKey() (crypto.PrivKey, error) {
	// TODO: Load from config.DataDir if persistence is enabled
	// For now, generate a new key each time
	privKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	return privKey, nil
}

// createDatastore creates the Badger-backed datastore.
func (c *clsetBackendImpl) createDatastore() (ds.Batching, error) {
	if c.config.DataDir == "" {
		// In-memory datastore using MapDatastore
		return ds.NewMapDatastore(), nil
	}

	// Persistent Badger datastore
	opts := badgerds.DefaultOptions
	return badgerds.NewDatastore(c.config.DataDir, &opts)
}

// createHost creates a libp2p host.
func (c *clsetBackendImpl) createHost(privKey crypto.PrivKey) (host.Host, error) {
	listenAddr := c.config.ListenAddr
	if listenAddr == "" {
		listenAddr = "/ip4/0.0.0.0/tcp/0" // Random port
	}

	listen, err := multiaddr.NewMultiaddr(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("parse listen addr: %w", err)
	}

	return libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrs(listen),
	)
}

// bootstrapPeers connects to bootstrap peers.
func (c *clsetBackendImpl) bootstrapPeers() {
	for _, addr := range c.config.BootstrapPeers {
		if err := c.p2pSync.ManualConnect(addr); err != nil {
			// Log warning but continue - peer might not be available yet
			fmt.Printf("Warning: failed to connect to bootstrap peer %s: %v\n", addr, err)
		}
	}
}

// handleMembershipUpdate processes membership changes from CLSet.
func (c *clsetBackendImpl) handleMembershipUpdate(members map[string]*clset.PeerMetadata) {
	c.membersMu.Lock()
	defer c.membersMu.Unlock()

	// Update members map
	newMembers := make(map[string]*ClusterMember)
	for id, peerMeta := range members {
		newMembers[id] = &ClusterMember{
			NodeID:     id,
			BestBefore: time.Unix(int64(peerMeta.BestBefore), 0),
			Role:       peerMeta.Metadata["role"],
			Metadata:   peerMeta.Metadata,
		}
	}
	c.members = newMembers
}

// notifyWatchers notifies all matching watchers of a change.
func (c *clsetBackendImpl) notifyWatchers(key string, value []byte, deleted bool) {
	c.watchersMu.RLock()
	defer c.watchersMu.RUnlock()

	for prefix, callbacks := range c.watchers {
		if strings.HasPrefix(key, prefix) {
			for _, cb := range callbacks {
				go cb(key, value, deleted)
			}
		}
	}
}

// --- crdtBackend interface implementation ---

func (c *clsetBackendImpl) Get(ctx context.Context, key string) ([]byte, error) {
	data, exists, err := c.crdt.Get(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	return data, nil
}

func (c *clsetBackendImpl) Put(ctx context.Context, key string, value []byte) error {
	return c.crdt.Set(key, value)
}

func (c *clsetBackendImpl) Delete(ctx context.Context, key string) error {
	return c.crdt.Delete(key)
}

func (c *clsetBackendImpl) Query(ctx context.Context, prefix string) ([]KeyValue, error) {
	// Use CLSet's Query method which handles namespace and prefix internally
	results, err := c.crdt.Query(ctx, dsquery.Query{Prefix: "/" + prefix})
	if err != nil {
		return nil, err
	}
	defer results.Close()

	var kvs []KeyValue
	for result := range results.Next() {
		if result.Error != nil {
			return nil, result.Error
		}

		// Strip leading slash from key
		key := strings.TrimPrefix(result.Key, "/")

		// Decode the entry to check if it's not deleted
		// CLSet Query returns raw encoded entries, use Get to verify existence
		val, exists, err := c.crdt.Get(key)
		if err != nil || !exists {
			continue
		}

		kvs = append(kvs, KeyValue{
			Key:   key,
			Value: val,
		})
	}

	return kvs, nil
}

func (c *clsetBackendImpl) Subscribe(prefix string, callback func(key string, value []byte, deleted bool)) {
	c.watchersMu.Lock()
	defer c.watchersMu.Unlock()
	c.watchers[prefix] = append(c.watchers[prefix], callback)
}

func (c *clsetBackendImpl) Members() []ClusterMember {
	c.membersMu.RLock()
	defer c.membersMu.RUnlock()

	members := make([]ClusterMember, 0, len(c.members))
	for _, m := range c.members {
		members = append(members, *m)
	}
	return members
}

func (c *clsetBackendImpl) Close() error {
	c.cancel()

	if c.p2pSync != nil {
		if err := c.p2pSync.Close(); err != nil {
			fmt.Printf("Warning: P2P sync close: %v\n", err)
		}
	}

	if c.host != nil {
		if err := c.host.Close(); err != nil {
			fmt.Printf("Warning: Host close: %v\n", err)
		}
	}

	if c.datastore != nil {
		if err := c.datastore.Close(); err != nil {
			fmt.Printf("Warning: Datastore close: %v\n", err)
		}
	}

	return nil
}
