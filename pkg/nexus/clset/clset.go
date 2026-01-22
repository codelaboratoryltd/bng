//go:build clset

// Package clset provides stub types for the CLSet CRDT library.
// This file is only compiled when the clset build tag is set.
// The actual implementation is in the external example.com/clset module.
package clset

import (
	"context"

	ds "github.com/ipfs/go-datastore"
	dsquery "github.com/ipfs/go-datastore/query"
	"github.com/libp2p/go-libp2p/core/host"
)

// CRDTKeyMeta contains metadata for a CRDT key.
type CRDTKeyMeta struct {
	Timestamp uint64
}

// PeerMetadata contains metadata about a peer.
type PeerMetadata struct {
	BestBefore uint64
	Metadata   map[string]string
}

// Option is a functional option for CRDT configuration.
type Option func(*CRDT)

// PeerOption is a functional option for Peer configuration.
type PeerOption func(*Peer)

// CRDT is the CLSet CRDT implementation.
type CRDT struct{}

// New creates a new CRDT instance.
func New(nodeID string, datastore ds.Batching, opts ...Option) *CRDT {
	return &CRDT{}
}

// WithInsertHook sets a callback for inserts.
func WithInsertHook(fn func(key string, val []byte, meta CRDTKeyMeta)) Option {
	return func(c *CRDT) {}
}

// WithUpdateHook sets a callback for updates.
func WithUpdateHook(fn func(key string, oldVal []byte, oldMeta CRDTKeyMeta, newVal []byte, newMeta CRDTKeyMeta)) Option {
	return func(c *CRDT) {}
}

// WithDeleteHook sets a callback for deletes.
func WithDeleteHook(fn func(key string, oldVal []byte, oldMeta CRDTKeyMeta)) Option {
	return func(c *CRDT) {}
}

// WithMembershipHook sets a callback for membership updates.
func WithMembershipHook(fn func(members map[string]*PeerMetadata)) Option {
	return func(c *CRDT) {}
}

// WithPeerTTL sets the peer TTL.
func WithPeerTTL(ttl interface{}) Option {
	return func(c *CRDT) {}
}

// Get retrieves a value by key.
func (c *CRDT) Get(key string) ([]byte, bool, error) {
	return nil, false, nil
}

// Set stores a value at the given key.
func (c *CRDT) Set(key string, value []byte) error {
	return nil
}

// Delete removes a value at the given key.
func (c *CRDT) Delete(key string) error {
	return nil
}

// Query returns all matching keys.
func (c *CRDT) Query(ctx context.Context, q dsquery.Query) (dsquery.Results, error) {
	return nil, nil
}

// UpdateMeta updates the node metadata.
func (c *CRDT) UpdateMeta(ctx context.Context, meta map[string]string) error {
	return nil
}

// AddSelfToPeerMetadata adds this node to peer metadata.
func (c *CRDT) AddSelfToPeerMetadata() {}

// Peer handles P2P synchronization.
type Peer struct{}

// NewPeer creates a new Peer instance.
func NewPeer(crdt *CRDT, ctx context.Context, h host.Host, opts ...PeerOption) (*Peer, error) {
	return &Peer{}, nil
}

// WithPeriodicSyncInterval sets the periodic sync interval.
func WithPeriodicSyncInterval(interval interface{}) PeerOption {
	return func(p *Peer) {}
}

// WithScheduledSyncInterval sets the scheduled sync interval.
func WithScheduledSyncInterval(interval interface{}) PeerOption {
	return func(p *Peer) {}
}

// ManualConnect connects to a peer.
func (p *Peer) ManualConnect(addr string) error {
	return nil
}

// Close shuts down the peer.
func (p *Peer) Close() error {
	return nil
}
