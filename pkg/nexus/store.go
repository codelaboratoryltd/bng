package nexus

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Store is the interface for a CRDT-backed distributed key-value store.
// This abstracts over CLSet or any other CRDT implementation.
type Store interface {
	// Get retrieves a value by key.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put stores a value at the given key.
	Put(ctx context.Context, key string, value []byte) error

	// Delete removes a value at the given key.
	Delete(ctx context.Context, key string) error

	// Query returns all key-value pairs matching the prefix.
	Query(ctx context.Context, prefix string) ([]KeyValue, error)

	// Watch registers a callback for changes matching the prefix.
	Watch(prefix string, callback WatchCallback)

	// Close shuts down the store.
	Close() error
}

// KeyValue represents a key-value pair from a query.
type KeyValue struct {
	Key   string
	Value []byte
}

// WatchCallback is called when a watched key changes.
type WatchCallback func(key string, value []byte, deleted bool)

// MemoryStore is an in-memory implementation of Store for development/testing.
type MemoryStore struct {
	mu       sync.RWMutex
	data     map[string][]byte
	watchers map[string][]WatchCallback
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data:     make(map[string][]byte),
		watchers: make(map[string][]WatchCallback),
	}
}

// Get retrieves a value by key.
func (m *MemoryStore) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if data, ok := m.data[key]; ok {
		return data, nil
	}
	return nil, ErrNotFound
}

// Put stores a value at the given key.
func (m *MemoryStore) Put(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	m.data[key] = value
	m.mu.Unlock()

	m.notifyWatchers(key, value, false)
	return nil
}

// Delete removes a value at the given key.
func (m *MemoryStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	delete(m.data, key)
	m.mu.Unlock()

	m.notifyWatchers(key, nil, true)
	return nil
}

// Query returns all key-value pairs matching the prefix.
func (m *MemoryStore) Query(ctx context.Context, prefix string) ([]KeyValue, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []KeyValue
	for key, value := range m.data {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			results = append(results, KeyValue{Key: key, Value: value})
		}
	}
	return results, nil
}

// Watch registers a callback for changes matching the prefix.
func (m *MemoryStore) Watch(prefix string, callback WatchCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.watchers[prefix] = append(m.watchers[prefix], callback)
}

// Close shuts down the store.
func (m *MemoryStore) Close() error {
	return nil
}

// notifyWatchers calls all matching watchers.
func (m *MemoryStore) notifyWatchers(key string, value []byte, deleted bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for prefix, callbacks := range m.watchers {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			for _, cb := range callbacks {
				go cb(key, value, deleted)
			}
		}
	}
}

// TypedStore provides type-safe operations on a Store.
type TypedStore[T any] struct {
	store  Store
	prefix string
}

// NewTypedStore creates a new typed store with the given prefix.
func NewTypedStore[T any](store Store, prefix string) *TypedStore[T] {
	return &TypedStore[T]{
		store:  store,
		prefix: prefix,
	}
}

// key returns the full key for an ID.
func (t *TypedStore[T]) key(id string) string {
	return t.prefix + "/" + id
}

// Get retrieves an item by ID.
func (t *TypedStore[T]) Get(ctx context.Context, id string) (*T, error) {
	data, err := t.store.Get(ctx, t.key(id))
	if err != nil {
		return nil, err
	}

	var item T
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &item, nil
}

// Put stores an item by ID.
func (t *TypedStore[T]) Put(ctx context.Context, id string, item *T) error {
	data, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return t.store.Put(ctx, t.key(id), data)
}

// Delete removes an item by ID.
func (t *TypedStore[T]) Delete(ctx context.Context, id string) error {
	return t.store.Delete(ctx, t.key(id))
}

// List returns all items.
func (t *TypedStore[T]) List(ctx context.Context) ([]*T, error) {
	results, err := t.store.Query(ctx, t.prefix+"/")
	if err != nil {
		return nil, err
	}

	items := make([]*T, 0, len(results))
	for _, kv := range results {
		var item T
		if err := json.Unmarshal(kv.Value, &item); err != nil {
			continue // Skip malformed entries
		}
		items = append(items, &item)
	}
	return items, nil
}

// Watch registers a callback for changes.
func (t *TypedStore[T]) Watch(callback func(id string, item *T, deleted bool)) {
	t.store.Watch(t.prefix+"/", func(key string, value []byte, deleted bool) {
		id := key[len(t.prefix)+1:]
		if deleted {
			callback(id, nil, true)
			return
		}

		var item T
		if err := json.Unmarshal(value, &item); err != nil {
			return
		}
		callback(id, &item, false)
	})
}

// Subscriber represents a subscriber in the system.
type Subscriber struct {
	ID string `json:"id"`

	// Physical layer (NetCo) - stable
	NTEID    string `json:"nte_id"`
	DeviceID string `json:"device_id"`
	STag     uint16 `json:"s_tag"`
	CTag     uint16 `json:"c_tag"`
	NetCoID  string `json:"netco_id"`

	// Service layer (ISPCo) - can change
	ISPID       string `json:"isp_id"`
	RADIUSRealm string `json:"radius_realm"`

	// IP allocation
	IPv4Pool string `json:"ipv4_pool,omitempty"`
	IPv4Addr string `json:"ipv4_addr,omitempty"`
	IPv6Pool string `json:"ipv6_pool,omitempty"`
	IPv6Addr string `json:"ipv6_addr,omitempty"`

	// State
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NTE represents a Network Termination Equipment (ONU/ONT).
type NTE struct {
	ID           string `json:"id"`
	DeviceID     string `json:"device_id"`
	SerialNumber string `json:"serial_number"`
	PONPort      string `json:"pon_port"`

	// Assigned VLANs
	STag uint16 `json:"s_tag"`
	CTag uint16 `json:"c_tag"`

	// State
	State       string    `json:"state"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Provisioned bool      `json:"provisioned"`
}

// ISPConfig represents ISP-specific configuration.
type ISPConfig struct {
	ID string `json:"id"`

	// RADIUS configuration
	RADIUSServers []string `json:"radius_servers"`
	RADIUSSecret  string   `json:"radius_secret"`
	RADIUSRealm   string   `json:"radius_realm"`

	// IP pools assigned to this ISP
	IPv4Pools []string `json:"ipv4_pools"`
	IPv6Pools []string `json:"ipv6_pools"`

	// Default gateway configuration
	DefaultGateway string   `json:"default_gateway,omitempty"`
	DNSServers     []string `json:"dns_servers,omitempty"`
}

// IPPool represents an IP address pool.
type IPPool struct {
	ID     string    `json:"id"`
	CIDR   string    `json:"cidr"`
	ISPID  string    `json:"isp_id,omitempty"`
	Type   string    `json:"type"` // "residential", "business", "infrastructure"
	UsedAt time.Time `json:"used_at,omitempty"`
}

// Device represents an OLT device.
type Device struct {
	ID           string    `json:"id"`
	SerialNumber string    `json:"serial_number"`
	Model        string    `json:"model"`
	Firmware     string    `json:"firmware"`
	MAC          string    `json:"mac"`
	State        string    `json:"state"`
	LastSeen     time.Time `json:"last_seen"`
	Capabilities []string  `json:"capabilities"`
}
