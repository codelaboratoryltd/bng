package state

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Store is the central state store for the BNG.
type Store struct {
	config Config
	logger *zap.Logger

	mu sync.RWMutex

	// Primary storage
	subscribers map[string]*Subscriber // ID -> Subscriber
	leases      map[string]*Lease      // ID -> Lease
	pools       map[string]*Pool       // ID -> Pool
	sessions    map[string]*Session    // ID -> Session
	natBindings map[string]*NATBinding // ID -> NATBinding

	// Indexes for fast lookup
	subscriberByMAC map[string]string // MAC -> subscriber ID
	subscriberByNTE map[string]string // NTE ID -> subscriber ID
	leaseByIP       map[string]string // IP -> lease ID
	leaseByMAC      map[string]string // MAC -> lease ID
	sessionByMAC    map[string]string // MAC -> session ID
	sessionByIP     map[string]string // IP -> session ID
	natByPrivate    map[string]string // "ip:port:proto" -> binding ID
	natByPublic     map[string]string // "ip:port:proto" -> binding ID

	// Statistics
	stats StoreStats

	// Background tasks
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds state store configuration.
type Config struct {
	// Cleanup intervals
	LeaseCleanupInterval   time.Duration `json:"lease_cleanup_interval"`
	SessionCleanupInterval time.Duration `json:"session_cleanup_interval"`
	NATCleanupInterval     time.Duration `json:"nat_cleanup_interval"`

	// Capacity limits
	MaxSubscribers int `json:"max_subscribers"`
	MaxSessions    int `json:"max_sessions"`
	MaxLeases      int `json:"max_leases"`
	MaxNATBindings int `json:"max_nat_bindings"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		LeaseCleanupInterval:   1 * time.Minute,
		SessionCleanupInterval: 30 * time.Second,
		NATCleanupInterval:     10 * time.Second,
		MaxSubscribers:         100000,
		MaxSessions:            100000,
		MaxLeases:              100000,
		MaxNATBindings:         1000000,
	}
}

// NewStore creates a new state store.
func NewStore(config Config, logger *zap.Logger) *Store {
	ctx, cancel := context.WithCancel(context.Background())

	return &Store{
		config:          config,
		logger:          logger,
		subscribers:     make(map[string]*Subscriber),
		leases:          make(map[string]*Lease),
		pools:           make(map[string]*Pool),
		sessions:        make(map[string]*Session),
		natBindings:     make(map[string]*NATBinding),
		subscriberByMAC: make(map[string]string),
		subscriberByNTE: make(map[string]string),
		leaseByIP:       make(map[string]string),
		leaseByMAC:      make(map[string]string),
		sessionByMAC:    make(map[string]string),
		sessionByIP:     make(map[string]string),
		natByPrivate:    make(map[string]string),
		natByPublic:     make(map[string]string),
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Start starts the state store background tasks.
func (s *Store) Start() error {
	s.logger.Info("Starting state store")

	// Start lease cleanup
	s.wg.Add(1)
	go s.leaseCleanupLoop()

	// Start session cleanup
	s.wg.Add(1)
	go s.sessionCleanupLoop()

	// Start NAT cleanup
	s.wg.Add(1)
	go s.natCleanupLoop()

	s.logger.Info("State store started")
	return nil
}

// Stop stops the state store.
func (s *Store) Stop() error {
	s.logger.Info("Stopping state store")
	s.cancel()
	s.wg.Wait()
	s.logger.Info("State store stopped")
	return nil
}

// Stats returns store statistics.
func (s *Store) Stats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return StoreStats{
		Subscribers:    len(s.subscribers),
		ActiveSessions: len(s.sessions),
		Leases:         len(s.leases),
		Pools:          len(s.pools),
		NATBindings:    len(s.natBindings),
		Reads:          s.stats.Reads,
		Writes:         s.stats.Writes,
		Deletes:        s.stats.Deletes,
	}
}

// --- Subscriber Operations ---

// CreateSubscriber creates a new subscriber.
func (s *Store) CreateSubscriber(sub *Subscriber) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.subscribers) >= s.config.MaxSubscribers {
		return fmt.Errorf("max subscribers reached")
	}

	if sub.ID == "" {
		sub.ID = uuid.New().String()
	}
	sub.CreatedAt = time.Now()
	sub.UpdatedAt = sub.CreatedAt

	// Store a copy to prevent external modifications
	stored := *sub
	s.subscribers[sub.ID] = &stored

	// Index by MAC
	if sub.MAC != nil {
		s.subscriberByMAC[sub.MAC.String()] = sub.ID
	}

	// Index by NTE
	if sub.NTEID != "" {
		s.subscriberByNTE[sub.NTEID] = sub.ID
	}

	s.stats.Writes++
	return nil
}

// GetSubscriber retrieves a subscriber by ID.
func (s *Store) GetSubscriber(id string) (*Subscriber, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sub, exists := s.subscribers[id]
	if !exists {
		return nil, fmt.Errorf("subscriber not found: %s", id)
	}

	s.stats.Reads++
	return sub, nil
}

// GetSubscriberByMAC retrieves a subscriber by MAC address.
func (s *Store) GetSubscriberByMAC(mac net.HardwareAddr) (*Subscriber, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.subscriberByMAC[mac.String()]
	if !exists {
		return nil, fmt.Errorf("subscriber not found for MAC: %s", mac)
	}

	sub := s.subscribers[id]
	s.stats.Reads++
	return sub, nil
}

// GetSubscriberByNTE retrieves a subscriber by NTE ID.
func (s *Store) GetSubscriberByNTE(nteID string) (*Subscriber, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.subscriberByNTE[nteID]
	if !exists {
		return nil, fmt.Errorf("subscriber not found for NTE: %s", nteID)
	}

	sub := s.subscribers[id]
	s.stats.Reads++
	return sub, nil
}

// UpdateSubscriber updates a subscriber.
func (s *Store) UpdateSubscriber(sub *Subscriber) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.subscribers[sub.ID]
	if !exists {
		return fmt.Errorf("subscriber not found: %s", sub.ID)
	}

	// Update indexes if MAC changed
	if existing.MAC != nil && (sub.MAC == nil || existing.MAC.String() != sub.MAC.String()) {
		delete(s.subscriberByMAC, existing.MAC.String())
	}
	if sub.MAC != nil {
		s.subscriberByMAC[sub.MAC.String()] = sub.ID
	}

	// Update indexes if NTE changed
	if existing.NTEID != "" && existing.NTEID != sub.NTEID {
		delete(s.subscriberByNTE, existing.NTEID)
	}
	if sub.NTEID != "" {
		s.subscriberByNTE[sub.NTEID] = sub.ID
	}

	sub.UpdatedAt = time.Now()

	// Store a copy to prevent external modifications
	stored := *sub
	s.subscribers[sub.ID] = &stored
	s.stats.Writes++
	return nil
}

// DeleteSubscriber deletes a subscriber.
func (s *Store) DeleteSubscriber(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, exists := s.subscribers[id]
	if !exists {
		return fmt.Errorf("subscriber not found: %s", id)
	}

	// Remove from indexes
	if sub.MAC != nil {
		delete(s.subscriberByMAC, sub.MAC.String())
	}
	if sub.NTEID != "" {
		delete(s.subscriberByNTE, sub.NTEID)
	}

	delete(s.subscribers, id)
	s.stats.Deletes++
	return nil
}

// ListSubscribers returns all subscribers.
func (s *Store) ListSubscribers() []*Subscriber {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Subscriber, 0, len(s.subscribers))
	for _, sub := range s.subscribers {
		result = append(result, sub)
	}
	return result
}

// --- Pool Operations ---

// CreatePool creates a new IP pool.
func (s *Store) CreatePool(pool *Pool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pool.ID == "" {
		pool.ID = uuid.New().String()
	}
	pool.CreatedAt = time.Now()
	pool.UpdatedAt = pool.CreatedAt

	// Calculate total addresses
	pool.TotalAddresses = countAddresses(pool.StartIP, pool.EndIP)

	s.pools[pool.ID] = pool
	s.stats.Writes++
	return nil
}

// GetPool retrieves a pool by ID.
func (s *Store) GetPool(id string) (*Pool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pool, exists := s.pools[id]
	if !exists {
		return nil, fmt.Errorf("pool not found: %s", id)
	}

	s.stats.Reads++
	return pool, nil
}

// GetPoolByName retrieves a pool by name.
func (s *Store) GetPoolByName(name string) (*Pool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, pool := range s.pools {
		if pool.Name == name {
			s.stats.Reads++
			return pool, nil
		}
	}
	return nil, fmt.Errorf("pool not found: %s", name)
}

// ListPools returns all pools.
func (s *Store) ListPools() []*Pool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Pool, 0, len(s.pools))
	for _, pool := range s.pools {
		result = append(result, pool)
	}
	return result
}

// FindPoolForSubscriber finds a suitable pool for a subscriber.
func (s *Store) FindPoolForSubscriber(sub *Subscriber, version int) (*Pool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var bestPool *Pool
	bestPriority := -1

	for _, pool := range s.pools {
		if !pool.Enabled || pool.Version != version {
			continue
		}

		// Check capacity
		if pool.AllocatedAddresses >= pool.TotalAddresses-pool.ReservedAddresses {
			continue
		}

		// Check ISP match
		if len(pool.ISPIDs) > 0 {
			found := false
			for _, isp := range pool.ISPIDs {
				if isp == sub.ISPID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Check class match
		if len(pool.SubscriberClass) > 0 {
			found := false
			for _, class := range pool.SubscriberClass {
				if class == sub.Class {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Track best priority
		if pool.Priority > bestPriority {
			bestPool = pool
			bestPriority = pool.Priority
		}
	}

	if bestPool == nil {
		return nil, fmt.Errorf("no suitable pool found")
	}

	return bestPool, nil
}

// UpdatePool updates a pool.
func (s *Store) UpdatePool(pool *Pool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pools[pool.ID]; !exists {
		return fmt.Errorf("pool not found: %s", pool.ID)
	}

	pool.UpdatedAt = time.Now()
	s.pools[pool.ID] = pool
	s.stats.Writes++
	return nil
}

// DeletePool deletes a pool.
func (s *Store) DeletePool(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pools[id]; !exists {
		return fmt.Errorf("pool not found: %s", id)
	}

	delete(s.pools, id)
	s.stats.Deletes++
	return nil
}

// --- Lease Operations ---

// CreateLease creates a new lease.
func (s *Store) CreateLease(lease *Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.leases) >= s.config.MaxLeases {
		return fmt.Errorf("max leases reached")
	}

	if lease.ID == "" {
		lease.ID = uuid.New().String()
	}
	lease.CreatedAt = time.Now()
	lease.UpdatedAt = lease.CreatedAt
	lease.LastActivity = lease.CreatedAt

	s.leases[lease.ID] = lease

	// Index by IP
	if lease.IPv4 != nil {
		s.leaseByIP[lease.IPv4.String()] = lease.ID
	}
	if lease.IPv6 != nil {
		s.leaseByIP[lease.IPv6.String()] = lease.ID
	}

	// Index by MAC
	if lease.MAC != nil {
		s.leaseByMAC[lease.MAC.String()] = lease.ID
	}

	// Update pool allocation count
	if pool, exists := s.pools[lease.PoolID]; exists {
		pool.AllocatedAddresses++
	}

	s.stats.Writes++
	return nil
}

// GetLease retrieves a lease by ID.
func (s *Store) GetLease(id string) (*Lease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	lease, exists := s.leases[id]
	if !exists {
		return nil, fmt.Errorf("lease not found: %s", id)
	}

	s.stats.Reads++
	return lease, nil
}

// GetLeaseByIP retrieves a lease by IP address.
func (s *Store) GetLeaseByIP(ip net.IP) (*Lease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.leaseByIP[ip.String()]
	if !exists {
		return nil, fmt.Errorf("lease not found for IP: %s", ip)
	}

	lease := s.leases[id]
	s.stats.Reads++
	return lease, nil
}

// GetLeaseByMAC retrieves a lease by MAC address.
func (s *Store) GetLeaseByMAC(mac net.HardwareAddr) (*Lease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.leaseByMAC[mac.String()]
	if !exists {
		return nil, fmt.Errorf("lease not found for MAC: %s", mac)
	}

	lease := s.leases[id]
	s.stats.Reads++
	return lease, nil
}

// UpdateLease updates a lease.
func (s *Store) UpdateLease(lease *Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.leases[lease.ID]; !exists {
		return fmt.Errorf("lease not found: %s", lease.ID)
	}

	lease.UpdatedAt = time.Now()
	lease.LastActivity = time.Now()
	s.leases[lease.ID] = lease
	s.stats.Writes++
	return nil
}

// RenewLease renews a lease.
func (s *Store) RenewLease(id string, duration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, exists := s.leases[id]
	if !exists {
		return fmt.Errorf("lease not found: %s", id)
	}

	lease.UpdatedAt = time.Now()
	lease.LastActivity = time.Now()
	lease.LastRenewAt = time.Now()
	lease.RenewCount++
	lease.ExpiresAt = time.Now().Add(duration)
	lease.State = LeaseStateBound

	s.stats.Writes++
	return nil
}

// DeleteLease deletes a lease.
func (s *Store) DeleteLease(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, exists := s.leases[id]
	if !exists {
		return fmt.Errorf("lease not found: %s", id)
	}

	// Remove from indexes
	if lease.IPv4 != nil {
		delete(s.leaseByIP, lease.IPv4.String())
	}
	if lease.IPv6 != nil {
		delete(s.leaseByIP, lease.IPv6.String())
	}
	if lease.MAC != nil {
		delete(s.leaseByMAC, lease.MAC.String())
	}

	// Update pool allocation count
	if pool, exists := s.pools[lease.PoolID]; exists {
		pool.AllocatedAddresses--
	}

	delete(s.leases, id)
	s.stats.Deletes++
	return nil
}

// ListLeases returns all leases.
func (s *Store) ListLeases() []*Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Lease, 0, len(s.leases))
	for _, lease := range s.leases {
		result = append(result, lease)
	}
	return result
}

// --- Session Operations ---

// CreateSession creates a new session.
func (s *Store) CreateSession(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.sessions) >= s.config.MaxSessions {
		return fmt.Errorf("max sessions reached")
	}

	if session.ID == "" {
		session.ID = uuid.New().String()
	}
	session.CreatedAt = time.Now()
	session.UpdatedAt = session.CreatedAt
	session.StartTime = session.CreatedAt
	session.LastActivity = session.CreatedAt

	s.sessions[session.ID] = session

	// Index by MAC
	if session.MAC != nil {
		s.sessionByMAC[session.MAC.String()] = session.ID
	}

	// Index by IP
	if session.IPv4 != nil {
		s.sessionByIP[session.IPv4.String()] = session.ID
	}

	s.stats.Writes++
	return nil
}

// GetSession retrieves a session by ID.
func (s *Store) GetSession(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[id]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	s.stats.Reads++
	return session, nil
}

// GetSessionByMAC retrieves a session by MAC address.
func (s *Store) GetSessionByMAC(mac net.HardwareAddr) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.sessionByMAC[mac.String()]
	if !exists {
		return nil, fmt.Errorf("session not found for MAC: %s", mac)
	}

	session := s.sessions[id]
	s.stats.Reads++
	return session, nil
}

// GetSessionByIP retrieves a session by IP address.
func (s *Store) GetSessionByIP(ip net.IP) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.sessionByIP[ip.String()]
	if !exists {
		return nil, fmt.Errorf("session not found for IP: %s", ip)
	}

	session := s.sessions[id]
	s.stats.Reads++
	return session, nil
}

// UpdateSession updates a session.
func (s *Store) UpdateSession(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[session.ID]; !exists {
		return fmt.Errorf("session not found: %s", session.ID)
	}

	session.UpdatedAt = time.Now()
	s.sessions[session.ID] = session
	s.stats.Writes++
	return nil
}

// UpdateSessionActivity updates session last activity and traffic stats.
func (s *Store) UpdateSessionActivity(id string, bytesIn, bytesOut uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[id]
	if !exists {
		return fmt.Errorf("session not found: %s", id)
	}

	session.LastActivity = time.Now()
	session.BytesIn += bytesIn
	session.BytesOut += bytesOut

	s.stats.Writes++
	return nil
}

// DeleteSession deletes a session.
func (s *Store) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[id]
	if !exists {
		return fmt.Errorf("session not found: %s", id)
	}

	// Remove from indexes
	if session.MAC != nil {
		delete(s.sessionByMAC, session.MAC.String())
	}
	if session.IPv4 != nil {
		delete(s.sessionByIP, session.IPv4.String())
	}

	delete(s.sessions, id)
	s.stats.Deletes++
	return nil
}

// ListSessions returns all sessions.
func (s *Store) ListSessions() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		result = append(result, session)
	}
	return result
}

// --- NAT Binding Operations ---

// CreateNATBinding creates a new NAT binding.
func (s *Store) CreateNATBinding(binding *NATBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.natBindings) >= s.config.MaxNATBindings {
		return fmt.Errorf("max NAT bindings reached")
	}

	if binding.ID == "" {
		binding.ID = uuid.New().String()
	}
	binding.CreatedAt = time.Now()
	binding.LastActivity = binding.CreatedAt

	s.natBindings[binding.ID] = binding

	// Index by private address
	privateKey := fmt.Sprintf("%s:%d:%d", binding.PrivateIP, binding.PrivatePort, binding.Protocol)
	s.natByPrivate[privateKey] = binding.ID

	// Index by public address
	publicKey := fmt.Sprintf("%s:%d:%d", binding.PublicIP, binding.PublicPort, binding.Protocol)
	s.natByPublic[publicKey] = binding.ID

	s.stats.Writes++
	return nil
}

// GetNATBinding retrieves a NAT binding by ID.
func (s *Store) GetNATBinding(id string) (*NATBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	binding, exists := s.natBindings[id]
	if !exists {
		return nil, fmt.Errorf("NAT binding not found: %s", id)
	}

	s.stats.Reads++
	return binding, nil
}

// GetNATBindingByPrivate retrieves a NAT binding by private address.
func (s *Store) GetNATBindingByPrivate(ip net.IP, port uint16, protocol uint8) (*NATBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%d:%d", ip, port, protocol)
	id, exists := s.natByPrivate[key]
	if !exists {
		return nil, fmt.Errorf("NAT binding not found")
	}

	binding := s.natBindings[id]
	s.stats.Reads++
	return binding, nil
}

// GetNATBindingByPublic retrieves a NAT binding by public address.
func (s *Store) GetNATBindingByPublic(ip net.IP, port uint16, protocol uint8) (*NATBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%d:%d", ip, port, protocol)
	id, exists := s.natByPublic[key]
	if !exists {
		return nil, fmt.Errorf("NAT binding not found")
	}

	binding := s.natBindings[id]
	s.stats.Reads++
	return binding, nil
}

// DeleteNATBinding deletes a NAT binding.
func (s *Store) DeleteNATBinding(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	binding, exists := s.natBindings[id]
	if !exists {
		return fmt.Errorf("NAT binding not found: %s", id)
	}

	// Remove from indexes
	privateKey := fmt.Sprintf("%s:%d:%d", binding.PrivateIP, binding.PrivatePort, binding.Protocol)
	delete(s.natByPrivate, privateKey)

	publicKey := fmt.Sprintf("%s:%d:%d", binding.PublicIP, binding.PublicPort, binding.Protocol)
	delete(s.natByPublic, publicKey)

	delete(s.natBindings, id)
	s.stats.Deletes++
	return nil
}

// --- Background cleanup loops ---

func (s *Store) leaseCleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.LeaseCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredLeases()
		}
	}
}

func (s *Store) cleanupExpiredLeases() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var expired []string

	for id, lease := range s.leases {
		if now.After(lease.ExpiresAt) {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		lease := s.leases[id]
		lease.State = LeaseStateExpired

		// Remove from indexes
		if lease.IPv4 != nil {
			delete(s.leaseByIP, lease.IPv4.String())
		}
		if lease.IPv6 != nil {
			delete(s.leaseByIP, lease.IPv6.String())
		}
		if lease.MAC != nil {
			delete(s.leaseByMAC, lease.MAC.String())
		}

		// Update pool allocation count
		if pool, exists := s.pools[lease.PoolID]; exists {
			pool.AllocatedAddresses--
		}

		delete(s.leases, id)
		s.stats.Deletes++
	}

	if len(expired) > 0 {
		s.logger.Info("Cleaned up expired leases", zap.Int("count", len(expired)))
	}
}

func (s *Store) sessionCleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.SessionCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupIdleSessions()
		}
	}
}

func (s *Store) cleanupIdleSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var idle []string

	for id, session := range s.sessions {
		// Check idle timeout
		if session.IdleTimeout > 0 {
			if now.Sub(session.LastActivity) > session.IdleTimeout {
				idle = append(idle, id)
				continue
			}
		}

		// Check session timeout
		if session.SessionTimeout > 0 {
			if now.Sub(session.StartTime) > session.SessionTimeout {
				idle = append(idle, id)
			}
		}
	}

	for _, id := range idle {
		session := s.sessions[id]

		// Remove from indexes
		if session.MAC != nil {
			delete(s.sessionByMAC, session.MAC.String())
		}
		if session.IPv4 != nil {
			delete(s.sessionByIP, session.IPv4.String())
		}

		delete(s.sessions, id)
		s.stats.Deletes++
	}

	if len(idle) > 0 {
		s.logger.Info("Cleaned up idle sessions", zap.Int("count", len(idle)))
	}
}

func (s *Store) natCleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.NATCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredNATBindings()
		}
	}
}

func (s *Store) cleanupExpiredNATBindings() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var expired []string

	for id, binding := range s.natBindings {
		if now.After(binding.ExpiresAt) {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		binding := s.natBindings[id]

		// Remove from indexes
		privateKey := fmt.Sprintf("%s:%d:%d", binding.PrivateIP, binding.PrivatePort, binding.Protocol)
		delete(s.natByPrivate, privateKey)

		publicKey := fmt.Sprintf("%s:%d:%d", binding.PublicIP, binding.PublicPort, binding.Protocol)
		delete(s.natByPublic, publicKey)

		delete(s.natBindings, id)
		s.stats.Deletes++
	}

	if len(expired) > 0 {
		s.logger.Debug("Cleaned up expired NAT bindings", zap.Int("count", len(expired)))
	}
}

// --- Helper functions ---

func countAddresses(start, end net.IP) int {
	start = start.To4()
	end = end.To4()
	if start == nil || end == nil {
		return 0
	}

	startInt := ipToUint32(start)
	endInt := ipToUint32(end)

	if endInt < startInt {
		return 0
	}

	return int(endInt - startInt + 1)
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
