package dhcp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/ebpf"
	"go.uber.org/zap"
)

// ClientClass represents subscriber classification
type ClientClass uint8

const (
	ClientClassResidential ClientClass = 1
	ClientClassBusiness    ClientClass = 2
	ClientClassGuest       ClientClass = 3
)

// Pool represents an IP address pool
type Pool struct {
	ID          uint32
	Name        string
	Network     *net.IPNet
	Gateway     net.IP
	SubnetMask  net.IPMask
	DNSServers  []net.IP
	LeaseTime   time.Duration
	ClientClass ClientClass
	VlanID      uint32

	// Allocation state
	allocated   map[string]net.IP   // MAC -> IP
	available   []net.IP            // Available IPs
	unavailable map[string]struct{} // IPs marked unavailable (declined)
	mu          sync.Mutex
}

// PoolConfig is the configuration for creating a pool
type PoolConfig struct {
	ID          uint32
	Name        string
	Network     string // CIDR notation (e.g., "10.0.1.0/24")
	Gateway     string
	DNSServers  []string
	LeaseTime   time.Duration
	ClientClass ClientClass
	VlanID      uint32
	// Reserved IPs to exclude from allocation
	ReservedStart int // First N IPs reserved (e.g., 10 for .1-.10)
	ReservedEnd   int // Last N IPs reserved
}

// NewPool creates a new IP pool
func NewPool(cfg PoolConfig) (*Pool, error) {
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
			return nil, fmt.Errorf("invalid DNS server IP: %s", dns)
		}
		dnsServers = append(dnsServers, ip)
	}

	pool := &Pool{
		ID:          cfg.ID,
		Name:        cfg.Name,
		Network:     network,
		Gateway:     gateway,
		SubnetMask:  network.Mask,
		DNSServers:  dnsServers,
		LeaseTime:   cfg.LeaseTime,
		ClientClass: cfg.ClientClass,
		VlanID:      cfg.VlanID,
		allocated:   make(map[string]net.IP),
		unavailable: make(map[string]struct{}),
	}

	// Generate available IPs
	pool.available = pool.generateAvailableIPs(cfg.ReservedStart, cfg.ReservedEnd)

	return pool, nil
}

// generateAvailableIPs generates the list of available IPs in the pool
func (p *Pool) generateAvailableIPs(reservedStart, reservedEnd int) []net.IP {
	var ips []net.IP

	// Get network range
	networkIP := p.Network.IP.To4()
	if networkIP == nil {
		return ips
	}

	ones, bits := p.Network.Mask.Size()
	hostBits := bits - ones
	numHosts := (1 << hostBits) - 2 // Exclude network and broadcast

	if numHosts <= 0 {
		return ips
	}

	for i := 1; i <= numHosts; i++ {
		// Skip reserved at start
		if i <= reservedStart {
			continue
		}
		// Skip reserved at end
		if i > numHosts-reservedEnd {
			continue
		}

		ip := make(net.IP, 4)
		copy(ip, networkIP)

		// Add host portion
		ip[0] += byte((i >> 24) & 0xFF)
		ip[1] += byte((i >> 16) & 0xFF)
		ip[2] += byte((i >> 8) & 0xFF)
		ip[3] += byte(i & 0xFF)

		// Skip gateway
		if ip.Equal(p.Gateway) {
			continue
		}

		ips = append(ips, ip)
	}

	return ips
}

// Allocate allocates an IP for the given MAC address
func (p *Pool) Allocate(mac net.HardwareAddr) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	macStr := mac.String()

	// Check if already allocated
	if ip, exists := p.allocated[macStr]; exists {
		return ip, nil
	}

	// Find available IP
	if len(p.available) == 0 {
		return nil, fmt.Errorf("pool %s exhausted", p.Name)
	}

	ip := p.available[0]
	p.available = p.available[1:]
	p.allocated[macStr] = ip

	return ip, nil
}

// Release releases an IP back to the pool
func (p *Pool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Find and remove from allocated
	for mac, allocatedIP := range p.allocated {
		if allocatedIP.Equal(ip) {
			delete(p.allocated, mac)
			// Add back to available (at the end)
			p.available = append(p.available, ip)
			return
		}
	}
}

// Contains checks if an IP is within this pool
func (p *Pool) Contains(ip net.IP) bool {
	return p.Network.Contains(ip)
}

// MarkUnavailable marks an IP as unavailable (e.g., after DECLINE)
func (p *Pool) MarkUnavailable(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.unavailable[ip.String()] = struct{}{}

	// Remove from available
	for i, avail := range p.available {
		if avail.Equal(ip) {
			p.available = append(p.available[:i], p.available[i+1:]...)
			break
		}
	}
}

// Stats returns pool statistics
func (p *Pool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return PoolStats{
		ID:          p.ID,
		Name:        p.Name,
		Total:       len(p.available) + len(p.allocated),
		Allocated:   len(p.allocated),
		Available:   len(p.available),
		Unavailable: len(p.unavailable),
	}
}

// PoolStats represents pool statistics
type PoolStats struct {
	ID          uint32
	Name        string
	Total       int
	Allocated   int
	Available   int
	Unavailable int
}

// PoolManager manages multiple IP pools
type PoolManager struct {
	pools         map[uint32]*Pool
	poolsMu       sync.RWMutex
	loader        *ebpf.Loader
	logger        *zap.Logger
	defaultPoolID uint32
}

// NewPoolManager creates a new pool manager
func NewPoolManager(loader *ebpf.Loader, logger *zap.Logger) *PoolManager {
	return &PoolManager{
		pools:  make(map[uint32]*Pool),
		loader: loader,
		logger: logger,
	}
}

// AddPool adds a pool to the manager
func (m *PoolManager) AddPool(pool *Pool) error {
	m.poolsMu.Lock()
	defer m.poolsMu.Unlock()

	if _, exists := m.pools[pool.ID]; exists {
		return fmt.Errorf("pool %d already exists", pool.ID)
	}

	m.pools[pool.ID] = pool

	// Set as default if first pool
	if len(m.pools) == 1 {
		m.defaultPoolID = pool.ID
	}

	// Sync to eBPF map
	if m.loader != nil {
		ebpfPool := &ebpf.IPPool{
			Network:      ebpf.IPToUint32(pool.Network.IP),
			PrefixLen:    uint8(prefixLen(pool.Network.Mask)),
			Gateway:      ebpf.IPToUint32(pool.Gateway),
			DNSPrimary:   dnsToUint32(pool.DNSServers, 0),
			DNSSecondary: dnsToUint32(pool.DNSServers, 1),
			LeaseTime:    uint32(pool.LeaseTime.Seconds()),
		}

		if err := m.loader.AddPool(pool.ID, ebpfPool); err != nil && m.logger != nil {
			m.logger.Warn("Failed to sync pool to eBPF map",
				zap.Uint32("pool_id", pool.ID),
				zap.Error(err),
			)
		}
	}

	if m.logger != nil {
		m.logger.Info("Pool added",
			zap.Uint32("id", pool.ID),
			zap.String("name", pool.Name),
			zap.String("network", pool.Network.String()),
		)
	}

	return nil
}

// RemovePool removes a pool
func (m *PoolManager) RemovePool(poolID uint32) error {
	m.poolsMu.Lock()
	defer m.poolsMu.Unlock()

	if _, exists := m.pools[poolID]; !exists {
		return fmt.Errorf("pool %d not found", poolID)
	}

	delete(m.pools, poolID)

	// Remove from eBPF map
	if m.loader != nil {
		m.loader.RemovePool(poolID)
	}

	return nil
}

// GetPool returns a pool by ID
func (m *PoolManager) GetPool(poolID uint32) *Pool {
	m.poolsMu.RLock()
	defer m.poolsMu.RUnlock()
	return m.pools[poolID]
}

// ClassifyClient determines which pool a client should use
// This is a simple implementation - production would use RADIUS or subscriber DB
func (m *PoolManager) ClassifyClient(mac net.HardwareAddr) *Pool {
	m.poolsMu.RLock()
	defer m.poolsMu.RUnlock()

	// Simple classification based on MAC prefix (OUI)
	// In production, this would query a subscriber database or RADIUS

	// For now, just return the default pool
	if pool, exists := m.pools[m.defaultPoolID]; exists {
		return pool
	}

	// Return first available pool
	for _, pool := range m.pools {
		return pool
	}

	return nil
}

// SetDefaultPool sets the default pool for unclassified clients
func (m *PoolManager) SetDefaultPool(poolID uint32) error {
	m.poolsMu.Lock()
	defer m.poolsMu.Unlock()

	if _, exists := m.pools[poolID]; !exists {
		return fmt.Errorf("pool %d not found", poolID)
	}

	m.defaultPoolID = poolID
	return nil
}

// AllStats returns statistics for all pools
func (m *PoolManager) AllStats() []PoolStats {
	m.poolsMu.RLock()
	defer m.poolsMu.RUnlock()

	var stats []PoolStats
	for _, pool := range m.pools {
		stats = append(stats, pool.Stats())
	}
	return stats
}

// Helper functions

func prefixLen(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

func dnsToUint32(servers []net.IP, index int) uint32 {
	if index >= len(servers) {
		return 0
	}
	return ebpf.IPToUint32(servers[index])
}
