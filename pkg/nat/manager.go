package nat

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// SubscriberNAT mirrors the eBPF struct for subscriber NAT allocation
type SubscriberNAT struct {
	PublicIP       uint32
	PortStart      uint16
	PortEnd        uint16
	NextPort       uint16
	_              uint16
	SessionsActive uint64
}

// NATSession mirrors the eBPF NAT session struct
type NATSession struct {
	NatIP    uint32
	NatPort  uint16
	OrigPort uint16
	OrigIP   uint32
	LastSeen uint64
	Created  uint64
	Packets  uint32
	Bytes    uint32
	State    uint8
	Protocol uint8
	_        [2]byte
}

// NATStats mirrors the eBPF stats struct
type NATStats struct {
	PacketsSNAT     uint64
	PacketsDNAT     uint64
	PacketsDropped  uint64
	SessionsCreated uint64
	SessionsExpired uint64
	PortExhaustion  uint64
}

// PoolEntry represents a public IP in the NAT pool
type PoolEntry struct {
	PublicIP       net.IP
	TotalPorts     int
	PortsPerSub    int
	Subscribers    int
	MaxSubscribers int
}

// Manager handles NAT44/CGNAT via eBPF
type Manager struct {
	iface   string
	bpfPath string
	logger  *zap.Logger

	// eBPF resources
	collection    *ebpf.Collection
	subscriberNAT *ebpf.Map
	natSessions   *ebpf.Map
	natReverse    *ebpf.Map
	natPool       *ebpf.Map
	natStats      *ebpf.Map

	// Public IP pool management
	pool         []PoolEntry
	poolMu       sync.RWMutex
	allocations  map[uint32]*Allocation // private IP -> allocation
	allocationMu sync.RWMutex

	// Configuration
	portsPerSubscriber int
	portRangeStart     int
	portRangeEnd       int
}

// Allocation tracks NAT allocation for a subscriber
type Allocation struct {
	PrivateIP   net.IP
	PublicIP    net.IP
	PortStart   uint16
	PortEnd     uint16
	PoolIndex   int
	AllocatedAt time.Time
}

// ManagerConfig configures the NAT manager
type ManagerConfig struct {
	Interface          string
	BPFPath            string
	PortsPerSubscriber int
	PortRangeStart     int
	PortRangeEnd       int
}

// NewManager creates a new NAT manager
func NewManager(cfg ManagerConfig, logger *zap.Logger) (*Manager, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface required")
	}

	bpfPath := cfg.BPFPath
	if bpfPath == "" {
		bpfPath = "bpf/nat44.bpf.o"
	}

	portsPerSub := cfg.PortsPerSubscriber
	if portsPerSub == 0 {
		portsPerSub = 1024
	}

	portStart := cfg.PortRangeStart
	if portStart == 0 {
		portStart = 1024
	}

	portEnd := cfg.PortRangeEnd
	if portEnd == 0 {
		portEnd = 65535
	}

	return &Manager{
		iface:              cfg.Interface,
		bpfPath:            bpfPath,
		logger:             logger,
		pool:               make([]PoolEntry, 0),
		allocations:        make(map[uint32]*Allocation),
		portsPerSubscriber: portsPerSub,
		portRangeStart:     portStart,
		portRangeEnd:       portEnd,
	}, nil
}

// AddPublicIP adds a public IP to the NAT pool
func (m *Manager) AddPublicIP(ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv4 address required")
	}

	m.poolMu.Lock()
	defer m.poolMu.Unlock()

	// Calculate max subscribers for this IP
	totalPorts := m.portRangeEnd - m.portRangeStart + 1
	maxSubs := totalPorts / m.portsPerSubscriber

	entry := PoolEntry{
		PublicIP:       ip4,
		TotalPorts:     totalPorts,
		PortsPerSub:    m.portsPerSubscriber,
		Subscribers:    0,
		MaxSubscribers: maxSubs,
	}

	m.pool = append(m.pool, entry)

	m.logger.Info("Added public IP to NAT pool",
		zap.String("ip", ip.String()),
		zap.Int("max_subscribers", maxSubs),
		zap.Int("ports_per_sub", m.portsPerSubscriber),
	)

	return nil
}

// AllocateNAT allocates NAT resources for a subscriber
func (m *Manager) AllocateNAT(privateIP net.IP) (*Allocation, error) {
	ip4 := privateIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("IPv4 address required")
	}

	privKey := ipToKey(ip4)

	// Check if already allocated
	m.allocationMu.RLock()
	if existing, ok := m.allocations[privKey]; ok {
		m.allocationMu.RUnlock()
		return existing, nil
	}
	m.allocationMu.RUnlock()

	// Find available pool entry
	m.poolMu.Lock()
	defer m.poolMu.Unlock()

	var selectedPool *PoolEntry
	var poolIndex int
	for i := range m.pool {
		if m.pool[i].Subscribers < m.pool[i].MaxSubscribers {
			selectedPool = &m.pool[i]
			poolIndex = i
			break
		}
	}

	if selectedPool == nil {
		return nil, fmt.Errorf("NAT pool exhausted: no available public IPs")
	}

	// Calculate port range for this subscriber
	portStart := uint16(m.portRangeStart + (selectedPool.Subscribers * m.portsPerSubscriber))
	portEnd := portStart + uint16(m.portsPerSubscriber) - 1

	allocation := &Allocation{
		PrivateIP:   ip4,
		PublicIP:    selectedPool.PublicIP,
		PortStart:   portStart,
		PortEnd:     portEnd,
		PoolIndex:   poolIndex,
		AllocatedAt: time.Now(),
	}

	// Update eBPF map
	if m.subscriberNAT != nil {
		subNAT := SubscriberNAT{
			PublicIP:  ipToKey(selectedPool.PublicIP),
			PortStart: portStart,
			PortEnd:   portEnd,
			NextPort:  portStart,
		}
		if err := m.subscriberNAT.Put(&privKey, &subNAT); err != nil {
			return nil, fmt.Errorf("failed to update eBPF map: %w", err)
		}
	}

	// Track allocation
	m.allocationMu.Lock()
	m.allocations[privKey] = allocation
	m.allocationMu.Unlock()

	selectedPool.Subscribers++

	m.logger.Info("Allocated NAT for subscriber",
		zap.String("private_ip", privateIP.String()),
		zap.String("public_ip", selectedPool.PublicIP.String()),
		zap.Uint16("port_start", portStart),
		zap.Uint16("port_end", portEnd),
	)

	return allocation, nil
}

// DeallocateNAT removes NAT allocation for a subscriber
func (m *Manager) DeallocateNAT(privateIP net.IP) error {
	ip4 := privateIP.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv4 address required")
	}

	privKey := ipToKey(ip4)

	m.allocationMu.Lock()
	allocation, ok := m.allocations[privKey]
	if !ok {
		m.allocationMu.Unlock()
		return nil // Not allocated
	}
	delete(m.allocations, privKey)
	m.allocationMu.Unlock()

	// Remove from eBPF map
	if m.subscriberNAT != nil {
		m.subscriberNAT.Delete(&privKey)
	}

	// Update pool count
	m.poolMu.Lock()
	if allocation.PoolIndex < len(m.pool) {
		m.pool[allocation.PoolIndex].Subscribers--
	}
	m.poolMu.Unlock()

	m.logger.Info("Deallocated NAT for subscriber",
		zap.String("private_ip", privateIP.String()),
	)

	return nil
}

// Start loads the eBPF programs and attaches them
func (m *Manager) Start(ctx context.Context) error {
	m.logger.Info("Starting NAT44 manager",
		zap.String("interface", m.iface),
		zap.String("bpf_path", m.bpfPath),
	)

	// Resolve BPF path
	bpfPath := m.bpfPath
	if !filepath.IsAbs(bpfPath) {
		if _, err := os.Stat(bpfPath); os.IsNotExist(err) {
			exe, _ := os.Executable()
			bpfPath = filepath.Join(filepath.Dir(exe), m.bpfPath)
		}
	}

	// Load eBPF collection
	spec, err := ebpf.LoadCollectionSpec(bpfPath)
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create eBPF collection: %w", err)
	}
	m.collection = coll

	// Get map references
	m.subscriberNAT = coll.Maps["subscriber_nat"]
	if m.subscriberNAT == nil {
		return fmt.Errorf("subscriber_nat map not found")
	}

	m.natSessions = coll.Maps["nat_sessions"]
	m.natReverse = coll.Maps["nat_reverse"]
	m.natPool = coll.Maps["nat_pool"]
	m.natStats = coll.Maps["nat_stats_map"]

	// Attach TC programs
	if err := m.attachTCPrograms(coll); err != nil {
		return err
	}

	m.logger.Info("NAT44 eBPF programs attached",
		zap.String("interface", m.iface),
	)

	return nil
}

// Stop cleans up resources
func (m *Manager) Stop() error {
	m.logger.Info("Stopping NAT44 manager")

	if m.collection != nil {
		m.collection.Close()
	}

	return nil
}

// GetStats returns NAT statistics
func (m *Manager) GetStats() (*NATStats, error) {
	if m.natStats == nil {
		return nil, fmt.Errorf("stats map not loaded")
	}

	var key uint32 = 0
	var stats NATStats

	if err := m.natStats.Lookup(&key, &stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// GetAllocationCount returns the number of active NAT allocations
func (m *Manager) GetAllocationCount() int {
	m.allocationMu.RLock()
	defer m.allocationMu.RUnlock()
	return len(m.allocations)
}

// GetPoolStats returns pool utilization statistics
func (m *Manager) GetPoolStats() []PoolEntry {
	m.poolMu.RLock()
	defer m.poolMu.RUnlock()

	result := make([]PoolEntry, len(m.pool))
	copy(result, m.pool)
	return result
}

// GetAllocation returns the NAT allocation for a private IP
func (m *Manager) GetAllocation(privateIP net.IP) *Allocation {
	ip4 := privateIP.To4()
	if ip4 == nil {
		return nil
	}

	m.allocationMu.RLock()
	defer m.allocationMu.RUnlock()

	return m.allocations[ipToKey(ip4)]
}

// ipToKey converts an IPv4 address to a uint32 key (network byte order)
func ipToKey(ip net.IP) uint32 {
	ip4 := ip.To4()
	return binary.BigEndian.Uint32(ip4)
}

// keyToIP converts a uint32 key to an IPv4 address
func keyToIP(key uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, key)
	return ip
}
