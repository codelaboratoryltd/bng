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

// NAT configuration flags (matches bpf/nat44.c)
const (
	NATFlagEIMEnabled     uint32 = 0x01 // Endpoint-Independent Mapping
	NATFlagEIFEnabled     uint32 = 0x02 // Endpoint-Independent Filtering
	NATFlagHairpinEnabled uint32 = 0x04 // Hairpinning enabled
	NATFlagALGFTP         uint32 = 0x08 // FTP ALG enabled
	NATFlagALGSIP         uint32 = 0x10 // SIP ALG enabled (often disabled)
	NATFlagPortParity     uint32 = 0x20 // Preserve port parity for RTP
	NATFlagPortContiguity uint32 = 0x40 // Allocate contiguous ports
)

// NAT log event types (matches bpf/nat44.c)
const (
	NATLogSessionCreate    uint32 = 1
	NATLogSessionDelete    uint32 = 2
	NATLogPortBlockAssign  uint32 = 3
	NATLogPortBlockRelease uint32 = 4
	NATLogPortExhaustion   uint32 = 5
	NATLogHairpin          uint32 = 6
	NATLogALGTrigger       uint32 = 7
)

// ALG types
const (
	ALGTypeFTP  uint8 = 1
	ALGTypeSIP  uint8 = 2
	ALGTypeRTSP uint8 = 3
)

// PortBlock represents a port block allocation per RFC 6431
type PortBlock struct {
	PublicIP      uint32
	PortStart     uint16
	PortEnd       uint16
	NextPort      uint16
	PortsInUse    uint16
	AllocatedAt   uint64
	SubscriberID  uint32
	BlockSizeLog2 uint8
	Flags         uint8
	_             [2]byte
}

// SubscriberNAT mirrors the eBPF struct for subscriber NAT allocation
type SubscriberNAT struct {
	Block          PortBlock
	SessionsActive uint64
	SessionsTotal  uint64
	BytesOut       uint64
	BytesIn        uint64
}

// NATSession mirrors the eBPF NAT session struct
type NATSession struct {
	NatIP      uint32
	NatPort    uint16
	OrigPort   uint16
	OrigIP     uint32
	DestIP     uint32
	DestPort   uint16
	_          uint16
	LastSeen   uint64
	Created    uint64
	PacketsOut uint64
	PacketsIn  uint64
	BytesOut   uint64
	BytesIn    uint64
	State      uint8
	Protocol   uint8
	Flags      uint8
	IsHairpin  uint8
}

// EIMKey is the key for Endpoint-Independent Mapping lookups
type EIMKey struct {
	InternalIP   uint32
	InternalPort uint16
	Protocol     uint8
	_            uint8
}

// EIMMapping represents an Endpoint-Independent Mapping entry
type EIMMapping struct {
	ExternalIP   uint32
	ExternalPort uint16
	_            uint16
	Created      uint64
	LastUsed     uint64
	RefCount     uint32
	Flags        uint32
}

// NATStats mirrors the eBPF stats struct
type NATStats struct {
	PacketsSNAT      uint64
	PacketsDNAT      uint64
	PacketsHairpin   uint64
	PacketsDropped   uint64
	PacketsPassed    uint64
	SessionsCreated  uint64
	SessionsExpired  uint64
	PortExhaustion   uint64
	EIMHits          uint64
	EIMMisses        uint64
	ALGTriggers      uint64
	ConntrackLookups uint64
	ConntrackHits    uint64
}

// NATConfig mirrors the eBPF NAT configuration struct
type NATConfig struct {
	Flags              uint32
	PortRangeStart     uint16
	PortRangeEnd       uint16
	DefaultPortsPerSub uint32
	_                  uint32
}

// BPFLogEntry mirrors the eBPF ring buffer log entry
type BPFLogEntry struct {
	Timestamp    uint64
	EventType    uint32
	SubscriberID uint32
	PrivateIP    uint32
	PublicIP     uint32
	PrivatePort  uint16
	PublicPort   uint16
	DestIP       uint32
	DestPort     uint16
	Protocol     uint8
	Flags        uint8
}

// ALGConfig represents ALG configuration for a port
type ALGConfig struct {
	Port     uint16
	Protocol uint8
	ALGType  uint8
	Flags    uint32
}

// PoolEntry represents a public IP in the NAT pool
type PoolEntry struct {
	PublicIP       net.IP
	TotalPorts     int
	PortsPerSub    int
	Subscribers    int
	MaxSubscribers int
	Flags          uint32
}

// Allocation tracks NAT allocation for a subscriber
type Allocation struct {
	PrivateIP    net.IP
	PublicIP     net.IP
	PortStart    uint16
	PortEnd      uint16
	PoolIndex    int
	SubscriberID uint32
	AllocatedAt  time.Time
}

// ManagerConfig configures the NAT manager
type ManagerConfig struct {
	Interface          string
	BPFPath            string
	PortsPerSubscriber int
	PortRangeStart     int
	PortRangeEnd       int

	// Interface overrides (default to Interface if empty)
	InsideInterface  string // Subscriber-facing interface
	OutsideInterface string // Public-facing interface

	// Feature flags
	EnableEIM            bool // Endpoint-Independent Mapping (RFC 4787)
	EnableEIF            bool // Endpoint-Independent Filtering
	EnableHairpin        bool // Hairpinning support
	EnablePortParity     bool // Preserve port parity for RTP/RTCP
	EnablePortContiguity bool // Allocate contiguous ports

	// ALG configuration
	EnableFTPALG bool // FTP ALG (port 21)
	EnableSIPALG bool // SIP ALG (port 5060) - often disabled

	// Logging configuration
	EnableLogging      bool
	LogBufferSize      int
	BulkLoggingEnabled bool // RFC 6908 bulk logging
}

// Manager handles NAT44/CGNAT via eBPF
type Manager struct {
	iface   string
	bpfPath string
	logger  *zap.Logger
	config  ManagerConfig

	// eBPF resources
	collection    *ebpf.Collection
	subscriberNAT *ebpf.Map
	natSessions   *ebpf.Map
	natReverse    *ebpf.Map
	natPool       *ebpf.Map
	natStats      *ebpf.Map
	natConfigMap  *ebpf.Map
	eimTable      *ebpf.Map
	hairpinIPs    *ebpf.Map
	algPorts      *ebpf.Map
	natLogRB      *ebpf.Map

	// Public IP pool management
	pool         []PoolEntry
	poolMu       sync.RWMutex
	allocations  map[uint32]*Allocation // private IP -> allocation
	allocationMu sync.RWMutex

	// Subscriber ID counter (deterministic)
	nextSubscriberID uint32
	subscriberIDs    map[uint32]uint32 // private IP -> subscriber ID
	subscriberIDMu   sync.RWMutex

	// Configuration
	portsPerSubscriber int
	portRangeStart     int
	portRangeEnd       int

	// NAT logging
	natLogger *Logger

	// Session cleanup
	cleanupTicker *time.Ticker
	cleanupDone   chan struct{}
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
		config:             cfg,
		pool:               make([]PoolEntry, 0),
		allocations:        make(map[uint32]*Allocation),
		subscriberIDs:      make(map[uint32]uint32),
		portsPerSubscriber: portsPerSub,
		portRangeStart:     portStart,
		portRangeEnd:       portEnd,
		nextSubscriberID:   1,
		cleanupDone:        make(chan struct{}),
	}, nil
}

// getOrCreateSubscriberID returns or creates a deterministic subscriber ID
func (m *Manager) getOrCreateSubscriberID(privateIP uint32) uint32 {
	m.subscriberIDMu.Lock()
	defer m.subscriberIDMu.Unlock()

	if id, ok := m.subscriberIDs[privateIP]; ok {
		return id
	}

	id := m.nextSubscriberID
	m.nextSubscriberID++
	m.subscriberIDs[privateIP] = id
	return id
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
		Flags:          m.buildFlags(),
	}

	m.pool = append(m.pool, entry)

	// Add to hairpin detection map if enabled
	if m.hairpinIPs != nil && m.config.EnableHairpin {
		ipKey := ipToKey(ip4)
		val := uint8(1)
		if err := m.hairpinIPs.Put(&ipKey, &val); err != nil {
			m.logger.Warn("Failed to add hairpin IP", zap.Error(err))
		}
	}

	m.logger.Info("Added public IP to NAT pool",
		zap.String("ip", ip.String()),
		zap.Int("max_subscribers", maxSubs),
		zap.Int("ports_per_sub", m.portsPerSubscriber),
	)

	return nil
}

// AddPublicIPRange adds a range of public IPs to the NAT pool
func (m *Manager) AddPublicIPRange(startIP, endIP net.IP) error {
	start := ipToKey(startIP.To4())
	end := ipToKey(endIP.To4())

	if start > end {
		return fmt.Errorf("start IP must be less than or equal to end IP")
	}

	for ip := start; ip <= end; ip++ {
		if err := m.AddPublicIP(keyToIP(ip)); err != nil {
			return fmt.Errorf("failed to add IP %s: %w", keyToIP(ip).String(), err)
		}
	}

	return nil
}

// buildFlags creates the NAT configuration flags
func (m *Manager) buildFlags() uint32 {
	var flags uint32
	if m.config.EnableEIM {
		flags |= NATFlagEIMEnabled
	}
	if m.config.EnableEIF {
		flags |= NATFlagEIFEnabled
	}
	if m.config.EnableHairpin {
		flags |= NATFlagHairpinEnabled
	}
	if m.config.EnableFTPALG {
		flags |= NATFlagALGFTP
	}
	if m.config.EnableSIPALG {
		flags |= NATFlagALGSIP
	}
	if m.config.EnablePortParity {
		flags |= NATFlagPortParity
	}
	if m.config.EnablePortContiguity {
		flags |= NATFlagPortContiguity
	}
	return flags
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

	// Calculate port range for this subscriber (deterministic based on subscriber count)
	portStart := uint16(m.portRangeStart + (selectedPool.Subscribers * m.portsPerSubscriber))
	portEnd := portStart + uint16(m.portsPerSubscriber) - 1

	// Get or create subscriber ID
	subscriberID := m.getOrCreateSubscriberID(privKey)

	allocation := &Allocation{
		PrivateIP:    ip4,
		PublicIP:     selectedPool.PublicIP,
		PortStart:    portStart,
		PortEnd:      portEnd,
		PoolIndex:    poolIndex,
		SubscriberID: subscriberID,
		AllocatedAt:  time.Now(),
	}

	// Update eBPF map
	if m.subscriberNAT != nil {
		subNAT := SubscriberNAT{
			Block: PortBlock{
				PublicIP:      ipToKey(selectedPool.PublicIP),
				PortStart:     portStart,
				PortEnd:       portEnd,
				NextPort:      portStart,
				PortsInUse:    0,
				AllocatedAt:   uint64(time.Now().UnixNano()),
				SubscriberID:  subscriberID,
				BlockSizeLog2: uint8(log2(m.portsPerSubscriber)),
				Flags:         0,
			},
			SessionsActive: 0,
			SessionsTotal:  0,
			BytesOut:       0,
			BytesIn:        0,
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

	// Log allocation event
	if m.natLogger != nil {
		m.natLogger.LogAllocation(allocation)
	}

	m.logger.Info("Allocated NAT for subscriber",
		zap.String("private_ip", privateIP.String()),
		zap.String("public_ip", selectedPool.PublicIP.String()),
		zap.Uint16("port_start", portStart),
		zap.Uint16("port_end", portEnd),
		zap.Uint32("subscriber_id", subscriberID),
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
		if err := m.subscriberNAT.Delete(&privKey); err != nil {
			m.logger.Warn("Failed to delete subscriber NAT entry", zap.Error(err))
		}
	}

	// Update pool count
	m.poolMu.Lock()
	if allocation.PoolIndex < len(m.pool) {
		m.pool[allocation.PoolIndex].Subscribers--
	}
	m.poolMu.Unlock()

	// Log deallocation event
	if m.natLogger != nil {
		duration := time.Since(allocation.AllocatedAt)
		m.natLogger.LogDeallocation(privateIP, allocation.PublicIP, allocation.PortStart, duration)
	}

	m.logger.Info("Deallocated NAT for subscriber",
		zap.String("private_ip", privateIP.String()),
	)

	return nil
}

// ConfigureALG configures an Application Layer Gateway for a specific port
func (m *Manager) ConfigureALG(port uint16, protocol uint8, algType uint8, enabled bool) error {
	if m.algPorts == nil {
		return fmt.Errorf("ALG map not loaded")
	}

	key := (uint32(port) << 16) | uint32(protocol)

	if enabled {
		cfg := ALGConfig{
			Port:     port,
			Protocol: protocol,
			ALGType:  algType,
			Flags:    0,
		}
		return m.algPorts.Put(&key, &cfg)
	} else {
		return m.algPorts.Delete(&key)
	}
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
	m.natConfigMap = coll.Maps["nat_config_map"]
	m.eimTable = coll.Maps["eim_table"]
	m.hairpinIPs = coll.Maps["hairpin_ips"]
	m.algPorts = coll.Maps["alg_ports"]
	m.natLogRB = coll.Maps["nat_log_rb"]

	// Configure NAT flags
	if m.natConfigMap != nil {
		cfg := NATConfig{
			Flags:              m.buildFlags(),
			PortRangeStart:     uint16(m.portRangeStart),
			PortRangeEnd:       uint16(m.portRangeEnd),
			DefaultPortsPerSub: uint32(m.portsPerSubscriber),
		}
		var key uint32 = 0
		if err := m.natConfigMap.Put(&key, &cfg); err != nil {
			m.logger.Warn("Failed to set NAT config", zap.Error(err))
		}
	}

	// Configure default ALG ports
	if m.config.EnableFTPALG {
		m.ConfigureALG(21, 6, ALGTypeFTP, true) // FTP control (TCP)
	}
	if m.config.EnableSIPALG {
		m.ConfigureALG(5060, 17, ALGTypeSIP, true) // SIP (UDP)
		m.ConfigureALG(5060, 6, ALGTypeSIP, true)  // SIP (TCP)
	}

	// Attach TC programs
	if err := m.attachTCPrograms(coll); err != nil {
		return err
	}

	// Start session cleanup routine
	m.cleanupTicker = time.NewTicker(30 * time.Second)
	go m.sessionCleanupLoop()

	// Start ring buffer reader for logging
	if m.natLogRB != nil && m.config.EnableLogging {
		go m.readLogRingBuffer(ctx)
	}

	m.logger.Info("NAT44 eBPF programs attached",
		zap.String("interface", m.iface),
		zap.Bool("eim_enabled", m.config.EnableEIM),
		zap.Bool("hairpin_enabled", m.config.EnableHairpin),
		zap.Bool("ftp_alg", m.config.EnableFTPALG),
		zap.Bool("sip_alg", m.config.EnableSIPALG),
	)

	return nil
}

// sessionCleanupLoop periodically cleans up expired sessions
func (m *Manager) sessionCleanupLoop() {
	for {
		select {
		case <-m.cleanupTicker.C:
			m.cleanupExpiredSessions()
		case <-m.cleanupDone:
			return
		}
	}
}

// cleanupExpiredSessions removes expired NAT sessions
func (m *Manager) cleanupExpiredSessions() {
	// In production, the LRU hash map handles eviction automatically
	// This is for additional cleanup and logging
	stats, err := m.GetStats()
	if err != nil {
		return
	}

	m.logger.Debug("NAT session cleanup",
		zap.Uint64("sessions_expired", stats.SessionsExpired),
		zap.Uint64("active_sessions", stats.SessionsCreated-stats.SessionsExpired),
	)
}

// readLogRingBuffer reads NAT log events from the eBPF ring buffer
func (m *Manager) readLogRingBuffer(ctx context.Context) {
	// TODO: Implement ring buffer reading using ringbuf.NewReader() from cilium/ebpf.
	// Example implementation:
	//   reader, err := ringbuf.NewReader(m.natLogRB)
	//   if err != nil { ... }
	//   defer reader.Close()
	//   for {
	//       record, err := reader.Read()
	//       if err != nil { ... }
	//       var entry BPFLogEntry
	//       if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &entry); err != nil { ... }
	//       m.natLogger.LogFromBPF(&entry)
	//   }
	m.logger.Info("NAT log ring buffer reader started (placeholder - needs ringbuf.NewReader() implementation)")
}

// Stop cleans up resources
func (m *Manager) Stop() error {
	m.logger.Info("Stopping NAT44 manager")

	// Stop cleanup routine
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
		close(m.cleanupDone)
	}

	// Stop NAT logger
	if m.natLogger != nil {
		m.natLogger.Stop()
	}

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

// GetEIMMapping returns the Endpoint-Independent Mapping for an internal endpoint
func (m *Manager) GetEIMMapping(internalIP net.IP, internalPort uint16, protocol uint8) (*EIMMapping, error) {
	if m.eimTable == nil {
		return nil, fmt.Errorf("EIM table not loaded")
	}

	key := EIMKey{
		InternalIP:   ipToKey(internalIP.To4()),
		InternalPort: internalPort,
		Protocol:     protocol,
	}

	var mapping EIMMapping
	if err := m.eimTable.Lookup(&key, &mapping); err != nil {
		return nil, err
	}

	return &mapping, nil
}

// LookupSession looks up a NAT session by 5-tuple
func (m *Manager) LookupSession(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) (*NATSession, error) {
	if m.natSessions == nil {
		return nil, fmt.Errorf("sessions map not loaded")
	}

	// Build the key structure matching the eBPF struct
	type natKey struct {
		SrcIP    uint32
		DstIP    uint32
		SrcPort  uint16
		DstPort  uint16
		Protocol uint8
		_        [3]byte
	}

	key := natKey{
		SrcIP:    ipToKey(srcIP.To4()),
		DstIP:    ipToKey(dstIP.To4()),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	var session NATSession
	if err := m.natSessions.Lookup(&key, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// SetLogger sets the NAT logger
func (m *Manager) SetLogger(logger *Logger) {
	m.natLogger = logger
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

// log2 calculates log base 2 (for block size)
func log2(n int) int {
	result := 0
	for n > 1 {
		n >>= 1
		result++
	}
	return result
}
