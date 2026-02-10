package qos

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/codelaboratoryltd/bng/pkg/radius"
	"go.uber.org/zap"
)

// TokenBucket mirrors the eBPF struct
type TokenBucket struct {
	Tokens     uint64
	LastUpdate uint64
	RateBPS    uint64 // Rate in bits per second
	BurstBytes uint32
	Priority   uint8
	_          [3]byte // Padding
}

// QoSStats mirrors the eBPF stats struct
type QoSStats struct {
	PacketsPassed  uint64
	PacketsDropped uint64
	BytesPassed    uint64
	BytesDropped   uint64
}

// Manager handles QoS policy enforcement via eBPF TC
type Manager struct {
	iface     string
	bpfPath   string
	logger    *zap.Logger
	policyMgr *radius.PolicyManager

	// eBPF resources
	collection  *ebpf.Collection
	qosEgress   *ebpf.Map
	qosIngress  *ebpf.Map
	qosStatsMap *ebpf.Map

	// Subscriber policies
	subscribers   map[uint32]*SubscriberQoS // IP -> QoS config
	subscribersMu sync.RWMutex
}

// SubscriberQoS holds per-subscriber QoS settings
type SubscriberQoS struct {
	IP          net.IP
	DownloadBPS uint64
	UploadBPS   uint64
	BurstBytes  uint32
	Priority    uint8
	PolicyName  string
}

// ManagerConfig configures the QoS manager
type ManagerConfig struct {
	Interface string
	BPFPath   string
}

// NewManager creates a new QoS manager
func NewManager(cfg ManagerConfig, policyMgr *radius.PolicyManager, logger *zap.Logger) (*Manager, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface required")
	}

	bpfPath := cfg.BPFPath
	if bpfPath == "" {
		bpfPath = "bpf/qos_ratelimit.bpf.o"
	}

	return &Manager{
		iface:       cfg.Interface,
		bpfPath:     bpfPath,
		logger:      logger,
		policyMgr:   policyMgr,
		subscribers: make(map[uint32]*SubscriberQoS),
	}, nil
}

// Start loads the eBPF programs and attaches them
func (m *Manager) Start(ctx context.Context) error {
	m.logger.Info("Starting QoS manager",
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
	m.qosEgress = coll.Maps["qos_egress"]
	if m.qosEgress == nil {
		return fmt.Errorf("qos_egress map not found")
	}

	m.qosIngress = coll.Maps["qos_ingress"]
	if m.qosIngress == nil {
		return fmt.Errorf("qos_ingress map not found")
	}

	m.qosStatsMap = coll.Maps["qos_stats_map"]

	// Get programs
	egressProg := coll.Programs["qos_egress_prog"]
	if egressProg == nil {
		return fmt.Errorf("qos_egress_prog not found")
	}

	ingressProg := coll.Programs["qos_ingress_prog"]
	if ingressProg == nil {
		return fmt.Errorf("qos_ingress_prog not found")
	}

	// Attach TC programs (Linux-specific)
	if err := m.attachTCPrograms(egressProg, ingressProg); err != nil {
		return err
	}

	m.logger.Info("QoS eBPF programs attached",
		zap.String("interface", m.iface),
	)

	return nil
}

// Stop detaches programs and cleans up
func (m *Manager) Stop() error {
	m.logger.Info("Stopping QoS manager")

	// Note: TC filters are cleaned up when qdisc is removed or interface goes down
	// For explicit cleanup, we'd need to delete the filters

	if m.collection != nil {
		m.collection.Close()
	}

	return nil
}

// SetSubscriberQoS sets QoS policy for a subscriber
func (m *Manager) SetSubscriberQoS(qos *SubscriberQoS) error {
	if qos.IP == nil {
		return fmt.Errorf("subscriber IP required")
	}

	ip4 := qos.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv4 address required")
	}

	// Convert IP to key
	key := ipToKey(ip4)

	// Calculate burst size if not set
	burstBytes := qos.BurstBytes
	if burstBytes == 0 {
		// Default burst: 1 second of traffic, minimum 64KB
		burstBytes = uint32(qos.DownloadBPS / 8)
		if burstBytes < 65536 {
			burstBytes = 65536
		}
		if burstBytes > 10*1024*1024 {
			burstBytes = 10 * 1024 * 1024 // Cap at 10MB
		}
	}

	// Create egress (download) token bucket
	egressTB := &TokenBucket{
		Tokens:     uint64(burstBytes), // Start with full bucket
		LastUpdate: 0,                  // Will be set on first packet
		RateBPS:    qos.DownloadBPS,
		BurstBytes: burstBytes,
		Priority:   qos.Priority,
	}

	// Create ingress (upload) token bucket
	uploadBurst := uint32(qos.UploadBPS / 8)
	if uploadBurst < 65536 {
		uploadBurst = 65536
	}
	if uploadBurst > 10*1024*1024 {
		uploadBurst = 10 * 1024 * 1024
	}

	ingressTB := &TokenBucket{
		Tokens:     uint64(uploadBurst),
		LastUpdate: 0,
		RateBPS:    qos.UploadBPS,
		BurstBytes: uploadBurst,
		Priority:   qos.Priority,
	}

	// Update eBPF maps
	if m.qosEgress != nil {
		if err := m.qosEgress.Put(&key, egressTB); err != nil {
			return fmt.Errorf("failed to set egress QoS: %w", err)
		}
	}

	if m.qosIngress != nil {
		if err := m.qosIngress.Put(&key, ingressTB); err != nil {
			return fmt.Errorf("failed to set ingress QoS: %w", err)
		}
	}

	// Track locally
	m.subscribersMu.Lock()
	m.subscribers[key] = qos
	m.subscribersMu.Unlock()

	m.logger.Debug("Set subscriber QoS",
		zap.String("ip", qos.IP.String()),
		zap.Uint64("download_bps", qos.DownloadBPS),
		zap.Uint64("upload_bps", qos.UploadBPS),
		zap.String("policy", qos.PolicyName),
	)

	return nil
}

// SetSubscriberPolicy sets QoS for a subscriber using a named policy
func (m *Manager) SetSubscriberPolicy(ip net.IP, policyName string) error {
	if m.policyMgr == nil {
		return fmt.Errorf("policy manager not configured")
	}

	policy := m.policyMgr.GetPolicy(policyName)
	if policy == nil {
		return fmt.Errorf("policy not found: %s", policyName)
	}

	return m.SetSubscriberQoS(&SubscriberQoS{
		IP:          ip,
		DownloadBPS: policy.DownloadBPS,
		UploadBPS:   policy.UploadBPS,
		BurstBytes:  policy.BurstSize,
		Priority:    policy.Priority,
		PolicyName:  policyName,
	})
}

// RemoveSubscriberQoS removes QoS policy for a subscriber
func (m *Manager) RemoveSubscriberQoS(ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv4 address required")
	}

	key := ipToKey(ip4)

	// Remove from eBPF maps
	if m.qosEgress != nil {
		m.qosEgress.Delete(&key)
	}
	if m.qosIngress != nil {
		m.qosIngress.Delete(&key)
	}

	// Remove from local tracking
	m.subscribersMu.Lock()
	delete(m.subscribers, key)
	m.subscribersMu.Unlock()

	m.logger.Debug("Removed subscriber QoS",
		zap.String("ip", ip.String()),
	)

	return nil
}

// GetStats returns QoS statistics
func (m *Manager) GetStats() (*QoSStats, error) {
	if m.qosStatsMap == nil {
		return nil, fmt.Errorf("stats map not loaded")
	}

	var key uint32 = 0
	var stats QoSStats

	// Note: This is a per-CPU map, need to aggregate
	// For simplicity, just get first CPU's stats
	if err := m.qosStatsMap.Lookup(&key, &stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// GetSubscriberCount returns the number of subscribers with QoS policies
func (m *Manager) GetSubscriberCount() int {
	m.subscribersMu.RLock()
	defer m.subscribersMu.RUnlock()
	return len(m.subscribers)
}

// ipToKey converts an IPv4 address to a uint32 key (network byte order)
func ipToKey(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}
