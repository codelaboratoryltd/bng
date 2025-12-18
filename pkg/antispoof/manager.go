package antispoof

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// Mode represents the anti-spoofing mode
type Mode uint8

const (
	ModeDisabled Mode = 0 // No validation
	ModeStrict   Mode = 1 // Source must match allocated IP exactly
	ModeLoose    Mode = 2 // Source must be in known ranges
	ModeLogOnly  Mode = 3 // Log violations but don't drop
)

// SubscriberBinding represents the allowed source addresses for a subscriber
type SubscriberBinding struct {
	IPv4Addr  uint32
	IPv6Addr  [16]byte
	IPv4Valid uint8
	IPv6Valid uint8
	Mode      uint8
	_         uint8
}

// Config holds anti-spoofing configuration
type Config struct {
	DefaultMode   uint8
	LogViolations uint8
	_             [6]byte
}

// Stats holds anti-spoofing statistics
type Stats struct {
	PacketsAllowed uint64
	PacketsDropped uint64
	PacketsLogged  uint64
	IPv4Violations uint64
	IPv6Violations uint64
	UnknownMAC     uint64
}

// SpoofEvent represents a detected spoofing attempt
type SpoofEvent struct {
	Timestamp   uint64
	SrcMAC      [6]byte
	Protocol    uint8 // 4 = IPv4, 6 = IPv6
	_           uint8
	SpoofedIP   uint32
	AllowedIP   uint32
	SpoofedIPv6 [16]byte
	AllowedIPv6 [16]byte
}

// Manager handles anti-spoofing via eBPF
type Manager struct {
	iface   string
	bpfPath string
	logger  *zap.Logger
	mode    Mode

	// eBPF resources
	collection *ebpf.Collection
	bindings   *ebpf.Map
	config     *ebpf.Map
	stats      *ebpf.Map
	ranges     *ebpf.Map

	// Local tracking
	subscribers   map[uint64]*Binding
	subscribersMu sync.RWMutex
}

// Binding tracks a subscriber's allowed addresses
type Binding struct {
	MAC      net.HardwareAddr
	IPv4     net.IP
	IPv6     net.IP
	Mode     Mode
	Verified bool
}

// ManagerConfig configures the anti-spoofing manager
type ManagerConfig struct {
	Interface   string
	BPFPath     string
	DefaultMode Mode
	LogEnabled  bool
}

// NewManager creates a new anti-spoofing manager
func NewManager(cfg ManagerConfig, logger *zap.Logger) (*Manager, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface required")
	}

	bpfPath := cfg.BPFPath
	if bpfPath == "" {
		bpfPath = "bpf/antispoof.bpf.o"
	}

	mode := cfg.DefaultMode
	if mode == 0 {
		mode = ModeStrict
	}

	return &Manager{
		iface:       cfg.Interface,
		bpfPath:     bpfPath,
		logger:      logger,
		mode:        mode,
		subscribers: make(map[uint64]*Binding),
	}, nil
}

// Start loads the eBPF programs and attaches them
func (m *Manager) Start(ctx context.Context) error {
	m.logger.Info("Starting anti-spoofing manager",
		zap.String("interface", m.iface),
		zap.String("mode", modeName(m.mode)),
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
	m.bindings = coll.Maps["subscriber_bindings"]
	if m.bindings == nil {
		return fmt.Errorf("subscriber_bindings map not found")
	}

	m.config = coll.Maps["antispoof_config"]
	m.stats = coll.Maps["antispoof_stats"]
	m.ranges = coll.Maps["allowed_ranges_v4"]

	// Set default configuration
	if m.config != nil {
		cfg := Config{
			DefaultMode:   uint8(m.mode),
			LogViolations: 1,
		}
		var key uint32 = 0
		if err := m.config.Put(&key, &cfg); err != nil {
			m.logger.Warn("Failed to set config", zap.Error(err))
		}
	}

	// Attach TC program
	if err := m.attachTCProgram(coll); err != nil {
		return err
	}

	m.logger.Info("Anti-spoofing eBPF program attached",
		zap.String("interface", m.iface),
	)

	return nil
}

// Stop cleans up resources
func (m *Manager) Stop() error {
	m.logger.Info("Stopping anti-spoofing manager")

	if m.collection != nil {
		m.collection.Close()
	}

	return nil
}

// AddBinding adds or updates a subscriber's allowed source address
func (m *Manager) AddBinding(mac net.HardwareAddr, ipv4 net.IP) error {
	if len(mac) != 6 {
		return fmt.Errorf("invalid MAC address")
	}

	macKey := macToUint64(mac)

	binding := SubscriberBinding{
		Mode: uint8(m.mode),
	}

	if ipv4 != nil {
		ip4 := ipv4.To4()
		if ip4 != nil {
			binding.IPv4Addr = binary.BigEndian.Uint32(ip4)
			binding.IPv4Valid = 1
		}
	}

	// Update eBPF map
	if m.bindings != nil {
		if err := m.bindings.Put(&macKey, &binding); err != nil {
			return fmt.Errorf("failed to update binding: %w", err)
		}
	}

	// Track locally
	m.subscribersMu.Lock()
	m.subscribers[macKey] = &Binding{
		MAC:      mac,
		IPv4:     ipv4,
		Mode:     m.mode,
		Verified: true,
	}
	m.subscribersMu.Unlock()

	m.logger.Debug("Added anti-spoof binding",
		zap.String("mac", mac.String()),
		zap.String("ipv4", ipv4.String()),
	)

	return nil
}

// AddBindingV6 adds an IPv6 binding for a subscriber
func (m *Manager) AddBindingV6(mac net.HardwareAddr, ipv6 net.IP) error {
	if len(mac) != 6 {
		return fmt.Errorf("invalid MAC address")
	}

	macKey := macToUint64(mac)

	// First get existing binding
	var existing SubscriberBinding
	if m.bindings != nil {
		m.bindings.Lookup(&macKey, &existing)
	}

	// Update IPv6
	if ipv6 != nil {
		ip6 := ipv6.To16()
		if ip6 != nil {
			copy(existing.IPv6Addr[:], ip6)
			existing.IPv6Valid = 1
		}
	}

	existing.Mode = uint8(m.mode)

	// Update eBPF map
	if m.bindings != nil {
		if err := m.bindings.Put(&macKey, &existing); err != nil {
			return fmt.Errorf("failed to update binding: %w", err)
		}
	}

	m.logger.Debug("Added anti-spoof IPv6 binding",
		zap.String("mac", mac.String()),
		zap.String("ipv6", ipv6.String()),
	)

	return nil
}

// RemoveBinding removes a subscriber's binding
func (m *Manager) RemoveBinding(mac net.HardwareAddr) error {
	macKey := macToUint64(mac)

	if m.bindings != nil {
		m.bindings.Delete(&macKey)
	}

	m.subscribersMu.Lock()
	delete(m.subscribers, macKey)
	m.subscribersMu.Unlock()

	m.logger.Debug("Removed anti-spoof binding",
		zap.String("mac", mac.String()),
	)

	return nil
}

// AddAllowedRange adds a network range for loose mode validation
func (m *Manager) AddAllowedRange(network *net.IPNet) error {
	if m.ranges == nil {
		return fmt.Errorf("ranges map not loaded")
	}

	ip4 := network.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv4 network required")
	}

	ones, _ := network.Mask.Size()

	type lpmKey struct {
		Prefixlen uint32
		IP        uint32
	}

	key := lpmKey{
		Prefixlen: uint32(ones),
		IP:        binary.BigEndian.Uint32(ip4),
	}

	var value uint8 = 1
	if err := m.ranges.Put(&key, &value); err != nil {
		return fmt.Errorf("failed to add range: %w", err)
	}

	m.logger.Info("Added allowed range",
		zap.String("network", network.String()),
	)

	return nil
}

// GetStats returns anti-spoofing statistics
func (m *Manager) GetStats() (*Stats, error) {
	if m.stats == nil {
		return nil, fmt.Errorf("stats map not loaded")
	}

	var key uint32 = 0
	var stats Stats

	if err := m.stats.Lookup(&key, &stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// GetBindingCount returns the number of active bindings
func (m *Manager) GetBindingCount() int {
	m.subscribersMu.RLock()
	defer m.subscribersMu.RUnlock()
	return len(m.subscribers)
}

// SetMode changes the anti-spoofing mode
func (m *Manager) SetMode(mode Mode) error {
	m.mode = mode

	if m.config != nil {
		cfg := Config{
			DefaultMode:   uint8(mode),
			LogViolations: 1,
		}
		var key uint32 = 0
		if err := m.config.Put(&key, &cfg); err != nil {
			return fmt.Errorf("failed to update config: %w", err)
		}
	}

	m.logger.Info("Anti-spoofing mode changed",
		zap.String("mode", modeName(mode)),
	)

	return nil
}

// Helper functions

func macToUint64(mac net.HardwareAddr) uint64 {
	return uint64(mac[0])<<40 |
		uint64(mac[1])<<32 |
		uint64(mac[2])<<24 |
		uint64(mac[3])<<16 |
		uint64(mac[4])<<8 |
		uint64(mac[5])
}

func modeName(mode Mode) string {
	switch mode {
	case ModeDisabled:
		return "disabled"
	case ModeStrict:
		return "strict"
	case ModeLoose:
		return "loose"
	case ModeLogOnly:
		return "log-only"
	default:
		return "unknown"
	}
}
