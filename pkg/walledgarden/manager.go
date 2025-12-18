package walledgarden

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// SubscriberState represents whether a subscriber is in the walled garden.
type SubscriberState uint8

const (
	// StateUnknown - subscriber is not known, apply walled garden.
	StateUnknown SubscriberState = iota
	// StateWalledGarden - subscriber is in walled garden (captive portal).
	StateWalledGarden
	// StateProvisioned - subscriber is fully provisioned, bypass walled garden.
	StateProvisioned
	// StateBlocked - subscriber is blocked from all access.
	StateBlocked
)

func (s SubscriberState) String() string {
	switch s {
	case StateUnknown:
		return "UNKNOWN"
	case StateWalledGarden:
		return "WALLED_GARDEN"
	case StateProvisioned:
		return "PROVISIONED"
	case StateBlocked:
		return "BLOCKED"
	default:
		return "INVALID"
	}
}

// WalledGardenEntry represents an entry in the walled garden eBPF map.
// Key: MAC address (uint64)
type WalledGardenEntry struct {
	State       uint8
	VlanID      uint16
	_           uint8  // padding
	PortalIP    uint32 // Network byte order - IP to redirect HTTP to
	ExpiryTime  uint64 // Unix timestamp when entry expires
	RedirectURL uint32 // Index into redirect URL table (for future use)
}

// AllowedDestination represents a destination that bypasses the walled garden.
type AllowedDestination struct {
	IP     uint32 // Network byte order
	Port   uint16
	Proto  uint8  // IPPROTO_TCP=6, IPPROTO_UDP=17
	_      uint8  // padding
	Reason uint32 // Reason code (for logging)
}

// Config contains walled garden configuration.
type Config struct {
	// Interface to attach eBPF program to.
	Interface string

	// PortalIP is the IP address of the captive portal server.
	PortalIP net.IP

	// PortalPort is the HTTP port of the captive portal (typically 80 or 8080).
	PortalPort uint16

	// AllowedDNS is the list of DNS servers subscribers can reach.
	AllowedDNS []net.IP

	// AllowedDestinations are additional destinations that bypass the walled garden.
	AllowedDestinations []AllowedDestEntry

	// DefaultTimeout is how long unknown MACs stay in walled garden before re-check.
	DefaultTimeout time.Duration

	// MaxEntries is the maximum number of entries in the eBPF map.
	MaxEntries uint32
}

// AllowedDestEntry represents an allowed destination.
type AllowedDestEntry struct {
	IP    net.IP
	Port  uint16
	Proto uint8
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		PortalIP:       net.ParseIP("10.255.255.1"),
		PortalPort:     8080,
		AllowedDNS:     []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		DefaultTimeout: 5 * time.Minute,
		MaxEntries:     100000,
	}
}

// Manager manages the walled garden eBPF program.
type Manager struct {
	config Config
	logger *zap.Logger

	mu sync.RWMutex

	// eBPF maps (populated when program is loaded)
	subscriberMap   *ebpf.Map
	allowedDestsMap *ebpf.Map
	statsMap        *ebpf.Map

	// Local cache for quick lookups
	cache map[uint64]SubscriberState

	// Callbacks
	onRedirect func(mac net.HardwareAddr, srcIP net.IP)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new walled garden manager.
func NewManager(config Config, logger *zap.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		config: config,
		logger: logger,
		cache:  make(map[uint64]SubscriberState),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start initializes the walled garden.
func (m *Manager) Start() error {
	m.logger.Info("Starting walled garden manager",
		zap.String("portal_ip", m.config.PortalIP.String()),
		zap.Uint16("portal_port", m.config.PortalPort),
	)

	// Initialize allowed destinations map if eBPF is loaded
	if m.allowedDestsMap != nil {
		if err := m.initAllowedDestinations(); err != nil {
			return fmt.Errorf("init allowed destinations: %w", err)
		}
	}

	// Start expiry checker
	m.wg.Add(1)
	go m.expiryChecker()

	m.logger.Info("Walled garden manager started")
	return nil
}

// Stop shuts down the walled garden manager.
func (m *Manager) Stop() error {
	m.logger.Info("Stopping walled garden manager")
	m.cancel()
	m.wg.Wait()
	return nil
}

// SetEBPFMaps sets the eBPF map references (called by eBPF loader).
func (m *Manager) SetEBPFMaps(subscriber, allowedDests, stats *ebpf.Map) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscriberMap = subscriber
	m.allowedDestsMap = allowedDests
	m.statsMap = stats
}

// OnRedirect registers a callback for redirect events.
func (m *Manager) OnRedirect(callback func(mac net.HardwareAddr, srcIP net.IP)) {
	m.onRedirect = callback
}

// initAllowedDestinations populates the allowed destinations map.
func (m *Manager) initAllowedDestinations() error {
	// Add DNS servers
	for _, dns := range m.config.AllowedDNS {
		entry := AllowedDestination{
			IP:     ipToUint32(dns),
			Port:   53,
			Proto:  17, // UDP
			Reason: 1,  // DNS
		}
		key := m.allowedDestKey(dns, 53, 17)
		if err := m.allowedDestsMap.Put(&key, &entry); err != nil {
			return fmt.Errorf("add DNS %s: %w", dns, err)
		}
	}

	// Add portal server
	portalEntry := AllowedDestination{
		IP:     ipToUint32(m.config.PortalIP),
		Port:   m.config.PortalPort,
		Proto:  6, // TCP
		Reason: 2, // Portal
	}
	key := m.allowedDestKey(m.config.PortalIP, m.config.PortalPort, 6)
	if err := m.allowedDestsMap.Put(&key, &portalEntry); err != nil {
		return fmt.Errorf("add portal: %w", err)
	}

	// Add additional allowed destinations
	for _, dest := range m.config.AllowedDestinations {
		entry := AllowedDestination{
			IP:     ipToUint32(dest.IP),
			Port:   dest.Port,
			Proto:  dest.Proto,
			Reason: 3, // Custom
		}
		key := m.allowedDestKey(dest.IP, dest.Port, dest.Proto)
		if err := m.allowedDestsMap.Put(&key, &entry); err != nil {
			return fmt.Errorf("add allowed dest %s: %w", dest.IP, err)
		}
	}

	m.logger.Info("Initialized allowed destinations",
		zap.Int("dns_servers", len(m.config.AllowedDNS)),
		zap.Int("custom_dests", len(m.config.AllowedDestinations)),
	)

	return nil
}

// allowedDestKey generates a key for the allowed destinations map.
func (m *Manager) allowedDestKey(ip net.IP, port uint16, proto uint8) uint64 {
	// Key: IP (32 bits) | Port (16 bits) | Proto (8 bits) | padding (8 bits)
	ipNum := ipToUint32(ip)
	return uint64(ipNum)<<32 | uint64(port)<<16 | uint64(proto)<<8
}

// SetSubscriberState sets the state for a MAC address.
func (m *Manager) SetSubscriberState(mac net.HardwareAddr, state SubscriberState) error {
	macKey := macToUint64(mac)

	m.mu.Lock()
	m.cache[macKey] = state
	m.mu.Unlock()

	// Update eBPF map if loaded
	if m.subscriberMap != nil {
		entry := WalledGardenEntry{
			State:      uint8(state),
			PortalIP:   ipToUint32(m.config.PortalIP),
			ExpiryTime: uint64(time.Now().Add(m.config.DefaultTimeout).Unix()),
		}
		if err := m.subscriberMap.Put(&macKey, &entry); err != nil {
			return fmt.Errorf("update eBPF map: %w", err)
		}
	}

	m.logger.Debug("Set subscriber state",
		zap.String("mac", mac.String()),
		zap.String("state", state.String()),
	)

	return nil
}

// GetSubscriberState returns the state for a MAC address.
func (m *Manager) GetSubscriberState(mac net.HardwareAddr) SubscriberState {
	macKey := macToUint64(mac)

	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, ok := m.cache[macKey]; ok {
		return state
	}
	return StateUnknown
}

// AddToWalledGarden adds a MAC to the walled garden.
func (m *Manager) AddToWalledGarden(mac net.HardwareAddr, vlanID uint16) error {
	macKey := macToUint64(mac)

	m.mu.Lock()
	m.cache[macKey] = StateWalledGarden
	m.mu.Unlock()

	if m.subscriberMap != nil {
		entry := WalledGardenEntry{
			State:      uint8(StateWalledGarden),
			VlanID:     vlanID,
			PortalIP:   ipToUint32(m.config.PortalIP),
			ExpiryTime: uint64(time.Now().Add(m.config.DefaultTimeout).Unix()),
		}
		if err := m.subscriberMap.Put(&macKey, &entry); err != nil {
			return fmt.Errorf("add to walled garden: %w", err)
		}
	}

	m.logger.Info("Added to walled garden",
		zap.String("mac", mac.String()),
		zap.Uint16("vlan", vlanID),
	)

	return nil
}

// ReleaseFromWalledGarden releases a MAC from the walled garden (provisioned).
func (m *Manager) ReleaseFromWalledGarden(mac net.HardwareAddr) error {
	return m.SetSubscriberState(mac, StateProvisioned)
}

// BlockMAC blocks a MAC from all network access.
func (m *Manager) BlockMAC(mac net.HardwareAddr) error {
	return m.SetSubscriberState(mac, StateBlocked)
}

// RemoveMAC removes a MAC from tracking completely.
func (m *Manager) RemoveMAC(mac net.HardwareAddr) error {
	macKey := macToUint64(mac)

	m.mu.Lock()
	delete(m.cache, macKey)
	m.mu.Unlock()

	if m.subscriberMap != nil {
		if err := m.subscriberMap.Delete(&macKey); err != nil {
			// Ignore not found errors
			if err.Error() != "key does not exist" {
				return fmt.Errorf("remove from eBPF map: %w", err)
			}
		}
	}

	m.logger.Debug("Removed MAC from walled garden",
		zap.String("mac", mac.String()),
	)

	return nil
}

// expiryChecker periodically checks for expired entries.
func (m *Manager) expiryChecker() {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkExpiredEntries()
		}
	}
}

// checkExpiredEntries removes expired entries from the map.
func (m *Manager) checkExpiredEntries() {
	if m.subscriberMap == nil {
		return
	}

	now := uint64(time.Now().Unix())
	var expired []uint64

	// Iterate through the map to find expired entries
	var key uint64
	var entry WalledGardenEntry
	iter := m.subscriberMap.Iterate()
	for iter.Next(&key, &entry) {
		if entry.ExpiryTime > 0 && entry.ExpiryTime < now {
			expired = append(expired, key)
		}
	}

	// Remove expired entries
	for _, key := range expired {
		m.subscriberMap.Delete(&key)
		m.mu.Lock()
		delete(m.cache, key)
		m.mu.Unlock()
	}

	if len(expired) > 0 {
		m.logger.Info("Removed expired walled garden entries",
			zap.Int("count", len(expired)),
		)
	}
}

// Stats returns walled garden statistics.
func (m *Manager) Stats() WalledGardenStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := WalledGardenStats{}
	for _, state := range m.cache {
		switch state {
		case StateWalledGarden:
			stats.InWalledGarden++
		case StateProvisioned:
			stats.Provisioned++
		case StateBlocked:
			stats.Blocked++
		default:
			stats.Unknown++
		}
	}
	stats.Total = len(m.cache)

	return stats
}

// WalledGardenStats contains statistics.
type WalledGardenStats struct {
	Total          int
	InWalledGarden int
	Provisioned    int
	Blocked        int
	Unknown        int
}

// ListWalledGardenMACs returns all MACs currently in the walled garden.
func (m *Manager) ListWalledGardenMACs() []net.HardwareAddr {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var macs []net.HardwareAddr
	for macKey, state := range m.cache {
		if state == StateWalledGarden {
			macs = append(macs, uint64ToMAC(macKey))
		}
	}
	return macs
}

// === Helper Functions ===

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func macToUint64(mac net.HardwareAddr) uint64 {
	if len(mac) < 6 {
		return 0
	}
	var result uint64
	for i := 0; i < 6; i++ {
		result = (result << 8) | uint64(mac[i])
	}
	return result
}

func uint64ToMAC(n uint64) net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	for i := 5; i >= 0; i-- {
		mac[i] = byte(n & 0xFF)
		n >>= 8
	}
	return mac
}
