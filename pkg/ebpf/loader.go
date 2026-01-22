package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// PoolAssignment represents a subscriber's pool assignment (mirrors eBPF struct)
type PoolAssignment struct {
	PoolID      uint32
	AllocatedIP uint32 // Network byte order
	VlanID      uint32 // Deprecated: use VLANKey for QinQ
	ClientClass uint8
	LeaseExpiry uint64 // Unix timestamp (seconds)
	Flags       uint8
	_           [3]byte // Padding
}

// VLANKey represents a QinQ VLAN key for subscriber lookup (mirrors eBPF struct)
// Used in European PoI deployments where subscribers are identified by
// S-VLAN (outer) + C-VLAN (inner) combination
type VLANKey struct {
	STag uint16 // Service VLAN (outer, 802.1ad)
	CTag uint16 // Customer VLAN (inner, 802.1Q)
}

// IPPool represents an IP pool configuration (mirrors eBPF struct)
type IPPool struct {
	Network      uint32 // Network address (network byte order)
	PrefixLen    uint8
	_            [3]byte
	Gateway      uint32 // Gateway IP (network byte order)
	DNSPrimary   uint32 // Primary DNS (network byte order)
	DNSSecondary uint32 // Secondary DNS (network byte order)
	LeaseTime    uint32 // Lease duration in seconds
	_            uint32 // Padding
}

// DHCPStats must match the layout of dhcp_stats in bpf/maps.h
type DHCPStats struct {
	TotalRequests    uint64
	FastpathHits     uint64
	FastpathMisses   uint64
	Errors           uint64
	CacheExpired     uint64
	Option82Present  uint64 // Issue #15: packets with Option 82
	Option82Absent   uint64 // Issue #15: packets without Option 82
	BroadcastReplies uint64 // Issue #17: broadcast L2 replies
	UnicastReplies   uint64 // Issue #17: unicast L2 replies
	VLANPackets      uint64 // Issue #17: VLAN-tagged packets
}

// ServerConfig represents DHCP server configuration for eBPF (mirrors eBPF struct)
type ServerConfig struct {
	ServerMAC      [6]byte
	_              [2]byte // Padding
	ServerIP       uint32  // Network byte order
	InterfaceIndex uint32
}

// Loader handles loading and managing eBPF programs
type Loader struct {
	iface   string
	bpfPath string
	logger  *zap.Logger
	xdpMode link.XDPAttachFlags

	// eBPF resources
	collection           *ebpf.Collection
	xdpLink              link.Link
	subscriberPools      *ebpf.Map
	vlanSubscriberPools  *ebpf.Map // QinQ VLAN-based subscriber lookup
	ipPools              *ebpf.Map
	statsMap             *ebpf.Map
	serverConfigMap      *ebpf.Map
	circuitIDMap         *ebpf.Map // Issue #15: Circuit-ID to MAC mapping (hash-based)
	circuitIDSubscribers *ebpf.Map // Issue #56: Circuit-ID to pool_assignment (fixed-size key)
}

// LoaderOption configures the Loader
type LoaderOption func(*Loader)

// WithBPFPath sets the path to the compiled eBPF program
func WithBPFPath(path string) LoaderOption {
	return func(l *Loader) {
		l.bpfPath = path
	}
}

// WithXDPMode sets the XDP attach mode (driver, skb, or hardware)
func WithXDPMode(mode link.XDPAttachFlags) LoaderOption {
	return func(l *Loader) {
		l.xdpMode = mode
	}
}

// NewLoader creates a new eBPF program loader
func NewLoader(iface string, logger *zap.Logger, opts ...LoaderOption) (*Loader, error) {
	if iface == "" {
		return nil, fmt.Errorf("interface name is required")
	}

	l := &Loader{
		iface:   iface,
		bpfPath: "bpf/dhcp_fastpath.bpf.o",
		logger:  logger,
		xdpMode: link.XDPGenericMode, // Default to SKB mode for compatibility
	}

	for _, opt := range opts {
		opt(l)
	}

	return l, nil
}

// Load loads the eBPF program and attaches it to the interface
func (l *Loader) Load(ctx context.Context) error {
	l.logger.Info("Loading eBPF program",
		zap.String("interface", l.iface),
		zap.String("bpf_path", l.bpfPath),
	)

	// Get interface
	iface, err := net.InterfaceByName(l.iface)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", l.iface, err)
	}

	l.logger.Info("Interface found",
		zap.String("name", iface.Name),
		zap.Int("index", iface.Index),
		zap.String("mac", iface.HardwareAddr.String()),
	)

	// Resolve BPF path
	bpfPath := l.bpfPath
	if !filepath.IsAbs(bpfPath) {
		// Try relative to working directory
		if _, err := os.Stat(bpfPath); os.IsNotExist(err) {
			// Try relative to executable
			exe, _ := os.Executable()
			bpfPath = filepath.Join(filepath.Dir(exe), l.bpfPath)
		}
	}

	// Load compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec(bpfPath)
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec from %s: %w", bpfPath, err)
	}

	l.logger.Debug("eBPF spec loaded",
		zap.Int("programs", len(spec.Programs)),
		zap.Int("maps", len(spec.Maps)),
	)

	// Create collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create eBPF collection: %w", err)
	}
	l.collection = coll

	// Get map references
	l.subscriberPools = coll.Maps["subscriber_pools"]
	if l.subscriberPools == nil {
		return fmt.Errorf("subscriber_pools map not found")
	}

	// QinQ VLAN-based subscriber map (optional - not all deployments use QinQ)
	l.vlanSubscriberPools = coll.Maps["vlan_subscriber_pools"]
	if l.vlanSubscriberPools != nil {
		l.logger.Info("QinQ VLAN subscriber map loaded")
	}

	l.ipPools = coll.Maps["ip_pools"]
	if l.ipPools == nil {
		return fmt.Errorf("ip_pools map not found")
	}

	l.statsMap = coll.Maps["stats_map"]
	if l.statsMap == nil {
		return fmt.Errorf("stats_map map not found")
	}

	l.serverConfigMap = coll.Maps["server_config"]
	if l.serverConfigMap == nil {
		return fmt.Errorf("server_config map not found")
	}

	// Issue #15: Circuit-ID map (optional - may not be present in older programs)
	// circuit_id_map uses FNV-1a hash as key. While FNV-1a has good distribution,
	// hash collisions are possible with very large subscriber counts (1M+).
	// For production deployments at scale, consider monitoring collision metrics
	// or implementing collision detection in the value struct.
	l.circuitIDMap = coll.Maps["circuit_id_map"]
	if l.circuitIDMap == nil {
		l.logger.Warn("circuit_id_map not found - Option 82 circuit-id lookup disabled")
	}

	// Issue #56: Circuit-ID subscribers map (fixed-size key for verifier-safe lookup)
	// This map uses a fixed 32-byte key for direct circuit-ID to pool_assignment lookup,
	// avoiding the hashing loop that caused verifier issues in Issue #31.
	l.circuitIDSubscribers = coll.Maps["circuit_id_subscribers"]
	if l.circuitIDSubscribers == nil {
		l.logger.Warn("circuit_id_subscribers not found - fixed-size circuit-id lookup disabled")
	} else {
		l.logger.Info("Circuit-ID subscriber map loaded (Issue #56)")
	}

	// Initialize stats map with zeroed entry
	var statsKey uint32 = 0
	var stats DHCPStats
	if err := l.statsMap.Put(&statsKey, &stats); err != nil {
		l.logger.Warn("Failed to initialize stats map", zap.Error(err))
	}

	// Get XDP program
	prog := coll.Programs["dhcp_fastpath_prog"]
	if prog == nil {
		return fmt.Errorf("dhcp_fastpath_prog not found in collection")
	}

	l.logger.Info("Attaching XDP program",
		zap.Int("ifindex", iface.Index),
		zap.Uint32("mode", uint32(l.xdpMode)),
	)

	// Attach XDP program to interface
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     l.xdpMode,
	})
	if err != nil {
		// If driver mode fails, try generic (SKB) mode
		if l.xdpMode != link.XDPGenericMode {
			l.logger.Warn("Driver mode XDP attach failed, trying generic mode",
				zap.Error(err),
			)
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: iface.Index,
				Flags:     link.XDPGenericMode,
			})
		}
		if err != nil {
			return fmt.Errorf("failed to attach XDP program: %w", err)
		}
	}
	l.xdpLink = xdpLink

	l.logger.Info("eBPF program loaded and attached successfully",
		zap.String("interface", l.iface),
	)

	return nil
}

// Close detaches the eBPF program and cleans up resources
func (l *Loader) Close() error {
	l.logger.Info("Cleaning up eBPF resources")

	var errs []error

	if l.xdpLink != nil {
		if err := l.xdpLink.Close(); err != nil {
			l.logger.Error("Failed to detach XDP program", zap.Error(err))
			errs = append(errs, err)
		}
	}

	if l.collection != nil {
		l.collection.Close()
	}

	l.logger.Info("eBPF resources cleaned up")

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// === Map Operations ===

// AddSubscriber adds a subscriber to the fast path cache
func (l *Loader) AddSubscriber(mac uint64, assignment *PoolAssignment) error {
	if l.subscriberPools == nil {
		return fmt.Errorf("subscriber_pools map not loaded")
	}

	return l.subscriberPools.Put(&mac, assignment)
}

// RemoveSubscriber removes a subscriber from the fast path cache
func (l *Loader) RemoveSubscriber(mac uint64) error {
	if l.subscriberPools == nil {
		return fmt.Errorf("subscriber_pools map not loaded")
	}

	return l.subscriberPools.Delete(&mac)
}

// GetSubscriber looks up a subscriber in the cache
func (l *Loader) GetSubscriber(mac uint64) (*PoolAssignment, error) {
	if l.subscriberPools == nil {
		return nil, fmt.Errorf("subscriber_pools map not loaded")
	}

	var assignment PoolAssignment
	if err := l.subscriberPools.Lookup(&mac, &assignment); err != nil {
		return nil, err
	}

	return &assignment, nil
}

// === QinQ VLAN-based Subscriber Operations ===

// AddVLANSubscriber adds a subscriber to the QinQ VLAN-based fast path cache
// Used in European PoI deployments where subscribers are identified by S-TAG/C-TAG
func (l *Loader) AddVLANSubscriber(sTag, cTag uint16, assignment *PoolAssignment) error {
	if l.vlanSubscriberPools == nil {
		return fmt.Errorf("vlan_subscriber_pools map not loaded (QinQ not enabled)")
	}

	key := VLANKey{STag: sTag, CTag: cTag}
	return l.vlanSubscriberPools.Put(&key, assignment)
}

// RemoveVLANSubscriber removes a subscriber from the QinQ VLAN-based cache
func (l *Loader) RemoveVLANSubscriber(sTag, cTag uint16) error {
	if l.vlanSubscriberPools == nil {
		return fmt.Errorf("vlan_subscriber_pools map not loaded (QinQ not enabled)")
	}

	key := VLANKey{STag: sTag, CTag: cTag}
	return l.vlanSubscriberPools.Delete(&key)
}

// GetVLANSubscriber looks up a subscriber by VLAN tags
func (l *Loader) GetVLANSubscriber(sTag, cTag uint16) (*PoolAssignment, error) {
	if l.vlanSubscriberPools == nil {
		return nil, fmt.Errorf("vlan_subscriber_pools map not loaded (QinQ not enabled)")
	}

	key := VLANKey{STag: sTag, CTag: cTag}
	var assignment PoolAssignment
	if err := l.vlanSubscriberPools.Lookup(&key, &assignment); err != nil {
		return nil, err
	}

	return &assignment, nil
}

// HasVLANSupport returns true if the QinQ VLAN subscriber map is loaded
func (l *Loader) HasVLANSupport() bool {
	return l.vlanSubscriberPools != nil
}

// AddPool adds an IP pool configuration
func (l *Loader) AddPool(poolID uint32, pool *IPPool) error {
	if l.ipPools == nil {
		return fmt.Errorf("ip_pools map not loaded")
	}

	return l.ipPools.Put(&poolID, pool)
}

// RemovePool removes an IP pool
func (l *Loader) RemovePool(poolID uint32) error {
	if l.ipPools == nil {
		return fmt.Errorf("ip_pools map not loaded")
	}

	return l.ipPools.Delete(&poolID)
}

// GetPool looks up a pool configuration
func (l *Loader) GetPool(poolID uint32) (*IPPool, error) {
	if l.ipPools == nil {
		return nil, fmt.Errorf("ip_pools map not loaded")
	}

	var pool IPPool
	if err := l.ipPools.Lookup(&poolID, &pool); err != nil {
		return nil, err
	}

	return &pool, nil
}

// GetStats returns current DHCP statistics
func (l *Loader) GetStats() (*DHCPStats, error) {
	if l.statsMap == nil {
		return nil, fmt.Errorf("stats_map not loaded")
	}

	var key uint32 = 0
	var stats DHCPStats
	if err := l.statsMap.Lookup(&key, &stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// ResetStats resets the statistics counters
func (l *Loader) ResetStats() error {
	if l.statsMap == nil {
		return fmt.Errorf("stats_map not loaded")
	}

	var key uint32 = 0
	var stats DHCPStats
	return l.statsMap.Put(&key, &stats)
}

// SetServerConfig configures the DHCP server parameters for eBPF fast path
func (l *Loader) SetServerConfig(serverMAC net.HardwareAddr, serverIP net.IP, ifIndex int) error {
	if l.serverConfigMap == nil {
		return fmt.Errorf("server_config map not loaded")
	}

	var config ServerConfig
	if len(serverMAC) >= 6 {
		copy(config.ServerMAC[:], serverMAC[:6])
	}
	config.ServerIP = IPToUint32(serverIP)
	config.InterfaceIndex = uint32(ifIndex)

	var key uint32 = 0
	return l.serverConfigMap.Put(&key, &config)
}

// GetServerConfig retrieves the current server configuration
func (l *Loader) GetServerConfig() (*ServerConfig, error) {
	if l.serverConfigMap == nil {
		return nil, fmt.Errorf("server_config map not loaded")
	}

	var key uint32 = 0
	var config ServerConfig
	if err := l.serverConfigMap.Lookup(&key, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// === Circuit-ID Map Operations (Issue #15) ===

// FNV-1a hash constants (must match eBPF implementation)
const (
	fnv1aInit  uint64 = 0xcbf29ce484222325
	fnv1aPrime uint64 = 0x100000001b3
)

// HashCircuitID computes FNV-1a hash of a circuit-id string
// This must match the hash function in the eBPF program
func HashCircuitID(circuitID []byte) uint64 {
	hash := fnv1aInit
	for _, b := range circuitID {
		hash ^= uint64(b)
		hash *= fnv1aPrime
	}
	return hash
}

// AddCircuitIDMapping adds a circuit-id to MAC address mapping
// This allows the eBPF fast path to look up subscribers by Option 82 circuit-id
func (l *Loader) AddCircuitIDMapping(circuitID []byte, mac uint64) error {
	if l.circuitIDMap == nil {
		return fmt.Errorf("circuit_id_map not loaded")
	}

	hash := HashCircuitID(circuitID)
	return l.circuitIDMap.Put(&hash, &mac)
}

// RemoveCircuitIDMapping removes a circuit-id mapping
func (l *Loader) RemoveCircuitIDMapping(circuitID []byte) error {
	if l.circuitIDMap == nil {
		return fmt.Errorf("circuit_id_map not loaded")
	}

	hash := HashCircuitID(circuitID)
	return l.circuitIDMap.Delete(&hash)
}

// GetCircuitIDMapping looks up the MAC address for a circuit-id
func (l *Loader) GetCircuitIDMapping(circuitID []byte) (uint64, error) {
	if l.circuitIDMap == nil {
		return 0, fmt.Errorf("circuit_id_map not loaded")
	}

	hash := HashCircuitID(circuitID)
	var mac uint64
	if err := l.circuitIDMap.Lookup(&hash, &mac); err != nil {
		return 0, err
	}
	return mac, nil
}

// === Circuit-ID Subscriber Map Operations (Issue #56) ===

// CircuitIDKeyLen must match CIRCUIT_ID_KEY_LEN in maps.h
const CircuitIDKeyLen = 32

// CircuitIDKey is the fixed-size key for circuit_id_subscribers map
type CircuitIDKey [CircuitIDKeyLen]byte

// MakeCircuitIDKey creates a fixed-size key from a circuit-ID
// Pads with zeros if shorter than 32 bytes, truncates if longer
func MakeCircuitIDKey(circuitID []byte) CircuitIDKey {
	var key CircuitIDKey
	copy(key[:], circuitID)
	return key
}

// AddCircuitIDSubscriber adds a circuit-ID to pool_assignment mapping
// This enables fast-path lookup by circuit-ID (Issue #56)
func (l *Loader) AddCircuitIDSubscriber(circuitID []byte, assignment *PoolAssignment) error {
	if l.circuitIDSubscribers == nil {
		return fmt.Errorf("circuit_id_subscribers map not loaded")
	}
	key := MakeCircuitIDKey(circuitID)
	return l.circuitIDSubscribers.Put(&key, assignment)
}

// RemoveCircuitIDSubscriber removes a circuit-ID subscriber mapping
func (l *Loader) RemoveCircuitIDSubscriber(circuitID []byte) error {
	if l.circuitIDSubscribers == nil {
		return fmt.Errorf("circuit_id_subscribers map not loaded")
	}
	key := MakeCircuitIDKey(circuitID)
	return l.circuitIDSubscribers.Delete(&key)
}

// GetCircuitIDSubscriber looks up pool assignment by circuit-ID
func (l *Loader) GetCircuitIDSubscriber(circuitID []byte) (*PoolAssignment, error) {
	if l.circuitIDSubscribers == nil {
		return nil, fmt.Errorf("circuit_id_subscribers map not loaded")
	}
	key := MakeCircuitIDKey(circuitID)
	var assignment PoolAssignment
	if err := l.circuitIDSubscribers.Lookup(&key, &assignment); err != nil {
		return nil, err
	}
	return &assignment, nil
}

// HasCircuitIDSubscriberSupport returns true if the circuit_id_subscribers map is loaded
func (l *Loader) HasCircuitIDSubscriberSupport() bool {
	return l.circuitIDSubscribers != nil
}

// === Helper Functions ===

// IPToUint32 converts a net.IP to uint32 (network byte order)
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Uint32ToIP converts a uint32 (network byte order) to net.IP
func Uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// MACToUint64 converts a MAC address to uint64
func MACToUint64(mac net.HardwareAddr) uint64 {
	if len(mac) < 6 {
		return 0
	}
	var result uint64
	for i := 0; i < 6; i++ {
		result = (result << 8) | uint64(mac[i])
	}
	return result
}

// Uint64ToMAC converts a uint64 to MAC address
func Uint64ToMAC(n uint64) net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	for i := 5; i >= 0; i-- {
		mac[i] = byte(n & 0xFF)
		n >>= 8
	}
	return mac
}

// LeaseExpiryFromDuration calculates lease expiry timestamp
func LeaseExpiryFromDuration(d time.Duration) uint64 {
	return uint64(time.Now().Add(d).Unix())
}
