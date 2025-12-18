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
	VlanID      uint32
	ClientClass uint8
	LeaseExpiry uint64 // Unix timestamp (seconds)
	Flags       uint8
	_           [3]byte // Padding
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

// DHCPStats represents DHCP performance counters (mirrors eBPF struct)
type DHCPStats struct {
	TotalRequests  uint64
	FastpathHits   uint64
	FastpathMisses uint64
	Errors         uint64
	CacheExpired   uint64
}

// Loader handles loading and managing eBPF programs
type Loader struct {
	iface   string
	bpfPath string
	logger  *zap.Logger
	xdpMode link.XDPAttachFlags

	// eBPF resources
	collection      *ebpf.Collection
	xdpLink         link.Link
	subscriberPools *ebpf.Map
	ipPools         *ebpf.Map
	statsMap        *ebpf.Map
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

	l.ipPools = coll.Maps["ip_pools"]
	if l.ipPools == nil {
		return fmt.Errorf("ip_pools map not found")
	}

	l.statsMap = coll.Maps["stats_map"]
	if l.statsMap == nil {
		return fmt.Errorf("stats_map map not found")
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
