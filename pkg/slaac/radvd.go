package slaac

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// ICMPv6 types
const (
	ICMPv6RouterSolicitation    = 133
	ICMPv6RouterAdvertisement   = 134
	ICMPv6NeighborSolicitation  = 135
	ICMPv6NeighborAdvertisement = 136
)

// RA flags
const (
	RAFlagManaged   = 0x80 // M flag - addresses via DHCPv6
	RAFlagOther     = 0x40 // O flag - other config via DHCPv6
	RAFlagHomeAgent = 0x20 // H flag - Mobile IPv6 home agent
)

// Prefix flags
const (
	PrefixFlagOnLink     = 0x80 // L flag - on-link
	PrefixFlagAutonomous = 0x40 // A flag - autonomous address config
)

// ICMPv6 option types
const (
	OptSourceLinkAddr = 1
	OptTargetLinkAddr = 2
	OptPrefixInfo     = 3
	OptMTU            = 5
	OptRDNSS          = 25 // Recursive DNS Server
	OptDNSSL          = 31 // DNS Search List
)

// Server is a Router Advertisement Daemon
type Server struct {
	iface      string
	logger     *zap.Logger
	running    int32
	conn       *ipv6.PacketConn
	ifaceIndex int
	linkAddr   net.HardwareAddr

	// Configuration
	prefixes        []PrefixConfig
	mtu             uint32
	curHopLimit     uint8
	defaultLifetime uint16 // Router lifetime in seconds
	reachableTime   uint32
	retransTimer    uint32
	managed         bool // M flag
	other           bool // O flag
	dnsServers      []net.IP
	dnsDomains      []string

	// Timing
	minRAInterval time.Duration
	maxRAInterval time.Duration

	// Statistics
	rasSent uint64
	rssRecv uint64

	mu sync.RWMutex
}

// PrefixConfig configures an advertised prefix
type PrefixConfig struct {
	Prefix            *net.IPNet
	OnLink            bool
	Autonomous        bool // Allow SLAAC
	ValidLifetime     uint32
	PreferredLifetime uint32
}

// Config configures the Router Advertisement daemon
type Config struct {
	Interface       string
	Prefixes        []string // CIDR prefixes to advertise
	MTU             uint32
	Managed         bool // Set M flag (use DHCPv6 for addresses)
	Other           bool // Set O flag (use DHCPv6 for other config)
	DNSServers      []string
	DNSDomains      []string
	DefaultLifetime uint16 // Router lifetime in seconds (0 = not a default router)
	MinRAInterval   time.Duration
	MaxRAInterval   time.Duration
}

// NewServer creates a new Router Advertisement daemon
func NewServer(cfg Config, logger *zap.Logger) (*Server, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface required")
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %w", err)
	}

	s := &Server{
		iface:           cfg.Interface,
		logger:          logger,
		ifaceIndex:      iface.Index,
		linkAddr:        iface.HardwareAddr,
		mtu:             cfg.MTU,
		curHopLimit:     64,
		defaultLifetime: cfg.DefaultLifetime,
		managed:         cfg.Managed,
		other:           cfg.Other,
		minRAInterval:   cfg.MinRAInterval,
		maxRAInterval:   cfg.MaxRAInterval,
	}

	// Default intervals per RFC 4861
	if s.minRAInterval == 0 {
		s.minRAInterval = 200 * time.Second
	}
	if s.maxRAInterval == 0 {
		s.maxRAInterval = 600 * time.Second
	}
	if s.defaultLifetime == 0 {
		s.defaultLifetime = 1800 // 30 minutes
	}

	// Parse prefixes
	for _, p := range cfg.Prefixes {
		_, ipnet, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %s: %w", p, err)
		}

		s.prefixes = append(s.prefixes, PrefixConfig{
			Prefix:            ipnet,
			OnLink:            true,
			Autonomous:        !cfg.Managed, // SLAAC if not managed
			ValidLifetime:     2592000,      // 30 days
			PreferredLifetime: 604800,       // 7 days
		})
	}

	// Parse DNS servers
	for _, dns := range cfg.DNSServers {
		ip := net.ParseIP(dns)
		if ip != nil && ip.To16() != nil && ip.To4() == nil {
			s.dnsServers = append(s.dnsServers, ip)
		}
	}
	s.dnsDomains = cfg.DNSDomains

	return s, nil
}

// Start starts the Router Advertisement daemon
func (s *Server) Start(ctx context.Context) error {
	// Listen for ICMPv6
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	p := ipv6.NewPacketConn(conn)
	s.conn = p

	// Join all-routers multicast group
	allRouters := net.ParseIP("ff02::2")
	if err := p.JoinGroup(&net.Interface{Index: s.ifaceIndex}, &net.IPAddr{IP: allRouters}); err != nil {
		conn.Close()
		return fmt.Errorf("failed to join multicast group: %w", err)
	}

	// Set hop limit for outgoing packets
	if err := p.SetHopLimit(255); err != nil {
		s.logger.Warn("Failed to set hop limit", zap.Error(err))
	}

	atomic.StoreInt32(&s.running, 1)

	s.logger.Info("Router Advertisement daemon started",
		zap.String("interface", s.iface),
		zap.Int("prefix_count", len(s.prefixes)),
		zap.Bool("managed", s.managed),
		zap.Bool("other", s.other),
	)

	// Start receiver
	go s.receiveLoop(ctx)

	// Start periodic RA sender
	go s.sendPeriodicRAs(ctx)

	return nil
}

// Stop stops the Router Advertisement daemon
func (s *Server) Stop() error {
	atomic.StoreInt32(&s.running, 0)
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// receiveLoop receives ICMPv6 messages
func (s *Server) receiveLoop(ctx context.Context) {
	buf := make([]byte, 1500)

	for atomic.LoadInt32(&s.running) == 1 {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, src, err := s.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		if n < 4 {
			continue
		}

		// Parse ICMPv6 header
		icmpType := buf[0]

		switch icmpType {
		case ICMPv6RouterSolicitation:
			atomic.AddUint64(&s.rssRecv, 1)
			s.handleRouterSolicitation(src)
		}
	}
}

// handleRouterSolicitation handles a Router Solicitation message
func (s *Server) handleRouterSolicitation(src net.Addr) {
	s.logger.Debug("Received Router Solicitation",
		zap.String("from", src.String()),
	)

	// Send RA in response
	s.sendRA(nil) // nil = multicast
}

// sendPeriodicRAs sends periodic Router Advertisements
func (s *Server) sendPeriodicRAs(ctx context.Context) {
	// Send initial RA
	s.sendRA(nil)

	// Random interval between min and max per RFC 4861
	interval := s.minRAInterval + time.Duration(rand.Float64()*float64(s.maxRAInterval-s.minRAInterval))

	for atomic.LoadInt32(&s.running) == 1 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			s.sendRA(nil)
			// Randomize next interval per RFC 4861
			interval = s.minRAInterval + time.Duration(rand.Float64()*float64(s.maxRAInterval-s.minRAInterval))
		}
	}
}

// sendRA sends a Router Advertisement
func (s *Server) sendRA(dst *net.IPAddr) {
	ra := s.buildRA()

	var dstAddr net.Addr
	if dst != nil {
		dstAddr = dst
	} else {
		// Multicast to all-nodes
		dstAddr = &net.IPAddr{
			IP:   net.ParseIP("ff02::1"),
			Zone: s.iface,
		}
	}

	_, err := s.conn.WriteTo(ra, nil, dstAddr)
	if err != nil {
		s.logger.Error("Failed to send RA",
			zap.Error(err),
			zap.String("to", dstAddr.String()),
		)
		return
	}

	atomic.AddUint64(&s.rasSent, 1)
	s.logger.Debug("Sent Router Advertisement",
		zap.String("to", dstAddr.String()),
	)
}

// buildRA builds a Router Advertisement message
func (s *Server) buildRA() []byte {
	// RA header: type(1) + code(1) + checksum(2) + cur_hop_limit(1) + flags(1) + router_lifetime(2) + reachable_time(4) + retrans_timer(4)
	buf := make([]byte, 16)
	buf[0] = ICMPv6RouterAdvertisement
	buf[1] = 0 // code
	// checksum at [2:4] - computed by kernel
	buf[4] = s.curHopLimit

	// Flags
	var flags uint8
	if s.managed {
		flags |= RAFlagManaged
	}
	if s.other {
		flags |= RAFlagOther
	}
	buf[5] = flags

	binary.BigEndian.PutUint16(buf[6:8], s.defaultLifetime)
	binary.BigEndian.PutUint32(buf[8:12], s.reachableTime)
	binary.BigEndian.PutUint32(buf[12:16], s.retransTimer)

	// Add options

	// Source Link-Layer Address option
	if len(s.linkAddr) > 0 {
		llOpt := make([]byte, 8)
		llOpt[0] = OptSourceLinkAddr
		llOpt[1] = 1 // length in 8-byte units
		copy(llOpt[2:8], s.linkAddr)
		buf = append(buf, llOpt...)
	}

	// MTU option
	if s.mtu > 0 {
		mtuOpt := make([]byte, 8)
		mtuOpt[0] = OptMTU
		mtuOpt[1] = 1 // length in 8-byte units
		// [2:4] reserved
		binary.BigEndian.PutUint32(mtuOpt[4:8], s.mtu)
		buf = append(buf, mtuOpt...)
	}

	// Prefix Information options
	for _, prefix := range s.prefixes {
		prefixOpt := s.buildPrefixOption(prefix)
		buf = append(buf, prefixOpt...)
	}

	// RDNSS option (DNS servers)
	if len(s.dnsServers) > 0 {
		rdnssOpt := s.buildRDNSSOption()
		buf = append(buf, rdnssOpt...)
	}

	// DNSSL option (DNS search domains)
	if len(s.dnsDomains) > 0 {
		dnsslOpt := s.buildDNSSLOption()
		buf = append(buf, dnsslOpt...)
	}

	return buf
}

// buildPrefixOption builds a Prefix Information option
func (s *Server) buildPrefixOption(prefix PrefixConfig) []byte {
	// Prefix Information option: type(1) + length(1) + prefix_length(1) + flags(1) + valid_lifetime(4) + preferred_lifetime(4) + reserved(4) + prefix(16)
	opt := make([]byte, 32)
	opt[0] = OptPrefixInfo
	opt[1] = 4 // length in 8-byte units (32 bytes)

	ones, _ := prefix.Prefix.Mask.Size()
	opt[2] = uint8(ones) // prefix length

	// Flags
	var flags uint8
	if prefix.OnLink {
		flags |= PrefixFlagOnLink
	}
	if prefix.Autonomous {
		flags |= PrefixFlagAutonomous
	}
	opt[3] = flags

	binary.BigEndian.PutUint32(opt[4:8], prefix.ValidLifetime)
	binary.BigEndian.PutUint32(opt[8:12], prefix.PreferredLifetime)
	// [12:16] reserved

	// Prefix (16 bytes)
	copy(opt[16:32], prefix.Prefix.IP.To16())

	return opt
}

// buildRDNSSOption builds a Recursive DNS Server option
func (s *Server) buildRDNSSOption() []byte {
	// RDNSS option: type(1) + length(1) + reserved(2) + lifetime(4) + addresses(16*n)
	numServers := len(s.dnsServers)
	length := (8 + 16*numServers + 7) / 8 // Round up to 8-byte units
	opt := make([]byte, length*8)

	opt[0] = OptRDNSS
	opt[1] = uint8(length)
	// [2:4] reserved
	binary.BigEndian.PutUint32(opt[4:8], uint32(s.defaultLifetime)*3) // Lifetime = 3x router lifetime

	for i, dns := range s.dnsServers {
		copy(opt[8+i*16:8+(i+1)*16], dns.To16())
	}

	return opt[:8+numServers*16]
}

// buildDNSSLOption builds a DNS Search List option
func (s *Server) buildDNSSLOption() []byte {
	// DNSSL option: type(1) + length(1) + reserved(2) + lifetime(4) + domain_names(variable)
	// Domain names are encoded as DNS labels

	// Encode domain names
	var domains []byte
	for _, domain := range s.dnsDomains {
		encoded := encodeDNSLabel(domain)
		domains = append(domains, encoded...)
	}

	// Pad to 8-byte boundary
	padding := (8 - (8+len(domains))%8) % 8
	for i := 0; i < padding; i++ {
		domains = append(domains, 0)
	}

	length := (8 + len(domains)) / 8
	opt := make([]byte, 8+len(domains))

	opt[0] = OptDNSSL
	opt[1] = uint8(length)
	// [2:4] reserved
	binary.BigEndian.PutUint32(opt[4:8], uint32(s.defaultLifetime)*3)
	copy(opt[8:], domains)

	return opt
}

// encodeDNSLabel encodes a domain name as DNS labels
func encodeDNSLabel(domain string) []byte {
	var result []byte
	labels := splitDomain(domain)
	for _, label := range labels {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0) // Terminating zero
	return result
}

// splitDomain splits a domain into labels
func splitDomain(domain string) []string {
	var labels []string
	var current string
	for _, c := range domain {
		if c == '.' {
			if current != "" {
				labels = append(labels, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		labels = append(labels, current)
	}
	return labels
}

// AddPrefix dynamically adds a prefix to advertise
func (s *Server) AddPrefix(prefix PrefixConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefixes = append(s.prefixes, prefix)
}

// RemovePrefix removes a prefix from advertisements
func (s *Server) RemovePrefix(prefixStr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, p := range s.prefixes {
		if p.Prefix.String() == prefixStr {
			s.prefixes = append(s.prefixes[:i], s.prefixes[i+1:]...)
			return
		}
	}
}

// GetStats returns statistics
func (s *Server) GetStats() map[string]uint64 {
	return map[string]uint64{
		"ras_sent":     atomic.LoadUint64(&s.rasSent),
		"rss_received": atomic.LoadUint64(&s.rssRecv),
	}
}

// SendImmediateRA sends an immediate Router Advertisement (for configuration changes)
func (s *Server) SendImmediateRA() {
	s.sendRA(nil)
}
