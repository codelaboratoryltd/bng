package dhcpv6

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Server is a DHCPv6 server
type Server struct {
	iface   string
	conn    *net.UDPConn
	logger  *zap.Logger
	running int32

	// Server configuration
	serverDUID   *DUID
	dnsServers   []net.IP
	domainSearch []string

	// Address pool
	addressPool *AddressPool

	// Prefix delegation pool
	prefixPool *PrefixPool

	// Lease management
	leases   map[string]*Lease // client DUID -> lease
	leasesMu sync.RWMutex

	// Statistics
	solicitReceived uint64
	advertisesSent  uint64
	requestsRecv    uint64
	repliesSent     uint64
	renewsRecv      uint64
	rebindsRecv     uint64
	releasesRecv    uint64
	declinesRecv    uint64
}

// AddressPool manages IPv6 address allocation
type AddressPool struct {
	network           *net.IPNet
	startOffset       uint64
	endOffset         uint64
	preferredLifetime uint32
	validLifetime     uint32
	allocated         map[string]net.IP // DUID string -> IP
	available         []net.IP
	mu                sync.Mutex
}

// PrefixPool manages delegated prefix allocation
type PrefixPool struct {
	basePrefix        *net.IPNet
	delegationLength  uint8
	preferredLifetime uint32
	validLifetime     uint32
	allocated         map[string]*net.IPNet // DUID string -> prefix
	available         []*net.IPNet
	mu                sync.Mutex
}

// Lease represents a DHCPv6 lease
type Lease struct {
	ClientDUID     []byte
	IAID           uint32
	Address        net.IP
	Prefix         *net.IPNet
	PreferredEnd   time.Time
	ValidEnd       time.Time
	LastRenew      time.Time
	ClientLinkAddr net.IP
}

// ServerConfig configures the DHCPv6 server
type ServerConfig struct {
	Interface         string
	AddressPool       string // CIDR for address pool
	PrefixPool        string // CIDR for prefix delegation pool
	DelegationLength  uint8  // Prefix length to delegate (e.g., 56, 60, 64)
	DNSServers        []string
	DomainSearch      []string
	PreferredLifetime uint32
	ValidLifetime     uint32
}

// NewServer creates a new DHCPv6 server
func NewServer(cfg ServerConfig, logger *zap.Logger) (*Server, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface required")
	}

	// Generate server DUID (DUID-LL based on interface MAC)
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %w", err)
	}

	serverDUID := &DUID{
		Type: DUIDTypeLL,
		Data: append([]byte{0x00, 0x01}, iface.HardwareAddr...), // Hardware type 1 (Ethernet) + MAC
	}

	s := &Server{
		iface:      cfg.Interface,
		logger:     logger,
		serverDUID: serverDUID,
		leases:     make(map[string]*Lease),
	}

	// Parse DNS servers
	for _, dns := range cfg.DNSServers {
		ip := net.ParseIP(dns)
		if ip != nil && ip.To16() != nil {
			s.dnsServers = append(s.dnsServers, ip)
		}
	}
	s.domainSearch = cfg.DomainSearch

	// Default lifetimes
	preferredLifetime := cfg.PreferredLifetime
	if preferredLifetime == 0 {
		preferredLifetime = 3600 // 1 hour
	}
	validLifetime := cfg.ValidLifetime
	if validLifetime == 0 {
		validLifetime = 7200 // 2 hours
	}

	// Create address pool
	if cfg.AddressPool != "" {
		pool, err := NewAddressPool(cfg.AddressPool, preferredLifetime, validLifetime)
		if err != nil {
			return nil, fmt.Errorf("failed to create address pool: %w", err)
		}
		s.addressPool = pool
	}

	// Create prefix delegation pool
	if cfg.PrefixPool != "" {
		delegationLen := cfg.DelegationLength
		if delegationLen == 0 {
			delegationLen = 60 // Default /60 delegation
		}
		pool, err := NewPrefixPool(cfg.PrefixPool, delegationLen, preferredLifetime, validLifetime)
		if err != nil {
			return nil, fmt.Errorf("failed to create prefix pool: %w", err)
		}
		s.prefixPool = pool
	}

	return s, nil
}

// NewAddressPool creates a new address pool
func NewAddressPool(cidr string, preferred, valid uint32) (*AddressPool, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	pool := &AddressPool{
		network:           ipnet,
		preferredLifetime: preferred,
		validLifetime:     valid,
		allocated:         make(map[string]net.IP),
		available:         make([]net.IP, 0),
	}

	// Generate available addresses (simplified - just first 1000)
	ip := ipnet.IP
	for i := 0; i < 1000; i++ {
		ip = nextIPv6(ip)
		if !ipnet.Contains(ip) {
			break
		}
		pool.available = append(pool.available, copyIPv6(ip))
	}

	return pool, nil
}

// Allocate allocates an address for a client
func (p *AddressPool) Allocate(duid string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if already allocated
	if ip, ok := p.allocated[duid]; ok {
		return ip
	}

	// Allocate new
	if len(p.available) == 0 {
		return nil
	}

	ip := p.available[0]
	p.available = p.available[1:]
	p.allocated[duid] = ip
	return ip
}

// Release releases an address
func (p *AddressPool) Release(duid string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ip, ok := p.allocated[duid]; ok {
		delete(p.allocated, duid)
		p.available = append(p.available, ip)
	}
}

// NewPrefixPool creates a new prefix delegation pool
func NewPrefixPool(cidr string, delegationLen uint8, preferred, valid uint32) (*PrefixPool, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, _ := ipnet.Mask.Size()
	if int(delegationLen) <= ones {
		return nil, fmt.Errorf("delegation length must be greater than pool prefix length")
	}

	pool := &PrefixPool{
		basePrefix:        ipnet,
		delegationLength:  delegationLen,
		preferredLifetime: preferred,
		validLifetime:     valid,
		allocated:         make(map[string]*net.IPNet),
		available:         make([]*net.IPNet, 0),
	}

	// Generate available prefixes
	numPrefixes := 1 << (int(delegationLen) - ones)
	if numPrefixes > 1000 {
		numPrefixes = 1000 // Limit for memory
	}

	baseIP := ipnet.IP.To16()
	for i := 0; i < numPrefixes; i++ {
		prefix := make(net.IP, 16)
		copy(prefix, baseIP)

		// Calculate the prefix for this index
		prefixIndex := uint64(i) << (128 - int(delegationLen))
		for j := 0; j < 8; j++ {
			prefix[8+j] |= byte(prefixIndex >> (56 - j*8))
		}

		pool.available = append(pool.available, &net.IPNet{
			IP:   prefix,
			Mask: net.CIDRMask(int(delegationLen), 128),
		})
	}

	return pool, nil
}

// Allocate allocates a prefix for a client
func (p *PrefixPool) Allocate(duid string) *net.IPNet {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if already allocated
	if prefix, ok := p.allocated[duid]; ok {
		return prefix
	}

	// Allocate new
	if len(p.available) == 0 {
		return nil
	}

	prefix := p.available[0]
	p.available = p.available[1:]
	p.allocated[duid] = prefix
	return prefix
}

// Release releases a prefix
func (p *PrefixPool) Release(duid string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if prefix, ok := p.allocated[duid]; ok {
		delete(p.allocated, duid)
		p.available = append(p.available, prefix)
	}
}

// Start starts the DHCPv6 server
func (s *Server) Start(ctx context.Context) error {
	addr := &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: DHCPv6ServerPort,
	}

	conn, err := net.ListenUDP("udp6", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.conn = conn

	atomic.StoreInt32(&s.running, 1)

	s.logger.Info("DHCPv6 server started",
		zap.String("interface", s.iface),
		zap.Int("port", DHCPv6ServerPort),
	)

	go s.receiveLoop(ctx)

	return nil
}

// Stop stops the DHCPv6 server
func (s *Server) Stop() error {
	atomic.StoreInt32(&s.running, 0)
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// receiveLoop receives and processes DHCPv6 messages
func (s *Server) receiveLoop(ctx context.Context) {
	buf := make([]byte, 65535)

	for atomic.LoadInt32(&s.running) == 1 {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.logger.Error("Read error", zap.Error(err))
			continue
		}

		// Parse message
		msg, err := ParseMessage(buf[:n])
		if err != nil {
			s.logger.Debug("Invalid DHCPv6 message", zap.Error(err))
			continue
		}

		// Handle message
		s.handleMessage(msg, addr)
	}
}

// handleMessage handles a DHCPv6 message
func (s *Server) handleMessage(msg *Message, addr *net.UDPAddr) {
	switch msg.Type {
	case MsgTypeSolicit:
		atomic.AddUint64(&s.solicitReceived, 1)
		s.handleSolicit(msg, addr)
	case MsgTypeRequest:
		atomic.AddUint64(&s.requestsRecv, 1)
		s.handleRequest(msg, addr)
	case MsgTypeRenew:
		atomic.AddUint64(&s.renewsRecv, 1)
		s.handleRenew(msg, addr)
	case MsgTypeRebind:
		atomic.AddUint64(&s.rebindsRecv, 1)
		s.handleRebind(msg, addr)
	case MsgTypeRelease:
		atomic.AddUint64(&s.releasesRecv, 1)
		s.handleRelease(msg, addr)
	case MsgTypeDecline:
		atomic.AddUint64(&s.declinesRecv, 1)
		s.handleDecline(msg, addr)
	case MsgTypeInformationRequest:
		s.handleInformationRequest(msg, addr)
	}
}

// handleSolicit handles a Solicit message
func (s *Server) handleSolicit(msg *Message, addr *net.UDPAddr) {
	s.logger.Debug("Received Solicit",
		zap.String("from", addr.String()),
	)

	// Get client DUID
	clientIDOpt := msg.GetOption(OptClientID)
	if clientIDOpt == nil {
		s.logger.Debug("Solicit without Client ID")
		return
	}

	clientDUID := string(clientIDOpt.Data)

	// Check for rapid commit
	rapidCommit := msg.GetOption(OptRapidCommit) != nil

	// Build response
	var response *Message
	if rapidCommit {
		response = s.buildReply(msg, clientDUID, addr.IP)
		response.Options = append(response.Options, Option{Code: OptRapidCommit})
	} else {
		response = s.buildAdvertise(msg, clientDUID, addr.IP)
	}

	if response == nil {
		return
	}

	s.sendResponse(response, addr)
	atomic.AddUint64(&s.advertisesSent, 1)
}

// handleRequest handles a Request message
func (s *Server) handleRequest(msg *Message, addr *net.UDPAddr) {
	s.logger.Debug("Received Request",
		zap.String("from", addr.String()),
	)

	// Get client DUID
	clientIDOpt := msg.GetOption(OptClientID)
	if clientIDOpt == nil {
		return
	}

	// Verify server ID matches us
	serverIDOpt := msg.GetOption(OptServerID)
	if serverIDOpt == nil {
		return
	}

	serverDUID, _ := ParseDUID(serverIDOpt.Data)
	if serverDUID == nil || string(serverDUID.Serialize()) != string(s.serverDUID.Serialize()) {
		return
	}

	clientDUID := string(clientIDOpt.Data)

	response := s.buildReply(msg, clientDUID, addr.IP)
	if response == nil {
		return
	}

	s.sendResponse(response, addr)
	atomic.AddUint64(&s.repliesSent, 1)
}

// handleRenew handles a Renew message
func (s *Server) handleRenew(msg *Message, addr *net.UDPAddr) {
	s.logger.Debug("Received Renew",
		zap.String("from", addr.String()),
	)

	clientIDOpt := msg.GetOption(OptClientID)
	if clientIDOpt == nil {
		return
	}

	clientDUID := string(clientIDOpt.Data)

	// Look up lease
	s.leasesMu.RLock()
	lease, ok := s.leases[clientDUID]
	s.leasesMu.RUnlock()

	if !ok {
		// No binding - send NoBinding status
		response := &Message{
			Type:          MsgTypeReply,
			TransactionID: msg.TransactionID,
			Options: []Option{
				MakeClientIDOption(clientIDOpt.Data),
				MakeServerIDOption(s.serverDUID),
				MakeStatusCodeOption(StatusNoBinding, "No binding found"),
			},
		}
		s.sendResponse(response, addr)
		return
	}

	// Extend lease
	s.leasesMu.Lock()
	lease.LastRenew = time.Now()
	if s.addressPool != nil {
		lease.PreferredEnd = time.Now().Add(time.Duration(s.addressPool.preferredLifetime) * time.Second)
		lease.ValidEnd = time.Now().Add(time.Duration(s.addressPool.validLifetime) * time.Second)
	}
	s.leasesMu.Unlock()

	response := s.buildReply(msg, clientDUID, addr.IP)
	if response != nil {
		s.sendResponse(response, addr)
		atomic.AddUint64(&s.repliesSent, 1)
	}
}

// handleRebind handles a Rebind message
func (s *Server) handleRebind(msg *Message, addr *net.UDPAddr) {
	// Similar to Renew but client doesn't know server
	s.handleRenew(msg, addr)
}

// handleRelease handles a Release message
func (s *Server) handleRelease(msg *Message, addr *net.UDPAddr) {
	s.logger.Debug("Received Release",
		zap.String("from", addr.String()),
	)

	clientIDOpt := msg.GetOption(OptClientID)
	if clientIDOpt == nil {
		return
	}

	clientDUID := string(clientIDOpt.Data)

	// Release lease
	s.leasesMu.Lock()
	if lease, ok := s.leases[clientDUID]; ok {
		if s.addressPool != nil && lease.Address != nil {
			s.addressPool.Release(clientDUID)
		}
		if s.prefixPool != nil && lease.Prefix != nil {
			s.prefixPool.Release(clientDUID)
		}
		delete(s.leases, clientDUID)
	}
	s.leasesMu.Unlock()

	// Send Reply
	response := &Message{
		Type:          MsgTypeReply,
		TransactionID: msg.TransactionID,
		Options: []Option{
			MakeClientIDOption(clientIDOpt.Data),
			MakeServerIDOption(s.serverDUID),
			MakeStatusCodeOption(StatusSuccess, "Released"),
		},
	}
	s.sendResponse(response, addr)
	atomic.AddUint64(&s.repliesSent, 1)
}

// handleDecline handles a Decline message
func (s *Server) handleDecline(msg *Message, addr *net.UDPAddr) {
	// Client detected address conflict - mark address as unusable
	s.logger.Warn("Received Decline - address conflict",
		zap.String("from", addr.String()),
	)

	// For now, just release and let client try again
	s.handleRelease(msg, addr)
}

// handleInformationRequest handles an Information-Request message
func (s *Server) handleInformationRequest(msg *Message, addr *net.UDPAddr) {
	s.logger.Debug("Received Information-Request",
		zap.String("from", addr.String()),
	)

	clientIDOpt := msg.GetOption(OptClientID)
	if clientIDOpt == nil {
		return
	}

	// Build Reply with requested options (DNS, domain search, etc.)
	response := &Message{
		Type:          MsgTypeReply,
		TransactionID: msg.TransactionID,
		Options: []Option{
			MakeClientIDOption(clientIDOpt.Data),
			MakeServerIDOption(s.serverDUID),
		},
	}

	// Add DNS servers if configured
	if len(s.dnsServers) > 0 {
		response.Options = append(response.Options, MakeDNSServersOption(s.dnsServers))
	}

	s.sendResponse(response, addr)
	atomic.AddUint64(&s.repliesSent, 1)
}

// buildAdvertise builds an Advertise message
func (s *Server) buildAdvertise(msg *Message, clientDUID string, clientAddr net.IP) *Message {
	clientIDOpt := msg.GetOption(OptClientID)
	if clientIDOpt == nil {
		return nil
	}

	response := &Message{
		Type:          MsgTypeAdvertise,
		TransactionID: msg.TransactionID,
		Options: []Option{
			MakeClientIDOption(clientIDOpt.Data),
			MakeServerIDOption(s.serverDUID),
		},
	}

	// Add preference (higher = more preferred)
	response.Options = append(response.Options, Option{
		Code: OptPreference,
		Data: []byte{255}, // Highest preference
	})

	// Handle IA_NA requests
	for _, ianaOpt := range msg.GetAllOptions(OptIANA) {
		iana, err := ParseIANA(ianaOpt.Data)
		if err != nil {
			continue
		}

		if s.addressPool != nil {
			addr := s.addressPool.Allocate(clientDUID)
			if addr != nil {
				iaAddr := &IAAddress{
					Address:           addr,
					PreferredLifetime: s.addressPool.preferredLifetime,
					ValidLifetime:     s.addressPool.validLifetime,
				}

				responseIANA := &IANA{
					IAID: iana.IAID,
					T1:   s.addressPool.preferredLifetime / 2,
					T2:   s.addressPool.preferredLifetime * 4 / 5,
					Options: []Option{
						MakeIAAddressOption(iaAddr),
					},
				}
				response.Options = append(response.Options, MakeIANAOption(responseIANA))
			}
		}
	}

	// Handle IA_PD requests
	for _, iapdOpt := range msg.GetAllOptions(OptIAPD) {
		iapd, err := ParseIAPD(iapdOpt.Data)
		if err != nil {
			continue
		}

		if s.prefixPool != nil {
			prefix := s.prefixPool.Allocate(clientDUID)
			if prefix != nil {
				prefixLen, _ := prefix.Mask.Size()
				iaPrefix := &IAPrefix{
					PreferredLifetime: s.prefixPool.preferredLifetime,
					ValidLifetime:     s.prefixPool.validLifetime,
					PrefixLength:      uint8(prefixLen),
					Prefix:            prefix.IP,
				}

				responseIAPD := &IAPD{
					IAID: iapd.IAID,
					T1:   s.prefixPool.preferredLifetime / 2,
					T2:   s.prefixPool.preferredLifetime * 4 / 5,
					Options: []Option{
						MakeIAPrefixOption(iaPrefix),
					},
				}
				response.Options = append(response.Options, MakeIAPDOption(responseIAPD))
			}
		}
	}

	// Add DNS servers
	if len(s.dnsServers) > 0 {
		response.Options = append(response.Options, MakeDNSServersOption(s.dnsServers))
	}

	return response
}

// buildReply builds a Reply message
func (s *Server) buildReply(msg *Message, clientDUID string, clientAddr net.IP) *Message {
	clientIDOpt := msg.GetOption(OptClientID)
	if clientIDOpt == nil {
		return nil
	}

	response := &Message{
		Type:          MsgTypeReply,
		TransactionID: msg.TransactionID,
		Options: []Option{
			MakeClientIDOption(clientIDOpt.Data),
			MakeServerIDOption(s.serverDUID),
		},
	}

	// Get or create lease
	s.leasesMu.Lock()
	lease, ok := s.leases[clientDUID]
	if !ok {
		lease = &Lease{
			ClientDUID:     []byte(clientDUID),
			ClientLinkAddr: clientAddr,
		}
		s.leases[clientDUID] = lease
	}
	s.leasesMu.Unlock()

	// Handle IA_NA
	for _, ianaOpt := range msg.GetAllOptions(OptIANA) {
		iana, err := ParseIANA(ianaOpt.Data)
		if err != nil {
			continue
		}

		if s.addressPool != nil {
			addr := s.addressPool.Allocate(clientDUID)
			if addr != nil {
				s.leasesMu.Lock()
				lease.Address = addr
				lease.IAID = iana.IAID
				lease.PreferredEnd = time.Now().Add(time.Duration(s.addressPool.preferredLifetime) * time.Second)
				lease.ValidEnd = time.Now().Add(time.Duration(s.addressPool.validLifetime) * time.Second)
				s.leasesMu.Unlock()

				iaAddr := &IAAddress{
					Address:           addr,
					PreferredLifetime: s.addressPool.preferredLifetime,
					ValidLifetime:     s.addressPool.validLifetime,
				}

				responseIANA := &IANA{
					IAID: iana.IAID,
					T1:   s.addressPool.preferredLifetime / 2,
					T2:   s.addressPool.preferredLifetime * 4 / 5,
					Options: []Option{
						MakeIAAddressOption(iaAddr),
					},
				}
				response.Options = append(response.Options, MakeIANAOption(responseIANA))

				s.logger.Info("DHCPv6 address allocated",
					zap.String("address", addr.String()),
					zap.String("client", clientAddr.String()),
				)
			} else {
				// No addresses available
				responseIANA := &IANA{
					IAID: iana.IAID,
					Options: []Option{
						MakeStatusCodeOption(StatusNoAddrsAvail, "No addresses available"),
					},
				}
				response.Options = append(response.Options, MakeIANAOption(responseIANA))
			}
		}
	}

	// Handle IA_PD
	for _, iapdOpt := range msg.GetAllOptions(OptIAPD) {
		iapd, err := ParseIAPD(iapdOpt.Data)
		if err != nil {
			continue
		}

		if s.prefixPool != nil {
			prefix := s.prefixPool.Allocate(clientDUID)
			if prefix != nil {
				s.leasesMu.Lock()
				lease.Prefix = prefix
				s.leasesMu.Unlock()

				prefixLen, _ := prefix.Mask.Size()
				iaPrefix := &IAPrefix{
					PreferredLifetime: s.prefixPool.preferredLifetime,
					ValidLifetime:     s.prefixPool.validLifetime,
					PrefixLength:      uint8(prefixLen),
					Prefix:            prefix.IP,
				}

				responseIAPD := &IAPD{
					IAID: iapd.IAID,
					T1:   s.prefixPool.preferredLifetime / 2,
					T2:   s.prefixPool.preferredLifetime * 4 / 5,
					Options: []Option{
						MakeIAPrefixOption(iaPrefix),
					},
				}
				response.Options = append(response.Options, MakeIAPDOption(responseIAPD))

				s.logger.Info("DHCPv6 prefix delegated",
					zap.String("prefix", prefix.String()),
					zap.String("client", clientAddr.String()),
				)
			} else {
				// No prefixes available
				responseIAPD := &IAPD{
					IAID: iapd.IAID,
					Options: []Option{
						MakeStatusCodeOption(StatusNoPrefixAvail, "No prefixes available"),
					},
				}
				response.Options = append(response.Options, MakeIAPDOption(responseIAPD))
			}
		}
	}

	// Add DNS servers
	if len(s.dnsServers) > 0 {
		response.Options = append(response.Options, MakeDNSServersOption(s.dnsServers))
	}

	// Add success status
	response.Options = append(response.Options, MakeStatusCodeOption(StatusSuccess, "Success"))

	return response
}

// sendResponse sends a DHCPv6 response
func (s *Server) sendResponse(msg *Message, addr *net.UDPAddr) {
	data := msg.Serialize()

	// Reply to client port
	dstAddr := &net.UDPAddr{
		IP:   addr.IP,
		Port: DHCPv6ClientPort,
		Zone: addr.Zone,
	}

	_, err := s.conn.WriteToUDP(data, dstAddr)
	if err != nil {
		s.logger.Error("Failed to send response",
			zap.Error(err),
			zap.String("to", dstAddr.String()),
		)
	}
}

// GetStats returns server statistics
func (s *Server) GetStats() map[string]uint64 {
	s.leasesMu.RLock()
	leaseCount := len(s.leases)
	s.leasesMu.RUnlock()

	return map[string]uint64{
		"solicit_received":  atomic.LoadUint64(&s.solicitReceived),
		"advertises_sent":   atomic.LoadUint64(&s.advertisesSent),
		"requests_received": atomic.LoadUint64(&s.requestsRecv),
		"replies_sent":      atomic.LoadUint64(&s.repliesSent),
		"renews_received":   atomic.LoadUint64(&s.renewsRecv),
		"rebinds_received":  atomic.LoadUint64(&s.rebindsRecv),
		"releases_received": atomic.LoadUint64(&s.releasesRecv),
		"declines_received": atomic.LoadUint64(&s.declinesRecv),
		"active_leases":     uint64(leaseCount),
	}
}

// Helper functions

func nextIPv6(ip net.IP) net.IP {
	next := make(net.IP, 16)
	copy(next, ip.To16())
	for i := 15; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func copyIPv6(ip net.IP) net.IP {
	dup := make(net.IP, 16)
	copy(dup, ip.To16())
	return dup
}

// GenerateDUID generates a random DUID for testing
func GenerateDUID() *DUID {
	data := make([]byte, 14)
	binary.BigEndian.PutUint16(data[0:2], 1) // Hardware type: Ethernet
	rand.Read(data[2:])
	return &DUID{
		Type: DUIDTypeLL,
		Data: data,
	}
}
