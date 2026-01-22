package dhcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/ebpf"
	"github.com/codelaboratoryltd/bng/pkg/nat"
	"github.com/codelaboratoryltd/bng/pkg/nexus"
	"github.com/codelaboratoryltd/bng/pkg/qos"
	"github.com/codelaboratoryltd/bng/pkg/radius"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"go.uber.org/zap"
)

// Server is the DHCP slow path server
// It handles cache misses from the eBPF fast path
type Server struct {
	iface    string
	serverIP net.IP
	logger   *zap.Logger
	loader   *ebpf.Loader
	poolMgr  *PoolManager
	server   *server4.Server
	leases   map[string]*Lease // MAC -> Lease
	leasesMu sync.RWMutex

	// RADIUS integration (optional)
	radiusClient *radius.Client
	policyMgr    *radius.PolicyManager

	// QoS integration (optional)
	qosMgr *qos.Manager

	// NAT integration (optional)
	natMgr *nat.Manager

	// Nexus integration (optional) - for centralized IP allocation
	nexusClient *nexus.Client

	// Enable RADIUS auth (if false, all MACs are accepted)
	radiusAuthEnabled bool

	// Metrics
	requestsTotal  uint64
	offersTotal    uint64
	acksTotal      uint64
	naksTotal      uint64
	releasesTotal  uint64
	radiusAuthOK   uint64
	radiusAuthFail uint64
}

// Lease represents an active DHCP lease
type Lease struct {
	MAC          net.HardwareAddr
	IP           net.IP
	PoolID       uint32
	ExpiresAt    time.Time
	Hostname     string
	SessionID    string    // RADIUS session ID
	SessionStart time.Time // Session start time
	Class        []byte    // RADIUS Class attribute
	PolicyName   string    // QoS policy applied
	InputBytes   uint64    // Upload bytes
	OutputBytes  uint64    // Download bytes

	// QinQ VLAN context (for European PoI deployments)
	STag uint16 // Service VLAN (outer, 802.1ad)
	CTag uint16 // Customer VLAN (inner, 802.1Q)

	// Issue #15: Option 82 information
	CircuitID []byte // Option 82 Circuit-ID
	RemoteID  []byte // Option 82 Remote-ID
}

// RelayAgentInfo contains parsed Option 82 data (Issue #15)
type RelayAgentInfo struct {
	CircuitID []byte // Sub-option 1: identifies physical port/VLAN
	RemoteID  []byte // Sub-option 2: identifies relay agent
}

// ServerConfig configures the DHCP server
type ServerConfig struct {
	Interface         string
	ServerIP          net.IP
	RADIUSAuthEnabled bool
}

// NewServer creates a new DHCP slow path server
func NewServer(cfg ServerConfig, loader *ebpf.Loader, poolMgr *PoolManager, logger *zap.Logger) (*Server, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface is required")
	}
	if cfg.ServerIP == nil {
		return nil, fmt.Errorf("server IP is required")
	}

	return &Server{
		iface:             cfg.Interface,
		serverIP:          cfg.ServerIP,
		logger:            logger,
		loader:            loader,
		poolMgr:           poolMgr,
		leases:            make(map[string]*Lease),
		radiusAuthEnabled: cfg.RADIUSAuthEnabled,
	}, nil
}

// SetRADIUSClient sets the RADIUS client for authentication
func (s *Server) SetRADIUSClient(client *radius.Client) {
	s.radiusClient = client
}

// SetPolicyManager sets the QoS policy manager
func (s *Server) SetPolicyManager(pm *radius.PolicyManager) {
	s.policyMgr = pm
}

// SetQoSManager sets the QoS manager for rate limiting
func (s *Server) SetQoSManager(qm *qos.Manager) {
	s.qosMgr = qm
}

// SetNATManager sets the NAT manager for CGNAT
func (s *Server) SetNATManager(nm *nat.Manager) {
	s.natMgr = nm
}

// SetNexusClient sets the Nexus client for centralized IP allocation.
// When set, IP allocation happens via Nexus (hashring-based) instead of local pools.
func (s *Server) SetNexusClient(nc *nexus.Client) {
	s.nexusClient = nc
}

// generateSessionID generates a unique RADIUS session ID
func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// parseOption82 extracts Relay Agent Information from DHCP packet (Issue #15)
// Returns nil if Option 82 is not present
func parseOption82(req *dhcpv4.DHCPv4) *RelayAgentInfo {
	opt82 := req.Options.Get(dhcpv4.OptionRelayAgentInformation)
	if opt82 == nil || len(opt82) == 0 {
		return nil
	}

	info := &RelayAgentInfo{}
	offset := 0

	// Parse TLV sub-options within Option 82
	for offset < len(opt82) {
		if offset+2 > len(opt82) {
			break
		}

		subOptType := opt82[offset]
		subOptLen := int(opt82[offset+1])
		offset += 2

		if offset+subOptLen > len(opt82) {
			break
		}

		subOptData := opt82[offset : offset+subOptLen]
		offset += subOptLen

		switch subOptType {
		case 1: // Circuit-ID
			info.CircuitID = make([]byte, len(subOptData))
			copy(info.CircuitID, subOptData)
		case 2: // Remote-ID
			info.RemoteID = make([]byte, len(subOptData))
			copy(info.RemoteID, subOptData)
		}
	}

	return info
}

// Start starts the DHCP server
func (s *Server) Start(ctx context.Context) error {
	laddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 67,
	}

	server, err := server4.NewServer(s.iface, laddr, s.handleDHCP)
	if err != nil {
		return fmt.Errorf("failed to create DHCP server: %w", err)
	}
	s.server = server

	s.logger.Info("Starting DHCP slow path server",
		zap.String("interface", s.iface),
		zap.String("server_ip", s.serverIP.String()),
	)

	// Configure eBPF fast path with server info
	if s.loader != nil {
		iface, err := net.InterfaceByName(s.iface)
		if err != nil {
			s.logger.Warn("Failed to get interface for eBPF config",
				zap.String("interface", s.iface),
				zap.Error(err),
			)
		} else {
			if err := s.loader.SetServerConfig(iface.HardwareAddr, s.serverIP, iface.Index); err != nil {
				s.logger.Warn("Failed to set eBPF server config",
					zap.Error(err),
				)
			} else {
				s.logger.Info("eBPF fast path configured",
					zap.String("server_mac", iface.HardwareAddr.String()),
					zap.String("server_ip", s.serverIP.String()),
					zap.Int("ifindex", iface.Index),
				)
			}
		}
	}

	// Start lease cleanup goroutine
	go s.leaseCleanup(ctx)

	// Serve in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve()
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		s.logger.Info("Stopping DHCP server")
		server.Close()
		return nil
	case err := <-errCh:
		return err
	}
}

// handleDHCP handles incoming DHCP packets (slow path)
func (s *Server) handleDHCP(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	s.requestsTotal++

	mac := req.ClientHWAddr.String()
	msgType := req.MessageType()

	// Parse Option 82 if present (Issue #15)
	opt82 := parseOption82(req)
	if opt82 != nil {
		s.logger.Debug("DHCP request with Option 82 (slow path)",
			zap.String("mac", mac),
			zap.String("type", msgType.String()),
			zap.String("xid", fmt.Sprintf("%08x", req.TransactionID)),
			zap.String("circuit_id", string(opt82.CircuitID)),
			zap.String("remote_id", string(opt82.RemoteID)),
		)
	} else {
		s.logger.Debug("DHCP request received (slow path)",
			zap.String("mac", mac),
			zap.String("type", msgType.String()),
			zap.String("xid", fmt.Sprintf("%08x", req.TransactionID)),
		)
	}

	var resp *dhcpv4.DHCPv4
	var err error

	switch msgType {
	case dhcpv4.MessageTypeDiscover:
		resp, err = s.handleDiscover(req)
	case dhcpv4.MessageTypeRequest:
		resp, err = s.handleRequest(req)
	case dhcpv4.MessageTypeRelease:
		s.handleRelease(req)
		return
	case dhcpv4.MessageTypeDecline:
		s.handleDecline(req)
		return
	case dhcpv4.MessageTypeInform:
		resp, err = s.handleInform(req)
	default:
		s.logger.Debug("Ignoring DHCP message type",
			zap.String("type", msgType.String()),
		)
		return
	}

	if err != nil {
		s.logger.Error("Failed to handle DHCP request",
			zap.String("mac", mac),
			zap.String("type", msgType.String()),
			zap.Error(err),
		)
		return
	}

	if resp == nil {
		return
	}

	// Send response
	if _, err := conn.WriteTo(resp.ToBytes(), peer); err != nil {
		s.logger.Error("Failed to send DHCP response",
			zap.String("mac", mac),
			zap.Error(err),
		)
	}
}

// handleDiscover handles DHCP DISCOVER - allocates new IP
func (s *Server) handleDiscover(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	mac := req.ClientHWAddr
	macStr := mac.String()

	// Check if client already has a lease
	s.leasesMu.RLock()
	existingLease := s.leases[macStr]
	s.leasesMu.RUnlock()

	var ip net.IP
	var poolID uint32
	var pool *Pool

	if existingLease != nil && time.Now().Before(existingLease.ExpiresAt) {
		// Reuse existing allocation
		ip = existingLease.IP
		poolID = existingLease.PoolID
		pool = s.poolMgr.GetPool(poolID)
	} else {
		// Try Nexus first for centralized IP allocation
		if s.nexusClient != nil {
			if sub, ok := s.nexusClient.GetSubscriberByMAC(macStr); ok {
				// Subscriber found in Nexus
				if sub.IPv4Addr != "" {
					// Already has IP allocated (at RADIUS time)
					ip = net.ParseIP(sub.IPv4Addr)
					s.logger.Debug("Using Nexus-allocated IP",
						zap.String("mac", macStr),
						zap.String("ip", sub.IPv4Addr),
						zap.String("subscriber_id", sub.ID),
					)
				} else {
					// Allocate IP via Nexus (hashring-based)
					allocatedIP, err := s.nexusClient.AllocateIPForSubscriber(context.Background(), sub.ID)
					if err != nil {
						s.logger.Warn("Nexus IP allocation failed, falling back to local pool",
							zap.String("mac", macStr),
							zap.Error(err),
						)
					} else {
						ip = net.ParseIP(allocatedIP)
						s.logger.Info("Allocated IP via Nexus",
							zap.String("mac", macStr),
							zap.String("ip", allocatedIP),
							zap.String("subscriber_id", sub.ID),
						)
					}
				}
			}
		}

		// Fall back to local pool if Nexus didn't provide an IP
		if ip == nil {
			// Classify client and get pool
			pool = s.poolMgr.ClassifyClient(mac)
			if pool == nil {
				return nil, fmt.Errorf("no pool available for client %s", mac)
			}
			poolID = pool.ID

			// Allocate IP from local pool
			var err error
			ip, err = pool.Allocate(mac)
			if err != nil {
				return nil, fmt.Errorf("failed to allocate IP: %w", err)
			}
		} else if pool == nil {
			// Got IP from Nexus, use default pool for metadata
			pool = s.poolMgr.ClassifyClient(mac)
			if pool != nil {
				poolID = pool.ID
			}
		}
	}

	s.logger.Info("Sending DHCP OFFER",
		zap.String("mac", mac.String()),
		zap.String("ip", ip.String()),
		zap.Uint32("pool_id", poolID),
	)

	// Build OFFER response
	resp, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithYourIP(ip),
		dhcpv4.WithServerIP(s.serverIP),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.serverIP)),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(pool.LeaseTime)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(pool.SubnetMask)),
		dhcpv4.WithOption(dhcpv4.OptRouter(pool.Gateway)),
		dhcpv4.WithOption(dhcpv4.OptDNS(pool.DNSServers...)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build OFFER: %w", err)
	}

	s.offersTotal++
	return resp, nil
}

// handleRequest handles DHCP REQUEST - confirms allocation
func (s *Server) handleRequest(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	mac := req.ClientHWAddr
	ctx := context.Background()

	// Get requested IP
	requestedIP := req.RequestedIPAddress()
	if requestedIP == nil || requestedIP.IsUnspecified() {
		requestedIP = req.ClientIPAddr
	}

	// Verify we offered this IP or it's a renewal
	s.leasesMu.RLock()
	existingLease := s.leases[mac.String()]
	s.leasesMu.RUnlock()

	var pool *Pool
	var poolID uint32
	var authResp *radius.AuthResponse
	isNewSession := existingLease == nil

	if existingLease != nil {
		// Renewal - verify IP matches
		if !existingLease.IP.Equal(requestedIP) {
			atomic.AddUint64(&s.naksTotal, 1)
			return s.buildNAK(req, "IP mismatch")
		}
		pool = s.poolMgr.GetPool(existingLease.PoolID)
		poolID = existingLease.PoolID
	} else {
		// New session - RADIUS authentication if enabled
		if s.radiusAuthEnabled && s.radiusClient != nil {
			var err error
			authResp, err = s.radiusClient.Authenticate(ctx, &radius.AuthRequest{
				Username:    mac.String(),
				MAC:         mac,
				NASPortType: 15, // Ethernet
			})
			if err != nil {
				s.logger.Error("RADIUS authentication failed",
					zap.String("mac", mac.String()),
					zap.Error(err),
				)
				atomic.AddUint64(&s.radiusAuthFail, 1)
				atomic.AddUint64(&s.naksTotal, 1)
				return s.buildNAK(req, "authentication failed")
			}

			if !authResp.Accepted {
				s.logger.Warn("RADIUS authentication rejected",
					zap.String("mac", mac.String()),
					zap.String("reason", authResp.RejectReason),
				)
				atomic.AddUint64(&s.radiusAuthFail, 1)
				atomic.AddUint64(&s.naksTotal, 1)
				return s.buildNAK(req, "access denied")
			}

			atomic.AddUint64(&s.radiusAuthOK, 1)
			s.logger.Info("RADIUS authentication successful",
				zap.String("mac", mac.String()),
				zap.String("filter_id", authResp.FilterID),
			)
		}

		// Classify client and get pool
		pool = s.poolMgr.ClassifyClient(mac)
		if pool == nil {
			atomic.AddUint64(&s.naksTotal, 1)
			return s.buildNAK(req, "no pool available")
		}
		poolID = pool.ID

		// Allocate or verify the requested IP
		if !pool.Contains(requestedIP) {
			atomic.AddUint64(&s.naksTotal, 1)
			return s.buildNAK(req, "IP not in pool")
		}
	}

	if pool == nil {
		atomic.AddUint64(&s.naksTotal, 1)
		return s.buildNAK(req, "pool not found")
	}

	// Create/update lease
	lease := &Lease{
		MAC:       mac,
		IP:        requestedIP,
		PoolID:    poolID,
		ExpiresAt: time.Now().Add(pool.LeaseTime),
		Hostname:  string(req.Options.Get(dhcpv4.OptionHostName)),
	}

	// Parse Option 82 for this request (Issue #15)
	opt82 := parseOption82(req)
	if opt82 != nil {
		lease.CircuitID = opt82.CircuitID
		lease.RemoteID = opt82.RemoteID
	}

	// For new sessions, set session tracking fields
	if isNewSession {
		lease.SessionID = generateSessionID()
		lease.SessionStart = time.Now()
		if authResp != nil {
			lease.Class = authResp.Class
			lease.PolicyName = authResp.FilterID
		}
	} else {
		// Preserve existing session data
		lease.SessionID = existingLease.SessionID
		lease.SessionStart = existingLease.SessionStart
		lease.Class = existingLease.Class
		lease.PolicyName = existingLease.PolicyName
		lease.InputBytes = existingLease.InputBytes
		lease.OutputBytes = existingLease.OutputBytes
		// Preserve Option 82 if not present in current request
		if lease.CircuitID == nil && existingLease.CircuitID != nil {
			lease.CircuitID = existingLease.CircuitID
			lease.RemoteID = existingLease.RemoteID
		}
	}

	s.leasesMu.Lock()
	s.leases[mac.String()] = lease
	s.leasesMu.Unlock()

	// Update eBPF fast path cache
	if err := s.updateFastPathCache(mac, lease, pool); err != nil {
		s.logger.Warn("Failed to update fast path cache",
			zap.String("mac", mac.String()),
			zap.Error(err),
		)
	}

	// Issue #15: Add circuit-id to MAC mapping for fast path lookup (legacy hash-based)
	if lease.CircuitID != nil && len(lease.CircuitID) > 0 && s.loader != nil {
		macU64 := ebpf.MACToUint64(mac)
		if err := s.loader.AddCircuitIDMapping(lease.CircuitID, macU64); err != nil {
			s.logger.Warn("Failed to add circuit-id to MAC mapping to eBPF",
				zap.String("mac", mac.String()),
				zap.String("circuit_id", string(lease.CircuitID)),
				zap.Error(err),
			)
		} else {
			s.logger.Debug("Added circuit-id to MAC mapping for fast path",
				zap.String("mac", mac.String()),
				zap.String("circuit_id", string(lease.CircuitID)),
			)
		}

		// Issue #56: Add circuit-id subscriber mapping for direct fast path lookup
		// This uses fixed-size keys to avoid verifier issues with hashing loops
		if s.loader.HasCircuitIDSubscriberSupport() {
			assignment := &ebpf.PoolAssignment{
				PoolID:      lease.PoolID,
				AllocatedIP: ebpf.IPToUint32(lease.IP),
				VlanID:      pool.VlanID,
				ClientClass: uint8(pool.ClientClass),
				LeaseExpiry: uint64(lease.ExpiresAt.Unix()),
				Flags:       0,
			}
			if err := s.loader.AddCircuitIDSubscriber(lease.CircuitID, assignment); err != nil {
				s.logger.Warn("Failed to add circuit-id subscriber mapping",
					zap.String("mac", mac.String()),
					zap.String("circuit_id", string(lease.CircuitID)),
					zap.Error(err),
				)
			} else {
				s.logger.Debug("Added circuit-id subscriber mapping for fast path (Issue #56)",
					zap.String("mac", mac.String()),
					zap.String("circuit_id", string(lease.CircuitID)),
					zap.String("ip", lease.IP.String()),
				)
			}
		}
	}

	// Apply QoS policy for new sessions
	if isNewSession && s.qosMgr != nil {
		policyName := lease.PolicyName
		if policyName == "" {
			policyName = "residential-100mbps" // Default policy
		}

		if err := s.qosMgr.SetSubscriberPolicy(requestedIP, policyName); err != nil {
			s.logger.Warn("Failed to apply QoS policy",
				zap.String("mac", mac.String()),
				zap.String("ip", requestedIP.String()),
				zap.String("policy", policyName),
				zap.Error(err),
			)
		} else {
			s.logger.Info("Applied QoS policy",
				zap.String("mac", mac.String()),
				zap.String("ip", requestedIP.String()),
				zap.String("policy", policyName),
			)
		}
	}

	// Allocate NAT for new sessions
	if isNewSession && s.natMgr != nil {
		alloc, err := s.natMgr.AllocateNAT(requestedIP)
		if err != nil {
			s.logger.Warn("Failed to allocate NAT",
				zap.String("mac", mac.String()),
				zap.String("ip", requestedIP.String()),
				zap.Error(err),
			)
		} else {
			s.logger.Info("Allocated NAT",
				zap.String("mac", mac.String()),
				zap.String("private_ip", requestedIP.String()),
				zap.String("public_ip", alloc.PublicIP.String()),
				zap.Uint16("port_start", alloc.PortStart),
				zap.Uint16("port_end", alloc.PortEnd),
			)
		}
	}

	// Send RADIUS Accounting-Start for new sessions
	if isNewSession && s.radiusClient != nil {
		go func() {
			err := s.radiusClient.SendAccounting(context.Background(), &radius.AcctRequest{
				SessionID:  lease.SessionID,
				Username:   mac.String(),
				MAC:        mac,
				FramedIP:   requestedIP,
				StatusType: radius.AcctStatusStart,
				Class:      lease.Class,
			})
			if err != nil {
				s.logger.Warn("Failed to send RADIUS Accounting-Start",
					zap.String("session_id", lease.SessionID),
					zap.Error(err),
				)
			}
		}()
	}

	s.logger.Info("Sending DHCP ACK",
		zap.String("mac", mac.String()),
		zap.String("ip", requestedIP.String()),
		zap.Uint32("pool_id", poolID),
		zap.Duration("lease_time", pool.LeaseTime),
		zap.String("session_id", lease.SessionID),
	)

	// Build ACK response
	resp, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(requestedIP),
		dhcpv4.WithServerIP(s.serverIP),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.serverIP)),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(pool.LeaseTime)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(pool.SubnetMask)),
		dhcpv4.WithOption(dhcpv4.OptRouter(pool.Gateway)),
		dhcpv4.WithOption(dhcpv4.OptDNS(pool.DNSServers...)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build ACK: %w", err)
	}

	atomic.AddUint64(&s.acksTotal, 1)
	return resp, nil
}

// handleRelease handles DHCP RELEASE
func (s *Server) handleRelease(req *dhcpv4.DHCPv4) {
	mac := req.ClientHWAddr

	s.leasesMu.Lock()
	lease, exists := s.leases[mac.String()]
	if exists {
		delete(s.leases, mac.String())
	}
	s.leasesMu.Unlock()

	if exists {
		// Send RADIUS Accounting-Stop
		if s.radiusClient != nil && lease.SessionID != "" {
			sessionTime := uint32(time.Since(lease.SessionStart).Seconds())
			go func() {
				err := s.radiusClient.SendAccounting(context.Background(), &radius.AcctRequest{
					SessionID:      lease.SessionID,
					Username:       mac.String(),
					MAC:            mac,
					FramedIP:       lease.IP,
					StatusType:     radius.AcctStatusStop,
					InputOctets:    lease.InputBytes,
					OutputOctets:   lease.OutputBytes,
					SessionTime:    sessionTime,
					TerminateCause: radius.TerminateCauseUserRequest,
					Class:          lease.Class,
				})
				if err != nil {
					s.logger.Warn("Failed to send RADIUS Accounting-Stop",
						zap.String("session_id", lease.SessionID),
						zap.Error(err),
					)
				}
			}()
		}

		// Remove QoS policy
		if s.qosMgr != nil {
			if err := s.qosMgr.RemoveSubscriberQoS(lease.IP); err != nil {
				s.logger.Warn("Failed to remove QoS policy",
					zap.String("ip", lease.IP.String()),
					zap.Error(err),
				)
			}
		}

		// Deallocate NAT
		if s.natMgr != nil {
			if err := s.natMgr.DeallocateNAT(lease.IP); err != nil {
				s.logger.Warn("Failed to deallocate NAT",
					zap.String("ip", lease.IP.String()),
					zap.Error(err),
				)
			}
		}

		// Release IP back to pool
		if pool := s.poolMgr.GetPool(lease.PoolID); pool != nil {
			pool.Release(lease.IP)
		}

		// Remove from fast path cache (MAC-based)
		macU64 := ebpf.MACToUint64(mac)
		if err := s.loader.RemoveSubscriber(macU64); err != nil {
			s.logger.Warn("Failed to remove from fast path cache",
				zap.String("mac", mac.String()),
				zap.Error(err),
			)
		}

		// Remove from VLAN-based cache for QinQ deployments
		if (lease.STag > 0 || lease.CTag > 0) && s.loader.HasVLANSupport() {
			if err := s.loader.RemoveVLANSubscriber(lease.STag, lease.CTag); err != nil {
				s.logger.Warn("Failed to remove from VLAN fast path cache",
					zap.Uint16("s_tag", lease.STag),
					zap.Uint16("c_tag", lease.CTag),
					zap.Error(err),
				)
			}
		}

		// Issue #15: Remove circuit-id to MAC mapping if present
		if lease.CircuitID != nil && len(lease.CircuitID) > 0 {
			if err := s.loader.RemoveCircuitIDMapping(lease.CircuitID); err != nil {
				s.logger.Warn("Failed to remove circuit-id to MAC mapping",
					zap.String("mac", mac.String()),
					zap.String("circuit_id", string(lease.CircuitID)),
					zap.Error(err),
				)
			}

			// Issue #56: Remove circuit-id subscriber mapping
			if s.loader.HasCircuitIDSubscriberSupport() {
				if err := s.loader.RemoveCircuitIDSubscriber(lease.CircuitID); err != nil {
					s.logger.Warn("Failed to remove circuit-id subscriber mapping",
						zap.String("mac", mac.String()),
						zap.String("circuit_id", string(lease.CircuitID)),
						zap.Error(err),
					)
				}
			}
		}

		s.logger.Info("DHCP RELEASE processed",
			zap.String("mac", mac.String()),
			zap.String("ip", lease.IP.String()),
			zap.String("session_id", lease.SessionID),
		)
	}

	atomic.AddUint64(&s.releasesTotal, 1)
}

// handleDecline handles DHCP DECLINE
func (s *Server) handleDecline(req *dhcpv4.DHCPv4) {
	mac := req.ClientHWAddr
	declinedIP := req.RequestedIPAddress()

	s.logger.Warn("DHCP DECLINE received",
		zap.String("mac", mac.String()),
		zap.String("ip", declinedIP.String()),
	)

	// Mark IP as unavailable in pool
	s.leasesMu.Lock()
	lease, exists := s.leases[mac.String()]
	if exists {
		delete(s.leases, mac.String())
	}
	s.leasesMu.Unlock()

	if exists && lease != nil {
		if pool := s.poolMgr.GetPool(lease.PoolID); pool != nil {
			pool.MarkUnavailable(declinedIP)
		}
	}
}

// handleInform handles DHCP INFORM
func (s *Server) handleInform(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	mac := req.ClientHWAddr
	clientIP := req.ClientIPAddr

	// Get pool for network info
	pool := s.poolMgr.ClassifyClient(mac)
	if pool == nil {
		return nil, fmt.Errorf("no pool available for client %s", mac)
	}

	s.logger.Debug("Sending DHCP ACK for INFORM",
		zap.String("mac", mac.String()),
		zap.String("ip", clientIP.String()),
	)

	// Build ACK response (no IP assignment for INFORM)
	resp, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithServerIP(s.serverIP),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.serverIP)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(pool.SubnetMask)),
		dhcpv4.WithOption(dhcpv4.OptRouter(pool.Gateway)),
		dhcpv4.WithOption(dhcpv4.OptDNS(pool.DNSServers...)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build ACK: %w", err)
	}

	return resp, nil
}

// buildNAK builds a DHCP NAK response
func (s *Server) buildNAK(req *dhcpv4.DHCPv4, reason string) (*dhcpv4.DHCPv4, error) {
	s.logger.Warn("Sending DHCP NAK",
		zap.String("mac", req.ClientHWAddr.String()),
		zap.String("reason", reason),
	)

	return dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithServerIP(s.serverIP),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.serverIP)),
	)
}

// updateFastPathCache updates the eBPF fast path cache
func (s *Server) updateFastPathCache(mac net.HardwareAddr, lease *Lease, pool *Pool) error {
	if s.loader == nil {
		return nil
	}

	assignment := &ebpf.PoolAssignment{
		PoolID:      lease.PoolID,
		AllocatedIP: ebpf.IPToUint32(lease.IP),
		VlanID:      pool.VlanID,
		ClientClass: uint8(pool.ClientClass),
		LeaseExpiry: uint64(lease.ExpiresAt.Unix()),
		Flags:       0,
	}

	// Always update MAC-based cache
	macU64 := ebpf.MACToUint64(mac)
	if err := s.loader.AddSubscriber(macU64, assignment); err != nil {
		return err
	}

	// Also update VLAN-based cache for QinQ deployments
	if lease.STag > 0 || lease.CTag > 0 {
		if s.loader.HasVLANSupport() {
			if err := s.loader.AddVLANSubscriber(lease.STag, lease.CTag, assignment); err != nil {
				s.logger.Warn("Failed to update VLAN subscriber cache",
					zap.Uint16("s_tag", lease.STag),
					zap.Uint16("c_tag", lease.CTag),
					zap.Error(err),
				)
			} else {
				s.logger.Debug("Updated VLAN subscriber cache",
					zap.Uint16("s_tag", lease.STag),
					zap.Uint16("c_tag", lease.CTag),
					zap.String("ip", lease.IP.String()),
				)
			}
		}
	}

	return nil
}

// leaseCleanup periodically removes expired leases
func (s *Server) leaseCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredLeases()
		}
	}
}

// cleanupExpiredLeases removes expired leases
func (s *Server) cleanupExpiredLeases() {
	now := time.Now()
	var expired []string

	s.leasesMu.RLock()
	for mac, lease := range s.leases {
		if now.After(lease.ExpiresAt) {
			expired = append(expired, mac)
		}
	}
	s.leasesMu.RUnlock()

	if len(expired) == 0 {
		return
	}

	s.leasesMu.Lock()
	for _, mac := range expired {
		lease := s.leases[mac]
		delete(s.leases, mac)

		// Release IP back to pool
		if pool := s.poolMgr.GetPool(lease.PoolID); pool != nil {
			pool.Release(lease.IP)
		}

		// Remove from fast path cache
		hwAddr, _ := net.ParseMAC(mac)
		if hwAddr != nil {
			macU64 := ebpf.MACToUint64(hwAddr)
			s.loader.RemoveSubscriber(macU64)
		}
	}
	s.leasesMu.Unlock()

	s.logger.Info("Cleaned up expired leases",
		zap.Int("count", len(expired)),
	)
}

// Stats returns DHCP server statistics
func (s *Server) Stats() map[string]uint64 {
	return map[string]uint64{
		"requests_total": s.requestsTotal,
		"offers_total":   s.offersTotal,
		"acks_total":     s.acksTotal,
		"naks_total":     s.naksTotal,
		"releases_total": s.releasesTotal,
	}
}

// ActiveLeases returns the count of active leases
func (s *Server) ActiveLeases() int {
	s.leasesMu.RLock()
	defer s.leasesMu.RUnlock()
	return len(s.leases)
}
