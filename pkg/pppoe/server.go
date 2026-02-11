package pppoe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/radius"
	"go.uber.org/zap"
)

// rawSocket is an interface for platform-specific raw socket operations
type rawSocket interface {
	open(iface string, etherType uint16) error
	close() error
	recv(buf []byte) (int, error)
	send(iface string, dstMAC net.HardwareAddr, etherType uint16, data []byte) error
}

// Server is a PPPoE Access Concentrator (AC) server
type Server struct {
	iface       string
	serverMAC   net.HardwareAddr
	acName      string
	serviceName string
	logger      *zap.Logger

	// Session management
	sessions *SessionManager

	// IP pool
	serverIP     net.IP
	clientIPPool *IPPool
	primaryDNS   net.IP
	secondaryDNS net.IP

	// RADIUS client (optional)
	radiusClient *radius.Client

	// Raw socket (platform-specific)
	socket rawSocket

	// Statistics
	padiReceived  uint64
	padoSent      uint64
	padrReceived  uint64
	padsSent      uint64
	padtReceived  uint64
	padtSent      uint64
	sessionsTotal uint64
}

// IPPool is a simple IP address pool for PPPoE clients
type IPPool struct {
	network   *net.IPNet
	gateway   net.IP
	available []net.IP
	allocated map[string]net.IP // session ID -> IP
}

// NewIPPool creates a new IP pool
func NewIPPool(network string, gateway string) (*IPPool, error) {
	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, fmt.Errorf("invalid network: %w", err)
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		return nil, fmt.Errorf("invalid gateway")
	}

	pool := &IPPool{
		network:   ipnet,
		gateway:   gw,
		available: make([]net.IP, 0),
		allocated: make(map[string]net.IP),
	}

	// Generate available IPs (skip network, gateway, and broadcast)
	ip := ipnet.IP.Mask(ipnet.Mask)
	for {
		ip = nextIP(ip)
		if !ipnet.Contains(ip) {
			break
		}
		// Skip gateway and broadcast
		if !ip.Equal(gw) && !isBroadcast(ip, ipnet) {
			pool.available = append(pool.available, copyIP(ip))
		}
	}

	return pool, nil
}

// Allocate allocates an IP for a session
func (p *IPPool) Allocate(sessionID string) net.IP {
	if len(p.available) == 0 {
		return nil
	}
	ip := p.available[0]
	p.available = p.available[1:]
	p.allocated[sessionID] = ip
	return ip
}

// Release releases an IP back to the pool
func (p *IPPool) Release(sessionID string) {
	if ip, ok := p.allocated[sessionID]; ok {
		delete(p.allocated, sessionID)
		p.available = append(p.available, ip)
	}
}

// ServerConfig configures the PPPoE server
type ServerConfig struct {
	Interface    string
	ACName       string
	ServiceName  string
	ServerIP     string
	ClientPool   string
	PoolGateway  string
	PrimaryDNS   string
	SecondaryDNS string
}

// NewServer creates a new PPPoE server
func NewServer(cfg ServerConfig, logger *zap.Logger) (*Server, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface required")
	}

	// Get interface MAC
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %w", err)
	}

	return newServerWithInterface(cfg, logger, iface)
}

// NewServerWithInterface creates a new PPPoE server with explicit interface (for testing)
func NewServerWithInterface(cfg ServerConfig, logger *zap.Logger, iface *net.Interface) (*Server, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface required")
	}
	if iface == nil {
		return nil, fmt.Errorf("interface cannot be nil")
	}
	return newServerWithInterface(cfg, logger, iface)
}

// newServerWithInterface is the internal server creation logic
func newServerWithInterface(cfg ServerConfig, logger *zap.Logger, iface *net.Interface) (*Server, error) {
	acName := cfg.ACName
	if acName == "" {
		acName = "BNG-AC"
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "internet"
	}

	serverIP := net.ParseIP(cfg.ServerIP)
	if serverIP == nil {
		serverIP = net.ParseIP("10.0.0.1")
	}

	// Create IP pool
	var pool *IPPool
	var err error
	if cfg.ClientPool != "" {
		gateway := cfg.PoolGateway
		if gateway == "" {
			gateway = cfg.ServerIP
		}
		pool, err = NewIPPool(cfg.ClientPool, gateway)
		if err != nil {
			return nil, fmt.Errorf("failed to create IP pool: %w", err)
		}
	}

	return &Server{
		iface:        cfg.Interface,
		serverMAC:    iface.HardwareAddr,
		acName:       acName,
		serviceName:  serviceName,
		logger:       logger,
		sessions:     NewSessionManager(),
		serverIP:     serverIP,
		clientIPPool: pool,
		primaryDNS:   net.ParseIP(cfg.PrimaryDNS),
		secondaryDNS: net.ParseIP(cfg.SecondaryDNS),
	}, nil
}

// SetRADIUSClient sets the RADIUS client for authentication
func (s *Server) SetRADIUSClient(client *radius.Client) {
	s.radiusClient = client
}

// Start starts the PPPoE server
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("Starting PPPoE server",
		zap.String("interface", s.iface),
		zap.String("ac_name", s.acName),
		zap.String("service", s.serviceName),
	)

	// Create platform-specific socket
	s.socket = newRawSocket()
	if err := s.socket.open(s.iface, EtherTypePPPoEDiscovery); err != nil {
		return fmt.Errorf("failed to open socket: %w", err)
	}

	// Start packet processing
	go s.receiveLoop(ctx)

	// Start session cleanup
	go s.cleanupLoop(ctx)

	return nil
}

// Stop stops the PPPoE server
func (s *Server) Stop() error {
	s.logger.Info("Stopping PPPoE server")
	if s.socket != nil {
		return s.socket.close()
	}
	return nil
}

// receiveLoop receives and processes PPPoE packets
func (s *Server) receiveLoop(ctx context.Context) {
	buf := make([]byte, 1522) // Max Ethernet frame size

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := s.socket.recv(buf)
		if err != nil {
			// Timeout or temporary error, continue
			continue
		}

		if n < 14 {
			continue
		}

		// Parse Ethernet header
		dstMAC := net.HardwareAddr(buf[0:6])
		srcMAC := net.HardwareAddr(buf[6:12])
		etherType := binary.BigEndian.Uint16(buf[12:14])

		// Check if it's for us (broadcast or our MAC)
		if !isBroadcastMAC(dstMAC) && dstMAC.String() != s.serverMAC.String() {
			continue
		}

		switch etherType {
		case EtherTypePPPoEDiscovery:
			s.handleDiscovery(srcMAC, buf[14:n])
		case EtherTypePPPoESession:
			s.handleSession(srcMAC, buf[14:n])
		}
	}
}

// handleDiscovery handles PPPoE discovery packets
func (s *Server) handleDiscovery(clientMAC net.HardwareAddr, data []byte) {
	if len(data) < 6 {
		return
	}

	hdr, err := ParsePPPoEHeader(data)
	if err != nil {
		s.logger.Debug("Invalid PPPoE header", zap.Error(err))
		return
	}

	payload := data[6 : 6+hdr.Length]
	tags, err := ParseTags(payload)
	if err != nil {
		s.logger.Debug("Invalid PPPoE tags", zap.Error(err))
		return
	}

	switch hdr.Code {
	case CodePADI:
		atomic.AddUint64(&s.padiReceived, 1)
		s.handlePADI(clientMAC, tags)
	case CodePADR:
		atomic.AddUint64(&s.padrReceived, 1)
		s.handlePADR(clientMAC, tags)
	case CodePADT:
		atomic.AddUint64(&s.padtReceived, 1)
		s.handlePADT(clientMAC, hdr.SessionID)
	}
}

// handlePADI handles PPPoE Active Discovery Initiation
func (s *Server) handlePADI(clientMAC net.HardwareAddr, tags []Tag) {
	s.logger.Debug("Received PADI",
		zap.String("client_mac", clientMAC.String()),
	)

	// Check service name (if specified, must match)
	if sn := FindTag(tags, TagServiceName); sn != nil {
		if len(sn.Value) > 0 && string(sn.Value) != s.serviceName {
			s.logger.Debug("Service name mismatch",
				zap.String("requested", string(sn.Value)),
				zap.String("offered", s.serviceName),
			)
			return
		}
	}

	// Get Host-Uniq for session correlation
	var hostUniq []byte
	if hu := FindTag(tags, TagHostUniq); hu != nil {
		hostUniq = hu.Value
	}

	// Generate AC-Cookie
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		s.logger.Error("Failed to generate AC-Cookie",
			zap.String("client_mac", clientMAC.String()),
			zap.Error(err),
		)
		return
	}

	// Build PADO response
	responseTags := []Tag{
		{Type: TagServiceName, Value: []byte(s.serviceName)},
		{Type: TagACName, Value: []byte(s.acName)},
		{Type: TagACCookie, Value: cookie},
	}

	if hostUniq != nil {
		responseTags = append(responseTags, Tag{Type: TagHostUniq, Value: hostUniq})
	}

	s.sendDiscoveryPacket(clientMAC, CodePADO, 0, responseTags)
	atomic.AddUint64(&s.padoSent, 1)

	s.logger.Debug("Sent PADO",
		zap.String("client_mac", clientMAC.String()),
	)
}

// handlePADR handles PPPoE Active Discovery Request
func (s *Server) handlePADR(clientMAC net.HardwareAddr, tags []Tag) {
	s.logger.Debug("Received PADR",
		zap.String("client_mac", clientMAC.String()),
	)

	// Verify AC-Cookie
	if cookie := FindTag(tags, TagACCookie); cookie == nil {
		s.logger.Warn("PADR without AC-Cookie")
		return
	}

	// Get Host-Uniq
	var hostUniq []byte
	if hu := FindTag(tags, TagHostUniq); hu != nil {
		hostUniq = hu.Value
	}

	// Create session
	session, err := s.sessions.CreateSession(clientMAC, s.serverMAC)
	if err != nil {
		s.logger.Error("Failed to create session",
			zap.String("client_mac", clientMAC.String()),
			zap.Error(err),
		)
		return
	}
	session.HostUniq = hostUniq

	if sn := FindTag(tags, TagServiceName); sn != nil {
		session.ServiceName = string(sn.Value)
	}

	// Build PADS response
	responseTags := []Tag{
		{Type: TagServiceName, Value: []byte(s.serviceName)},
	}

	if hostUniq != nil {
		responseTags = append(responseTags, Tag{Type: TagHostUniq, Value: hostUniq})
	}

	s.sendDiscoveryPacket(clientMAC, CodePADS, session.ID, responseTags)
	atomic.AddUint64(&s.padsSent, 1)
	atomic.AddUint64(&s.sessionsTotal, 1)

	// Move to LCP negotiation
	session.SetState(StateLCPNegotiation)

	s.logger.Info("PPPoE session created",
		zap.Uint16("session_id", session.ID),
		zap.String("client_mac", clientMAC.String()),
	)

	// Start LCP negotiation
	go s.startLCPNegotiation(session)
}

// handlePADT handles PPPoE Active Discovery Terminate
func (s *Server) handlePADT(clientMAC net.HardwareAddr, sessionID uint16) {
	session := s.sessions.GetSession(sessionID)
	if session == nil {
		return
	}

	s.logger.Info("PPPoE session terminated by client",
		zap.Uint16("session_id", sessionID),
		zap.String("client_mac", clientMAC.String()),
	)

	// Release IP
	if s.clientIPPool != nil {
		s.clientIPPool.Release(session.SessionID)
	}

	// Remove session
	s.sessions.RemoveSession(sessionID)
}

// handleSession handles PPPoE session packets (PPP)
func (s *Server) handleSession(clientMAC net.HardwareAddr, data []byte) {
	if len(data) < 8 {
		return
	}

	hdr, err := ParsePPPoEHeader(data)
	if err != nil {
		return
	}

	session := s.sessions.GetSession(hdr.SessionID)
	if session == nil {
		return
	}

	session.UpdateActivity()
	session.AddBytesIn(uint64(len(data)))

	// Parse PPP header
	pppProto := binary.BigEndian.Uint16(data[6:8])
	pppPayload := data[8 : 6+int(hdr.Length)]

	switch pppProto {
	case ProtocolLCP:
		s.handleLCP(session, pppPayload)
	case ProtocolPAP:
		s.handlePAP(session, pppPayload)
	case ProtocolIPCP:
		s.handleIPCP(session, pppPayload)
	case ProtocolIP:
		s.handleIPPacket(session, pppPayload)
	}
}

// startLCPNegotiation initiates LCP negotiation
func (s *Server) startLCPNegotiation(session *Session) {
	// Send Configure-Request
	opts := []LCPOption{
		{Type: LCPOptMRU, Data: []byte{0x05, 0xD4}}, // MRU 1492
		{Type: LCPOptMagicNumber, Data: magicToBytes(session.MagicNumber)},
		{Type: LCPOptAuthProto, Data: []byte{0xC0, 0x23}}, // PAP
	}

	pkt := &LCPPacket{
		Code:       LCPCodeConfigRequest,
		Identifier: session.NextLCPIdentifier(),
		Data:       SerializeLCPOptions(opts),
	}

	s.sendPPPPacket(session, ProtocolLCP, pkt.Serialize())
}

// handleLCP handles LCP packets
func (s *Server) handleLCP(session *Session, data []byte) {
	pkt, err := ParseLCPPacket(data)
	if err != nil {
		return
	}

	switch pkt.Code {
	case LCPCodeConfigRequest:
		s.handleLCPConfigRequest(session, pkt)
	case LCPCodeConfigAck:
		s.handleLCPConfigAck(session, pkt)
	case LCPCodeConfigNak:
		s.handleLCPConfigNak(session, pkt)
	case LCPCodeEchoRequest:
		s.handleLCPEchoRequest(session, pkt)
	case LCPCodeTermRequest:
		s.handleLCPTermRequest(session, pkt)
	}
}

// handleLCPConfigRequest handles LCP Configure-Request
func (s *Server) handleLCPConfigRequest(session *Session, pkt *LCPPacket) {
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return
	}

	// Check options and build response
	accepted := true
	for _, opt := range opts {
		switch opt.Type {
		case LCPOptMRU:
			if len(opt.Data) >= 2 {
				session.PeerMRU = binary.BigEndian.Uint16(opt.Data)
			}
		case LCPOptMagicNumber:
			if len(opt.Data) >= 4 {
				session.PeerMagic = binary.BigEndian.Uint32(opt.Data)
			}
		}
	}

	var respCode uint8
	if accepted {
		respCode = LCPCodeConfigAck
	} else {
		respCode = LCPCodeConfigNak
	}

	resp := &LCPPacket{
		Code:       respCode,
		Identifier: pkt.Identifier,
		Data:       pkt.Data,
	}

	s.sendPPPPacket(session, ProtocolLCP, resp.Serialize())
}

// handleLCPConfigAck handles LCP Configure-Ack
func (s *Server) handleLCPConfigAck(session *Session, pkt *LCPPacket) {
	s.logger.Debug("LCP Configure-Ack received",
		zap.Uint16("session_id", session.ID),
	)

	// Move to authentication phase
	session.SetState(StateAuthentication)
}

// handleLCPConfigNak handles LCP Configure-Nak
func (s *Server) handleLCPConfigNak(session *Session, pkt *LCPPacket) {
	// Re-send with suggested values
	s.startLCPNegotiation(session)
}

// handleLCPEchoRequest handles LCP Echo-Request
func (s *Server) handleLCPEchoRequest(session *Session, pkt *LCPPacket) {
	resp := &LCPPacket{
		Code:       LCPCodeEchoReply,
		Identifier: pkt.Identifier,
		Data:       magicToBytes(session.MagicNumber),
	}
	s.sendPPPPacket(session, ProtocolLCP, resp.Serialize())
}

// handleLCPTermRequest handles LCP Terminate-Request
func (s *Server) handleLCPTermRequest(session *Session, pkt *LCPPacket) {
	// Send Terminate-Ack
	resp := &LCPPacket{
		Code:       LCPCodeTermAck,
		Identifier: pkt.Identifier,
	}
	s.sendPPPPacket(session, ProtocolLCP, resp.Serialize())

	// Terminate session
	session.SetState(StateClosed)
	s.sessions.RemoveSession(session.ID)
}

// handlePAP handles PAP authentication packets
func (s *Server) handlePAP(session *Session, data []byte) {
	if len(data) < 4 {
		return
	}

	code := data[0]
	identifier := data[1]
	// length := binary.BigEndian.Uint16(data[2:4])

	if code != PAPCodeAuthRequest {
		return
	}

	// Parse username and password
	if len(data) < 6 {
		return
	}

	usernameLen := int(data[4])
	if len(data) < 5+usernameLen+1 {
		return
	}

	username := string(data[5 : 5+usernameLen])
	passwordLen := int(data[5+usernameLen])
	if len(data) < 6+usernameLen+passwordLen {
		return
	}

	passwordBytes := make([]byte, passwordLen)
	copy(passwordBytes, data[6+usernameLen:6+usernameLen+passwordLen])
	// Zero password in the original packet buffer
	for i := 0; i < passwordLen; i++ {
		data[6+usernameLen+i] = 0
	}

	s.logger.Debug("PAP authentication attempt",
		zap.Uint16("session_id", session.ID),
		zap.String("username", username),
	)

	// Authenticate (via RADIUS if configured)
	var authenticated bool
	var authResp *radius.AuthResponse

	if s.radiusClient != nil {
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		authResp, err = s.radiusClient.Authenticate(ctx, &radius.AuthRequest{
			Username: username,
			Password: string(passwordBytes),
			MAC:      session.ClientMAC,
		})
		authenticated = err == nil && authResp != nil && authResp.Accepted
	} else {
		// Accept all if no RADIUS
		authenticated = true
	}
	// Zero password now that authentication is complete
	zeroBytes(passwordBytes)

	session.Username = username
	session.Authenticated = authenticated
	session.AuthMethod = "PAP"

	// Send response
	var respCode uint8
	var msg string
	if authenticated {
		respCode = PAPCodeAuthAck
		msg = "Login OK"
		s.logger.Info("PAP authentication successful",
			zap.Uint16("session_id", session.ID),
			zap.String("username", username),
		)
	} else {
		respCode = PAPCodeAuthNak
		msg = "Login incorrect"
		s.logger.Warn("PAP authentication failed",
			zap.Uint16("session_id", session.ID),
			zap.String("username", username),
		)
	}

	respData := make([]byte, 5+len(msg))
	respData[0] = respCode
	respData[1] = identifier
	binary.BigEndian.PutUint16(respData[2:4], uint16(5+len(msg)))
	respData[4] = byte(len(msg))
	copy(respData[5:], msg)

	s.sendPPPPacket(session, ProtocolPAP, respData)

	if authenticated {
		// Store RADIUS class if present
		if authResp != nil {
			session.Class = authResp.Class
		}
		// Move to IPCP
		session.SetState(StateIPCPNegotiation)
		s.startIPCPNegotiation(session)
	} else {
		// Terminate
		session.SetState(StateClosed)
	}
}

// startIPCPNegotiation initiates IPCP negotiation
func (s *Server) startIPCPNegotiation(session *Session) {
	// Allocate IP for client
	if s.clientIPPool != nil {
		session.ClientIP = s.clientIPPool.Allocate(session.SessionID)
	}
	session.ServerIP = s.serverIP

	if session.ClientIP == nil {
		s.logger.Error("Failed to allocate IP for session",
			zap.Uint16("session_id", session.ID),
		)
		return
	}

	// Send IPCP Configure-Request
	opts := []LCPOption{
		{Type: IPCPOptIPAddress, Data: session.ServerIP.To4()},
	}

	pkt := &LCPPacket{
		Code:       LCPCodeConfigRequest,
		Identifier: session.NextLCPIdentifier(),
		Data:       SerializeLCPOptions(opts),
	}

	s.sendPPPPacket(session, ProtocolIPCP, pkt.Serialize())
}

// handleIPCP handles IPCP packets
func (s *Server) handleIPCP(session *Session, data []byte) {
	pkt, err := ParseLCPPacket(data)
	if err != nil {
		return
	}

	switch pkt.Code {
	case LCPCodeConfigRequest:
		s.handleIPCPConfigRequest(session, pkt)
	case LCPCodeConfigAck:
		s.handleIPCPConfigAck(session, pkt)
	}
}

// handleIPCPConfigRequest handles IPCP Configure-Request
func (s *Server) handleIPCPConfigRequest(session *Session, pkt *LCPPacket) {
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return
	}

	// Build response options
	var respOpts []LCPOption
	nakOptions := false

	for _, opt := range opts {
		switch opt.Type {
		case IPCPOptIPAddress:
			// Client requesting IP - give them the allocated one
			if session.ClientIP != nil {
				respOpts = append(respOpts, LCPOption{
					Type: IPCPOptIPAddress,
					Data: session.ClientIP.To4(),
				})
				nakOptions = true
			}
		case IPCPOptPrimaryDNS:
			if s.primaryDNS != nil {
				respOpts = append(respOpts, LCPOption{
					Type: IPCPOptPrimaryDNS,
					Data: s.primaryDNS.To4(),
				})
				nakOptions = true
			}
		case IPCPOptSecondaryDNS:
			if s.secondaryDNS != nil {
				respOpts = append(respOpts, LCPOption{
					Type: IPCPOptSecondaryDNS,
					Data: s.secondaryDNS.To4(),
				})
				nakOptions = true
			}
		}
	}

	var respCode uint8
	var respData []byte
	if nakOptions {
		respCode = LCPCodeConfigNak
		respData = SerializeLCPOptions(respOpts)
	} else {
		respCode = LCPCodeConfigAck
		respData = pkt.Data
	}

	resp := &LCPPacket{
		Code:       respCode,
		Identifier: pkt.Identifier,
		Data:       respData,
	}

	s.sendPPPPacket(session, ProtocolIPCP, resp.Serialize())
}

// handleIPCPConfigAck handles IPCP Configure-Ack
func (s *Server) handleIPCPConfigAck(session *Session, pkt *LCPPacket) {
	session.SetState(StateEstablished)

	s.logger.Info("PPPoE session established",
		zap.Uint16("session_id", session.ID),
		zap.String("username", session.Username),
		zap.String("client_ip", session.ClientIP.String()),
	)
}

// handleIPPacket handles encapsulated IP packets
func (s *Server) handleIPPacket(session *Session, data []byte) {
	if !session.IsEstablished() {
		return
	}

	// In a real implementation, this would forward the packet
	// For now, just log it
	s.logger.Debug("IP packet received",
		zap.Uint16("session_id", session.ID),
		zap.Int("length", len(data)),
	)
}

// sendDiscoveryPacket sends a PPPoE discovery packet
func (s *Server) sendDiscoveryPacket(dstMAC net.HardwareAddr, code uint8, sessionID uint16, tags []Tag) {
	tagData := SerializeTags(tags)

	hdr := &PPPoEHeader{
		VerType:   0x11,
		Code:      code,
		SessionID: sessionID,
		Length:    uint16(len(tagData)),
	}

	payload := append(hdr.Serialize(), tagData...)
	frame := BuildEthernetFrame(dstMAC, s.serverMAC, EtherTypePPPoEDiscovery, payload)

	s.socket.send(s.iface, dstMAC, EtherTypePPPoEDiscovery, frame)
}

// sendPPPPacket sends a PPP packet over PPPoE session
func (s *Server) sendPPPPacket(session *Session, protocol uint16, data []byte) {
	payload := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(payload[0:2], protocol)
	copy(payload[2:], data)

	hdr := &PPPoEHeader{
		VerType:   0x11,
		Code:      CodeSession,
		SessionID: session.ID,
		Length:    uint16(len(payload)),
	}

	frame := append(hdr.Serialize(), payload...)
	ethFrame := BuildEthernetFrame(session.ClientMAC, s.serverMAC, EtherTypePPPoESession, frame)

	s.socket.send(s.iface, session.ClientMAC, EtherTypePPPoESession, ethFrame)
	session.AddBytesOut(uint64(len(ethFrame)))
}

// cleanupLoop periodically cleans up expired sessions
func (s *Server) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed := s.sessions.CleanupExpired(5 * time.Minute)
			if removed > 0 {
				s.logger.Info("Cleaned up expired PPPoE sessions",
					zap.Int("count", removed),
				)
			}
		}
	}
}

// GetSessionCount returns the number of active sessions
func (s *Server) GetSessionCount() int {
	return s.sessions.Count()
}

// GetStats returns PPPoE statistics
func (s *Server) GetStats() map[string]uint64 {
	return map[string]uint64{
		"padi_received":   atomic.LoadUint64(&s.padiReceived),
		"pado_sent":       atomic.LoadUint64(&s.padoSent),
		"padr_received":   atomic.LoadUint64(&s.padrReceived),
		"pads_sent":       atomic.LoadUint64(&s.padsSent),
		"padt_received":   atomic.LoadUint64(&s.padtReceived),
		"padt_sent":       atomic.LoadUint64(&s.padtSent),
		"sessions_total":  atomic.LoadUint64(&s.sessionsTotal),
		"sessions_active": uint64(s.sessions.Count()),
	}
}

// Helper functions

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func isBroadcast(ip net.IP, network *net.IPNet) bool {
	if ip == nil {
		return false
	}
	// Check for all-ones broadcast
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255
	}
	// For MAC address broadcast check
	if len(ip) == 6 {
		for _, b := range ip {
			if b != 0xff {
				return false
			}
		}
		return true
	}
	return false
}

func magicToBytes(magic uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, magic)
	return b
}

func isBroadcastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}
