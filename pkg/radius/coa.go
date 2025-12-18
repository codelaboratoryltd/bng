package radius

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// RADIUS attribute types (RFC 2865)
const (
	AttrUserName         = 1
	AttrUserPassword     = 2
	AttrNASIPAddress     = 4
	AttrNASPort          = 5
	AttrFramedIPAddress  = 8
	AttrFilterID         = 11
	AttrReplyMessage     = 18
	AttrCallingStationID = 31
	AttrCalledStationID  = 30
	AttrAcctSessionID    = 44
	AttrNASPortType      = 61
	AttrSessionTimeout   = 27
	AttrIdleTimeout      = 28
	AttrClass            = 25
	AttrVendorSpecific   = 26
)

// Attribute represents a RADIUS attribute
type Attribute struct {
	Type  uint8
	Value []byte
}

// CoA/DM packet codes
const (
	CodeDisconnectRequest = 40
	CodeDisconnectACK     = 41
	CodeDisconnectNAK     = 42
	CodeCoARequest        = 43
	CodeCoAACK            = 44
	CodeCoANAK            = 45
)

// Error-Cause attribute values
const (
	ErrorCauseResidualSessionContextRemoved = 201
	ErrorCauseMissingAttribute              = 402
	ErrorCauseNASIdentificationMismatch     = 403
	ErrorCauseInvalidRequest                = 404
	ErrorCauseUnsupportedService            = 405
	ErrorCauseUnsupportedExtension          = 406
	ErrorCauseAdministrativelyProhibited    = 501
	ErrorCauseSessionContextNotFound        = 503
	ErrorCauseSessionContextNotRemovable    = 504
	ErrorCauseResourcesUnavailable          = 506
	ErrorCauseRequestInitiatedByNAS         = 508
)

// CoAHandler is called when a CoA request is received
type CoAHandler func(ctx context.Context, req *CoARequest) *CoAResponse

// DisconnectHandler is called when a Disconnect request is received
type DisconnectHandler func(ctx context.Context, req *DisconnectRequest) *DisconnectResponse

// CoARequest represents a Change of Authorization request
type CoARequest struct {
	SessionID      string
	Username       string
	NASIPAddress   net.IP
	FramedIP       net.IP
	CallingStation string // MAC address

	// Changed attributes
	FramedPool     string
	SessionTimeout uint32
	IdleTimeout    uint32
	FilterID       string

	// QoS changes
	QoSDownload uint32 // kbps
	QoSUpload   uint32 // kbps

	// Raw attributes
	Attributes []Attribute
}

// CoAResponse represents a Change of Authorization response
type CoAResponse struct {
	Success    bool
	ErrorCause uint32
	Message    string
}

// DisconnectRequest represents a Disconnect request
type DisconnectRequest struct {
	SessionID      string
	Username       string
	NASIPAddress   net.IP
	FramedIP       net.IP
	CallingStation string
	AcctSessionID  string
}

// DisconnectResponse represents a Disconnect response
type DisconnectResponse struct {
	Success    bool
	ErrorCause uint32
	Message    string
}

// CoAServer listens for CoA and Disconnect-Message requests
type CoAServer struct {
	addr    string
	secret  string
	logger  *zap.Logger
	conn    *net.UDPConn
	running int32

	// Handlers
	coaHandler        CoAHandler
	disconnectHandler DisconnectHandler

	// Session lookup (typically injected from session manager)
	sessionLookup func(sessionID string) bool

	// Statistics
	coaRequestsRecv uint64
	coaACKsSent     uint64
	coaNAKsSent     uint64
	dmRequestsRecv  uint64
	dmACKsSent      uint64
	dmNAKsSent      uint64

	mu sync.RWMutex
}

// CoAServerConfig configures the CoA server
type CoAServerConfig struct {
	Address string // Listen address (default :3799)
	Secret  string // RADIUS shared secret
}

// NewCoAServer creates a new CoA server
func NewCoAServer(cfg CoAServerConfig, logger *zap.Logger) (*CoAServer, error) {
	if cfg.Secret == "" {
		return nil, fmt.Errorf("RADIUS secret required")
	}

	addr := cfg.Address
	if addr == "" {
		addr = ":3799" // Standard CoA port
	}

	return &CoAServer{
		addr:   addr,
		secret: cfg.Secret,
		logger: logger,
	}, nil
}

// SetCoAHandler sets the handler for CoA requests
func (s *CoAServer) SetCoAHandler(handler CoAHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.coaHandler = handler
}

// SetDisconnectHandler sets the handler for Disconnect requests
func (s *CoAServer) SetDisconnectHandler(handler DisconnectHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disconnectHandler = handler
}

// SetSessionLookup sets the function to verify session existence
func (s *CoAServer) SetSessionLookup(lookup func(sessionID string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionLookup = lookup
}

// Start starts the CoA server
func (s *CoAServer) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.conn = conn

	atomic.StoreInt32(&s.running, 1)

	s.logger.Info("CoA server started",
		zap.String("address", s.addr),
	)

	go s.receiveLoop(ctx)

	return nil
}

// Stop stops the CoA server
func (s *CoAServer) Stop() error {
	atomic.StoreInt32(&s.running, 0)
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// receiveLoop receives and processes CoA/DM packets
func (s *CoAServer) receiveLoop(ctx context.Context) {
	buf := make([]byte, 4096)

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

		if n < 20 {
			continue
		}

		// Parse RADIUS packet
		code := buf[0]
		identifier := buf[1]
		length := binary.BigEndian.Uint16(buf[2:4])
		authenticator := buf[4:20]

		if int(length) > n {
			continue
		}

		// Verify authenticator
		if !s.verifyRequestAuthenticator(buf[:length], authenticator) {
			s.logger.Warn("Invalid authenticator from",
				zap.String("addr", addr.String()),
			)
			continue
		}

		// Parse attributes
		attrs, err := parseAttributes(buf[20:length])
		if err != nil {
			s.logger.Debug("Failed to parse attributes", zap.Error(err))
			continue
		}

		switch code {
		case CodeCoARequest:
			atomic.AddUint64(&s.coaRequestsRecv, 1)
			s.handleCoARequest(ctx, identifier, authenticator, attrs, addr)
		case CodeDisconnectRequest:
			atomic.AddUint64(&s.dmRequestsRecv, 1)
			s.handleDisconnectRequest(ctx, identifier, authenticator, attrs, addr)
		default:
			s.logger.Debug("Unknown RADIUS code",
				zap.Uint8("code", code),
				zap.String("from", addr.String()),
			)
		}
	}
}

// handleCoARequest handles a Change of Authorization request
func (s *CoAServer) handleCoARequest(ctx context.Context, identifier uint8, authenticator []byte, attrs []Attribute, addr *net.UDPAddr) {
	s.logger.Info("Received CoA request",
		zap.String("from", addr.String()),
	)

	req := s.parseCoARequest(attrs)

	s.mu.RLock()
	handler := s.coaHandler
	s.mu.RUnlock()

	var response *CoAResponse
	if handler != nil {
		response = handler(ctx, req)
	} else {
		// Default: accept all CoA requests
		response = &CoAResponse{Success: true}
	}

	s.sendCoAResponse(identifier, authenticator, response, addr)
}

// handleDisconnectRequest handles a Disconnect request
func (s *CoAServer) handleDisconnectRequest(ctx context.Context, identifier uint8, authenticator []byte, attrs []Attribute, addr *net.UDPAddr) {
	s.logger.Info("Received Disconnect request",
		zap.String("from", addr.String()),
	)

	req := s.parseDisconnectRequest(attrs)

	s.mu.RLock()
	handler := s.disconnectHandler
	s.mu.RUnlock()

	var response *DisconnectResponse
	if handler != nil {
		response = handler(ctx, req)
	} else {
		// Default: reject (no session found)
		response = &DisconnectResponse{
			Success:    false,
			ErrorCause: ErrorCauseSessionContextNotFound,
			Message:    "Session not found",
		}
	}

	s.sendDisconnectResponse(identifier, authenticator, response, addr)
}

// parseCoARequest parses attributes into a CoARequest
func (s *CoAServer) parseCoARequest(attrs []Attribute) *CoARequest {
	req := &CoARequest{
		Attributes: attrs,
	}

	for _, attr := range attrs {
		switch attr.Type {
		case AttrUserName:
			req.Username = string(attr.Value)
		case AttrNASIPAddress:
			if len(attr.Value) == 4 {
				req.NASIPAddress = net.IP(attr.Value)
			}
		case AttrFramedIPAddress:
			if len(attr.Value) == 4 {
				req.FramedIP = net.IP(attr.Value)
			}
		case AttrCallingStationID:
			req.CallingStation = string(attr.Value)
		case AttrAcctSessionID:
			req.SessionID = string(attr.Value)
		case AttrSessionTimeout:
			if len(attr.Value) == 4 {
				req.SessionTimeout = binary.BigEndian.Uint32(attr.Value)
			}
		case AttrIdleTimeout:
			if len(attr.Value) == 4 {
				req.IdleTimeout = binary.BigEndian.Uint32(attr.Value)
			}
		case AttrFilterID:
			req.FilterID = string(attr.Value)
			// Vendor-specific QoS attributes would be handled here
		}
	}

	return req
}

// parseDisconnectRequest parses attributes into a DisconnectRequest
func (s *CoAServer) parseDisconnectRequest(attrs []Attribute) *DisconnectRequest {
	req := &DisconnectRequest{}

	for _, attr := range attrs {
		switch attr.Type {
		case AttrUserName:
			req.Username = string(attr.Value)
		case AttrNASIPAddress:
			if len(attr.Value) == 4 {
				req.NASIPAddress = net.IP(attr.Value)
			}
		case AttrFramedIPAddress:
			if len(attr.Value) == 4 {
				req.FramedIP = net.IP(attr.Value)
			}
		case AttrCallingStationID:
			req.CallingStation = string(attr.Value)
		case AttrAcctSessionID:
			req.SessionID = string(attr.Value)
			req.AcctSessionID = string(attr.Value)
		}
	}

	return req
}

// sendCoAResponse sends a CoA-ACK or CoA-NAK response
func (s *CoAServer) sendCoAResponse(identifier uint8, requestAuth []byte, resp *CoAResponse, addr *net.UDPAddr) {
	var code uint8
	if resp.Success {
		code = CodeCoAACK
		atomic.AddUint64(&s.coaACKsSent, 1)
	} else {
		code = CodeCoANAK
		atomic.AddUint64(&s.coaNAKsSent, 1)
	}

	s.sendResponse(code, identifier, requestAuth, resp.ErrorCause, resp.Message, addr)
}

// sendDisconnectResponse sends a Disconnect-ACK or Disconnect-NAK response
func (s *CoAServer) sendDisconnectResponse(identifier uint8, requestAuth []byte, resp *DisconnectResponse, addr *net.UDPAddr) {
	var code uint8
	if resp.Success {
		code = CodeDisconnectACK
		atomic.AddUint64(&s.dmACKsSent, 1)
	} else {
		code = CodeDisconnectNAK
		atomic.AddUint64(&s.dmNAKsSent, 1)
	}

	s.sendResponse(code, identifier, requestAuth, resp.ErrorCause, resp.Message, addr)
}

// sendResponse sends a RADIUS response
func (s *CoAServer) sendResponse(code, identifier uint8, requestAuth []byte, errorCause uint32, message string, addr *net.UDPAddr) {
	// Build response packet
	var attrs []byte

	// Add Error-Cause attribute if present
	if errorCause != 0 {
		errorAttr := make([]byte, 6)
		errorAttr[0] = 101 // Error-Cause attribute type
		errorAttr[1] = 6   // Length
		binary.BigEndian.PutUint32(errorAttr[2:6], errorCause)
		attrs = append(attrs, errorAttr...)
	}

	// Add Reply-Message if present
	if message != "" {
		msgAttr := make([]byte, 2+len(message))
		msgAttr[0] = 18 // Reply-Message attribute type
		msgAttr[1] = uint8(2 + len(message))
		copy(msgAttr[2:], message)
		attrs = append(attrs, msgAttr...)
	}

	// Build packet
	length := 20 + len(attrs)
	packet := make([]byte, length)
	packet[0] = code
	packet[1] = identifier
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))

	// Copy attributes
	copy(packet[20:], attrs)

	// Calculate response authenticator
	// Response Auth = MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
	hash := md5.New()
	hash.Write(packet[:4])
	hash.Write(requestAuth)
	hash.Write(packet[20:])
	hash.Write([]byte(s.secret))
	responseAuth := hash.Sum(nil)
	copy(packet[4:20], responseAuth)

	// Send response
	_, err := s.conn.WriteToUDP(packet, addr)
	if err != nil {
		s.logger.Error("Failed to send response",
			zap.Error(err),
			zap.String("to", addr.String()),
		)
	}
}

// verifyRequestAuthenticator verifies the request authenticator
func (s *CoAServer) verifyRequestAuthenticator(packet []byte, authenticator []byte) bool {
	// For CoA/DM requests: Authenticator = MD5(Code + ID + Length + 16 zero bytes + Attributes + Secret)
	hash := md5.New()
	hash.Write(packet[:4])
	hash.Write(make([]byte, 16)) // 16 zero bytes
	hash.Write(packet[20:])
	hash.Write([]byte(s.secret))
	expected := hash.Sum(nil)

	for i := range authenticator {
		if authenticator[i] != expected[i] {
			return false
		}
	}
	return true
}

// parseAttributes parses RADIUS attributes from bytes
func parseAttributes(data []byte) ([]Attribute, error) {
	var attrs []Attribute
	offset := 0

	for offset+2 <= len(data) {
		attrType := data[offset]
		attrLen := int(data[offset+1])

		if attrLen < 2 || offset+attrLen > len(data) {
			return nil, fmt.Errorf("invalid attribute length")
		}

		attr := Attribute{
			Type:  attrType,
			Value: make([]byte, attrLen-2),
		}
		copy(attr.Value, data[offset+2:offset+attrLen])
		attrs = append(attrs, attr)

		offset += attrLen
	}

	return attrs, nil
}

// GetStats returns CoA server statistics
func (s *CoAServer) GetStats() map[string]uint64 {
	return map[string]uint64{
		"coa_requests_received":        atomic.LoadUint64(&s.coaRequestsRecv),
		"coa_acks_sent":                atomic.LoadUint64(&s.coaACKsSent),
		"coa_naks_sent":                atomic.LoadUint64(&s.coaNAKsSent),
		"disconnect_requests_received": atomic.LoadUint64(&s.dmRequestsRecv),
		"disconnect_acks_sent":         atomic.LoadUint64(&s.dmACKsSent),
		"disconnect_naks_sent":         atomic.LoadUint64(&s.dmNAKsSent),
	}
}
