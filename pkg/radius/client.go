package radius

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
)

// Client is a RADIUS client for AAA operations
type Client struct {
	servers    []ServerConfig
	nasID      string
	logger     *zap.Logger
	timeout    time.Duration
	retries    int
	currentIdx int
	mu         sync.Mutex
}

// ServerConfig holds RADIUS server configuration
type ServerConfig struct {
	Host   string
	Port   int
	Secret string
}

// ClientConfig holds RADIUS client configuration
type ClientConfig struct {
	Servers []ServerConfig
	NASID   string
	Timeout time.Duration
	Retries int
}

// AuthRequest holds authentication request parameters
type AuthRequest struct {
	Username    string           // Usually MAC address
	Password    string           // May be empty for MAC auth
	MAC         net.HardwareAddr // Client MAC
	CircuitID   string           // Option 82 circuit ID
	RemoteID    string           // Option 82 remote ID (NTE ID)
	NASPort     uint32           // NAS port number
	NASPortType uint32           // NAS port type (Ethernet = 15)
	CalledID    string           // Called-Station-Id
	CallingID   string           // Calling-Station-Id
}

// AuthResponse holds authentication response data
type AuthResponse struct {
	Accepted       bool
	RejectReason   string
	SessionTimeout uint32 // Session-Timeout attribute
	IdleTimeout    uint32 // Idle-Timeout attribute
	FramedIP       net.IP // Framed-IP-Address
	FramedPool     string // Framed-Pool
	FilterID       string // Filter-Id (QoS policy name)
	Class          []byte // Class attribute (for accounting)
	DownloadBPS    uint64 // Download rate limit (bits/sec)
	UploadBPS      uint64 // Upload rate limit (bits/sec)
	Attributes     map[string]interface{}
}

// AcctRequest holds accounting request parameters
type AcctRequest struct {
	SessionID      string
	Username       string
	MAC            net.HardwareAddr
	FramedIP       net.IP
	StatusType     AcctStatusType
	InputOctets    uint64
	OutputOctets   uint64
	InputPackets   uint64
	OutputPackets  uint64
	SessionTime    uint32
	TerminateCause uint32
	Class          []byte
	NASPort        uint32
	CircuitID      string
	RemoteID       string
}

// AcctStatusType represents RADIUS accounting status types
type AcctStatusType uint32

const (
	AcctStatusStart         AcctStatusType = 1
	AcctStatusStop          AcctStatusType = 2
	AcctStatusInterimUpdate AcctStatusType = 3
	AcctStatusAccountingOn  AcctStatusType = 7
	AcctStatusAccountingOff AcctStatusType = 8
)

// NewClient creates a new RADIUS client
func NewClient(cfg ClientConfig, logger *zap.Logger) (*Client, error) {
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("at least one RADIUS server required")
	}
	if cfg.NASID == "" {
		return nil, fmt.Errorf("NAS-Identifier required")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	retries := cfg.Retries
	if retries == 0 {
		retries = 3
	}

	return &Client{
		servers: cfg.Servers,
		nasID:   cfg.NASID,
		logger:  logger,
		timeout: timeout,
		retries: retries,
	}, nil
}

// Authenticate sends an Access-Request and returns the response
func (c *Client) Authenticate(ctx context.Context, req *AuthRequest) (*AuthResponse, error) {
	server := c.getServer()

	packet := radius.New(radius.CodeAccessRequest, []byte(server.Secret))

	// Standard attributes
	rfc2865.UserName_SetString(packet, req.Username)
	if req.Password != "" {
		rfc2865.UserPassword_SetString(packet, req.Password)
	}
	rfc2865.NASIdentifier_SetString(packet, c.nasID)
	rfc2865.NASPortType_Set(packet, rfc2865.NASPortType(req.NASPortType))
	rfc2865.NASPort_Set(packet, rfc2865.NASPort(req.NASPort))

	// Calling/Called Station IDs
	if req.CallingID != "" {
		rfc2865.CallingStationID_SetString(packet, req.CallingID)
	} else if req.MAC != nil {
		rfc2865.CallingStationID_SetString(packet, formatMAC(req.MAC))
	}
	if req.CalledID != "" {
		rfc2865.CalledStationID_SetString(packet, req.CalledID)
	}

	// Add Message-Authenticator
	if err := addMessageAuthenticator(packet, []byte(server.Secret)); err != nil {
		return nil, fmt.Errorf("failed to add message authenticator: %w", err)
	}

	// Send request with retries
	addr := fmt.Sprintf("%s:%d", server.Host, server.Port)
	var response *radius.Packet
	var err error

	for attempt := 0; attempt < c.retries; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
		response, err = radius.Exchange(reqCtx, packet, addr)
		cancel()

		if err == nil {
			break
		}

		c.logger.Warn("RADIUS request failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Error(err),
		)

		// Try next server on failure
		if attempt < c.retries-1 {
			c.nextServer()
			server = c.getServer()
			addr = fmt.Sprintf("%s:%d", server.Host, server.Port)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("RADIUS authentication failed after %d attempts: %w", c.retries, err)
	}

	// Parse response
	authResp := &AuthResponse{
		Attributes: make(map[string]interface{}),
	}

	switch response.Code {
	case radius.CodeAccessAccept:
		authResp.Accepted = true
		c.parseAuthAttributes(response, authResp)
	case radius.CodeAccessReject:
		authResp.Accepted = false
		if msg, err := rfc2865.ReplyMessage_LookupString(response); err == nil {
			authResp.RejectReason = msg
		}
	case radius.CodeAccessChallenge:
		return nil, fmt.Errorf("access challenge not supported")
	default:
		return nil, fmt.Errorf("unexpected RADIUS response code: %d", response.Code)
	}

	c.logger.Debug("RADIUS authentication complete",
		zap.String("username", req.Username),
		zap.Bool("accepted", authResp.Accepted),
	)

	return authResp, nil
}

// SendAccounting sends an Accounting-Request
func (c *Client) SendAccounting(ctx context.Context, req *AcctRequest) error {
	server := c.getServer()

	// Accounting uses port +1 by convention
	acctPort := server.Port + 1
	if server.Port == 1812 {
		acctPort = 1813
	}

	packet := radius.New(radius.CodeAccountingRequest, []byte(server.Secret))

	// Status type
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType(req.StatusType))

	// Session ID
	rfc2866.AcctSessionID_SetString(packet, req.SessionID)

	// User identification
	rfc2865.UserName_SetString(packet, req.Username)
	rfc2865.NASIdentifier_SetString(packet, c.nasID)
	rfc2865.NASPort_Set(packet, rfc2865.NASPort(req.NASPort))

	if req.MAC != nil {
		rfc2865.CallingStationID_SetString(packet, formatMAC(req.MAC))
	}

	if req.FramedIP != nil {
		rfc2865.FramedIPAddress_Set(packet, req.FramedIP)
	}

	// Class attribute (from auth response)
	if req.Class != nil {
		rfc2865.Class_Set(packet, req.Class)
	}

	// Counters (for interim and stop)
	if req.StatusType == AcctStatusStop || req.StatusType == AcctStatusInterimUpdate {
		rfc2866.AcctInputOctets_Set(packet, rfc2866.AcctInputOctets(req.InputOctets&0xFFFFFFFF))
		rfc2866.AcctOutputOctets_Set(packet, rfc2866.AcctOutputOctets(req.OutputOctets&0xFFFFFFFF))
		rfc2866.AcctInputPackets_Set(packet, rfc2866.AcctInputPackets(req.InputPackets&0xFFFFFFFF))
		rfc2866.AcctOutputPackets_Set(packet, rfc2866.AcctOutputPackets(req.OutputPackets&0xFFFFFFFF))
		rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(req.SessionTime))

		// Gigaword counters for >4GB
		if req.InputOctets > 0xFFFFFFFF {
			rfc2869.AcctInputGigawords_Set(packet, rfc2869.AcctInputGigawords(req.InputOctets>>32))
		}
		if req.OutputOctets > 0xFFFFFFFF {
			rfc2869.AcctOutputGigawords_Set(packet, rfc2869.AcctOutputGigawords(req.OutputOctets>>32))
		}
	}

	// Terminate cause (for stop only)
	if req.StatusType == AcctStatusStop && req.TerminateCause != 0 {
		rfc2866.AcctTerminateCause_Set(packet, rfc2866.AcctTerminateCause(req.TerminateCause))
	}

	// Add Message-Authenticator
	if err := addMessageAuthenticator(packet, []byte(server.Secret)); err != nil {
		return fmt.Errorf("failed to add message authenticator: %w", err)
	}

	// Send request
	addr := fmt.Sprintf("%s:%d", server.Host, acctPort)
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	response, err := radius.Exchange(reqCtx, packet, addr)
	if err != nil {
		return fmt.Errorf("RADIUS accounting failed: %w", err)
	}

	if response.Code != radius.CodeAccountingResponse {
		return fmt.Errorf("unexpected accounting response code: %d", response.Code)
	}

	c.logger.Debug("RADIUS accounting sent",
		zap.String("session_id", req.SessionID),
		zap.Uint32("status_type", uint32(req.StatusType)),
	)

	return nil
}

// parseAuthAttributes extracts attributes from Access-Accept
func (c *Client) parseAuthAttributes(response *radius.Packet, authResp *AuthResponse) {
	// Session-Timeout
	if timeout, err := rfc2865.SessionTimeout_Lookup(response); err == nil {
		authResp.SessionTimeout = uint32(timeout)
	}

	// Idle-Timeout
	if timeout, err := rfc2865.IdleTimeout_Lookup(response); err == nil {
		authResp.IdleTimeout = uint32(timeout)
	}

	// Framed-IP-Address
	if ip, err := rfc2865.FramedIPAddress_Lookup(response); err == nil {
		authResp.FramedIP = ip
	}

	// Note: Framed-Pool is not in the standard layeh/radius RFC packages
	// It would need to be defined as a vendor-specific attribute if required

	// Filter-Id (QoS policy)
	if filter, err := rfc2865.FilterID_LookupString(response); err == nil {
		authResp.FilterID = filter
	}

	// Class (for accounting)
	if class, err := rfc2865.Class_Lookup(response); err == nil {
		authResp.Class = class
	}

	// Look for vendor-specific QoS attributes
	// Common vendor attribute types for bandwidth:
	// - Cisco: AV-Pair (upload-bandwidth, download-bandwidth)
	// - Mikrotik: Mikrotik-Rate-Limit
	// - ChilliSpot: ChilliSpot-Bandwidth-Max-Up/Down
	// For now, we'll use Filter-Id as a policy name lookup
}

// getServer returns the current RADIUS server
func (c *Client) getServer() ServerConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.servers[c.currentIdx]
}

// nextServer advances to the next RADIUS server
func (c *Client) nextServer() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentIdx = (c.currentIdx + 1) % len(c.servers)
}

// addMessageAuthenticator adds RFC 2869 Message-Authenticator
func addMessageAuthenticator(packet *radius.Packet, secret []byte) error {
	// Delete existing
	rfc2869.MessageAuthenticator_Del(packet)

	// Set to zeros for calculation
	rfc2869.MessageAuthenticator_Set(packet, make([]byte, 16))

	// Encode packet
	encoded, err := packet.Encode()
	if err != nil {
		return err
	}

	// Calculate HMAC-MD5
	hash := hmac.New(md5.New, secret)
	hash.Write(encoded)

	// Set actual authenticator
	rfc2869.MessageAuthenticator_Set(packet, hash.Sum(nil))

	return nil
}

// formatMAC formats a MAC address for RADIUS (uppercase with dashes)
func formatMAC(mac net.HardwareAddr) string {
	return fmt.Sprintf("%02X-%02X-%02X-%02X-%02X-%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// TerminateCause constants
const (
	TerminateCauseUserRequest    = 1
	TerminateCauseLostCarrier    = 2
	TerminateCauseLostService    = 3
	TerminateCauseIdleTimeout    = 4
	TerminateCauseSessionTimeout = 5
	TerminateCauseAdminReset     = 6
	TerminateCauseAdminReboot    = 7
	TerminateCausePortError      = 8
	TerminateCauseNASError       = 9
	TerminateCauseNASRequest     = 10
	TerminateCauseNASReboot      = 11
	TerminateCausePortUnneeded   = 12
	TerminateCausePortPreempted  = 13
	TerminateCausePortSuspended  = 14
	TerminateCauseServiceUnavail = 15
	TerminateCauseCallback       = 16
	TerminateCauseUserError      = 17
	TerminateCauseHostRequest    = 18
)
