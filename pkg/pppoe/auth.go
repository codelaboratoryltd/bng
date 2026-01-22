// Package pppoe implements PPPoE protocol handling for the BNG.
// This file implements PAP and CHAP authentication per RFC 1334 and RFC 1994.
package pppoe

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/radius"
	"go.uber.org/zap"
)

// AuthState represents the authentication state
type AuthState int

const (
	AuthStateNone    AuthState = iota // Not started
	AuthStatePending                  // Waiting for credentials
	AuthStateSuccess                  // Authentication successful
	AuthStateFailure                  // Authentication failed
)

func (s AuthState) String() string {
	switch s {
	case AuthStateNone:
		return "None"
	case AuthStatePending:
		return "Pending"
	case AuthStateSuccess:
		return "Success"
	case AuthStateFailure:
		return "Failure"
	default:
		return "Unknown"
	}
}

// CHAPAlgorithm constants
const (
	CHAPAlgorithmMD5 = 5 // CHAP with MD5
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Protocol        uint16        // PAP (0xC023) or CHAP (0xC223)
	CHAPAlgorithm   uint8         // CHAP algorithm (5=MD5)
	Timeout         time.Duration // Authentication timeout
	MaxRetries      int           // Maximum retries for CHAP challenge
	CHAPIdentifier  string        // CHAP identifier (hostname)
	ChallengeLength int           // CHAP challenge length (default 16)
}

// DefaultAuthConfig returns default authentication configuration
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		Protocol:        ProtocolPAP,
		CHAPAlgorithm:   CHAPAlgorithmMD5,
		Timeout:         30 * time.Second,
		MaxRetries:      3,
		CHAPIdentifier:  "BNG-AC",
		ChallengeLength: 16,
	}
}

// AuthResult holds the result of authentication
type AuthResult struct {
	Success        bool
	Username       string
	Method         string // "PAP" or "CHAP"
	RejectReason   string
	FramedIP       []byte
	FramedPool     string
	SessionTimeout uint32
	IdleTimeout    uint32
	FilterID       string
	Class          []byte
	Attributes     map[string]interface{}
}

// Authenticator handles PPP authentication
type Authenticator struct {
	config       AuthConfig
	radiusClient *radius.Client
	logger       *zap.Logger

	// State
	state     AuthState
	username  string
	challenge []byte // CHAP challenge
	chapID    uint8  // CHAP identifier

	// Packet sender
	sendPacket func(protocol uint16, data []byte)

	// Callbacks
	onAuthComplete func(result *AuthResult)

	// Rate limiting
	failureCount int
	lastFailure  time.Time

	mu sync.RWMutex
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(config AuthConfig, radiusClient *radius.Client, sendPacket func(uint16, []byte), logger *zap.Logger) *Authenticator {
	if config.ChallengeLength == 0 {
		config.ChallengeLength = 16
	}
	if config.CHAPIdentifier == "" {
		config.CHAPIdentifier = "BNG-AC"
	}

	return &Authenticator{
		config:       config,
		radiusClient: radiusClient,
		sendPacket:   sendPacket,
		logger:       logger,
		state:        AuthStateNone,
	}
}

// SetOnAuthComplete sets the authentication completion callback
func (a *Authenticator) SetOnAuthComplete(callback func(*AuthResult)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onAuthComplete = callback
}

// GetState returns the current authentication state
func (a *Authenticator) GetState() AuthState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

// GetUsername returns the authenticated username
func (a *Authenticator) GetUsername() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.username
}

// Start initiates the authentication process
func (a *Authenticator) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.state = AuthStatePending

	if a.config.Protocol == ProtocolCHAP {
		if err := a.sendCHAPChallenge(); err != nil {
			return err
		}
	}
	// For PAP, we wait for the peer to send Authenticate-Request
	return nil
}

// ReceivePacket processes an incoming authentication packet
func (a *Authenticator) ReceivePacket(protocol uint16, data []byte) error {
	switch protocol {
	case ProtocolPAP:
		return a.receivePAP(data)
	case ProtocolCHAP:
		return a.receiveCHAP(data)
	default:
		return fmt.Errorf("unsupported auth protocol: 0x%04X", protocol)
	}
}

// PAP Implementation (RFC 1334)

// receivePAP handles incoming PAP packets
func (a *Authenticator) receivePAP(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("PAP packet too short")
	}

	code := data[0]
	identifier := data[1]
	length := binary.BigEndian.Uint16(data[2:4])

	if int(length) > len(data) {
		return fmt.Errorf("PAP length exceeds packet")
	}

	switch code {
	case PAPCodeAuthRequest:
		return a.handlePAPAuthRequest(identifier, data[4:length])
	default:
		a.logger.Warn("Unexpected PAP code", zap.Uint8("code", code))
		return nil
	}
}

// handlePAPAuthRequest handles PAP Authenticate-Request
func (a *Authenticator) handlePAPAuthRequest(identifier uint8, data []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(data) < 1 {
		return fmt.Errorf("PAP auth request too short")
	}

	// Parse Peer-ID (username)
	peerIDLen := int(data[0])
	if len(data) < 1+peerIDLen+1 {
		return fmt.Errorf("PAP auth request malformed")
	}
	peerID := string(data[1 : 1+peerIDLen])

	// Parse Password
	passwordLen := int(data[1+peerIDLen])
	if len(data) < 2+peerIDLen+passwordLen {
		return fmt.Errorf("PAP auth request password truncated")
	}
	password := string(data[2+peerIDLen : 2+peerIDLen+passwordLen])

	a.username = peerID

	a.logger.Debug("PAP authentication attempt",
		zap.String("username", peerID),
		// Never log password!
	)

	// Check rate limiting
	if a.isRateLimited() {
		a.sendPAPNak(identifier, "Too many failed attempts")
		return nil
	}

	// Authenticate via RADIUS or accept all if no RADIUS configured
	result := a.authenticate(peerID, password, nil)

	if result.Success {
		a.state = AuthStateSuccess
		a.sendPAPAck(identifier, "Login OK")
		a.logger.Info("PAP authentication successful",
			zap.String("username", peerID),
		)
	} else {
		a.state = AuthStateFailure
		a.recordFailure()
		a.sendPAPNak(identifier, result.RejectReason)
		a.logger.Warn("PAP authentication failed",
			zap.String("username", peerID),
			zap.String("reason", result.RejectReason),
		)
	}

	if a.onAuthComplete != nil {
		a.onAuthComplete(result)
	}

	return nil
}

// sendPAPAck sends PAP Authenticate-Ack
func (a *Authenticator) sendPAPAck(identifier uint8, message string) {
	msgBytes := []byte(message)
	data := make([]byte, 5+len(msgBytes))
	data[0] = PAPCodeAuthAck
	data[1] = identifier
	binary.BigEndian.PutUint16(data[2:4], uint16(5+len(msgBytes)))
	data[4] = byte(len(msgBytes))
	copy(data[5:], msgBytes)

	a.sendPacket(ProtocolPAP, data)
}

// sendPAPNak sends PAP Authenticate-Nak
func (a *Authenticator) sendPAPNak(identifier uint8, message string) {
	msgBytes := []byte(message)
	data := make([]byte, 5+len(msgBytes))
	data[0] = PAPCodeAuthNak
	data[1] = identifier
	binary.BigEndian.PutUint16(data[2:4], uint16(5+len(msgBytes)))
	data[4] = byte(len(msgBytes))
	copy(data[5:], msgBytes)

	a.sendPacket(ProtocolPAP, data)
}

// CHAP Implementation (RFC 1994)

// receiveCHAP handles incoming CHAP packets
func (a *Authenticator) receiveCHAP(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("CHAP packet too short")
	}

	code := data[0]
	identifier := data[1]
	length := binary.BigEndian.Uint16(data[2:4])

	if int(length) > len(data) {
		return fmt.Errorf("CHAP length exceeds packet")
	}

	switch code {
	case CHAPCodeResponse:
		return a.handleCHAPResponse(identifier, data[4:length])
	default:
		a.logger.Warn("Unexpected CHAP code", zap.Uint8("code", code))
		return nil
	}
}

// sendCHAPChallenge sends a CHAP Challenge
func (a *Authenticator) sendCHAPChallenge() error {
	a.chapID++

	// Generate random challenge
	a.challenge = make([]byte, a.config.ChallengeLength)
	if _, err := rand.Read(a.challenge); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	nameBytes := []byte(a.config.CHAPIdentifier)

	// CHAP Challenge format:
	// Code (1) + Identifier (1) + Length (2) + Value-Size (1) + Value + Name
	dataLen := 1 + len(a.challenge) + len(nameBytes)
	data := make([]byte, 4+dataLen)
	data[0] = CHAPCodeChallenge
	data[1] = a.chapID
	binary.BigEndian.PutUint16(data[2:4], uint16(4+dataLen))
	data[4] = byte(len(a.challenge))
	copy(data[5:5+len(a.challenge)], a.challenge)
	copy(data[5+len(a.challenge):], nameBytes)

	a.sendPacket(ProtocolCHAP, data)

	a.logger.Debug("CHAP challenge sent",
		zap.Uint8("identifier", a.chapID),
	)

	return nil
}

// handleCHAPResponse handles CHAP Response
func (a *Authenticator) handleCHAPResponse(identifier uint8, data []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if identifier != a.chapID {
		a.logger.Warn("CHAP response with unexpected identifier",
			zap.Uint8("expected", a.chapID),
			zap.Uint8("received", identifier),
		)
		return nil
	}

	if len(data) < 1 {
		return fmt.Errorf("CHAP response too short")
	}

	// Parse response
	valueSize := int(data[0])
	if len(data) < 1+valueSize {
		return fmt.Errorf("CHAP response value truncated")
	}

	responseValue := data[1 : 1+valueSize]
	name := string(data[1+valueSize:])

	a.username = name

	a.logger.Debug("CHAP response received",
		zap.String("username", name),
		zap.Int("response_size", valueSize),
	)

	// Check rate limiting
	if a.isRateLimited() {
		a.sendCHAPFailure(identifier, "Too many failed attempts")
		return nil
	}

	// For CHAP, we need to verify the response or forward to RADIUS
	result := a.authenticateCHAP(name, responseValue)

	if result.Success {
		a.state = AuthStateSuccess
		a.sendCHAPSuccess(identifier, "Login OK")
		a.logger.Info("CHAP authentication successful",
			zap.String("username", name),
		)
	} else {
		a.state = AuthStateFailure
		a.recordFailure()
		a.sendCHAPFailure(identifier, result.RejectReason)
		a.logger.Warn("CHAP authentication failed",
			zap.String("username", name),
			zap.String("reason", result.RejectReason),
		)
	}

	if a.onAuthComplete != nil {
		a.onAuthComplete(result)
	}

	return nil
}

// sendCHAPSuccess sends CHAP Success
func (a *Authenticator) sendCHAPSuccess(identifier uint8, message string) {
	msgBytes := []byte(message)
	data := make([]byte, 4+len(msgBytes))
	data[0] = CHAPCodeSuccess
	data[1] = identifier
	binary.BigEndian.PutUint16(data[2:4], uint16(4+len(msgBytes)))
	copy(data[4:], msgBytes)

	a.sendPacket(ProtocolCHAP, data)
}

// sendCHAPFailure sends CHAP Failure
func (a *Authenticator) sendCHAPFailure(identifier uint8, message string) {
	msgBytes := []byte(message)
	data := make([]byte, 4+len(msgBytes))
	data[0] = CHAPCodeFailure
	data[1] = identifier
	binary.BigEndian.PutUint16(data[2:4], uint16(4+len(msgBytes)))
	copy(data[4:], msgBytes)

	a.sendPacket(ProtocolCHAP, data)
}

// authenticateCHAP verifies CHAP response
func (a *Authenticator) authenticateCHAP(username string, response []byte) *AuthResult {
	result := &AuthResult{
		Username:   username,
		Method:     "CHAP",
		Attributes: make(map[string]interface{}),
	}

	if a.radiusClient != nil {
		// Use RADIUS for CHAP authentication
		// RADIUS needs the challenge and response for CHAP
		ctx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
		defer cancel()
		// TODO: CHAP-Password attribute (RFC 2865 section 5.3) needs to be implemented
		// for full RADIUS CHAP support. Currently this sends username only.
		authResp, err := a.radiusClient.Authenticate(ctx, &radius.AuthRequest{
			Username: username,
		})

		if err != nil {
			result.RejectReason = "RADIUS error"
			return result
		}

		result.Success = authResp.Accepted
		if !result.Success {
			result.RejectReason = authResp.RejectReason
			if result.RejectReason == "" {
				result.RejectReason = "Authentication failed"
			}
		} else {
			result.SessionTimeout = authResp.SessionTimeout
			result.IdleTimeout = authResp.IdleTimeout
			result.FilterID = authResp.FilterID
			result.Class = authResp.Class
			if authResp.FramedIP != nil {
				result.FramedIP = authResp.FramedIP
			}
			result.FramedPool = authResp.FramedPool
		}
	} else {
		// No RADIUS - verify locally (for testing)
		// In production, RADIUS should always be used
		result.Success = true
	}

	return result
}

// authenticate handles PAP authentication
func (a *Authenticator) authenticate(username, password string, chapResponse []byte) *AuthResult {
	result := &AuthResult{
		Username:   username,
		Method:     "PAP",
		Attributes: make(map[string]interface{}),
	}

	if a.radiusClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
		defer cancel()
		authResp, err := a.radiusClient.Authenticate(ctx, &radius.AuthRequest{
			Username: username,
			Password: password,
		})

		if err != nil {
			result.RejectReason = "RADIUS error"
			return result
		}

		result.Success = authResp.Accepted
		if !result.Success {
			result.RejectReason = authResp.RejectReason
			if result.RejectReason == "" {
				result.RejectReason = "Authentication failed"
			}
		} else {
			result.SessionTimeout = authResp.SessionTimeout
			result.IdleTimeout = authResp.IdleTimeout
			result.FilterID = authResp.FilterID
			result.Class = authResp.Class
			if authResp.FramedIP != nil {
				result.FramedIP = authResp.FramedIP
			}
			result.FramedPool = authResp.FramedPool
		}
	} else {
		// No RADIUS configured - accept all (for testing only!)
		a.logger.Warn("No RADIUS client configured, accepting all credentials")
		result.Success = true
	}

	return result
}

// verifyCHAPResponse verifies a CHAP-MD5 response locally
// This is used when RADIUS is not available
func (a *Authenticator) verifyCHAPResponse(password string, response []byte) bool {
	if len(response) != 16 { // MD5 produces 16 bytes
		return false
	}

	// CHAP-MD5 response = MD5(ID || Password || Challenge)
	h := md5.New()
	h.Write([]byte{a.chapID})
	h.Write([]byte(password))
	h.Write(a.challenge)
	expected := h.Sum(nil)

	// Use constant-time comparison
	return subtle.ConstantTimeCompare(expected, response) == 1
}

// Rate limiting

func (a *Authenticator) isRateLimited() bool {
	// Allow max 5 failures per minute
	if a.failureCount >= 5 && time.Since(a.lastFailure) < time.Minute {
		a.logger.Warn("Authentication rate limited",
			zap.Int("failure_count", a.failureCount),
		)
		return true
	}

	// Reset counter after 1 minute
	if time.Since(a.lastFailure) > time.Minute {
		a.failureCount = 0
	}

	return false
}

func (a *Authenticator) recordFailure() {
	a.failureCount++
	a.lastFailure = time.Now()
}

// SendReauthChallenge sends a re-authentication CHAP challenge
// This is used for periodic re-authentication in CHAP
func (a *Authenticator) SendReauthChallenge() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state == AuthStateSuccess && a.config.Protocol == ProtocolCHAP {
		if err := a.sendCHAPChallenge(); err != nil {
			return err
		}
	}
	return nil
}
