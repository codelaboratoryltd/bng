// Package pppoe implements PPPoE protocol handling for the BNG.
// This file implements the LCP (Link Control Protocol) state machine per RFC 1661.
package pppoe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// LCPState represents the LCP state machine state per RFC 1661
type LCPState int

const (
	LCPStateInitial  LCPState = iota // Lower layer unavailable, no Open
	LCPStateStarting                 // Lower layer unavailable, Open
	LCPStateClosed                   // Lower layer available, no Open
	LCPStateStopped                  // Open, waiting for Configure-Request
	LCPStateClosing                  // Terminate-Request sent
	LCPStateStopping                 // Terminate-Request sent (from Opened)
	LCPStateReqSent                  // Configure-Request sent
	LCPStateAckRcvd                  // Configure-Request sent, Configure-Ack received
	LCPStateAckSent                  // Configure-Request and Configure-Ack sent
	LCPStateOpened                   // Connection fully established
)

func (s LCPState) String() string {
	switch s {
	case LCPStateInitial:
		return "Initial"
	case LCPStateStarting:
		return "Starting"
	case LCPStateClosed:
		return "Closed"
	case LCPStateStopped:
		return "Stopped"
	case LCPStateClosing:
		return "Closing"
	case LCPStateStopping:
		return "Stopping"
	case LCPStateReqSent:
		return "Req-Sent"
	case LCPStateAckRcvd:
		return "Ack-Rcvd"
	case LCPStateAckSent:
		return "Ack-Sent"
	case LCPStateOpened:
		return "Opened"
	default:
		return "Unknown"
	}
}

// LCPConfig holds LCP negotiation configuration options
type LCPConfig struct {
	MRU           uint16        // Maximum Receive Unit (default 1492 for PPPoE)
	MagicNumber   uint32        // Magic number for loop detection
	AuthProtocol  uint16        // Authentication protocol (PAP=0xC023, CHAP=0xC223)
	CHAPAlgorithm uint8         // CHAP algorithm (5=MD5)
	PFC           bool          // Protocol Field Compression
	ACFC          bool          // Address/Control Field Compression
	MaxRetransmit int           // Maximum retransmissions (default 10)
	RestartTimer  time.Duration // Restart timer (default 3s)
	MaxTerminate  int           // Max Terminate-Request retransmissions
	MaxConfigure  int           // Max Configure-Request retransmissions
	MaxFailure    int           // Max Configure-Nak before Configure-Reject
}

// DefaultLCPConfig returns default LCP configuration
func DefaultLCPConfig() LCPConfig {
	return LCPConfig{
		MRU:           1492, // PPPoE MTU constraint
		AuthProtocol:  ProtocolPAP,
		CHAPAlgorithm: 5, // MD5
		PFC:           false,
		ACFC:          false,
		MaxRetransmit: 10,
		RestartTimer:  3 * time.Second,
		MaxTerminate:  2,
		MaxConfigure:  10,
		MaxFailure:    5,
	}
}

// LCPNegotiatedOptions holds the negotiated LCP options
type LCPNegotiatedOptions struct {
	LocalMRU      uint16
	PeerMRU       uint16
	LocalMagic    uint32
	PeerMagic     uint32
	AuthProtocol  uint16
	CHAPAlgorithm uint8
	LocalPFC      bool
	PeerPFC       bool
	LocalACFC     bool
	PeerACFC      bool
}

// LCPStateMachine implements the RFC 1661 LCP state machine
type LCPStateMachine struct {
	state      LCPState
	config     LCPConfig
	negotiated LCPNegotiatedOptions

	// Counters
	restartCount   int   // Restart counter
	failureCount   int   // Configure-Nak counter per option
	identifier     uint8 // Current identifier for outgoing packets
	lastIdentifier uint8 // Last identifier used in our Configure-Request

	// Packet sender callback
	sendPacket func(protocol uint16, data []byte)

	// State change callback
	onStateChange func(oldState, newState LCPState)

	// Timers
	restartTimer *time.Timer
	timerMu      sync.Mutex

	// Logger
	logger *zap.Logger

	mu sync.RWMutex
}

// NewLCPStateMachine creates a new LCP state machine
func NewLCPStateMachine(config LCPConfig, sendPacket func(uint16, []byte), logger *zap.Logger) (*LCPStateMachine, error) {
	// Generate random magic number if not set
	if config.MagicNumber == 0 {
		magic, err := generateMagicNumber()
		if err != nil {
			return nil, fmt.Errorf("failed to generate magic number: %w", err)
		}
		config.MagicNumber = magic
	}

	return &LCPStateMachine{
		state:      LCPStateInitial,
		config:     config,
		sendPacket: sendPacket,
		logger:     logger,
		negotiated: LCPNegotiatedOptions{
			LocalMRU:   config.MRU,
			LocalMagic: config.MagicNumber,
		},
	}, nil
}

// SetOnStateChange sets the state change callback
func (lcp *LCPStateMachine) SetOnStateChange(callback func(LCPState, LCPState)) {
	lcp.mu.Lock()
	defer lcp.mu.Unlock()
	lcp.onStateChange = callback
}

// GetState returns the current LCP state
func (lcp *LCPStateMachine) GetState() LCPState {
	lcp.mu.RLock()
	defer lcp.mu.RUnlock()
	return lcp.state
}

// GetNegotiatedOptions returns the negotiated options
func (lcp *LCPStateMachine) GetNegotiatedOptions() LCPNegotiatedOptions {
	lcp.mu.RLock()
	defer lcp.mu.RUnlock()
	return lcp.negotiated
}

// setState changes the state and calls the callback
func (lcp *LCPStateMachine) setState(newState LCPState) {
	oldState := lcp.state
	lcp.state = newState

	lcp.logger.Debug("LCP state change",
		zap.String("from", oldState.String()),
		zap.String("to", newState.String()),
	)

	if lcp.onStateChange != nil {
		lcp.onStateChange(oldState, newState)
	}
}

// Up is called when the lower layer is up (PPPoE session established)
func (lcp *LCPStateMachine) Up() {
	lcp.mu.Lock()
	defer lcp.mu.Unlock()

	switch lcp.state {
	case LCPStateInitial:
		lcp.setState(LCPStateClosed)
	case LCPStateStarting:
		lcp.initializeRestartCount()
		lcp.sendConfigureRequest()
		lcp.setState(LCPStateReqSent)
	}
}

// Down is called when the lower layer is down
func (lcp *LCPStateMachine) Down() {
	lcp.mu.Lock()
	defer lcp.mu.Unlock()

	lcp.stopTimer()

	switch lcp.state {
	case LCPStateClosed:
		lcp.setState(LCPStateInitial)
	case LCPStateStopped:
		lcp.setState(LCPStateStarting)
		// This-Layer-Started would be called here
	case LCPStateClosing:
		lcp.setState(LCPStateInitial)
	case LCPStateStopping, LCPStateReqSent, LCPStateAckRcvd, LCPStateAckSent:
		lcp.setState(LCPStateStarting)
	case LCPStateOpened:
		// This-Layer-Down
		lcp.setState(LCPStateStarting)
	}
}

// Open is called to administratively open the connection
func (lcp *LCPStateMachine) Open() {
	lcp.mu.Lock()
	defer lcp.mu.Unlock()

	switch lcp.state {
	case LCPStateInitial:
		// This-Layer-Started
		lcp.setState(LCPStateStarting)
	case LCPStateClosed:
		lcp.initializeRestartCount()
		lcp.sendConfigureRequest()
		lcp.setState(LCPStateReqSent)
	case LCPStateClosing:
		lcp.setState(LCPStateStopping)
	}
}

// Close is called to administratively close the connection
func (lcp *LCPStateMachine) Close() {
	lcp.mu.Lock()
	defer lcp.mu.Unlock()

	lcp.closeInternal("Admin close")
}

func (lcp *LCPStateMachine) closeInternal(reason string) {
	switch lcp.state {
	case LCPStateStarting:
		// This-Layer-Finished
		lcp.setState(LCPStateInitial)
	case LCPStateStopped:
		lcp.setState(LCPStateClosed)
	case LCPStateStopping:
		lcp.setState(LCPStateClosing)
	case LCPStateOpened:
		// This-Layer-Down
		lcp.initializeRestartCount()
		lcp.sendTerminateRequest(reason)
		lcp.setState(LCPStateClosing)
	case LCPStateReqSent, LCPStateAckRcvd, LCPStateAckSent:
		lcp.initializeRestartCount()
		lcp.sendTerminateRequest(reason)
		lcp.setState(LCPStateClosing)
	}
}

// ReceivePacket processes an incoming LCP packet
func (lcp *LCPStateMachine) ReceivePacket(data []byte) error {
	pkt, err := ParseLCPPacket(data)
	if err != nil {
		return fmt.Errorf("failed to parse LCP packet: %w", err)
	}

	lcp.mu.Lock()
	defer lcp.mu.Unlock()

	lcp.logger.Debug("LCP packet received",
		zap.Uint8("code", pkt.Code),
		zap.Uint8("identifier", pkt.Identifier),
		zap.String("state", lcp.state.String()),
	)

	switch pkt.Code {
	case LCPCodeConfigRequest:
		return lcp.receiveConfigureRequest(pkt)
	case LCPCodeConfigAck:
		return lcp.receiveConfigureAck(pkt)
	case LCPCodeConfigNak:
		return lcp.receiveConfigureNak(pkt)
	case LCPCodeConfigReject:
		return lcp.receiveConfigureReject(pkt)
	case LCPCodeTermRequest:
		return lcp.receiveTerminateRequest(pkt)
	case LCPCodeTermAck:
		return lcp.receiveTerminateAck(pkt)
	case LCPCodeCodeReject:
		return lcp.receiveCodeReject(pkt)
	case LCPCodeProtoReject:
		return lcp.receiveProtocolReject(pkt)
	case LCPCodeEchoRequest:
		return lcp.receiveEchoRequest(pkt)
	case LCPCodeEchoReply:
		return lcp.receiveEchoReply(pkt)
	case LCPCodeDiscardReq:
		// Silently discard
		return nil
	default:
		lcp.sendCodeReject(pkt)
		return nil
	}
}

// receiveConfigureRequest handles incoming Configure-Request
func (lcp *LCPStateMachine) receiveConfigureRequest(pkt *LCPPacket) error {
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return fmt.Errorf("failed to parse LCP options: %w", err)
	}

	// Process options and determine response
	ackOpts, nakOpts, rejOpts := lcp.processConfigureOptions(opts)

	var respCode uint8
	var respOpts []LCPOption

	if len(rejOpts) > 0 {
		respCode = LCPCodeConfigReject
		respOpts = rejOpts
	} else if len(nakOpts) > 0 {
		respCode = LCPCodeConfigNak
		respOpts = nakOpts
	} else {
		respCode = LCPCodeConfigAck
		respOpts = ackOpts
		// Store negotiated peer options
		lcp.storePeerOptions(opts)
	}

	// Send response
	resp := &LCPPacket{
		Code:       respCode,
		Identifier: pkt.Identifier,
		Data:       SerializeLCPOptions(respOpts),
	}
	lcp.sendPacket(ProtocolLCP, resp.Serialize())

	// State machine transitions
	switch lcp.state {
	case LCPStateClosed:
		lcp.sendTerminateAck(pkt.Identifier)
	case LCPStateStopped:
		lcp.initializeRestartCount()
		lcp.sendConfigureRequest()
		if respCode == LCPCodeConfigAck {
			lcp.setState(LCPStateAckSent)
		} else {
			lcp.setState(LCPStateReqSent)
		}
	case LCPStateReqSent:
		if respCode == LCPCodeConfigAck {
			lcp.setState(LCPStateAckSent)
		}
	case LCPStateAckRcvd:
		if respCode == LCPCodeConfigAck {
			// This-Layer-Up
			lcp.setState(LCPStateOpened)
		}
	case LCPStateAckSent:
		if respCode != LCPCodeConfigAck {
			lcp.setState(LCPStateReqSent)
		}
	case LCPStateOpened:
		// This-Layer-Down
		lcp.sendConfigureRequest()
		if respCode == LCPCodeConfigAck {
			lcp.setState(LCPStateAckSent)
		} else {
			lcp.setState(LCPStateReqSent)
		}
	}

	return nil
}

// processConfigureOptions processes incoming options and returns ack/nak/reject lists
func (lcp *LCPStateMachine) processConfigureOptions(opts []LCPOption) (ack, nak, reject []LCPOption) {
	for _, opt := range opts {
		switch opt.Type {
		case LCPOptMRU:
			if len(opt.Data) != 2 {
				reject = append(reject, opt)
				continue
			}
			mru := binary.BigEndian.Uint16(opt.Data)
			// Accept any MRU >= 64 and <= 1492 (PPPoE limit)
			if mru >= 64 && mru <= 1492 {
				ack = append(ack, opt)
			} else if mru < 64 {
				// NAK with minimum
				nakOpt := LCPOption{Type: LCPOptMRU, Data: make([]byte, 2)}
				binary.BigEndian.PutUint16(nakOpt.Data, 64)
				nak = append(nak, nakOpt)
			} else {
				// NAK with our maximum (1492)
				nakOpt := LCPOption{Type: LCPOptMRU, Data: make([]byte, 2)}
				binary.BigEndian.PutUint16(nakOpt.Data, 1492)
				nak = append(nak, nakOpt)
			}

		case LCPOptAuthProto:
			if len(opt.Data) < 2 {
				reject = append(reject, opt)
				continue
			}
			authProto := binary.BigEndian.Uint16(opt.Data)
			// We require authentication, so reject peer requesting auth (we're the server)
			// In PPP, the authenticator (us) tells the peer which auth to use
			// Peer should not be requesting auth protocol in their Configure-Request
			// However, some implementations do this, so we reject it
			_ = authProto
			reject = append(reject, opt)

		case LCPOptMagicNumber:
			if len(opt.Data) != 4 {
				reject = append(reject, opt)
				continue
			}
			magic := binary.BigEndian.Uint32(opt.Data)
			if magic == 0 {
				// NAK with a random value
				nakOpt := LCPOption{Type: LCPOptMagicNumber, Data: make([]byte, 4)}
				suggestedMagic, err := generateMagicNumber()
				if err != nil {
					lcp.logger.Error("Failed to generate magic number for NAK", zap.Error(err))
					reject = append(reject, opt)
					continue
				}
				binary.BigEndian.PutUint32(nakOpt.Data, suggestedMagic)
				nak = append(nak, nakOpt)
			} else if magic == lcp.config.MagicNumber {
				// Loop detected! NAK with a different value
				lcp.logger.Warn("LCP magic number collision detected, regenerating")
				newMagic, err := generateMagicNumber()
				if err != nil {
					lcp.logger.Error("Failed to regenerate magic number", zap.Error(err))
					reject = append(reject, opt)
					continue
				}
				lcp.config.MagicNumber = newMagic
				lcp.negotiated.LocalMagic = lcp.config.MagicNumber
				nakOpt := LCPOption{Type: LCPOptMagicNumber, Data: make([]byte, 4)}
				suggestedMagic, err := generateMagicNumber()
				if err != nil {
					lcp.logger.Error("Failed to generate magic number for NAK", zap.Error(err))
					reject = append(reject, opt)
					continue
				}
				binary.BigEndian.PutUint32(nakOpt.Data, suggestedMagic)
				nak = append(nak, nakOpt)
			} else {
				ack = append(ack, opt)
			}

		case LCPOptPFC:
			if len(opt.Data) != 0 {
				reject = append(reject, opt)
				continue
			}
			// We accept PFC
			ack = append(ack, opt)

		case LCPOptACFC:
			if len(opt.Data) != 0 {
				reject = append(reject, opt)
				continue
			}
			// We accept ACFC
			ack = append(ack, opt)

		default:
			// Unknown option - reject
			reject = append(reject, opt)
		}
	}

	return ack, nak, reject
}

// storePeerOptions stores the negotiated peer options
func (lcp *LCPStateMachine) storePeerOptions(opts []LCPOption) {
	for _, opt := range opts {
		switch opt.Type {
		case LCPOptMRU:
			if len(opt.Data) >= 2 {
				lcp.negotiated.PeerMRU = binary.BigEndian.Uint16(opt.Data)
			}
		case LCPOptMagicNumber:
			if len(opt.Data) >= 4 {
				lcp.negotiated.PeerMagic = binary.BigEndian.Uint32(opt.Data)
			}
		case LCPOptPFC:
			lcp.negotiated.PeerPFC = true
		case LCPOptACFC:
			lcp.negotiated.PeerACFC = true
		}
	}
}

// receiveConfigureAck handles incoming Configure-Ack
func (lcp *LCPStateMachine) receiveConfigureAck(pkt *LCPPacket) error {
	// Verify identifier matches our last request
	if pkt.Identifier != lcp.lastIdentifier {
		lcp.logger.Debug("LCP Configure-Ack with unexpected identifier",
			zap.Uint8("expected", lcp.lastIdentifier),
			zap.Uint8("received", pkt.Identifier),
		)
		return nil
	}

	lcp.stopTimer()

	switch lcp.state {
	case LCPStateClosed, LCPStateStopped:
		lcp.sendTerminateAck(pkt.Identifier)
	case LCPStateReqSent:
		lcp.initializeRestartCount()
		lcp.setState(LCPStateAckRcvd)
	case LCPStateAckRcvd:
		lcp.sendConfigureRequest()
		lcp.setState(LCPStateReqSent)
	case LCPStateAckSent:
		lcp.initializeRestartCount()
		// This-Layer-Up
		lcp.setState(LCPStateOpened)
	case LCPStateOpened:
		// This-Layer-Down
		lcp.sendConfigureRequest()
		lcp.setState(LCPStateReqSent)
	}

	return nil
}

// receiveConfigureNak handles incoming Configure-Nak
func (lcp *LCPStateMachine) receiveConfigureNak(pkt *LCPPacket) error {
	if pkt.Identifier != lcp.lastIdentifier {
		return nil
	}

	lcp.stopTimer()

	// Process NAK options and update our config
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return err
	}

	for _, opt := range opts {
		switch opt.Type {
		case LCPOptMRU:
			if len(opt.Data) >= 2 {
				mru := binary.BigEndian.Uint16(opt.Data)
				if mru >= 64 && mru <= 1492 {
					lcp.negotiated.LocalMRU = mru
				}
			}
		case LCPOptAuthProto:
			if len(opt.Data) >= 2 {
				authProto := binary.BigEndian.Uint16(opt.Data)
				// Switch to suggested auth protocol if we support it
				if authProto == ProtocolPAP || authProto == ProtocolCHAP {
					lcp.negotiated.AuthProtocol = authProto
					if authProto == ProtocolCHAP && len(opt.Data) >= 3 {
						lcp.negotiated.CHAPAlgorithm = opt.Data[2]
					}
				}
			}
		case LCPOptMagicNumber:
			if len(opt.Data) >= 4 {
				// Regenerate magic number
				newMagic, err := generateMagicNumber()
				if err != nil {
					lcp.logger.Error("Failed to regenerate magic number on NAK", zap.Error(err))
				} else {
					lcp.config.MagicNumber = newMagic
					lcp.negotiated.LocalMagic = lcp.config.MagicNumber
				}
			}
		}
	}

	lcp.failureCount++

	switch lcp.state {
	case LCPStateClosed, LCPStateStopped:
		lcp.sendTerminateAck(pkt.Identifier)
	case LCPStateReqSent, LCPStateAckSent:
		lcp.initializeRestartCount()
		lcp.sendConfigureRequest()
	case LCPStateAckRcvd:
		lcp.sendConfigureRequest()
		lcp.setState(LCPStateReqSent)
	case LCPStateOpened:
		// This-Layer-Down
		lcp.sendConfigureRequest()
		lcp.setState(LCPStateReqSent)
	}

	return nil
}

// receiveConfigureReject handles incoming Configure-Reject
func (lcp *LCPStateMachine) receiveConfigureReject(pkt *LCPPacket) error {
	if pkt.Identifier != lcp.lastIdentifier {
		return nil
	}

	lcp.stopTimer()

	// Process rejected options and remove them from our config
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return err
	}

	for _, opt := range opts {
		switch opt.Type {
		case LCPOptPFC:
			lcp.config.PFC = false
		case LCPOptACFC:
			lcp.config.ACFC = false
		case LCPOptAuthProto:
			// Peer rejected our auth request - this is a problem
			lcp.logger.Warn("Peer rejected authentication protocol")
		}
	}

	switch lcp.state {
	case LCPStateClosed, LCPStateStopped:
		lcp.sendTerminateAck(pkt.Identifier)
	case LCPStateReqSent, LCPStateAckSent:
		lcp.initializeRestartCount()
		lcp.sendConfigureRequest()
	case LCPStateAckRcvd:
		lcp.sendConfigureRequest()
		lcp.setState(LCPStateReqSent)
	case LCPStateOpened:
		// This-Layer-Down
		lcp.sendConfigureRequest()
		lcp.setState(LCPStateReqSent)
	}

	return nil
}

// receiveTerminateRequest handles incoming Terminate-Request
func (lcp *LCPStateMachine) receiveTerminateRequest(pkt *LCPPacket) error {
	lcp.stopTimer()

	switch lcp.state {
	case LCPStateClosed, LCPStateStopped, LCPStateClosing, LCPStateStopping:
		lcp.sendTerminateAck(pkt.Identifier)
	case LCPStateReqSent, LCPStateAckRcvd, LCPStateAckSent:
		lcp.sendTerminateAck(pkt.Identifier)
		lcp.setState(LCPStateStopped)
	case LCPStateOpened:
		// This-Layer-Down
		lcp.zeroRestartCount()
		lcp.sendTerminateAck(pkt.Identifier)
		lcp.setState(LCPStateStopping)
	}

	return nil
}

// receiveTerminateAck handles incoming Terminate-Ack
func (lcp *LCPStateMachine) receiveTerminateAck(pkt *LCPPacket) error {
	lcp.stopTimer()

	switch lcp.state {
	case LCPStateClosing:
		// This-Layer-Finished
		lcp.setState(LCPStateClosed)
	case LCPStateStopping:
		// This-Layer-Finished
		lcp.setState(LCPStateStopped)
	case LCPStateAckRcvd:
		lcp.setState(LCPStateReqSent)
	case LCPStateOpened:
		// This-Layer-Down
		lcp.sendConfigureRequest()
		lcp.setState(LCPStateReqSent)
	}

	return nil
}

// receiveCodeReject handles incoming Code-Reject
func (lcp *LCPStateMachine) receiveCodeReject(pkt *LCPPacket) error {
	// Check if it's for a critical code
	if len(pkt.Data) > 0 {
		rejectedCode := pkt.Data[0]
		if rejectedCode >= LCPCodeConfigRequest && rejectedCode <= LCPCodeConfigReject {
			// Critical code rejected - close connection
			lcp.closeInternal("Critical code rejected")
		}
	}

	return nil
}

// receiveProtocolReject handles incoming Protocol-Reject
func (lcp *LCPStateMachine) receiveProtocolReject(pkt *LCPPacket) error {
	if len(pkt.Data) < 2 {
		return nil
	}

	rejectedProto := binary.BigEndian.Uint16(pkt.Data[:2])
	lcp.logger.Warn("Protocol rejected by peer",
		zap.Uint16("protocol", rejectedProto),
	)

	// If LCP itself is rejected, close the connection
	if rejectedProto == ProtocolLCP {
		lcp.closeInternal("LCP rejected")
	}

	return nil
}

// receiveEchoRequest handles incoming Echo-Request
func (lcp *LCPStateMachine) receiveEchoRequest(pkt *LCPPacket) error {
	if lcp.state != LCPStateOpened {
		return nil
	}

	// Build Echo-Reply with our magic number
	replyData := make([]byte, 4+len(pkt.Data)-4)
	binary.BigEndian.PutUint32(replyData[:4], lcp.config.MagicNumber)
	if len(pkt.Data) > 4 {
		copy(replyData[4:], pkt.Data[4:])
	}

	reply := &LCPPacket{
		Code:       LCPCodeEchoReply,
		Identifier: pkt.Identifier,
		Data:       replyData,
	}

	lcp.sendPacket(ProtocolLCP, reply.Serialize())
	return nil
}

// receiveEchoReply handles incoming Echo-Reply
func (lcp *LCPStateMachine) receiveEchoReply(pkt *LCPPacket) error {
	// Echo replies are handled by the keep-alive mechanism
	return nil
}

// SendEchoRequest sends an LCP Echo-Request
func (lcp *LCPStateMachine) SendEchoRequest() uint8 {
	lcp.mu.Lock()
	defer lcp.mu.Unlock()

	if lcp.state != LCPStateOpened {
		return 0
	}

	lcp.identifier++

	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, lcp.config.MagicNumber)

	pkt := &LCPPacket{
		Code:       LCPCodeEchoRequest,
		Identifier: lcp.identifier,
		Data:       data,
	}

	lcp.sendPacket(ProtocolLCP, pkt.Serialize())
	return lcp.identifier
}

// sendConfigureRequest sends a Configure-Request packet
func (lcp *LCPStateMachine) sendConfigureRequest() {
	lcp.identifier++
	lcp.lastIdentifier = lcp.identifier

	var opts []LCPOption

	// MRU option
	mruData := make([]byte, 2)
	binary.BigEndian.PutUint16(mruData, lcp.negotiated.LocalMRU)
	opts = append(opts, LCPOption{Type: LCPOptMRU, Data: mruData})

	// Magic Number option
	magicData := make([]byte, 4)
	binary.BigEndian.PutUint32(magicData, lcp.config.MagicNumber)
	opts = append(opts, LCPOption{Type: LCPOptMagicNumber, Data: magicData})

	// Authentication Protocol option
	authData := make([]byte, 2)
	binary.BigEndian.PutUint16(authData, lcp.config.AuthProtocol)
	if lcp.config.AuthProtocol == ProtocolCHAP {
		authData = append(authData, lcp.config.CHAPAlgorithm)
	}
	opts = append(opts, LCPOption{Type: LCPOptAuthProto, Data: authData})

	// Optional: PFC
	if lcp.config.PFC {
		opts = append(opts, LCPOption{Type: LCPOptPFC, Data: nil})
	}

	// Optional: ACFC
	if lcp.config.ACFC {
		opts = append(opts, LCPOption{Type: LCPOptACFC, Data: nil})
	}

	pkt := &LCPPacket{
		Code:       LCPCodeConfigRequest,
		Identifier: lcp.identifier,
		Data:       SerializeLCPOptions(opts),
	}

	lcp.sendPacket(ProtocolLCP, pkt.Serialize())
	lcp.startTimer()
	lcp.restartCount--
}

// sendTerminateRequest sends a Terminate-Request packet
func (lcp *LCPStateMachine) sendTerminateRequest(reason string) {
	lcp.identifier++

	pkt := &LCPPacket{
		Code:       LCPCodeTermRequest,
		Identifier: lcp.identifier,
		Data:       []byte(reason),
	}

	lcp.sendPacket(ProtocolLCP, pkt.Serialize())
	lcp.startTimer()
	lcp.restartCount--
}

// sendTerminateAck sends a Terminate-Ack packet
func (lcp *LCPStateMachine) sendTerminateAck(identifier uint8) {
	pkt := &LCPPacket{
		Code:       LCPCodeTermAck,
		Identifier: identifier,
	}

	lcp.sendPacket(ProtocolLCP, pkt.Serialize())
}

// sendCodeReject sends a Code-Reject packet
func (lcp *LCPStateMachine) sendCodeReject(rejected *LCPPacket) {
	lcp.identifier++

	// Include the rejected packet in the data
	rejectedData := rejected.Serialize()

	pkt := &LCPPacket{
		Code:       LCPCodeCodeReject,
		Identifier: lcp.identifier,
		Data:       rejectedData,
	}

	lcp.sendPacket(ProtocolLCP, pkt.Serialize())
}

// SendProtocolReject sends a Protocol-Reject packet
func (lcp *LCPStateMachine) SendProtocolReject(protocol uint16, data []byte) {
	lcp.mu.Lock()
	defer lcp.mu.Unlock()

	lcp.identifier++

	// Protocol-Reject data: 2-byte rejected protocol + rejected packet
	rejectData := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(rejectData[:2], protocol)
	copy(rejectData[2:], data)

	pkt := &LCPPacket{
		Code:       LCPCodeProtoReject,
		Identifier: lcp.identifier,
		Data:       rejectData,
	}

	lcp.sendPacket(ProtocolLCP, pkt.Serialize())
}

// Timer management

func (lcp *LCPStateMachine) initializeRestartCount() {
	lcp.restartCount = lcp.config.MaxConfigure
}

func (lcp *LCPStateMachine) zeroRestartCount() {
	lcp.restartCount = 0
}

func (lcp *LCPStateMachine) startTimer() {
	lcp.timerMu.Lock()
	defer lcp.timerMu.Unlock()

	if lcp.restartTimer != nil {
		lcp.restartTimer.Stop()
	}

	lcp.restartTimer = time.AfterFunc(lcp.config.RestartTimer, func() {
		lcp.timeout()
	})
}

func (lcp *LCPStateMachine) stopTimer() {
	lcp.timerMu.Lock()
	defer lcp.timerMu.Unlock()

	if lcp.restartTimer != nil {
		lcp.restartTimer.Stop()
		lcp.restartTimer = nil
	}
}

// timeout handles restart timer expiration
func (lcp *LCPStateMachine) timeout() {
	lcp.mu.Lock()
	defer lcp.mu.Unlock()

	if lcp.restartCount > 0 {
		// Timeout with restart counter > 0
		switch lcp.state {
		case LCPStateClosing, LCPStateStopping:
			lcp.sendTerminateRequest("Timeout")
		case LCPStateReqSent, LCPStateAckRcvd, LCPStateAckSent:
			lcp.sendConfigureRequest()
		}
	} else {
		// Timeout with restart counter expired
		switch lcp.state {
		case LCPStateClosing:
			// This-Layer-Finished
			lcp.setState(LCPStateClosed)
		case LCPStateStopping:
			// This-Layer-Finished
			lcp.setState(LCPStateStopped)
		case LCPStateReqSent, LCPStateAckRcvd, LCPStateAckSent:
			// This-Layer-Finished
			lcp.setState(LCPStateStopped)
		}
	}
}

// IsOpened returns true if LCP is in the Opened state
func (lcp *LCPStateMachine) IsOpened() bool {
	lcp.mu.RLock()
	defer lcp.mu.RUnlock()
	return lcp.state == LCPStateOpened
}

// generateMagicNumber generates a random 32-bit magic number
func generateMagicNumber() (uint32, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}
