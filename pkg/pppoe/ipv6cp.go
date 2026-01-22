// Package pppoe implements PPPoE protocol handling for the BNG.
// This file implements IPV6CP (IPv6 Control Protocol) per RFC 5072.
package pppoe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// IPV6CP option types
const (
	IPV6CPOptInterfaceID = 1 // Interface-Identifier
)

// IPV6CPState represents the IPV6CP state machine state
type IPV6CPState int

const (
	IPV6CPStateInitial  IPV6CPState = iota // Lower layer unavailable, no Open
	IPV6CPStateStarting                    // Lower layer unavailable, Open
	IPV6CPStateClosed                      // Lower layer available, no Open
	IPV6CPStateStopped                     // Open, waiting for Configure-Request
	IPV6CPStateClosing                     // Terminate-Request sent
	IPV6CPStateStopping                    // Terminate-Request sent (from Opened)
	IPV6CPStateReqSent                     // Configure-Request sent
	IPV6CPStateAckRcvd                     // Configure-Request sent, Configure-Ack received
	IPV6CPStateAckSent                     // Configure-Request and Configure-Ack sent
	IPV6CPStateOpened                      // Connection fully established
)

func (s IPV6CPState) String() string {
	switch s {
	case IPV6CPStateInitial:
		return "Initial"
	case IPV6CPStateStarting:
		return "Starting"
	case IPV6CPStateClosed:
		return "Closed"
	case IPV6CPStateStopped:
		return "Stopped"
	case IPV6CPStateClosing:
		return "Closing"
	case IPV6CPStateStopping:
		return "Stopping"
	case IPV6CPStateReqSent:
		return "Req-Sent"
	case IPV6CPStateAckRcvd:
		return "Ack-Rcvd"
	case IPV6CPStateAckSent:
		return "Ack-Sent"
	case IPV6CPStateOpened:
		return "Opened"
	default:
		return "Unknown"
	}
}

// IPV6CPConfig holds IPV6CP negotiation configuration
type IPV6CPConfig struct {
	LocalInterfaceID uint64        // Our interface identifier (8 bytes)
	MaxRetransmit    int           // Maximum retransmissions
	RestartTimer     time.Duration // Restart timer
}

// DefaultIPV6CPConfig returns default IPV6CP configuration
func DefaultIPV6CPConfig() (IPV6CPConfig, error) {
	id, err := generateInterfaceID()
	if err != nil {
		return IPV6CPConfig{}, fmt.Errorf("failed to generate interface ID: %w", err)
	}
	return IPV6CPConfig{
		LocalInterfaceID: id,
		MaxRetransmit:    10,
		RestartTimer:     3 * time.Second,
	}, nil
}

// IPV6CPNegotiatedOptions holds the negotiated IPV6CP options
type IPV6CPNegotiatedOptions struct {
	LocalInterfaceID uint64
	PeerInterfaceID  uint64
}

// IPV6CPStateMachine implements the RFC 1661 NCP state machine for IPV6CP
type IPV6CPStateMachine struct {
	state      IPV6CPState
	config     IPV6CPConfig
	negotiated IPV6CPNegotiatedOptions

	// Counters
	restartCount   int
	identifier     uint8
	lastIdentifier uint8

	// Packet sender callback
	sendPacket func(protocol uint16, data []byte)

	// State change callback
	onStateChange func(oldState, newState IPV6CPState)

	// Timers
	restartTimer *time.Timer
	timerMu      sync.Mutex

	// Logger
	logger *zap.Logger

	mu sync.RWMutex
}

// NewIPV6CPStateMachine creates a new IPV6CP state machine
func NewIPV6CPStateMachine(config IPV6CPConfig, sendPacket func(uint16, []byte), logger *zap.Logger) (*IPV6CPStateMachine, error) {
	if config.LocalInterfaceID == 0 {
		id, err := generateInterfaceID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate interface ID: %w", err)
		}
		config.LocalInterfaceID = id
	}

	return &IPV6CPStateMachine{
		state:      IPV6CPStateInitial,
		config:     config,
		sendPacket: sendPacket,
		logger:     logger,
		negotiated: IPV6CPNegotiatedOptions{
			LocalInterfaceID: config.LocalInterfaceID,
		},
	}, nil
}

// SetOnStateChange sets the state change callback
func (ipv6cp *IPV6CPStateMachine) SetOnStateChange(callback func(IPV6CPState, IPV6CPState)) {
	ipv6cp.mu.Lock()
	defer ipv6cp.mu.Unlock()
	ipv6cp.onStateChange = callback
}

// GetState returns the current IPV6CP state
func (ipv6cp *IPV6CPStateMachine) GetState() IPV6CPState {
	ipv6cp.mu.RLock()
	defer ipv6cp.mu.RUnlock()
	return ipv6cp.state
}

// GetNegotiatedOptions returns the negotiated options
func (ipv6cp *IPV6CPStateMachine) GetNegotiatedOptions() IPV6CPNegotiatedOptions {
	ipv6cp.mu.RLock()
	defer ipv6cp.mu.RUnlock()
	return ipv6cp.negotiated
}

// setState changes the state and calls the callback
func (ipv6cp *IPV6CPStateMachine) setState(newState IPV6CPState) {
	oldState := ipv6cp.state
	ipv6cp.state = newState

	ipv6cp.logger.Debug("IPV6CP state change",
		zap.String("from", oldState.String()),
		zap.String("to", newState.String()),
	)

	if ipv6cp.onStateChange != nil {
		ipv6cp.onStateChange(oldState, newState)
	}
}

// Up is called when LCP is opened
func (ipv6cp *IPV6CPStateMachine) Up() {
	ipv6cp.mu.Lock()
	defer ipv6cp.mu.Unlock()

	switch ipv6cp.state {
	case IPV6CPStateInitial:
		ipv6cp.setState(IPV6CPStateClosed)
	case IPV6CPStateStarting:
		ipv6cp.initializeRestartCount()
		ipv6cp.sendConfigureRequest()
		ipv6cp.setState(IPV6CPStateReqSent)
	}
}

// Down is called when LCP goes down
func (ipv6cp *IPV6CPStateMachine) Down() {
	ipv6cp.mu.Lock()
	defer ipv6cp.mu.Unlock()

	ipv6cp.stopTimer()

	switch ipv6cp.state {
	case IPV6CPStateClosed:
		ipv6cp.setState(IPV6CPStateInitial)
	case IPV6CPStateStopped:
		ipv6cp.setState(IPV6CPStateStarting)
	case IPV6CPStateClosing:
		ipv6cp.setState(IPV6CPStateInitial)
	case IPV6CPStateStopping, IPV6CPStateReqSent, IPV6CPStateAckRcvd, IPV6CPStateAckSent:
		ipv6cp.setState(IPV6CPStateStarting)
	case IPV6CPStateOpened:
		ipv6cp.setState(IPV6CPStateStarting)
	}
}

// Open is called to administratively open IPV6CP
func (ipv6cp *IPV6CPStateMachine) Open() {
	ipv6cp.mu.Lock()
	defer ipv6cp.mu.Unlock()

	switch ipv6cp.state {
	case IPV6CPStateInitial:
		ipv6cp.setState(IPV6CPStateStarting)
	case IPV6CPStateClosed:
		ipv6cp.initializeRestartCount()
		ipv6cp.sendConfigureRequest()
		ipv6cp.setState(IPV6CPStateReqSent)
	case IPV6CPStateClosing:
		ipv6cp.setState(IPV6CPStateStopping)
	}
}

// Close is called to administratively close IPV6CP
func (ipv6cp *IPV6CPStateMachine) Close() {
	ipv6cp.mu.Lock()
	defer ipv6cp.mu.Unlock()

	ipv6cp.closeInternal("Admin close")
}

func (ipv6cp *IPV6CPStateMachine) closeInternal(reason string) {
	switch ipv6cp.state {
	case IPV6CPStateStarting:
		ipv6cp.setState(IPV6CPStateInitial)
	case IPV6CPStateStopped:
		ipv6cp.setState(IPV6CPStateClosed)
	case IPV6CPStateStopping:
		ipv6cp.setState(IPV6CPStateClosing)
	case IPV6CPStateOpened:
		ipv6cp.initializeRestartCount()
		ipv6cp.sendTerminateRequest(reason)
		ipv6cp.setState(IPV6CPStateClosing)
	case IPV6CPStateReqSent, IPV6CPStateAckRcvd, IPV6CPStateAckSent:
		ipv6cp.initializeRestartCount()
		ipv6cp.sendTerminateRequest(reason)
		ipv6cp.setState(IPV6CPStateClosing)
	}
}

// ReceivePacket processes an incoming IPV6CP packet
func (ipv6cp *IPV6CPStateMachine) ReceivePacket(data []byte) error {
	pkt, err := ParseLCPPacket(data)
	if err != nil {
		return fmt.Errorf("failed to parse IPV6CP packet: %w", err)
	}

	ipv6cp.mu.Lock()
	defer ipv6cp.mu.Unlock()

	ipv6cp.logger.Debug("IPV6CP packet received",
		zap.Uint8("code", pkt.Code),
		zap.Uint8("identifier", pkt.Identifier),
		zap.String("state", ipv6cp.state.String()),
	)

	switch pkt.Code {
	case LCPCodeConfigRequest:
		return ipv6cp.receiveConfigureRequest(pkt)
	case LCPCodeConfigAck:
		return ipv6cp.receiveConfigureAck(pkt)
	case LCPCodeConfigNak:
		return ipv6cp.receiveConfigureNak(pkt)
	case LCPCodeConfigReject:
		return ipv6cp.receiveConfigureReject(pkt)
	case LCPCodeTermRequest:
		return ipv6cp.receiveTerminateRequest(pkt)
	case LCPCodeTermAck:
		return ipv6cp.receiveTerminateAck(pkt)
	default:
		return nil
	}
}

// receiveConfigureRequest handles incoming Configure-Request
func (ipv6cp *IPV6CPStateMachine) receiveConfigureRequest(pkt *LCPPacket) error {
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return fmt.Errorf("failed to parse IPV6CP options: %w", err)
	}

	// Process options
	ackOpts, nakOpts, rejOpts := ipv6cp.processConfigureOptions(opts)

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
	}

	// Send response
	resp := &LCPPacket{
		Code:       respCode,
		Identifier: pkt.Identifier,
		Data:       SerializeLCPOptions(respOpts),
	}
	ipv6cp.sendPacket(ProtocolIPv6CP, resp.Serialize())

	// State transitions
	switch ipv6cp.state {
	case IPV6CPStateClosed:
		ipv6cp.sendTerminateAck(pkt.Identifier)
	case IPV6CPStateStopped:
		ipv6cp.initializeRestartCount()
		ipv6cp.sendConfigureRequest()
		if respCode == LCPCodeConfigAck {
			ipv6cp.setState(IPV6CPStateAckSent)
		} else {
			ipv6cp.setState(IPV6CPStateReqSent)
		}
	case IPV6CPStateReqSent:
		if respCode == LCPCodeConfigAck {
			ipv6cp.setState(IPV6CPStateAckSent)
		}
	case IPV6CPStateAckRcvd:
		if respCode == LCPCodeConfigAck {
			ipv6cp.setState(IPV6CPStateOpened)
		}
	case IPV6CPStateAckSent:
		if respCode != LCPCodeConfigAck {
			ipv6cp.setState(IPV6CPStateReqSent)
		}
	case IPV6CPStateOpened:
		ipv6cp.sendConfigureRequest()
		if respCode == LCPCodeConfigAck {
			ipv6cp.setState(IPV6CPStateAckSent)
		} else {
			ipv6cp.setState(IPV6CPStateReqSent)
		}
	}

	return nil
}

// processConfigureOptions processes incoming IPV6CP options
func (ipv6cp *IPV6CPStateMachine) processConfigureOptions(opts []LCPOption) (ack, nak, reject []LCPOption) {
	for _, opt := range opts {
		switch opt.Type {
		case IPV6CPOptInterfaceID:
			if len(opt.Data) != 8 {
				reject = append(reject, opt)
				continue
			}

			peerID := binary.BigEndian.Uint64(opt.Data)

			// Check for zero interface ID
			if peerID == 0 {
				// NAK with a random interface ID
				newID, err := generateInterfaceID()
				if err != nil {
					ipv6cp.logger.Error("Failed to generate interface ID for NAK", zap.Error(err))
					reject = append(reject, opt)
					continue
				}
				nakOpt := LCPOption{
					Type: IPV6CPOptInterfaceID,
					Data: make([]byte, 8),
				}
				binary.BigEndian.PutUint64(nakOpt.Data, newID)
				nak = append(nak, nakOpt)
				continue
			}

			// Check for collision with our ID
			if peerID == ipv6cp.config.LocalInterfaceID {
				// Collision - regenerate our ID and NAK with new one for peer
				newLocalID, err := generateInterfaceID()
				if err != nil {
					ipv6cp.logger.Error("Failed to regenerate local interface ID", zap.Error(err))
					reject = append(reject, opt)
					continue
				}
				ipv6cp.config.LocalInterfaceID = newLocalID
				ipv6cp.negotiated.LocalInterfaceID = ipv6cp.config.LocalInterfaceID

				newPeerID, err := generateInterfaceID()
				if err != nil {
					ipv6cp.logger.Error("Failed to generate peer interface ID for NAK", zap.Error(err))
					reject = append(reject, opt)
					continue
				}
				nakOpt := LCPOption{
					Type: IPV6CPOptInterfaceID,
					Data: make([]byte, 8),
				}
				binary.BigEndian.PutUint64(nakOpt.Data, newPeerID)
				nak = append(nak, nakOpt)
				continue
			}

			// Accept the interface ID
			ipv6cp.negotiated.PeerInterfaceID = peerID
			ack = append(ack, opt)

		default:
			// Unknown option - reject
			reject = append(reject, opt)
		}
	}

	return ack, nak, reject
}

// receiveConfigureAck handles incoming Configure-Ack
func (ipv6cp *IPV6CPStateMachine) receiveConfigureAck(pkt *LCPPacket) error {
	if pkt.Identifier != ipv6cp.lastIdentifier {
		return nil
	}

	ipv6cp.stopTimer()

	switch ipv6cp.state {
	case IPV6CPStateClosed, IPV6CPStateStopped:
		ipv6cp.sendTerminateAck(pkt.Identifier)
	case IPV6CPStateReqSent:
		ipv6cp.initializeRestartCount()
		ipv6cp.setState(IPV6CPStateAckRcvd)
	case IPV6CPStateAckRcvd:
		ipv6cp.sendConfigureRequest()
		ipv6cp.setState(IPV6CPStateReqSent)
	case IPV6CPStateAckSent:
		ipv6cp.initializeRestartCount()
		ipv6cp.setState(IPV6CPStateOpened)
	case IPV6CPStateOpened:
		ipv6cp.sendConfigureRequest()
		ipv6cp.setState(IPV6CPStateReqSent)
	}

	return nil
}

// receiveConfigureNak handles incoming Configure-Nak
func (ipv6cp *IPV6CPStateMachine) receiveConfigureNak(pkt *LCPPacket) error {
	if pkt.Identifier != ipv6cp.lastIdentifier {
		return nil
	}

	ipv6cp.stopTimer()

	// Process NAK options
	opts, _ := ParseLCPOptions(pkt.Data)
	for _, opt := range opts {
		switch opt.Type {
		case IPV6CPOptInterfaceID:
			if len(opt.Data) == 8 {
				// Accept suggested interface ID
				ipv6cp.negotiated.LocalInterfaceID = binary.BigEndian.Uint64(opt.Data)
			}
		}
	}

	switch ipv6cp.state {
	case IPV6CPStateClosed, IPV6CPStateStopped:
		ipv6cp.sendTerminateAck(pkt.Identifier)
	case IPV6CPStateReqSent, IPV6CPStateAckSent:
		ipv6cp.initializeRestartCount()
		ipv6cp.sendConfigureRequest()
	case IPV6CPStateAckRcvd:
		ipv6cp.sendConfigureRequest()
		ipv6cp.setState(IPV6CPStateReqSent)
	case IPV6CPStateOpened:
		ipv6cp.sendConfigureRequest()
		ipv6cp.setState(IPV6CPStateReqSent)
	}

	return nil
}

// receiveConfigureReject handles incoming Configure-Reject
func (ipv6cp *IPV6CPStateMachine) receiveConfigureReject(pkt *LCPPacket) error {
	if pkt.Identifier != ipv6cp.lastIdentifier {
		return nil
	}

	ipv6cp.stopTimer()

	switch ipv6cp.state {
	case IPV6CPStateClosed, IPV6CPStateStopped:
		ipv6cp.sendTerminateAck(pkt.Identifier)
	case IPV6CPStateReqSent, IPV6CPStateAckSent:
		ipv6cp.initializeRestartCount()
		ipv6cp.sendConfigureRequest()
	case IPV6CPStateAckRcvd:
		ipv6cp.sendConfigureRequest()
		ipv6cp.setState(IPV6CPStateReqSent)
	case IPV6CPStateOpened:
		ipv6cp.sendConfigureRequest()
		ipv6cp.setState(IPV6CPStateReqSent)
	}

	return nil
}

// receiveTerminateRequest handles incoming Terminate-Request
func (ipv6cp *IPV6CPStateMachine) receiveTerminateRequest(pkt *LCPPacket) error {
	ipv6cp.stopTimer()

	switch ipv6cp.state {
	case IPV6CPStateClosed, IPV6CPStateStopped, IPV6CPStateClosing, IPV6CPStateStopping:
		ipv6cp.sendTerminateAck(pkt.Identifier)
	case IPV6CPStateReqSent, IPV6CPStateAckRcvd, IPV6CPStateAckSent:
		ipv6cp.sendTerminateAck(pkt.Identifier)
		ipv6cp.setState(IPV6CPStateStopped)
	case IPV6CPStateOpened:
		ipv6cp.zeroRestartCount()
		ipv6cp.sendTerminateAck(pkt.Identifier)
		ipv6cp.setState(IPV6CPStateStopping)
	}

	return nil
}

// receiveTerminateAck handles incoming Terminate-Ack
func (ipv6cp *IPV6CPStateMachine) receiveTerminateAck(pkt *LCPPacket) error {
	ipv6cp.stopTimer()

	switch ipv6cp.state {
	case IPV6CPStateClosing:
		ipv6cp.setState(IPV6CPStateClosed)
	case IPV6CPStateStopping:
		ipv6cp.setState(IPV6CPStateStopped)
	case IPV6CPStateAckRcvd:
		ipv6cp.setState(IPV6CPStateReqSent)
	case IPV6CPStateOpened:
		ipv6cp.sendConfigureRequest()
		ipv6cp.setState(IPV6CPStateReqSent)
	}

	return nil
}

// sendConfigureRequest sends an IPV6CP Configure-Request
func (ipv6cp *IPV6CPStateMachine) sendConfigureRequest() {
	ipv6cp.identifier++
	ipv6cp.lastIdentifier = ipv6cp.identifier

	// Interface-Identifier option
	idData := make([]byte, 8)
	binary.BigEndian.PutUint64(idData, ipv6cp.negotiated.LocalInterfaceID)

	opts := []LCPOption{
		{Type: IPV6CPOptInterfaceID, Data: idData},
	}

	pkt := &LCPPacket{
		Code:       LCPCodeConfigRequest,
		Identifier: ipv6cp.identifier,
		Data:       SerializeLCPOptions(opts),
	}

	ipv6cp.sendPacket(ProtocolIPv6CP, pkt.Serialize())
	ipv6cp.startTimer()
	ipv6cp.restartCount--
}

// sendTerminateRequest sends an IPV6CP Terminate-Request
func (ipv6cp *IPV6CPStateMachine) sendTerminateRequest(reason string) {
	ipv6cp.identifier++

	pkt := &LCPPacket{
		Code:       LCPCodeTermRequest,
		Identifier: ipv6cp.identifier,
		Data:       []byte(reason),
	}

	ipv6cp.sendPacket(ProtocolIPv6CP, pkt.Serialize())
	ipv6cp.startTimer()
	ipv6cp.restartCount--
}

// sendTerminateAck sends an IPV6CP Terminate-Ack
func (ipv6cp *IPV6CPStateMachine) sendTerminateAck(identifier uint8) {
	pkt := &LCPPacket{
		Code:       LCPCodeTermAck,
		Identifier: identifier,
	}

	ipv6cp.sendPacket(ProtocolIPv6CP, pkt.Serialize())
}

// Timer management

func (ipv6cp *IPV6CPStateMachine) initializeRestartCount() {
	ipv6cp.restartCount = ipv6cp.config.MaxRetransmit
	if ipv6cp.restartCount == 0 {
		ipv6cp.restartCount = 10
	}
}

func (ipv6cp *IPV6CPStateMachine) zeroRestartCount() {
	ipv6cp.restartCount = 0
}

func (ipv6cp *IPV6CPStateMachine) startTimer() {
	ipv6cp.timerMu.Lock()
	defer ipv6cp.timerMu.Unlock()

	if ipv6cp.restartTimer != nil {
		ipv6cp.restartTimer.Stop()
	}

	timeout := ipv6cp.config.RestartTimer
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	ipv6cp.restartTimer = time.AfterFunc(timeout, func() {
		ipv6cp.timeout()
	})
}

func (ipv6cp *IPV6CPStateMachine) stopTimer() {
	ipv6cp.timerMu.Lock()
	defer ipv6cp.timerMu.Unlock()

	if ipv6cp.restartTimer != nil {
		ipv6cp.restartTimer.Stop()
		ipv6cp.restartTimer = nil
	}
}

func (ipv6cp *IPV6CPStateMachine) timeout() {
	ipv6cp.mu.Lock()
	defer ipv6cp.mu.Unlock()

	if ipv6cp.restartCount > 0 {
		switch ipv6cp.state {
		case IPV6CPStateClosing, IPV6CPStateStopping:
			ipv6cp.sendTerminateRequest("Timeout")
		case IPV6CPStateReqSent, IPV6CPStateAckRcvd, IPV6CPStateAckSent:
			ipv6cp.sendConfigureRequest()
		}
	} else {
		switch ipv6cp.state {
		case IPV6CPStateClosing:
			ipv6cp.setState(IPV6CPStateClosed)
		case IPV6CPStateStopping:
			ipv6cp.setState(IPV6CPStateStopped)
		case IPV6CPStateReqSent, IPV6CPStateAckRcvd, IPV6CPStateAckSent:
			ipv6cp.setState(IPV6CPStateStopped)
		}
	}
}

// IsOpened returns true if IPV6CP is in the Opened state
func (ipv6cp *IPV6CPStateMachine) IsOpened() bool {
	ipv6cp.mu.RLock()
	defer ipv6cp.mu.RUnlock()
	return ipv6cp.state == IPV6CPStateOpened
}

// generateInterfaceID generates a random 64-bit interface identifier
func generateInterfaceID() (uint64, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	// Set the universal/local bit to indicate locally administered
	b[0] |= 0x02
	return binary.BigEndian.Uint64(b), nil
}
