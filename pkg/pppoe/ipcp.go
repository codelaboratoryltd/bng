// Package pppoe implements PPPoE protocol handling for the BNG.
// This file implements IPCP (IP Control Protocol) per RFC 1332 and RFC 1877.
package pppoe

import (
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// IPCPState represents the IPCP state machine state (same as LCP per RFC 1661)
type IPCPState int

const (
	IPCPStateInitial  IPCPState = iota // Lower layer unavailable, no Open
	IPCPStateStarting                  // Lower layer unavailable, Open
	IPCPStateClosed                    // Lower layer available, no Open
	IPCPStateStopped                   // Open, waiting for Configure-Request
	IPCPStateClosing                   // Terminate-Request sent
	IPCPStateStopping                  // Terminate-Request sent (from Opened)
	IPCPStateReqSent                   // Configure-Request sent
	IPCPStateAckRcvd                   // Configure-Request sent, Configure-Ack received
	IPCPStateAckSent                   // Configure-Request and Configure-Ack sent
	IPCPStateOpened                    // Connection fully established
)

func (s IPCPState) String() string {
	switch s {
	case IPCPStateInitial:
		return "Initial"
	case IPCPStateStarting:
		return "Starting"
	case IPCPStateClosed:
		return "Closed"
	case IPCPStateStopped:
		return "Stopped"
	case IPCPStateClosing:
		return "Closing"
	case IPCPStateStopping:
		return "Stopping"
	case IPCPStateReqSent:
		return "Req-Sent"
	case IPCPStateAckRcvd:
		return "Ack-Rcvd"
	case IPCPStateAckSent:
		return "Ack-Sent"
	case IPCPStateOpened:
		return "Opened"
	default:
		return "Unknown"
	}
}

// IPCPConfig holds IPCP negotiation configuration
type IPCPConfig struct {
	LocalIP       net.IP          // Our (server) IP address
	PeerIP        net.IP          // IP to assign to peer (can be nil for dynamic)
	PrimaryDNS    net.IP          // Primary DNS server
	SecondaryDNS  net.IP          // Secondary DNS server
	MaxRetransmit int             // Maximum retransmissions
	RestartTimer  time.Duration   // Restart timer
	IPPool        IPPoolAllocator // IP pool for dynamic allocation
}

// IPPoolAllocator interface for IP address allocation
type IPPoolAllocator interface {
	Allocate(sessionID string) net.IP
	Release(sessionID string)
}

// DefaultIPCPConfig returns default IPCP configuration
func DefaultIPCPConfig() IPCPConfig {
	return IPCPConfig{
		LocalIP:       net.ParseIP("10.0.0.1"),
		MaxRetransmit: 10,
		RestartTimer:  3 * time.Second,
	}
}

// IPCPNegotiatedOptions holds the negotiated IPCP options
type IPCPNegotiatedOptions struct {
	LocalIP      net.IP
	PeerIP       net.IP
	PrimaryDNS   net.IP
	SecondaryDNS net.IP
}

// IPCPStateMachine implements the RFC 1661 NCP state machine for IPCP
type IPCPStateMachine struct {
	state      IPCPState
	config     IPCPConfig
	negotiated IPCPNegotiatedOptions
	sessionID  string // For IP pool allocation

	// Counters
	restartCount   int
	identifier     uint8
	lastIdentifier uint8

	// Packet sender callback
	sendPacket func(protocol uint16, data []byte)

	// State change callback
	onStateChange func(oldState, newState IPCPState)

	// Timers
	restartTimer *time.Timer
	timerMu      sync.Mutex

	// Logger
	logger *zap.Logger

	mu sync.RWMutex
}

// NewIPCPStateMachine creates a new IPCP state machine
func NewIPCPStateMachine(config IPCPConfig, sessionID string, sendPacket func(uint16, []byte), logger *zap.Logger) *IPCPStateMachine {
	return &IPCPStateMachine{
		state:      IPCPStateInitial,
		config:     config,
		sessionID:  sessionID,
		sendPacket: sendPacket,
		logger:     logger,
		negotiated: IPCPNegotiatedOptions{
			LocalIP: config.LocalIP,
		},
	}
}

// SetOnStateChange sets the state change callback
func (ipcp *IPCPStateMachine) SetOnStateChange(callback func(IPCPState, IPCPState)) {
	ipcp.mu.Lock()
	defer ipcp.mu.Unlock()
	ipcp.onStateChange = callback
}

// GetState returns the current IPCP state
func (ipcp *IPCPStateMachine) GetState() IPCPState {
	ipcp.mu.RLock()
	defer ipcp.mu.RUnlock()
	return ipcp.state
}

// GetNegotiatedOptions returns the negotiated options
func (ipcp *IPCPStateMachine) GetNegotiatedOptions() IPCPNegotiatedOptions {
	ipcp.mu.RLock()
	defer ipcp.mu.RUnlock()
	return ipcp.negotiated
}

// SetPeerIP sets the IP address to assign to the peer
func (ipcp *IPCPStateMachine) SetPeerIP(ip net.IP) {
	ipcp.mu.Lock()
	defer ipcp.mu.Unlock()
	ipcp.config.PeerIP = ip
	ipcp.negotiated.PeerIP = ip
}

// setState changes the state and calls the callback
func (ipcp *IPCPStateMachine) setState(newState IPCPState) {
	oldState := ipcp.state
	ipcp.state = newState

	ipcp.logger.Debug("IPCP state change",
		zap.String("from", oldState.String()),
		zap.String("to", newState.String()),
	)

	if ipcp.onStateChange != nil {
		ipcp.onStateChange(oldState, newState)
	}
}

// Up is called when LCP is opened
func (ipcp *IPCPStateMachine) Up() {
	ipcp.mu.Lock()
	defer ipcp.mu.Unlock()

	// Allocate IP if using pool and no static IP assigned
	if ipcp.config.PeerIP == nil && ipcp.config.IPPool != nil {
		ipcp.config.PeerIP = ipcp.config.IPPool.Allocate(ipcp.sessionID)
		ipcp.negotiated.PeerIP = ipcp.config.PeerIP
		ipcp.logger.Debug("Allocated IP for peer",
			zap.String("ip", ipcp.config.PeerIP.String()),
		)
	}

	switch ipcp.state {
	case IPCPStateInitial:
		ipcp.setState(IPCPStateClosed)
	case IPCPStateStarting:
		ipcp.initializeRestartCount()
		ipcp.sendConfigureRequest()
		ipcp.setState(IPCPStateReqSent)
	}
}

// Down is called when LCP goes down
func (ipcp *IPCPStateMachine) Down() {
	ipcp.mu.Lock()
	defer ipcp.mu.Unlock()

	ipcp.stopTimer()

	// Release allocated IP
	if ipcp.config.IPPool != nil && ipcp.negotiated.PeerIP != nil {
		ipcp.config.IPPool.Release(ipcp.sessionID)
	}

	switch ipcp.state {
	case IPCPStateClosed:
		ipcp.setState(IPCPStateInitial)
	case IPCPStateStopped:
		ipcp.setState(IPCPStateStarting)
	case IPCPStateClosing:
		ipcp.setState(IPCPStateInitial)
	case IPCPStateStopping, IPCPStateReqSent, IPCPStateAckRcvd, IPCPStateAckSent:
		ipcp.setState(IPCPStateStarting)
	case IPCPStateOpened:
		ipcp.setState(IPCPStateStarting)
	}
}

// Open is called to administratively open IPCP
func (ipcp *IPCPStateMachine) Open() {
	ipcp.mu.Lock()
	defer ipcp.mu.Unlock()

	switch ipcp.state {
	case IPCPStateInitial:
		ipcp.setState(IPCPStateStarting)
	case IPCPStateClosed:
		ipcp.initializeRestartCount()
		ipcp.sendConfigureRequest()
		ipcp.setState(IPCPStateReqSent)
	case IPCPStateClosing:
		ipcp.setState(IPCPStateStopping)
	}
}

// Close is called to administratively close IPCP
func (ipcp *IPCPStateMachine) Close() {
	ipcp.mu.Lock()
	defer ipcp.mu.Unlock()

	ipcp.closeInternal("Admin close")
}

func (ipcp *IPCPStateMachine) closeInternal(reason string) {
	switch ipcp.state {
	case IPCPStateStarting:
		ipcp.setState(IPCPStateInitial)
	case IPCPStateStopped:
		ipcp.setState(IPCPStateClosed)
	case IPCPStateStopping:
		ipcp.setState(IPCPStateClosing)
	case IPCPStateOpened:
		ipcp.initializeRestartCount()
		ipcp.sendTerminateRequest(reason)
		ipcp.setState(IPCPStateClosing)
	case IPCPStateReqSent, IPCPStateAckRcvd, IPCPStateAckSent:
		ipcp.initializeRestartCount()
		ipcp.sendTerminateRequest(reason)
		ipcp.setState(IPCPStateClosing)
	}
}

// ReceivePacket processes an incoming IPCP packet
func (ipcp *IPCPStateMachine) ReceivePacket(data []byte) error {
	pkt, err := ParseLCPPacket(data) // IPCP uses same packet format as LCP
	if err != nil {
		return fmt.Errorf("failed to parse IPCP packet: %w", err)
	}

	ipcp.mu.Lock()
	defer ipcp.mu.Unlock()

	ipcp.logger.Debug("IPCP packet received",
		zap.Uint8("code", pkt.Code),
		zap.Uint8("identifier", pkt.Identifier),
		zap.String("state", ipcp.state.String()),
	)

	switch pkt.Code {
	case LCPCodeConfigRequest:
		return ipcp.receiveConfigureRequest(pkt)
	case LCPCodeConfigAck:
		return ipcp.receiveConfigureAck(pkt)
	case LCPCodeConfigNak:
		return ipcp.receiveConfigureNak(pkt)
	case LCPCodeConfigReject:
		return ipcp.receiveConfigureReject(pkt)
	case LCPCodeTermRequest:
		return ipcp.receiveTerminateRequest(pkt)
	case LCPCodeTermAck:
		return ipcp.receiveTerminateAck(pkt)
	default:
		// Unknown code - ignore
		return nil
	}
}

// receiveConfigureRequest handles incoming Configure-Request
func (ipcp *IPCPStateMachine) receiveConfigureRequest(pkt *LCPPacket) error {
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return fmt.Errorf("failed to parse IPCP options: %w", err)
	}

	// Process options and determine response
	ackOpts, nakOpts, rejOpts := ipcp.processConfigureOptions(opts)

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
	ipcp.sendPacket(ProtocolIPCP, resp.Serialize())

	// State machine transitions
	switch ipcp.state {
	case IPCPStateClosed:
		ipcp.sendTerminateAck(pkt.Identifier)
	case IPCPStateStopped:
		ipcp.initializeRestartCount()
		ipcp.sendConfigureRequest()
		if respCode == LCPCodeConfigAck {
			ipcp.setState(IPCPStateAckSent)
		} else {
			ipcp.setState(IPCPStateReqSent)
		}
	case IPCPStateReqSent:
		if respCode == LCPCodeConfigAck {
			ipcp.setState(IPCPStateAckSent)
		}
	case IPCPStateAckRcvd:
		if respCode == LCPCodeConfigAck {
			ipcp.setState(IPCPStateOpened)
		}
	case IPCPStateAckSent:
		if respCode != LCPCodeConfigAck {
			ipcp.setState(IPCPStateReqSent)
		}
	case IPCPStateOpened:
		ipcp.sendConfigureRequest()
		if respCode == LCPCodeConfigAck {
			ipcp.setState(IPCPStateAckSent)
		} else {
			ipcp.setState(IPCPStateReqSent)
		}
	}

	return nil
}

// processConfigureOptions processes incoming IPCP options
func (ipcp *IPCPStateMachine) processConfigureOptions(opts []LCPOption) (ack, nak, reject []LCPOption) {
	for _, opt := range opts {
		switch opt.Type {
		case IPCPOptIPAddress:
			if len(opt.Data) != 4 {
				reject = append(reject, opt)
				continue
			}

			requestedIP := net.IP(opt.Data)

			// If peer requests 0.0.0.0, we must NAK with the assigned IP
			if requestedIP.Equal(net.IPv4zero) || requestedIP.IsUnspecified() {
				if ipcp.config.PeerIP != nil {
					nakOpt := LCPOption{
						Type: IPCPOptIPAddress,
						Data: ipcp.config.PeerIP.To4(),
					}
					nak = append(nak, nakOpt)
				} else {
					// No IP to assign
					reject = append(reject, opt)
				}
				continue
			}

			// Peer requests specific IP - check if it matches our assignment
			if ipcp.config.PeerIP != nil && !requestedIP.Equal(ipcp.config.PeerIP) {
				// NAK with our assigned IP
				nakOpt := LCPOption{
					Type: IPCPOptIPAddress,
					Data: ipcp.config.PeerIP.To4(),
				}
				nak = append(nak, nakOpt)
				continue
			}

			// Accept the requested IP
			ipcp.negotiated.PeerIP = requestedIP
			ack = append(ack, opt)

		case IPCPOptPrimaryDNS:
			if len(opt.Data) != 4 {
				reject = append(reject, opt)
				continue
			}

			// Peer requesting DNS - NAK with our DNS if they request 0.0.0.0
			requestedDNS := net.IP(opt.Data)
			if requestedDNS.Equal(net.IPv4zero) || requestedDNS.IsUnspecified() {
				if ipcp.config.PrimaryDNS != nil {
					nakOpt := LCPOption{
						Type: IPCPOptPrimaryDNS,
						Data: ipcp.config.PrimaryDNS.To4(),
					}
					nak = append(nak, nakOpt)
				} else {
					ack = append(ack, opt)
				}
			} else {
				// Accept whatever they request
				ipcp.negotiated.PrimaryDNS = requestedDNS
				ack = append(ack, opt)
			}

		case IPCPOptSecondaryDNS:
			if len(opt.Data) != 4 {
				reject = append(reject, opt)
				continue
			}

			requestedDNS := net.IP(opt.Data)
			if requestedDNS.Equal(net.IPv4zero) || requestedDNS.IsUnspecified() {
				if ipcp.config.SecondaryDNS != nil {
					nakOpt := LCPOption{
						Type: IPCPOptSecondaryDNS,
						Data: ipcp.config.SecondaryDNS.To4(),
					}
					nak = append(nak, nakOpt)
				} else {
					ack = append(ack, opt)
				}
			} else {
				ipcp.negotiated.SecondaryDNS = requestedDNS
				ack = append(ack, opt)
			}

		case IPCPOptIPCompression:
			// We don't support IP compression
			reject = append(reject, opt)

		default:
			// Unknown option - reject
			reject = append(reject, opt)
		}
	}

	return ack, nak, reject
}

// receiveConfigureAck handles incoming Configure-Ack
func (ipcp *IPCPStateMachine) receiveConfigureAck(pkt *LCPPacket) error {
	if pkt.Identifier != ipcp.lastIdentifier {
		return nil
	}

	ipcp.stopTimer()

	switch ipcp.state {
	case IPCPStateClosed, IPCPStateStopped:
		ipcp.sendTerminateAck(pkt.Identifier)
	case IPCPStateReqSent:
		ipcp.initializeRestartCount()
		ipcp.setState(IPCPStateAckRcvd)
	case IPCPStateAckRcvd:
		ipcp.sendConfigureRequest()
		ipcp.setState(IPCPStateReqSent)
	case IPCPStateAckSent:
		ipcp.initializeRestartCount()
		ipcp.setState(IPCPStateOpened)
	case IPCPStateOpened:
		ipcp.sendConfigureRequest()
		ipcp.setState(IPCPStateReqSent)
	}

	return nil
}

// receiveConfigureNak handles incoming Configure-Nak
func (ipcp *IPCPStateMachine) receiveConfigureNak(pkt *LCPPacket) error {
	if pkt.Identifier != ipcp.lastIdentifier {
		return nil
	}

	ipcp.stopTimer()

	// Process NAK options
	opts, err := ParseLCPOptions(pkt.Data)
	if err != nil {
		return err
	}

	for _, opt := range opts {
		switch opt.Type {
		case IPCPOptIPAddress:
			// Peer NAKed our IP - accept their suggestion
			if len(opt.Data) == 4 {
				ipcp.negotiated.LocalIP = net.IP(opt.Data)
			}
		}
	}

	switch ipcp.state {
	case IPCPStateClosed, IPCPStateStopped:
		ipcp.sendTerminateAck(pkt.Identifier)
	case IPCPStateReqSent, IPCPStateAckSent:
		ipcp.initializeRestartCount()
		ipcp.sendConfigureRequest()
	case IPCPStateAckRcvd:
		ipcp.sendConfigureRequest()
		ipcp.setState(IPCPStateReqSent)
	case IPCPStateOpened:
		ipcp.sendConfigureRequest()
		ipcp.setState(IPCPStateReqSent)
	}

	return nil
}

// receiveConfigureReject handles incoming Configure-Reject
func (ipcp *IPCPStateMachine) receiveConfigureReject(pkt *LCPPacket) error {
	if pkt.Identifier != ipcp.lastIdentifier {
		return nil
	}

	ipcp.stopTimer()

	// Process rejected options - stop sending them
	opts, _ := ParseLCPOptions(pkt.Data)
	for _, opt := range opts {
		ipcp.logger.Warn("IPCP option rejected by peer",
			zap.Uint8("option", opt.Type),
		)
	}

	switch ipcp.state {
	case IPCPStateClosed, IPCPStateStopped:
		ipcp.sendTerminateAck(pkt.Identifier)
	case IPCPStateReqSent, IPCPStateAckSent:
		ipcp.initializeRestartCount()
		ipcp.sendConfigureRequest()
	case IPCPStateAckRcvd:
		ipcp.sendConfigureRequest()
		ipcp.setState(IPCPStateReqSent)
	case IPCPStateOpened:
		ipcp.sendConfigureRequest()
		ipcp.setState(IPCPStateReqSent)
	}

	return nil
}

// receiveTerminateRequest handles incoming Terminate-Request
func (ipcp *IPCPStateMachine) receiveTerminateRequest(pkt *LCPPacket) error {
	ipcp.stopTimer()

	switch ipcp.state {
	case IPCPStateClosed, IPCPStateStopped, IPCPStateClosing, IPCPStateStopping:
		ipcp.sendTerminateAck(pkt.Identifier)
	case IPCPStateReqSent, IPCPStateAckRcvd, IPCPStateAckSent:
		ipcp.sendTerminateAck(pkt.Identifier)
		ipcp.setState(IPCPStateStopped)
	case IPCPStateOpened:
		ipcp.zeroRestartCount()
		ipcp.sendTerminateAck(pkt.Identifier)
		ipcp.setState(IPCPStateStopping)
	}

	return nil
}

// receiveTerminateAck handles incoming Terminate-Ack
func (ipcp *IPCPStateMachine) receiveTerminateAck(pkt *LCPPacket) error {
	ipcp.stopTimer()

	switch ipcp.state {
	case IPCPStateClosing:
		ipcp.setState(IPCPStateClosed)
	case IPCPStateStopping:
		ipcp.setState(IPCPStateStopped)
	case IPCPStateAckRcvd:
		ipcp.setState(IPCPStateReqSent)
	case IPCPStateOpened:
		ipcp.sendConfigureRequest()
		ipcp.setState(IPCPStateReqSent)
	}

	return nil
}

// sendConfigureRequest sends an IPCP Configure-Request
func (ipcp *IPCPStateMachine) sendConfigureRequest() {
	ipcp.identifier++
	ipcp.lastIdentifier = ipcp.identifier

	var opts []LCPOption

	// IP-Address option (our server IP)
	if ipcp.negotiated.LocalIP != nil {
		opts = append(opts, LCPOption{
			Type: IPCPOptIPAddress,
			Data: ipcp.negotiated.LocalIP.To4(),
		})
	}

	pkt := &LCPPacket{
		Code:       LCPCodeConfigRequest,
		Identifier: ipcp.identifier,
		Data:       SerializeLCPOptions(opts),
	}

	ipcp.sendPacket(ProtocolIPCP, pkt.Serialize())
	ipcp.startTimer()
	ipcp.restartCount--
}

// sendTerminateRequest sends an IPCP Terminate-Request
func (ipcp *IPCPStateMachine) sendTerminateRequest(reason string) {
	ipcp.identifier++

	pkt := &LCPPacket{
		Code:       LCPCodeTermRequest,
		Identifier: ipcp.identifier,
		Data:       []byte(reason),
	}

	ipcp.sendPacket(ProtocolIPCP, pkt.Serialize())
	ipcp.startTimer()
	ipcp.restartCount--
}

// sendTerminateAck sends an IPCP Terminate-Ack
func (ipcp *IPCPStateMachine) sendTerminateAck(identifier uint8) {
	pkt := &LCPPacket{
		Code:       LCPCodeTermAck,
		Identifier: identifier,
	}

	ipcp.sendPacket(ProtocolIPCP, pkt.Serialize())
}

// Timer management

func (ipcp *IPCPStateMachine) initializeRestartCount() {
	ipcp.restartCount = ipcp.config.MaxRetransmit
	if ipcp.restartCount == 0 {
		ipcp.restartCount = 10
	}
}

func (ipcp *IPCPStateMachine) zeroRestartCount() {
	ipcp.restartCount = 0
}

func (ipcp *IPCPStateMachine) startTimer() {
	ipcp.timerMu.Lock()
	defer ipcp.timerMu.Unlock()

	if ipcp.restartTimer != nil {
		ipcp.restartTimer.Stop()
	}

	timeout := ipcp.config.RestartTimer
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	ipcp.restartTimer = time.AfterFunc(timeout, func() {
		ipcp.timeout()
	})
}

func (ipcp *IPCPStateMachine) stopTimer() {
	ipcp.timerMu.Lock()
	defer ipcp.timerMu.Unlock()

	if ipcp.restartTimer != nil {
		ipcp.restartTimer.Stop()
		ipcp.restartTimer = nil
	}
}

func (ipcp *IPCPStateMachine) timeout() {
	ipcp.mu.Lock()
	defer ipcp.mu.Unlock()

	if ipcp.restartCount > 0 {
		switch ipcp.state {
		case IPCPStateClosing, IPCPStateStopping:
			ipcp.sendTerminateRequest("Timeout")
		case IPCPStateReqSent, IPCPStateAckRcvd, IPCPStateAckSent:
			ipcp.sendConfigureRequest()
		}
	} else {
		switch ipcp.state {
		case IPCPStateClosing:
			ipcp.setState(IPCPStateClosed)
		case IPCPStateStopping:
			ipcp.setState(IPCPStateStopped)
		case IPCPStateReqSent, IPCPStateAckRcvd, IPCPStateAckSent:
			ipcp.setState(IPCPStateStopped)
		}
	}
}

// IsOpened returns true if IPCP is in the Opened state
func (ipcp *IPCPStateMachine) IsOpened() bool {
	ipcp.mu.RLock()
	defer ipcp.mu.RUnlock()
	return ipcp.state == IPCPStateOpened
}
