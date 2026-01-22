// Package pppoe implements PPPoE protocol handling for the BNG.
// This file implements graceful session teardown per RFC 2516 and RFC 1661.
package pppoe

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/radius"
	"go.uber.org/zap"
)

// TerminateCause represents the reason for session termination (RFC 2866)
type TerminateCause uint32

const (
	TerminateCauseUserRequest    TerminateCause = 1  // Client initiated
	TerminateCauseLostCarrier    TerminateCause = 2  // Connection lost
	TerminateCauseLostService    TerminateCause = 3  // Service unavailable
	TerminateCauseIdleTimeout    TerminateCause = 4  // No activity
	TerminateCauseSessionTimeout TerminateCause = 5  // Max session time
	TerminateCauseAdminReset     TerminateCause = 6  // Operator initiated
	TerminateCauseAdminReboot    TerminateCause = 7  // System reboot
	TerminateCausePortError      TerminateCause = 8  // Interface error
	TerminateCauseNASError       TerminateCause = 9  // BNG error
	TerminateCauseNASRequest     TerminateCause = 10 // BNG initiated
	TerminateCauseNASReboot      TerminateCause = 11 // BNG reboot
	TerminateCausePortUnneeded   TerminateCause = 12 // Port no longer needed
	TerminateCausePortPreempted  TerminateCause = 13 // Port preempted
	TerminateCausePortSuspended  TerminateCause = 14 // Port suspended
	TerminateCauseServiceUnavail TerminateCause = 15 // Service unavailable
	TerminateCauseCallback       TerminateCause = 16 // Callback
	TerminateCauseUserError      TerminateCause = 17 // User error
	TerminateCauseHostRequest    TerminateCause = 18 // Host request
)

func (c TerminateCause) String() string {
	switch c {
	case TerminateCauseUserRequest:
		return "User-Request"
	case TerminateCauseLostCarrier:
		return "Lost-Carrier"
	case TerminateCauseLostService:
		return "Lost-Service"
	case TerminateCauseIdleTimeout:
		return "Idle-Timeout"
	case TerminateCauseSessionTimeout:
		return "Session-Timeout"
	case TerminateCauseAdminReset:
		return "Admin-Reset"
	case TerminateCauseAdminReboot:
		return "Admin-Reboot"
	case TerminateCausePortError:
		return "Port-Error"
	case TerminateCauseNASError:
		return "NAS-Error"
	case TerminateCauseNASRequest:
		return "NAS-Request"
	case TerminateCauseNASReboot:
		return "NAS-Reboot"
	case TerminateCausePortUnneeded:
		return "Port-Unneeded"
	case TerminateCausePortPreempted:
		return "Port-Preempted"
	case TerminateCausePortSuspended:
		return "Port-Suspended"
	case TerminateCauseServiceUnavail:
		return "Service-Unavailable"
	case TerminateCauseCallback:
		return "Callback"
	case TerminateCauseUserError:
		return "User-Error"
	case TerminateCauseHostRequest:
		return "Host-Request"
	default:
		return "Unknown"
	}
}

// SessionStats holds session statistics for RADIUS accounting
type SessionStats struct {
	SessionTime   uint32 // Session duration in seconds
	InputOctets   uint64 // Bytes received from client
	OutputOctets  uint64 // Bytes sent to client
	InputPackets  uint64 // Packets received from client
	OutputPackets uint64 // Packets sent to client
}

// TeardownConfig holds teardown configuration
type TeardownConfig struct {
	LCPTermTimeout time.Duration // Timeout for LCP Terminate-Ack (default: 3s)
	PADTRetries    int           // Number of PADT retries (default: 1)
	PADTRetryDelay time.Duration // Delay between PADT retries (default: 1s)
	CleanupTimeout time.Duration // Overall cleanup timeout (default: 10s)
	RADIUSTimeout  time.Duration // RADIUS accounting timeout (default: 5s)
}

// DefaultTeardownConfig returns default teardown configuration
func DefaultTeardownConfig() TeardownConfig {
	return TeardownConfig{
		LCPTermTimeout: 3 * time.Second,
		PADTRetries:    1,
		PADTRetryDelay: 1 * time.Second,
		CleanupTimeout: 10 * time.Second,
		RADIUSTimeout:  5 * time.Second,
	}
}

// SessionTeardown handles graceful session termination
type SessionTeardown struct {
	config TeardownConfig
	logger *zap.Logger

	// Dependencies
	radiusClient *radius.Client
	ipPool       IPPoolAllocator
	sessions     *SessionManager

	// Callbacks
	sendPADT       func(session *Session, tags []Tag)
	sendLCPTermReq func(session *Session, reason string)
	updateEBPFMaps func(session *Session, remove bool) error

	mu sync.Mutex
}

// NewSessionTeardown creates a new session teardown handler
func NewSessionTeardown(config TeardownConfig, logger *zap.Logger) *SessionTeardown {
	return &SessionTeardown{
		config: config,
		logger: logger,
	}
}

// SetRADIUSClient sets the RADIUS client for accounting
func (t *SessionTeardown) SetRADIUSClient(client *radius.Client) {
	t.radiusClient = client
}

// SetIPPool sets the IP pool for address release
func (t *SessionTeardown) SetIPPool(pool IPPoolAllocator) {
	t.ipPool = pool
}

// SetSessionManager sets the session manager
func (t *SessionTeardown) SetSessionManager(manager *SessionManager) {
	t.sessions = manager
}

// SetSendPADT sets the callback for sending PADT
func (t *SessionTeardown) SetSendPADT(callback func(*Session, []Tag)) {
	t.sendPADT = callback
}

// SetSendLCPTermReq sets the callback for sending LCP Terminate-Request
func (t *SessionTeardown) SetSendLCPTermReq(callback func(*Session, string)) {
	t.sendLCPTermReq = callback
}

// SetUpdateEBPFMaps sets the callback for updating eBPF maps
func (t *SessionTeardown) SetUpdateEBPFMaps(callback func(*Session, bool) error) {
	t.updateEBPFMaps = callback
}

// HandleClientPADT processes a PADT received from the client
func (t *SessionTeardown) HandleClientPADT(session *Session, clientMAC net.HardwareAddr, sessionID uint16) error {
	t.logger.Info("Client-initiated session termination",
		zap.Uint16("session_id", sessionID),
		zap.String("client_mac", clientMAC.String()),
		zap.String("username", session.Username),
	)

	// Validate session
	if session.ClientMAC.String() != clientMAC.String() {
		t.logger.Warn("PADT MAC mismatch",
			zap.String("expected", session.ClientMAC.String()),
			zap.String("received", clientMAC.String()),
		)
		return nil // Silently ignore invalid PADT
	}

	// Do NOT send PADT in response - client already terminated
	// Proceed directly to cleanup
	return t.cleanup(session, TerminateCauseUserRequest)
}

// TerminateSession initiates server-side session termination
func (t *SessionTeardown) TerminateSession(session *Session, cause TerminateCause, errorMessage string) error {
	t.logger.Info("Server-initiated session termination",
		zap.Uint16("session_id", session.ID),
		zap.String("username", session.Username),
		zap.String("cause", cause.String()),
	)

	// Update session state
	session.SetState(StateTerminating)

	// Try graceful LCP termination first
	if t.sendLCPTermReq != nil && session.GetState() == StateEstablished {
		t.sendLCPTermReq(session, cause.String())

		// Wait for Terminate-Ack with timeout
		if !t.waitForLCPTermAck(session) {
			t.logger.Debug("LCP Terminate-Ack timeout, proceeding to PADT",
				zap.Uint16("session_id", session.ID),
			)
		}
	}

	// Send PADT
	if t.sendPADT != nil {
		var tags []Tag

		// Add error tag if there's an error message
		if errorMessage != "" {
			tags = append(tags, Tag{
				Type:  TagGenericErr,
				Value: []byte(errorMessage),
			})
		}

		// Try to send PADT with retries
		for i := 0; i <= t.config.PADTRetries; i++ {
			t.sendPADT(session, tags)

			if i < t.config.PADTRetries {
				time.Sleep(t.config.PADTRetryDelay)
			}
		}
	}

	// Cleanup
	return t.cleanup(session, cause)
}

// waitForLCPTermAck waits for LCP Terminate-Ack with timeout
func (t *SessionTeardown) waitForLCPTermAck(session *Session) bool {
	// Simple timeout-based wait
	// In a real implementation, this would use a channel/callback
	deadline := time.Now().Add(t.config.LCPTermTimeout)

	for time.Now().Before(deadline) {
		if session.GetState() == StateClosed {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}

	return false
}

// cleanup performs all resource cleanup for a session
func (t *SessionTeardown) cleanup(session *Session, cause TerminateCause) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), t.config.CleanupTimeout)
	defer cancel()

	// Gather statistics before cleanup
	stats := t.gatherStats(session)

	// 1. Update eBPF maps (remove subscriber entry)
	if t.updateEBPFMaps != nil {
		if err := t.updateEBPFMaps(session, true); err != nil {
			t.logger.Error("Failed to update eBPF maps",
				zap.Uint16("session_id", session.ID),
				zap.Error(err),
			)
			// Continue cleanup even if eBPF update fails
		}
	}

	// 2. Send RADIUS Accounting-Stop
	if t.radiusClient != nil && session.Authenticated {
		t.sendAccountingStop(ctx, session, cause, stats)
	}

	// 3. Release IP address back to pool
	if t.ipPool != nil && session.ClientIP != nil {
		t.ipPool.Release(session.SessionID)
		t.logger.Debug("Released IP address",
			zap.Uint16("session_id", session.ID),
			zap.String("ip", session.ClientIP.String()),
		)
	}

	// 4. Update session state
	session.SetState(StateClosed)

	// 5. Remove from session manager
	if t.sessions != nil {
		t.sessions.RemoveSession(session.ID)
	}

	t.logger.Info("Session cleanup complete",
		zap.Uint16("session_id", session.ID),
		zap.String("username", session.Username),
		zap.Duration("duration", session.Duration()),
		zap.Uint64("bytes_in", stats.InputOctets),
		zap.Uint64("bytes_out", stats.OutputOctets),
	)

	return nil
}

// gatherStats gathers session statistics
func (t *SessionTeardown) gatherStats(session *Session) SessionStats {
	duration := session.Duration()
	if duration < 0 {
		duration = 0
	}

	return SessionStats{
		SessionTime:   uint32(duration.Seconds()),
		InputOctets:   session.BytesIn,
		OutputOctets:  session.BytesOut,
		InputPackets:  session.PacketsIn,
		OutputPackets: session.PacketsOut,
	}
}

// sendAccountingStop sends RADIUS Accounting-Stop
func (t *SessionTeardown) sendAccountingStop(ctx context.Context, session *Session, cause TerminateCause, stats SessionStats) {
	acctCtx, cancel := context.WithTimeout(ctx, t.config.RADIUSTimeout)
	defer cancel()

	err := t.radiusClient.SendAccounting(acctCtx, &radius.AcctRequest{
		SessionID:      session.SessionID,
		Username:       session.Username,
		MAC:            session.ClientMAC,
		FramedIP:       session.ClientIP,
		StatusType:     radius.AcctStatusStop,
		InputOctets:    stats.InputOctets,
		OutputOctets:   stats.OutputOctets,
		InputPackets:   stats.InputPackets,
		OutputPackets:  stats.OutputPackets,
		SessionTime:    stats.SessionTime,
		TerminateCause: uint32(cause),
		Class:          session.Class,
	})

	if err != nil {
		t.logger.Error("Failed to send RADIUS Accounting-Stop",
			zap.Uint16("session_id", session.ID),
			zap.Error(err),
		)
	} else {
		t.logger.Debug("RADIUS Accounting-Stop sent",
			zap.Uint16("session_id", session.ID),
			zap.Uint32("session_time", stats.SessionTime),
		)
	}
}

// TerminateByID terminates a session by ID (admin action)
func (t *SessionTeardown) TerminateByID(sessionID uint16, reason string) error {
	if t.sessions == nil {
		return nil
	}

	session := t.sessions.GetSession(sessionID)
	if session == nil {
		return nil
	}

	return t.TerminateSession(session, TerminateCauseAdminReset, reason)
}

// TerminateByMAC terminates a session by MAC address (admin action)
func (t *SessionTeardown) TerminateByMAC(mac net.HardwareAddr, reason string) error {
	if t.sessions == nil {
		return nil
	}

	session := t.sessions.GetSessionByMAC(mac)
	if session == nil {
		return nil
	}

	return t.TerminateSession(session, TerminateCauseAdminReset, reason)
}

// TerminateByUsername terminates all sessions for a username (admin action)
func (t *SessionTeardown) TerminateByUsername(username string, reason string) int {
	if t.sessions == nil {
		return 0
	}

	count := 0
	for _, session := range t.sessions.GetAllSessions() {
		if session.Username == username {
			t.TerminateSession(session, TerminateCauseAdminReset, reason)
			count++
		}
	}

	return count
}

// TerminateAll terminates all sessions (for maintenance/shutdown)
func (t *SessionTeardown) TerminateAll(cause TerminateCause, reason string) int {
	if t.sessions == nil {
		return 0
	}

	sessions := t.sessions.GetAllSessions()
	count := len(sessions)

	for _, session := range sessions {
		t.TerminateSession(session, cause, reason)
	}

	t.logger.Info("Terminated all sessions",
		zap.Int("count", count),
		zap.String("cause", cause.String()),
	)

	return count
}

// PADT Error Tags

// BuildPADTErrorTags builds error tags for PADT
func BuildPADTErrorTags(errType uint16, message string) []Tag {
	var tags []Tag

	if message != "" {
		tags = append(tags, Tag{
			Type:  errType,
			Value: []byte(message),
		})
	}

	return tags
}

// BuildGenericErrorTag builds a Generic-Error tag
func BuildGenericErrorTag(message string) Tag {
	return Tag{
		Type:  TagGenericErr,
		Value: []byte(message),
	}
}

// BuildServiceNameErrorTag builds a Service-Name-Error tag
func BuildServiceNameErrorTag(message string) Tag {
	return Tag{
		Type:  TagServiceNameErr,
		Value: []byte(message),
	}
}

// BuildACSystemErrorTag builds an AC-System-Error tag
func BuildACSystemErrorTag(message string) Tag {
	return Tag{
		Type:  TagACSystemErr,
		Value: []byte(message),
	}
}

// SerializePADT creates a PADT packet
func SerializePADT(sessionID uint16, tags []Tag) []byte {
	tagData := SerializeTags(tags)

	hdr := &PPPoEHeader{
		VerType:   0x11,
		Code:      CodePADT,
		SessionID: sessionID,
		Length:    uint16(len(tagData)),
	}

	return append(hdr.Serialize(), tagData...)
}

// ParsePADT parses a PADT packet
func ParsePADT(data []byte) (sessionID uint16, tags []Tag, err error) {
	hdr, err := ParsePPPoEHeader(data)
	if err != nil {
		return 0, nil, err
	}

	if hdr.Code != CodePADT {
		return 0, nil, nil
	}

	if len(data) > 6 {
		tags, err = ParseTags(data[6 : 6+int(hdr.Length)])
		if err != nil {
			return 0, nil, err
		}
	}

	return hdr.SessionID, tags, nil
}

// LCP Terminate packet builders

// SerializeLCPTerminateRequest creates an LCP Terminate-Request packet
func SerializeLCPTerminateRequest(identifier uint8, reason string) []byte {
	data := []byte(reason)
	length := uint16(4 + len(data))

	pkt := make([]byte, length)
	pkt[0] = LCPCodeTermRequest
	pkt[1] = identifier
	binary.BigEndian.PutUint16(pkt[2:4], length)
	copy(pkt[4:], data)

	return pkt
}

// SerializeLCPTerminateAck creates an LCP Terminate-Ack packet
func SerializeLCPTerminateAck(identifier uint8) []byte {
	pkt := make([]byte, 4)
	pkt[0] = LCPCodeTermAck
	pkt[1] = identifier
	binary.BigEndian.PutUint16(pkt[2:4], 4)

	return pkt
}
