package radius

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// CoAProcessor handles CoA and Disconnect-Request processing with
// proper session management integration, eBPF map updates, and audit logging.
type CoAProcessor struct {
	logger            *zap.Logger
	accountingManager *AccountingManager

	// Callbacks for session operations
	sessionLookupByID    SessionLookupFunc
	sessionLookupByIP    SessionLookupByIPFunc
	sessionLookupByMAC   SessionLookupByMACFunc
	sessionTerminator    SessionTerminatorFunc
	sessionPolicyUpdater SessionPolicyUpdaterFunc
	ebpfQoSUpdater       EBPFQoSUpdaterFunc

	// Audit logging
	auditLogger AuditLogger

	// Statistics
	coaProcessed     uint64
	coaSucceeded     uint64
	coaFailed        uint64
	disconnProcessed uint64
	disconnSucceeded uint64
	disconnFailed    uint64
	policyUpdates    uint64
	processingTimeNs uint64
	processingCount  uint64

	mu sync.RWMutex
}

// SessionLookupFunc looks up a session by ID
type SessionLookupFunc func(sessionID string) (*SessionInfo, bool)

// SessionLookupByIPFunc looks up a session by IP address
type SessionLookupByIPFunc func(ip net.IP) (*SessionInfo, bool)

// SessionLookupByMACFunc looks up a session by MAC address
type SessionLookupByMACFunc func(mac string) (*SessionInfo, bool)

// SessionTerminatorFunc terminates a session
type SessionTerminatorFunc func(ctx context.Context, sessionID string, reason uint32) error

// SessionPolicyUpdaterFunc updates session policy
type SessionPolicyUpdaterFunc func(ctx context.Context, sessionID string, update *PolicyUpdate) error

// EBPFQoSUpdaterFunc updates QoS in eBPF maps
type EBPFQoSUpdaterFunc func(sessionID string, downloadBPS, uploadBPS uint64) error

// AuditLogger logs CoA operations for compliance
type AuditLogger interface {
	LogCoARequest(req *CoARequest, response *CoAResponse, duration time.Duration)
	LogDisconnectRequest(req *DisconnectRequest, response *DisconnectResponse, duration time.Duration)
}

// SessionInfo contains session information for CoA processing
type SessionInfo struct {
	SessionID       string
	Username        string
	MAC             net.HardwareAddr
	FramedIP        net.IP
	State           string
	QoSPolicyID     string
	DownloadRateBPS uint64
	UploadRateBPS   uint64
	SessionTimeout  time.Duration
	IdleTimeout     time.Duration
}

// PolicyUpdate contains policy changes to apply
type PolicyUpdate struct {
	FilterID        string        // QoS policy name
	DownloadRateBPS uint64        // Download rate in bits/sec (0 = no change)
	UploadRateBPS   uint64        // Upload rate in bits/sec (0 = no change)
	SessionTimeout  time.Duration // New session timeout (0 = no change)
	IdleTimeout     time.Duration // New idle timeout (0 = no change)
}

// CoAProcessorConfig configures the CoA processor
type CoAProcessorConfig struct {
	// Timeout for policy application
	PolicyUpdateTimeout time.Duration

	// Allow operations without session ID if other identifiers present
	AllowSessionLookupByIP  bool
	AllowSessionLookupByMAC bool
}

// DefaultCoAProcessorConfig returns sensible defaults
func DefaultCoAProcessorConfig() CoAProcessorConfig {
	return CoAProcessorConfig{
		PolicyUpdateTimeout:     5 * time.Second,
		AllowSessionLookupByIP:  true,
		AllowSessionLookupByMAC: true,
	}
}

// NewCoAProcessor creates a new CoA processor
func NewCoAProcessor(logger *zap.Logger) *CoAProcessor {
	return &CoAProcessor{
		logger: logger,
	}
}

// SetAccountingManager sets the accounting manager for teardown accounting
func (p *CoAProcessor) SetAccountingManager(am *AccountingManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accountingManager = am
}

// SetSessionLookup sets the session lookup function
func (p *CoAProcessor) SetSessionLookup(fn SessionLookupFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessionLookupByID = fn
}

// SetSessionLookupByIP sets the session lookup by IP function
func (p *CoAProcessor) SetSessionLookupByIP(fn SessionLookupByIPFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessionLookupByIP = fn
}

// SetSessionLookupByMAC sets the session lookup by MAC function
func (p *CoAProcessor) SetSessionLookupByMAC(fn SessionLookupByMACFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessionLookupByMAC = fn
}

// SetSessionTerminator sets the session terminator function
func (p *CoAProcessor) SetSessionTerminator(fn SessionTerminatorFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessionTerminator = fn
}

// SetSessionPolicyUpdater sets the session policy updater function
func (p *CoAProcessor) SetSessionPolicyUpdater(fn SessionPolicyUpdaterFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessionPolicyUpdater = fn
}

// SetEBPFQoSUpdater sets the eBPF QoS updater function
func (p *CoAProcessor) SetEBPFQoSUpdater(fn EBPFQoSUpdaterFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ebpfQoSUpdater = fn
}

// SetAuditLogger sets the audit logger
func (p *CoAProcessor) SetAuditLogger(logger AuditLogger) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.auditLogger = logger
}

// HandleCoA handles a CoA request
func (p *CoAProcessor) HandleCoA(ctx context.Context, req *CoARequest) *CoAResponse {
	startTime := time.Now()
	atomic.AddUint64(&p.coaProcessed, 1)

	framedIPStr := ""
	if req.FramedIP != nil {
		framedIPStr = req.FramedIP.String()
	}

	p.logger.Info("Processing CoA request",
		zap.String("session_id", req.SessionID),
		zap.String("username", req.Username),
		zap.String("framed_ip", framedIPStr),
		zap.String("calling_station", req.CallingStation),
		zap.String("filter_id", req.FilterID),
	)

	// Find the session
	session, err := p.findSession(req)
	if err != nil {
		atomic.AddUint64(&p.coaFailed, 1)
		response := &CoAResponse{
			Success:    false,
			ErrorCause: ErrorCauseSessionContextNotFound,
			Message:    err.Error(),
		}
		p.logCoAOperation(req, response, time.Since(startTime))
		return response
	}

	// Build policy update from request
	update := p.buildPolicyUpdate(req)
	if update == nil {
		atomic.AddUint64(&p.coaFailed, 1)
		response := &CoAResponse{
			Success:    false,
			ErrorCause: ErrorCauseMissingAttribute,
			Message:    "No policy changes specified",
		}
		p.logCoAOperation(req, response, time.Since(startTime))
		return response
	}

	// Apply policy update
	if err := p.applyPolicyUpdate(ctx, session, update); err != nil {
		atomic.AddUint64(&p.coaFailed, 1)
		response := &CoAResponse{
			Success:    false,
			ErrorCause: ErrorCauseResourcesUnavailable,
			Message:    fmt.Sprintf("Failed to apply policy: %v", err),
		}
		p.logCoAOperation(req, response, time.Since(startTime))
		return response
	}

	atomic.AddUint64(&p.coaSucceeded, 1)
	atomic.AddUint64(&p.policyUpdates, 1)

	duration := time.Since(startTime)
	atomic.AddUint64(&p.processingTimeNs, uint64(duration.Nanoseconds()))
	atomic.AddUint64(&p.processingCount, 1)

	response := &CoAResponse{
		Success: true,
		Message: "Policy updated successfully",
	}
	p.logCoAOperation(req, response, duration)

	p.logger.Info("CoA request processed successfully",
		zap.String("session_id", session.SessionID),
		zap.Duration("duration", duration),
	)

	return response
}

// HandleDisconnect handles a Disconnect-Request
func (p *CoAProcessor) HandleDisconnect(ctx context.Context, req *DisconnectRequest) *DisconnectResponse {
	startTime := time.Now()
	atomic.AddUint64(&p.disconnProcessed, 1)

	disconnFramedIPStr := ""
	if req.FramedIP != nil {
		disconnFramedIPStr = req.FramedIP.String()
	}

	p.logger.Info("Processing Disconnect request",
		zap.String("session_id", req.SessionID),
		zap.String("username", req.Username),
		zap.String("framed_ip", disconnFramedIPStr),
		zap.String("calling_station", req.CallingStation),
	)

	// Find the session
	session, err := p.findSessionFromDisconnect(req)
	if err != nil {
		atomic.AddUint64(&p.disconnFailed, 1)
		response := &DisconnectResponse{
			Success:    false,
			ErrorCause: ErrorCauseSessionContextNotFound,
			Message:    err.Error(),
		}
		p.logDisconnectOperation(req, response, time.Since(startTime))
		return response
	}

	// Terminate the session
	if err := p.terminateSession(ctx, session.SessionID); err != nil {
		atomic.AddUint64(&p.disconnFailed, 1)
		response := &DisconnectResponse{
			Success:    false,
			ErrorCause: ErrorCauseSessionContextNotRemovable,
			Message:    fmt.Sprintf("Failed to terminate session: %v", err),
		}
		p.logDisconnectOperation(req, response, time.Since(startTime))
		return response
	}

	atomic.AddUint64(&p.disconnSucceeded, 1)

	duration := time.Since(startTime)
	atomic.AddUint64(&p.processingTimeNs, uint64(duration.Nanoseconds()))
	atomic.AddUint64(&p.processingCount, 1)

	response := &DisconnectResponse{
		Success: true,
		Message: "Session disconnected",
	}
	p.logDisconnectOperation(req, response, duration)

	p.logger.Info("Disconnect request processed successfully",
		zap.String("session_id", session.SessionID),
		zap.Duration("duration", duration),
	)

	return response
}

// findSession finds a session from a CoA request
func (p *CoAProcessor) findSession(req *CoARequest) (*SessionInfo, error) {
	p.mu.RLock()
	lookupByID := p.sessionLookupByID
	lookupByIP := p.sessionLookupByIP
	lookupByMAC := p.sessionLookupByMAC
	p.mu.RUnlock()

	// Try by session ID first
	if req.SessionID != "" && lookupByID != nil {
		if session, found := lookupByID(req.SessionID); found {
			return session, nil
		}
	}

	// Try by IP address
	if req.FramedIP != nil && lookupByIP != nil {
		if session, found := lookupByIP(req.FramedIP); found {
			return session, nil
		}
	}

	// Try by MAC address
	if req.CallingStation != "" && lookupByMAC != nil {
		if session, found := lookupByMAC(req.CallingStation); found {
			return session, nil
		}
	}

	return nil, fmt.Errorf("session not found for session_id=%s, ip=%v, mac=%s",
		req.SessionID, req.FramedIP, req.CallingStation)
}

// findSessionFromDisconnect finds a session from a Disconnect request
func (p *CoAProcessor) findSessionFromDisconnect(req *DisconnectRequest) (*SessionInfo, error) {
	p.mu.RLock()
	lookupByID := p.sessionLookupByID
	lookupByIP := p.sessionLookupByIP
	lookupByMAC := p.sessionLookupByMAC
	p.mu.RUnlock()

	// Try by session ID first
	if req.SessionID != "" && lookupByID != nil {
		if session, found := lookupByID(req.SessionID); found {
			return session, nil
		}
	}

	// Try by accounting session ID
	if req.AcctSessionID != "" && req.AcctSessionID != req.SessionID && lookupByID != nil {
		if session, found := lookupByID(req.AcctSessionID); found {
			return session, nil
		}
	}

	// Try by IP address
	if req.FramedIP != nil && lookupByIP != nil {
		if session, found := lookupByIP(req.FramedIP); found {
			return session, nil
		}
	}

	// Try by MAC address
	if req.CallingStation != "" && lookupByMAC != nil {
		if session, found := lookupByMAC(req.CallingStation); found {
			return session, nil
		}
	}

	return nil, fmt.Errorf("session not found for session_id=%s, acct_session_id=%s, ip=%v, mac=%s",
		req.SessionID, req.AcctSessionID, req.FramedIP, req.CallingStation)
}

// buildPolicyUpdate builds a PolicyUpdate from a CoA request
func (p *CoAProcessor) buildPolicyUpdate(req *CoARequest) *PolicyUpdate {
	update := &PolicyUpdate{}
	hasChanges := false

	if req.FilterID != "" {
		update.FilterID = req.FilterID
		hasChanges = true
	}

	if req.QoSDownload > 0 {
		update.DownloadRateBPS = uint64(req.QoSDownload) * 1000 // kbps to bps
		hasChanges = true
	}

	if req.QoSUpload > 0 {
		update.UploadRateBPS = uint64(req.QoSUpload) * 1000 // kbps to bps
		hasChanges = true
	}

	if req.SessionTimeout > 0 {
		update.SessionTimeout = time.Duration(req.SessionTimeout) * time.Second
		hasChanges = true
	}

	if req.IdleTimeout > 0 {
		update.IdleTimeout = time.Duration(req.IdleTimeout) * time.Second
		hasChanges = true
	}

	if !hasChanges {
		return nil
	}

	return update
}

// applyPolicyUpdate applies a policy update to a session
func (p *CoAProcessor) applyPolicyUpdate(ctx context.Context, session *SessionInfo, update *PolicyUpdate) error {
	p.mu.RLock()
	policyUpdater := p.sessionPolicyUpdater
	ebpfUpdater := p.ebpfQoSUpdater
	p.mu.RUnlock()

	// Update session in session manager
	if policyUpdater != nil {
		if err := policyUpdater(ctx, session.SessionID, update); err != nil {
			return fmt.Errorf("update session policy: %w", err)
		}
	}

	// Update eBPF maps for QoS
	if ebpfUpdater != nil && (update.DownloadRateBPS > 0 || update.UploadRateBPS > 0) {
		downloadBPS := update.DownloadRateBPS
		if downloadBPS == 0 {
			downloadBPS = session.DownloadRateBPS
		}
		uploadBPS := update.UploadRateBPS
		if uploadBPS == 0 {
			uploadBPS = session.UploadRateBPS
		}

		if err := ebpfUpdater(session.SessionID, downloadBPS, uploadBPS); err != nil {
			p.logger.Warn("Failed to update eBPF QoS, session policy updated but fast path not updated",
				zap.String("session_id", session.SessionID),
				zap.Error(err),
			)
			// Don't fail the CoA - the session policy was updated
		}
	}

	return nil
}

// terminateSession terminates a session with accounting
func (p *CoAProcessor) terminateSession(ctx context.Context, sessionID string) error {
	p.mu.RLock()
	terminator := p.sessionTerminator
	acctMgr := p.accountingManager
	p.mu.RUnlock()

	// Send Accounting-Stop first (CoA disconnect = NAS-Request terminate cause)
	if acctMgr != nil {
		if err := acctMgr.StopSession(sessionID, TerminateCauseNASRequest); err != nil {
			p.logger.Warn("Failed to send Accounting-Stop for disconnect",
				zap.String("session_id", sessionID),
				zap.Error(err),
			)
			// Continue with session termination even if accounting fails
		}
	}

	// Terminate the session
	if terminator != nil {
		if err := terminator(ctx, sessionID, TerminateCauseNASRequest); err != nil {
			return fmt.Errorf("terminate session: %w", err)
		}
	}

	return nil
}

// logCoAOperation logs a CoA operation for audit
func (p *CoAProcessor) logCoAOperation(req *CoARequest, response *CoAResponse, duration time.Duration) {
	p.mu.RLock()
	auditLogger := p.auditLogger
	p.mu.RUnlock()

	if auditLogger != nil {
		auditLogger.LogCoARequest(req, response, duration)
	}
}

// logDisconnectOperation logs a disconnect operation for audit
func (p *CoAProcessor) logDisconnectOperation(req *DisconnectRequest, response *DisconnectResponse, duration time.Duration) {
	p.mu.RLock()
	auditLogger := p.auditLogger
	p.mu.RUnlock()

	if auditLogger != nil {
		auditLogger.LogDisconnectRequest(req, response, duration)
	}
}

// GetStats returns CoA processor statistics
func (p *CoAProcessor) GetStats() CoAProcessorStats {
	count := atomic.LoadUint64(&p.processingCount)
	var avgProcessingMs float64
	if count > 0 {
		avgProcessingMs = float64(atomic.LoadUint64(&p.processingTimeNs)) / float64(count) / 1e6
	}

	return CoAProcessorStats{
		CoAProcessed:        atomic.LoadUint64(&p.coaProcessed),
		CoASucceeded:        atomic.LoadUint64(&p.coaSucceeded),
		CoAFailed:           atomic.LoadUint64(&p.coaFailed),
		DisconnectProcessed: atomic.LoadUint64(&p.disconnProcessed),
		DisconnectSucceeded: atomic.LoadUint64(&p.disconnSucceeded),
		DisconnectFailed:    atomic.LoadUint64(&p.disconnFailed),
		PolicyUpdates:       atomic.LoadUint64(&p.policyUpdates),
		AvgProcessingMs:     avgProcessingMs,
	}
}

// CoAProcessorStats holds CoA processor statistics
type CoAProcessorStats struct {
	CoAProcessed        uint64  `json:"coa_processed"`
	CoASucceeded        uint64  `json:"coa_succeeded"`
	CoAFailed           uint64  `json:"coa_failed"`
	DisconnectProcessed uint64  `json:"disconnect_processed"`
	DisconnectSucceeded uint64  `json:"disconnect_succeeded"`
	DisconnectFailed    uint64  `json:"disconnect_failed"`
	PolicyUpdates       uint64  `json:"policy_updates"`
	AvgProcessingMs     float64 `json:"avg_processing_ms"`
}

// DefaultAuditLogger is a simple audit logger that logs to zap
type DefaultAuditLogger struct {
	logger *zap.Logger
}

// NewDefaultAuditLogger creates a new default audit logger
func NewDefaultAuditLogger(logger *zap.Logger) *DefaultAuditLogger {
	return &DefaultAuditLogger{logger: logger}
}

// LogCoARequest logs a CoA request
func (l *DefaultAuditLogger) LogCoARequest(req *CoARequest, response *CoAResponse, duration time.Duration) {
	framedIPStr := ""
	if req.FramedIP != nil {
		framedIPStr = req.FramedIP.String()
	}

	l.logger.Info("AUDIT: CoA Request",
		zap.String("session_id", req.SessionID),
		zap.String("username", req.Username),
		zap.String("framed_ip", framedIPStr),
		zap.String("calling_station", req.CallingStation),
		zap.String("filter_id", req.FilterID),
		zap.Uint32("qos_download_kbps", req.QoSDownload),
		zap.Uint32("qos_upload_kbps", req.QoSUpload),
		zap.Uint32("session_timeout", req.SessionTimeout),
		zap.Uint32("idle_timeout", req.IdleTimeout),
		zap.Bool("success", response.Success),
		zap.Uint32("error_cause", response.ErrorCause),
		zap.String("message", response.Message),
		zap.Duration("duration", duration),
	)
}

// LogDisconnectRequest logs a Disconnect request
func (l *DefaultAuditLogger) LogDisconnectRequest(req *DisconnectRequest, response *DisconnectResponse, duration time.Duration) {
	framedIPStr := ""
	if req.FramedIP != nil {
		framedIPStr = req.FramedIP.String()
	}

	l.logger.Info("AUDIT: Disconnect Request",
		zap.String("session_id", req.SessionID),
		zap.String("acct_session_id", req.AcctSessionID),
		zap.String("username", req.Username),
		zap.String("framed_ip", framedIPStr),
		zap.String("calling_station", req.CallingStation),
		zap.Bool("success", response.Success),
		zap.Uint32("error_cause", response.ErrorCause),
		zap.String("message", response.Message),
		zap.Duration("duration", duration),
	)
}
