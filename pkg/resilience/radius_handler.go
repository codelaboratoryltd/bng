package resilience

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// RADIUSAuthenticator provides RADIUS authentication functionality.
type RADIUSAuthenticator interface {
	// Authenticate performs RADIUS authentication.
	Authenticate(ctx context.Context, mac net.HardwareAddr, username string) (*AuthResult, error)
	// SendAccounting sends a RADIUS accounting record.
	SendAccounting(ctx context.Context, record *AccountingRecord) error
	// IsReachable checks if RADIUS server is reachable.
	IsReachable(ctx context.Context) bool
}

// AuthResult represents a RADIUS authentication result.
type AuthResult struct {
	Success         bool
	SubscriberID    string
	ISPID           string
	QoSPolicyID     string
	DownloadRateBps uint64
	UploadRateBps   uint64
	IPv4PoolID      string
	IPv6PoolID      string
	SessionTimeout  time.Duration
	IdleTimeout     time.Duration
	Error           string
}

// AccountingRecord represents a RADIUS accounting record.
type AccountingRecord struct {
	SessionID      string
	MAC            net.HardwareAddr
	FramedIP       net.IP
	StatusType     int // 1=Start, 2=Stop, 3=Interim
	InputOctets    uint64
	OutputOctets   uint64
	SessionTime    uint32
	TerminateCause uint32
}

// RADIUSHandler manages RADIUS resilience during network partitions.
type RADIUSHandler struct {
	config        PartitionConfig
	logger        *zap.Logger
	authenticator RADIUSAuthenticator

	mu sync.RWMutex

	// Profile cache for degraded mode authentication
	profileCache map[string]*CachedProfile // MAC or SubscriberID -> profile

	// Degraded sessions needing re-authentication
	degradedSessions map[string]*DegradedSession // SessionID -> session

	// Re-authentication queue
	reauthQueue []*DegradedSession

	// Accounting buffer
	acctBuffer      []*BufferedAcctRecord
	acctBufferLimit int

	// Statistics
	degradedAuthsIssued int64
	reauthsCompleted    int64
	reauthsFailed       int64
	acctRecordsBuffered int64
	acctRecordsSynced   int64
	acctRecordsDropped  int64
}

// NewRADIUSHandler creates a new RADIUS handler.
func NewRADIUSHandler(config PartitionConfig, logger *zap.Logger) *RADIUSHandler {
	return &RADIUSHandler{
		config:           config,
		logger:           logger,
		profileCache:     make(map[string]*CachedProfile),
		degradedSessions: make(map[string]*DegradedSession),
		acctBuffer:       make([]*BufferedAcctRecord, 0, config.AccountingBufferSize),
		acctBufferLimit:  config.AccountingBufferSize,
	}
}

// SetAuthenticator sets the RADIUS authenticator.
func (h *RADIUSHandler) SetAuthenticator(auth RADIUSAuthenticator) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authenticator = auth
}

// CacheProfile caches a subscriber profile for degraded mode.
func (h *RADIUSHandler) CacheProfile(profile *CachedProfile) {
	h.mu.Lock()
	defer h.mu.Unlock()

	profile.CachedAt = time.Now()
	profile.LastVerified = time.Now()
	h.profileCache[profile.SubscriberID] = profile

	h.logger.Debug("Cached subscriber profile",
		zap.String("subscriber_id", profile.SubscriberID),
		zap.String("isp_id", profile.ISPID),
	)
}

// GetCachedProfile returns a cached profile if valid.
func (h *RADIUSHandler) GetCachedProfile(subscriberID string) (*CachedProfile, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	profile, ok := h.profileCache[subscriberID]
	if !ok {
		return nil, false
	}

	// Check TTL
	if time.Since(profile.CachedAt) > h.config.CachedProfileTTL {
		return nil, false
	}

	return profile, true
}

// AuthenticateDegraded performs degraded mode authentication using cached profile.
func (h *RADIUSHandler) AuthenticateDegraded(mac net.HardwareAddr, subscriberID string) (*DegradedSession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Try to find cached profile
	profile, ok := h.profileCache[subscriberID]
	if !ok {
		h.logger.Warn("No cached profile for degraded auth",
			zap.String("subscriber_id", subscriberID),
			zap.String("mac", mac.String()),
		)
		return nil, &NoCachedProfileError{SubscriberID: subscriberID}
	}

	// Check TTL
	if time.Since(profile.CachedAt) > h.config.CachedProfileTTL {
		h.logger.Warn("Cached profile expired for degraded auth",
			zap.String("subscriber_id", subscriberID),
			zap.Duration("age", time.Since(profile.CachedAt)),
		)
		return nil, &ProfileExpiredError{SubscriberID: subscriberID}
	}

	// Create degraded session
	session := &DegradedSession{
		SessionID:       uuid.New().String(),
		MAC:             mac,
		SubscriberID:    subscriberID,
		AuthenticatedAt: time.Now(),
		CachedProfile:   profile,
		NeedsReauth:     true,
	}

	h.degradedSessions[session.SessionID] = session
	h.degradedAuthsIssued++

	h.logger.Info("Issued degraded mode authentication",
		zap.String("session_id", session.SessionID),
		zap.String("subscriber_id", subscriberID),
		zap.String("mac", mac.String()),
		zap.String("isp_id", profile.ISPID),
	)

	return session, nil
}

// GetDegradedSessions returns all sessions needing re-authentication.
func (h *RADIUSHandler) GetDegradedSessions() []*DegradedSession {
	h.mu.RLock()
	defer h.mu.RUnlock()

	sessions := make([]*DegradedSession, 0, len(h.degradedSessions))
	for _, session := range h.degradedSessions {
		if session.NeedsReauth {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// GetDegradedSession returns a specific degraded session.
func (h *RADIUSHandler) GetDegradedSession(sessionID string) (*DegradedSession, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	session, ok := h.degradedSessions[sessionID]
	return session, ok
}

// QueueReauth queues a session for re-authentication.
func (h *RADIUSHandler) QueueReauth(session *DegradedSession) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.reauthQueue = append(h.reauthQueue, session)
	h.logger.Debug("Queued session for re-auth",
		zap.String("session_id", session.SessionID),
		zap.String("mac", session.MAC.String()),
	)
}

// ProcessReauths processes re-authentication queue with rate limiting.
func (h *RADIUSHandler) ProcessReauths(ctx context.Context, rateLimit int) (completed, failed int) {
	h.mu.Lock()
	auth := h.authenticator
	queue := h.reauthQueue
	h.reauthQueue = nil
	h.mu.Unlock()

	if auth == nil {
		h.logger.Warn("No authenticator configured, cannot process re-auths")
		return 0, len(queue)
	}

	// Create rate limiter
	limiter := rate.NewLimiter(rate.Limit(rateLimit), rateLimit)

	for _, session := range queue {
		select {
		case <-ctx.Done():
			// Re-queue remaining
			h.mu.Lock()
			h.reauthQueue = append(h.reauthQueue, queue[completed:]...)
			h.mu.Unlock()
			return completed, failed
		default:
		}

		// Wait for rate limiter
		if err := limiter.Wait(ctx); err != nil {
			continue
		}

		// Perform re-authentication
		result, err := auth.Authenticate(ctx, session.MAC, session.SubscriberID)
		if err != nil {
			h.logger.Warn("Re-authentication failed",
				zap.String("session_id", session.SessionID),
				zap.Error(err),
			)
			session.ReauthAttempts++
			failed++

			// Re-queue if not too many attempts
			if session.ReauthAttempts < 3 {
				h.QueueReauth(session)
			}
			continue
		}

		if !result.Success {
			h.logger.Warn("Re-authentication rejected",
				zap.String("session_id", session.SessionID),
				zap.String("error", result.Error),
			)
			failed++
			continue
		}

		// Update session
		h.mu.Lock()
		session.NeedsReauth = false
		delete(h.degradedSessions, session.SessionID)

		// Update cached profile with verified data
		if session.CachedProfile != nil {
			session.CachedProfile.LastVerified = time.Now()
		}
		h.mu.Unlock()

		completed++
		h.logger.Info("Re-authentication successful",
			zap.String("session_id", session.SessionID),
			zap.String("subscriber_id", session.SubscriberID),
		)
	}

	h.mu.Lock()
	h.reauthsCompleted += int64(completed)
	h.reauthsFailed += int64(failed)
	h.mu.Unlock()

	return completed, failed
}

// BufferAccounting buffers an accounting record during partition.
func (h *RADIUSHandler) BufferAccounting(record *BufferedAcctRecord) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check buffer capacity
	if len(h.acctBuffer) >= h.acctBufferLimit {
		h.acctRecordsDropped++
		h.logger.Warn("Accounting buffer full, dropping record",
			zap.String("session_id", record.SessionID),
		)
		return &BufferFullError{Limit: h.acctBufferLimit}
	}

	// Generate ID if not set
	if record.ID == "" {
		record.ID = uuid.New().String()
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}

	h.acctBuffer = append(h.acctBuffer, record)
	h.acctRecordsBuffered++

	h.logger.Debug("Buffered accounting record",
		zap.String("id", record.ID),
		zap.String("session_id", record.SessionID),
		zap.Int("status_type", record.StatusType),
	)

	return nil
}

// SyncBufferedAccounting syncs buffered accounting records to RADIUS.
func (h *RADIUSHandler) SyncBufferedAccounting(ctx context.Context, batchSize int) int {
	h.mu.Lock()
	auth := h.authenticator
	buffer := h.acctBuffer
	h.acctBuffer = nil
	h.mu.Unlock()

	if auth == nil {
		h.logger.Warn("No authenticator configured, cannot sync accounting")
		return 0
	}

	synced := 0
	failed := 0

	for i, record := range buffer {
		select {
		case <-ctx.Done():
			// Re-buffer remaining
			h.mu.Lock()
			h.acctBuffer = append(h.acctBuffer, buffer[i:]...)
			h.mu.Unlock()
			return synced
		default:
		}

		// Convert to AccountingRecord
		acctRecord := &AccountingRecord{
			SessionID:      record.SessionID,
			MAC:            record.MAC,
			FramedIP:       record.FramedIP,
			StatusType:     record.StatusType,
			InputOctets:    record.InputOctets,
			OutputOctets:   record.OutputOctets,
			SessionTime:    record.SessionTime,
			TerminateCause: record.TerminateCause,
		}

		if err := auth.SendAccounting(ctx, acctRecord); err != nil {
			h.logger.Warn("Failed to sync accounting record",
				zap.String("id", record.ID),
				zap.Error(err),
			)
			record.SyncAttempts++
			record.LastAttempt = time.Now()

			// Re-buffer if not too many attempts
			if record.SyncAttempts < 3 {
				h.mu.Lock()
				h.acctBuffer = append(h.acctBuffer, record)
				h.mu.Unlock()
			} else {
				h.mu.Lock()
				h.acctRecordsDropped++
				h.mu.Unlock()
			}
			failed++
			continue
		}

		synced++

		// Pause between batches
		if synced%batchSize == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	h.mu.Lock()
	h.acctRecordsSynced += int64(synced)
	h.mu.Unlock()

	h.logger.Info("Synced buffered accounting records",
		zap.Int("synced", synced),
		zap.Int("failed", failed),
	)

	return synced
}

// GetBufferedAccountingCount returns the number of buffered accounting records.
func (h *RADIUSHandler) GetBufferedAccountingCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.acctBuffer)
}

// Stats returns RADIUS handler statistics.
func (h *RADIUSHandler) Stats() (degradedAuths, reauthsCompleted, reauthsFailed, acctBuffered, acctSynced, acctDropped int64) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.degradedAuthsIssued, h.reauthsCompleted, h.reauthsFailed,
		h.acctRecordsBuffered, h.acctRecordsSynced, h.acctRecordsDropped
}

// ClearDegradedSession removes a degraded session (e.g., when session ends).
func (h *RADIUSHandler) ClearDegradedSession(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.degradedSessions, sessionID)
}

// MarkSessionReauthenticated marks a session as successfully re-authenticated.
func (h *RADIUSHandler) MarkSessionReauthenticated(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if session, ok := h.degradedSessions[sessionID]; ok {
		session.NeedsReauth = false
	}
}

// GetReauthQueueLength returns the number of sessions queued for re-auth.
func (h *RADIUSHandler) GetReauthQueueLength() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.reauthQueue)
}

// GetCachedProfileCount returns the number of cached profiles.
func (h *RADIUSHandler) GetCachedProfileCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.profileCache)
}

// PurgeCachedProfile removes a cached profile.
func (h *RADIUSHandler) PurgeCachedProfile(subscriberID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.profileCache, subscriberID)
}

// PurgeExpiredProfiles removes expired cached profiles.
func (h *RADIUSHandler) PurgeExpiredProfiles() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	purged := 0
	now := time.Now()

	for id, profile := range h.profileCache {
		if now.Sub(profile.CachedAt) > h.config.CachedProfileTTL {
			delete(h.profileCache, id)
			purged++
		}
	}

	if purged > 0 {
		h.logger.Info("Purged expired cached profiles", zap.Int("count", purged))
	}

	return purged
}

// Error types

// NoCachedProfileError indicates no cached profile was found.
type NoCachedProfileError struct {
	SubscriberID string
}

func (e *NoCachedProfileError) Error() string {
	return "no cached profile for subscriber: " + e.SubscriberID
}

// ProfileExpiredError indicates the cached profile has expired.
type ProfileExpiredError struct {
	SubscriberID string
}

func (e *ProfileExpiredError) Error() string {
	return "cached profile expired for subscriber: " + e.SubscriberID
}

// BufferFullError indicates the accounting buffer is full.
type BufferFullError struct {
	Limit int
}

func (e *BufferFullError) Error() string {
	return "accounting buffer full"
}
