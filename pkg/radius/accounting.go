package radius

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// AccountingManager manages RADIUS accounting operations including
// interim updates, reliable stop accounting, and crash recovery.
type AccountingManager struct {
	client *Client
	logger *zap.Logger
	config AccountingConfig

	// Session tracking
	sessions   map[string]*AccountingSession
	sessionsMu sync.RWMutex

	// Pending accounting queue for reliability
	pendingQueue   chan *PendingAcctRecord
	pendingRecords map[string]*PendingAcctRecord
	pendingMu      sync.RWMutex

	// Statistics
	interimTotal      uint64
	interimFailed     uint64
	stopTotal         uint64
	stopFailed        uint64
	stopAbandoned     uint64
	stopRetries       uint64
	orphanedRecovered uint64
	pendingQueueDepth uint64

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Counter fetcher (callback to get session counters from eBPF)
	counterFetcher CounterFetcher

	// Persistence path
	persistPath string

	running int32
}

// AccountingConfig configures the accounting manager
type AccountingConfig struct {
	// Interim update settings
	DefaultInterimInterval time.Duration // Default interval for interim updates (default: 300s)
	InterimEnabled         bool          // Enable interim updates globally
	// TODO: BatchSize will be used in future for batching eBPF counter reads for efficiency
	BatchSize int // Number of counter reads to batch (default: 100)

	// Reliability settings
	MaxRetries     int           // Maximum retries for accounting records (default: 10)
	RetryBaseDelay time.Duration // Base delay for exponential backoff (default: 1s)
	RetryMaxDelay  time.Duration // Maximum delay between retries (default: 60s)
	QueueSize      int           // Size of pending accounting queue (default: 10000)
	PersistPath    string        // Path to persist pending records (default: /var/lib/bng/accounting)

	// Shutdown settings
	ShutdownTimeout time.Duration // Timeout for graceful shutdown (default: 30s)
	DrainOnShutdown bool          // Drain all sessions on shutdown (default: true)
}

// DefaultAccountingConfig returns sensible defaults
func DefaultAccountingConfig() AccountingConfig {
	return AccountingConfig{
		DefaultInterimInterval: 5 * time.Minute,
		InterimEnabled:         true,
		BatchSize:              100,
		MaxRetries:             10,
		RetryBaseDelay:         1 * time.Second,
		RetryMaxDelay:          60 * time.Second,
		QueueSize:              10000,
		PersistPath:            "/var/lib/bng/accounting",
		ShutdownTimeout:        30 * time.Second,
		DrainOnShutdown:        true,
	}
}

// AccountingSession tracks accounting state for a session
type AccountingSession struct {
	SessionID       string
	Username        string
	MAC             net.HardwareAddr
	FramedIP        net.IP
	NASPort         uint32
	CircuitID       string
	RemoteID        string
	Class           []byte
	InterimInterval time.Duration

	// State
	StartTime        time.Time
	LastInterimTime  time.Time
	LastInputOctets  uint64
	LastOutputOctets uint64
	LastInputPkts    uint64
	LastOutputPkts   uint64

	// Stop pending flag (for crash recovery)
	StopPending bool
	StopCause   uint32
}

// PendingAcctRecord represents a pending accounting record that needs to be sent
type PendingAcctRecord struct {
	ID         string       `json:"id"`
	Request    *AcctRequest `json:"request"`
	CreatedAt  time.Time    `json:"created_at"`
	RetryCount int          `json:"retry_count"`
	NextRetry  time.Time    `json:"next_retry"`
	LastError  string       `json:"last_error,omitempty"`
}

// CounterFetcher is a callback to fetch session counters from eBPF maps
type CounterFetcher func(sessionID string) (*SessionCounters, error)

// SessionCounters holds traffic counters for a session
type SessionCounters struct {
	InputOctets   uint64
	OutputOctets  uint64
	InputPackets  uint64
	OutputPackets uint64
}

// NewAccountingManager creates a new accounting manager
func NewAccountingManager(client *Client, config AccountingConfig, logger *zap.Logger) (*AccountingManager, error) {
	if client == nil {
		return nil, fmt.Errorf("RADIUS client required")
	}

	// Apply defaults
	if config.DefaultInterimInterval == 0 {
		config.DefaultInterimInterval = 5 * time.Minute
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 10
	}
	if config.RetryBaseDelay == 0 {
		config.RetryBaseDelay = 1 * time.Second
	}
	if config.RetryMaxDelay == 0 {
		config.RetryMaxDelay = 60 * time.Second
	}
	if config.QueueSize == 0 {
		config.QueueSize = 10000
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 30 * time.Second
	}
	if config.PersistPath == "" {
		config.PersistPath = "/var/lib/bng/accounting"
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &AccountingManager{
		client:         client,
		logger:         logger,
		config:         config,
		sessions:       make(map[string]*AccountingSession),
		pendingQueue:   make(chan *PendingAcctRecord, config.QueueSize),
		pendingRecords: make(map[string]*PendingAcctRecord),
		ctx:            ctx,
		cancel:         cancel,
		persistPath:    config.PersistPath,
	}, nil
}

// SetCounterFetcher sets the callback for fetching session counters
func (am *AccountingManager) SetCounterFetcher(fetcher CounterFetcher) {
	am.counterFetcher = fetcher
}

// Start starts the accounting manager
func (am *AccountingManager) Start() error {
	if !atomic.CompareAndSwapInt32(&am.running, 0, 1) {
		return fmt.Errorf("accounting manager already running")
	}

	am.logger.Info("Starting accounting manager",
		zap.Duration("interim_interval", am.config.DefaultInterimInterval),
		zap.Bool("interim_enabled", am.config.InterimEnabled),
	)

	// Ensure persistence directory exists
	if err := os.MkdirAll(am.persistPath, 0755); err != nil {
		am.logger.Warn("Failed to create persistence directory",
			zap.String("path", am.persistPath),
			zap.Error(err),
		)
	}

	// Recover orphaned sessions on startup
	if err := am.recoverOrphanedSessions(); err != nil {
		am.logger.Warn("Failed to recover orphaned sessions", zap.Error(err))
	}

	// Start workers
	am.wg.Add(2)
	go am.interimUpdateLoop()
	go am.pendingRecordProcessor()

	am.logger.Info("Accounting manager started")
	return nil
}

// Stop stops the accounting manager gracefully
func (am *AccountingManager) Stop() error {
	if !atomic.CompareAndSwapInt32(&am.running, 1, 0) {
		return nil
	}

	am.logger.Info("Stopping accounting manager")

	// Drain sessions if configured
	if am.config.DrainOnShutdown {
		am.drainAllSessions()
	}

	// Persist pending records before shutdown
	if err := am.persistPendingRecords(); err != nil {
		am.logger.Warn("Failed to persist pending records", zap.Error(err))
	}

	// Cancel context and wait for workers
	am.cancel()
	am.wg.Wait()

	am.logger.Info("Accounting manager stopped")
	return nil
}

// StartSession starts accounting for a session
func (am *AccountingManager) StartSession(session *AccountingSession) error {
	if session.SessionID == "" {
		return fmt.Errorf("session ID required")
	}

	am.sessionsMu.Lock()
	if _, exists := am.sessions[session.SessionID]; exists {
		am.sessionsMu.Unlock()
		return fmt.Errorf("session already exists: %s", session.SessionID)
	}

	// Set defaults
	if session.InterimInterval == 0 {
		session.InterimInterval = am.config.DefaultInterimInterval
	}
	session.StartTime = time.Now()
	session.LastInterimTime = time.Now()

	am.sessions[session.SessionID] = session
	am.sessionsMu.Unlock()

	// Send Accounting-Start
	req := &AcctRequest{
		SessionID:  session.SessionID,
		Username:   session.Username,
		MAC:        session.MAC,
		FramedIP:   session.FramedIP,
		NASPort:    session.NASPort,
		StatusType: AcctStatusStart,
		Class:      session.Class,
		CircuitID:  session.CircuitID,
		RemoteID:   session.RemoteID,
	}

	ctx, cancel := context.WithTimeout(am.ctx, 5*time.Second)
	defer cancel()

	if err := am.client.SendAccounting(ctx, req); err != nil {
		// Queue for retry
		am.queuePendingRecord(req)
		am.logger.Warn("Failed to send Accounting-Start, queued for retry",
			zap.String("session_id", session.SessionID),
			zap.Error(err),
		)
	}

	// Persist session for crash recovery
	am.persistActiveSession(session)

	am.logger.Info("Accounting started for session",
		zap.String("session_id", session.SessionID),
		zap.Duration("interim_interval", session.InterimInterval),
	)

	return nil
}

// StopSession stops accounting for a session
func (am *AccountingManager) StopSession(sessionID string, terminateCause uint32) error {
	am.sessionsMu.Lock()
	session, exists := am.sessions[sessionID]
	if !exists {
		am.sessionsMu.Unlock()
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Mark as stop pending for crash recovery
	session.StopPending = true
	session.StopCause = terminateCause
	am.sessionsMu.Unlock()

	// Persist state before attempting stop
	am.persistActiveSession(session)

	// Send Accounting-Stop
	if err := am.sendAccountingStop(session, terminateCause); err != nil {
		am.logger.Warn("Failed to send Accounting-Stop immediately, queued for retry",
			zap.String("session_id", sessionID),
			zap.Error(err),
		)
	}

	// Remove from active sessions
	am.sessionsMu.Lock()
	delete(am.sessions, sessionID)
	am.sessionsMu.Unlock()

	// Remove persisted session
	am.removePersistedSession(sessionID)

	return nil
}

// UpdateSessionInterval updates the interim interval for a session
// (e.g., from RADIUS Acct-Interim-Interval attribute)
func (am *AccountingManager) UpdateSessionInterval(sessionID string, interval time.Duration) error {
	am.sessionsMu.Lock()
	defer am.sessionsMu.Unlock()

	session, exists := am.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.InterimInterval = interval
	am.logger.Debug("Updated interim interval",
		zap.String("session_id", sessionID),
		zap.Duration("interval", interval),
	)

	return nil
}

// sendAccountingStop sends an Accounting-Stop with retries
func (am *AccountingManager) sendAccountingStop(session *AccountingSession, terminateCause uint32) error {
	// Fetch final counters
	counters := am.fetchCounters(session.SessionID)

	sessionTime := uint32(time.Since(session.StartTime).Seconds())

	req := &AcctRequest{
		SessionID:      session.SessionID,
		Username:       session.Username,
		MAC:            session.MAC,
		FramedIP:       session.FramedIP,
		NASPort:        session.NASPort,
		StatusType:     AcctStatusStop,
		InputOctets:    counters.InputOctets,
		OutputOctets:   counters.OutputOctets,
		InputPackets:   counters.InputPackets,
		OutputPackets:  counters.OutputPackets,
		SessionTime:    sessionTime,
		TerminateCause: terminateCause,
		Class:          session.Class,
		CircuitID:      session.CircuitID,
		RemoteID:       session.RemoteID,
	}

	ctx, cancel := context.WithTimeout(am.ctx, 5*time.Second)
	defer cancel()

	err := am.client.SendAccounting(ctx, req)
	if err != nil {
		// Queue for reliable delivery
		am.queuePendingRecord(req)
		atomic.AddUint64(&am.stopFailed, 1)
		return err
	}

	atomic.AddUint64(&am.stopTotal, 1)
	am.logger.Info("Accounting-Stop sent",
		zap.String("session_id", session.SessionID),
		zap.Uint32("terminate_cause", terminateCause),
		zap.Uint32("session_time", sessionTime),
		zap.Uint64("input_octets", counters.InputOctets),
		zap.Uint64("output_octets", counters.OutputOctets),
	)

	return nil
}

// interimUpdateLoop sends periodic interim updates for all sessions
func (am *AccountingManager) interimUpdateLoop() {
	defer am.wg.Done()

	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			if am.config.InterimEnabled {
				am.sendInterimUpdates()
			}
		}
	}
}

// sendInterimUpdates sends interim updates for sessions that are due
func (am *AccountingManager) sendInterimUpdates() {
	am.sessionsMu.RLock()
	var sessionsToUpdate []*AccountingSession
	now := time.Now()

	for _, session := range am.sessions {
		if session.StopPending {
			continue // Skip sessions pending stop
		}
		if now.Sub(session.LastInterimTime) >= session.InterimInterval {
			sessionsToUpdate = append(sessionsToUpdate, session)
		}
	}
	am.sessionsMu.RUnlock()

	// Batch counter fetches for efficiency
	for _, session := range sessionsToUpdate {
		am.sendInterimUpdate(session)
	}
}

// sendInterimUpdate sends an interim update for a single session
func (am *AccountingManager) sendInterimUpdate(session *AccountingSession) {
	counters := am.fetchCounters(session.SessionID)
	sessionTime := uint32(time.Since(session.StartTime).Seconds())

	req := &AcctRequest{
		SessionID:     session.SessionID,
		Username:      session.Username,
		MAC:           session.MAC,
		FramedIP:      session.FramedIP,
		NASPort:       session.NASPort,
		StatusType:    AcctStatusInterimUpdate,
		InputOctets:   counters.InputOctets,
		OutputOctets:  counters.OutputOctets,
		InputPackets:  counters.InputPackets,
		OutputPackets: counters.OutputPackets,
		SessionTime:   sessionTime,
		Class:         session.Class,
		CircuitID:     session.CircuitID,
		RemoteID:      session.RemoteID,
	}

	ctx, cancel := context.WithTimeout(am.ctx, 5*time.Second)
	defer cancel()

	err := am.client.SendAccounting(ctx, req)

	am.sessionsMu.Lock()
	if err != nil {
		atomic.AddUint64(&am.interimFailed, 1)
		// Queue for retry
		am.queuePendingRecord(req)
		am.logger.Debug("Interim update failed, queued for retry",
			zap.String("session_id", session.SessionID),
			zap.Error(err),
		)
	} else {
		atomic.AddUint64(&am.interimTotal, 1)
		// Update session state
		session.LastInterimTime = time.Now()
		session.LastInputOctets = counters.InputOctets
		session.LastOutputOctets = counters.OutputOctets
		session.LastInputPkts = counters.InputPackets
		session.LastOutputPkts = counters.OutputPackets
	}
	am.sessionsMu.Unlock()
}

// fetchCounters fetches counters for a session
func (am *AccountingManager) fetchCounters(sessionID string) *SessionCounters {
	if am.counterFetcher != nil {
		counters, err := am.counterFetcher(sessionID)
		if err == nil {
			return counters
		}
		am.logger.Debug("Failed to fetch counters from eBPF",
			zap.String("session_id", sessionID),
			zap.Error(err),
		)
	}

	// Return last known values if counter fetch fails
	am.sessionsMu.RLock()
	session, exists := am.sessions[sessionID]
	am.sessionsMu.RUnlock()

	if exists {
		return &SessionCounters{
			InputOctets:   session.LastInputOctets,
			OutputOctets:  session.LastOutputOctets,
			InputPackets:  session.LastInputPkts,
			OutputPackets: session.LastOutputPkts,
		}
	}

	return &SessionCounters{}
}

// queuePendingRecord adds a record to the pending queue for reliable delivery
func (am *AccountingManager) queuePendingRecord(req *AcctRequest) {
	record := &PendingAcctRecord{
		ID:         fmt.Sprintf("%s-%d-%d", req.SessionID, req.StatusType, time.Now().UnixNano()),
		Request:    req,
		CreatedAt:  time.Now(),
		RetryCount: 0,
		NextRetry:  time.Now().Add(am.config.RetryBaseDelay),
	}

	am.pendingMu.Lock()
	am.pendingRecords[record.ID] = record
	atomic.StoreUint64(&am.pendingQueueDepth, uint64(len(am.pendingRecords)))
	am.pendingMu.Unlock()

	select {
	case am.pendingQueue <- record:
	default:
		am.logger.Warn("Pending queue full, record may be lost",
			zap.String("session_id", req.SessionID),
		)
	}
}

// pendingRecordProcessor processes pending accounting records with retries
func (am *AccountingManager) pendingRecordProcessor() {
	defer am.wg.Done()

	retryTicker := time.NewTicker(1 * time.Second)
	defer retryTicker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return

		case record := <-am.pendingQueue:
			am.processPendingRecord(record)

		case <-retryTicker.C:
			am.retryPendingRecords()
		}
	}
}

// processPendingRecord attempts to send a pending record
func (am *AccountingManager) processPendingRecord(record *PendingAcctRecord) {
	ctx, cancel := context.WithTimeout(am.ctx, 5*time.Second)
	defer cancel()

	err := am.client.SendAccounting(ctx, record.Request)
	if err == nil {
		// Success - remove from pending
		am.pendingMu.Lock()
		delete(am.pendingRecords, record.ID)
		atomic.StoreUint64(&am.pendingQueueDepth, uint64(len(am.pendingRecords)))
		am.pendingMu.Unlock()

		if record.Request.StatusType == AcctStatusStop {
			atomic.AddUint64(&am.stopTotal, 1)
		} else if record.Request.StatusType == AcctStatusInterimUpdate {
			atomic.AddUint64(&am.interimTotal, 1)
		}
		return
	}

	// Failed - update for retry
	am.pendingMu.Lock()
	record.RetryCount++
	record.LastError = err.Error()

	if record.RetryCount >= am.config.MaxRetries {
		// Abandon record after max retries
		delete(am.pendingRecords, record.ID)
		atomic.StoreUint64(&am.pendingQueueDepth, uint64(len(am.pendingRecords)))
		am.pendingMu.Unlock()

		if record.Request.StatusType == AcctStatusStop {
			atomic.AddUint64(&am.stopAbandoned, 1)
		}
		am.logger.Error("Accounting record abandoned after max retries",
			zap.String("session_id", record.Request.SessionID),
			zap.Uint32("status_type", uint32(record.Request.StatusType)),
			zap.Int("retries", record.RetryCount),
		)
		return
	}

	// Calculate exponential backoff
	delay := am.config.RetryBaseDelay * time.Duration(1<<uint(record.RetryCount))
	if delay > am.config.RetryMaxDelay {
		delay = am.config.RetryMaxDelay
	}
	record.NextRetry = time.Now().Add(delay)

	if record.Request.StatusType == AcctStatusStop {
		atomic.AddUint64(&am.stopRetries, 1)
	}
	am.pendingMu.Unlock()

	am.logger.Debug("Accounting record retry scheduled",
		zap.String("session_id", record.Request.SessionID),
		zap.Int("retry_count", record.RetryCount),
		zap.Duration("delay", delay),
	)
}

// retryPendingRecords retries pending records that are due
func (am *AccountingManager) retryPendingRecords() {
	am.pendingMu.RLock()
	var toRetry []*PendingAcctRecord
	now := time.Now()

	for _, record := range am.pendingRecords {
		if now.After(record.NextRetry) {
			toRetry = append(toRetry, record)
		}
	}
	am.pendingMu.RUnlock()

	for _, record := range toRetry {
		am.processPendingRecord(record)
	}
}

// drainAllSessions sends Accounting-Stop for all active sessions
func (am *AccountingManager) drainAllSessions() {
	am.logger.Info("Draining all sessions for shutdown")

	am.sessionsMu.RLock()
	sessions := make([]*AccountingSession, 0, len(am.sessions))
	for _, session := range am.sessions {
		sessions = append(sessions, session)
	}
	am.sessionsMu.RUnlock()

	// Create a context with shutdown timeout
	ctx, cancel := context.WithTimeout(context.Background(), am.config.ShutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, session := range sessions {
		wg.Add(1)
		go func(s *AccountingSession) {
			defer wg.Done()
			am.sendAccountingStopSync(ctx, s, TerminateCauseNASReboot)
		}(session)
	}

	// Wait for all stops to complete or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		am.logger.Info("All sessions drained successfully", zap.Int("count", len(sessions)))
	case <-ctx.Done():
		am.logger.Warn("Shutdown timeout reached, some sessions may not have sent Accounting-Stop",
			zap.Int("total", len(sessions)),
		)
	}
}

// sendAccountingStopSync sends an Accounting-Stop synchronously with the given context
func (am *AccountingManager) sendAccountingStopSync(ctx context.Context, session *AccountingSession, terminateCause uint32) {
	counters := am.fetchCounters(session.SessionID)
	sessionTime := uint32(time.Since(session.StartTime).Seconds())

	req := &AcctRequest{
		SessionID:      session.SessionID,
		Username:       session.Username,
		MAC:            session.MAC,
		FramedIP:       session.FramedIP,
		NASPort:        session.NASPort,
		StatusType:     AcctStatusStop,
		InputOctets:    counters.InputOctets,
		OutputOctets:   counters.OutputOctets,
		InputPackets:   counters.InputPackets,
		OutputPackets:  counters.OutputPackets,
		SessionTime:    sessionTime,
		TerminateCause: terminateCause,
		Class:          session.Class,
	}

	if err := am.client.SendAccounting(ctx, req); err != nil {
		am.logger.Warn("Failed to send Accounting-Stop during drain",
			zap.String("session_id", session.SessionID),
			zap.Error(err),
		)
		// Queue for persistence - will be recovered on next startup
		am.queuePendingRecord(req)
	}
}

// Persistence methods for crash recovery

// persistActiveSession persists an active session to disk
func (am *AccountingManager) persistActiveSession(session *AccountingSession) {
	path := filepath.Join(am.persistPath, "sessions", session.SessionID+".json")

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		am.logger.Debug("Failed to create session persistence directory", zap.Error(err))
		return
	}

	data, err := json.Marshal(session)
	if err != nil {
		am.logger.Debug("Failed to marshal session for persistence", zap.Error(err))
		return
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		am.logger.Debug("Failed to persist session", zap.Error(err))
	}
}

// removePersistedSession removes a persisted session file
func (am *AccountingManager) removePersistedSession(sessionID string) {
	path := filepath.Join(am.persistPath, "sessions", sessionID+".json")
	os.Remove(path)
}

// persistPendingRecords persists pending records to disk
func (am *AccountingManager) persistPendingRecords() error {
	am.pendingMu.RLock()
	defer am.pendingMu.RUnlock()

	if len(am.pendingRecords) == 0 {
		return nil
	}

	path := filepath.Join(am.persistPath, "pending.json")
	data, err := json.Marshal(am.pendingRecords)
	if err != nil {
		return fmt.Errorf("marshal pending records: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write pending records: %w", err)
	}

	am.logger.Info("Persisted pending accounting records", zap.Int("count", len(am.pendingRecords)))
	return nil
}

// recoverOrphanedSessions recovers orphaned sessions from disk
func (am *AccountingManager) recoverOrphanedSessions() error {
	am.logger.Info("Checking for orphaned sessions")

	// Recover persisted sessions
	sessionsPath := filepath.Join(am.persistPath, "sessions")
	entries, err := os.ReadDir(sessionsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(sessionsPath, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var session AccountingSession
		if err := json.Unmarshal(data, &session); err != nil {
			os.Remove(path) // Remove corrupt file
			continue
		}

		// Send Accounting-Stop for orphaned session
		am.logger.Info("Recovering orphaned session",
			zap.String("session_id", session.SessionID),
		)

		terminateCause := session.StopCause
		if terminateCause == 0 {
			terminateCause = TerminateCauseNASReboot
		}

		req := &AcctRequest{
			SessionID:      session.SessionID,
			Username:       session.Username,
			MAC:            session.MAC,
			FramedIP:       session.FramedIP,
			NASPort:        session.NASPort,
			StatusType:     AcctStatusStop,
			InputOctets:    session.LastInputOctets,
			OutputOctets:   session.LastOutputOctets,
			InputPackets:   session.LastInputPkts,
			OutputPackets:  session.LastOutputPkts,
			SessionTime:    uint32(time.Since(session.StartTime).Seconds()),
			TerminateCause: terminateCause,
			Class:          session.Class,
		}

		ctx, cancel := context.WithTimeout(am.ctx, 5*time.Second)
		if err := am.client.SendAccounting(ctx, req); err != nil {
			am.queuePendingRecord(req)
		}
		cancel()

		atomic.AddUint64(&am.orphanedRecovered, 1)
		os.Remove(path)
	}

	// Recover pending records
	pendingPath := filepath.Join(am.persistPath, "pending.json")
	data, err := os.ReadFile(pendingPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read pending records: %w", err)
		}
		return nil
	}

	var records map[string]*PendingAcctRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("unmarshal pending records: %w", err)
	}

	am.pendingMu.Lock()
	for id, record := range records {
		am.pendingRecords[id] = record
		select {
		case am.pendingQueue <- record:
		default:
		}
	}
	atomic.StoreUint64(&am.pendingQueueDepth, uint64(len(am.pendingRecords)))
	am.pendingMu.Unlock()

	am.logger.Info("Recovered pending accounting records", zap.Int("count", len(records)))
	os.Remove(pendingPath)

	return nil
}

// GetStats returns accounting manager statistics
func (am *AccountingManager) GetStats() AccountingStats {
	am.sessionsMu.RLock()
	activeSessions := len(am.sessions)
	am.sessionsMu.RUnlock()

	return AccountingStats{
		ActiveSessions:    activeSessions,
		InterimTotal:      atomic.LoadUint64(&am.interimTotal),
		InterimFailed:     atomic.LoadUint64(&am.interimFailed),
		StopTotal:         atomic.LoadUint64(&am.stopTotal),
		StopFailed:        atomic.LoadUint64(&am.stopFailed),
		StopAbandoned:     atomic.LoadUint64(&am.stopAbandoned),
		StopRetries:       atomic.LoadUint64(&am.stopRetries),
		OrphanedRecovered: atomic.LoadUint64(&am.orphanedRecovered),
		PendingQueueDepth: atomic.LoadUint64(&am.pendingQueueDepth),
	}
}

// AccountingStats holds accounting manager statistics
type AccountingStats struct {
	ActiveSessions    int    `json:"active_sessions"`
	InterimTotal      uint64 `json:"interim_total"`
	InterimFailed     uint64 `json:"interim_failed"`
	StopTotal         uint64 `json:"stop_total"`
	StopFailed        uint64 `json:"stop_failed"`
	StopAbandoned     uint64 `json:"stop_abandoned"`
	StopRetries       uint64 `json:"stop_retries"`
	OrphanedRecovered uint64 `json:"orphaned_recovered"`
	PendingQueueDepth uint64 `json:"pending_queue_depth"`
}

// GetSession returns an accounting session by ID
func (am *AccountingManager) GetSession(sessionID string) (*AccountingSession, bool) {
	am.sessionsMu.RLock()
	defer am.sessionsMu.RUnlock()
	session, exists := am.sessions[sessionID]
	return session, exists
}

// ListSessions returns all active accounting sessions
func (am *AccountingManager) ListSessions() []*AccountingSession {
	am.sessionsMu.RLock()
	defer am.sessionsMu.RUnlock()

	sessions := make([]*AccountingSession, 0, len(am.sessions))
	for _, s := range am.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}
