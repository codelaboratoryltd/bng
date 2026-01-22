package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Logger is the main audit logging system.
type Logger struct {
	config Config
	logger *zap.Logger

	mu sync.RWMutex

	// Storage backends
	storage   Storage
	exporters []Exporter

	// Buffering for async writes
	eventChan chan *Event
	buffer    []*Event

	// Retention manager
	retention *RetentionManager

	// Statistics
	stats LoggerStats

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds audit logger configuration.
type Config struct {
	// DeviceID identifies this BNG device.
	DeviceID string

	// BufferSize is the event buffer size for async processing.
	BufferSize int

	// FlushInterval is how often to flush buffered events.
	FlushInterval time.Duration

	// DefaultRetentionDays is the default retention period.
	DefaultRetentionDays int

	// RetentionByCategory allows different retention per event category.
	RetentionByCategory map[string]int

	// EnabledCategories lists which categories to log (empty = all).
	EnabledCategories []string

	// MinSeverity is the minimum severity to log.
	MinSeverity Severity

	// SyncWrites forces synchronous writes (slower but safer).
	SyncWrites bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		BufferSize:           10000,
		FlushInterval:        5 * time.Second,
		DefaultRetentionDays: 90,
		RetentionByCategory: map[string]int{
			"session":  365, // 1 year for session logs
			"nat":      90,  // 90 days for NAT logs (legal requirement)
			"auth":     365, // 1 year for auth logs
			"dhcp":     30,  // 30 days for DHCP logs
			"admin":    730, // 2 years for admin actions
			"device":   365, // 1 year for device registration
			"api":      365, // 1 year for API access logs
			"security": 730, // 2 years for security events (compliance)
			"resource": 365, // 1 year for resource allocation
		},
		MinSeverity: SeverityDebug,
	}
}

// Storage is the interface for audit event persistence.
type Storage interface {
	// Store persists an event.
	Store(ctx context.Context, event *Event) error

	// StoreBatch persists multiple events.
	StoreBatch(ctx context.Context, events []*Event) error

	// Query retrieves events matching criteria.
	Query(ctx context.Context, query *Query) ([]*Event, error)

	// Delete removes events by ID.
	Delete(ctx context.Context, ids []string) error

	// DeleteExpired removes events past their retention.
	DeleteExpired(ctx context.Context) (int64, error)

	// Close releases storage resources.
	Close() error
}

// Query represents a query for audit events.
type Query struct {
	// Time range
	StartTime time.Time
	EndTime   time.Time

	// Filters
	Types        []EventType
	Categories   []string
	SubscriberID string
	MAC          string
	IPv4         string
	SessionID    string
	ISPID        string
	MinSeverity  Severity

	// Pagination
	Limit  int
	Offset int

	// Ordering
	OrderBy   string
	Ascending bool
}

// Exporter sends audit events to external systems.
type Exporter interface {
	// Name returns the exporter name.
	Name() string

	// Export sends an event to the external system.
	Export(ctx context.Context, event *Event) error

	// ExportBatch sends multiple events.
	ExportBatch(ctx context.Context, events []*Event) error

	// Close releases exporter resources.
	Close() error
}

// LoggerStats holds audit logger statistics.
type LoggerStats struct {
	EventsLogged   int64
	EventsExported int64
	EventsDropped  int64
	EventsExpired  int64
	BufferSize     int
	StorageErrors  int64
	ExportErrors   int64
}

// NewLogger creates a new audit logger.
func NewLogger(config Config, storage Storage, logger *zap.Logger) *Logger {
	ctx, cancel := context.WithCancel(context.Background())

	l := &Logger{
		config:    config,
		logger:    logger,
		storage:   storage,
		exporters: make([]Exporter, 0),
		eventChan: make(chan *Event, config.BufferSize),
		buffer:    make([]*Event, 0, 1000),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Initialize retention manager
	l.retention = NewRetentionManager(config.DefaultRetentionDays, config.RetentionByCategory)

	return l
}

// Start begins the audit logger.
func (l *Logger) Start() error {
	l.logger.Info("Starting audit logger",
		zap.String("device_id", l.config.DeviceID),
		zap.Int("buffer_size", l.config.BufferSize),
		zap.Duration("flush_interval", l.config.FlushInterval),
	)

	// Log system start
	l.LogEvent(&Event{
		Type:     EventSystemStart,
		DeviceID: l.config.DeviceID,
		Metadata: map[string]string{
			"version": "1.0.0",
		},
	})

	// Start async processor
	if !l.config.SyncWrites {
		l.wg.Add(1)
		go l.processEvents()
	}

	// Start flush loop
	l.wg.Add(1)
	go l.flushLoop()

	// Start retention cleanup
	l.wg.Add(1)
	go l.retentionLoop()

	l.logger.Info("Audit logger started")
	return nil
}

// Stop shuts down the audit logger.
func (l *Logger) Stop() error {
	l.logger.Info("Stopping audit logger")

	// Log system stop
	l.LogEvent(&Event{
		Type:     EventSystemStop,
		DeviceID: l.config.DeviceID,
	})

	l.cancel()

	// Close event channel and wait for processing
	close(l.eventChan)
	l.wg.Wait()

	// Final flush
	l.flush()

	// Close exporters
	for _, exp := range l.exporters {
		if err := exp.Close(); err != nil {
			l.logger.Warn("Error closing exporter",
				zap.String("exporter", exp.Name()),
				zap.Error(err),
			)
		}
	}

	// Close storage
	if l.storage != nil {
		if err := l.storage.Close(); err != nil {
			l.logger.Warn("Error closing storage", zap.Error(err))
		}
	}

	l.logger.Info("Audit logger stopped")
	return nil
}

// AddExporter adds an exporter for audit events.
func (l *Logger) AddExporter(exporter Exporter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.exporters = append(l.exporters, exporter)
	l.logger.Info("Added audit exporter", zap.String("name", exporter.Name()))
}

// LogEvent logs a single audit event.
func (l *Logger) LogEvent(event *Event) {
	l.prepareEvent(event)

	// Check if event should be logged
	if !l.shouldLog(event) {
		return
	}

	if l.config.SyncWrites {
		l.storeAndExport(event)
	} else {
		select {
		case l.eventChan <- event:
		default:
			l.mu.Lock()
			l.stats.EventsDropped++
			l.mu.Unlock()
			l.logger.Warn("Audit event dropped - buffer full",
				zap.String("type", string(event.Type)),
			)
		}
	}
}

// LogSessionStart logs a session start event.
func (l *Logger) LogSessionStart(session *SessionEvent) {
	// Create a copy of the event to avoid ID reuse
	event := session.Event
	event.ID = "" // Clear ID so a new one is generated
	event.Type = EventSessionStart
	session.StartTime = time.Now()
	l.LogEvent(&event)
}

// LogSessionStop logs a session stop event.
func (l *Logger) LogSessionStop(session *SessionEvent) {
	// Create a copy of the event to avoid ID reuse
	event := session.Event
	event.ID = "" // Clear ID so a new one is generated
	event.Type = EventSessionStop
	session.EndTime = time.Now()
	if !session.StartTime.IsZero() {
		event.Duration = session.EndTime.Sub(session.StartTime)
	}
	event.BytesIn = session.BytesIn
	event.BytesOut = session.BytesOut
	l.LogEvent(&event)
}

// LogNATMapping logs a NAT translation event.
func (l *Logger) LogNATMapping(nat *NATEvent) {
	// Create a copy of the event to avoid ID reuse
	event := nat.Event
	event.ID = "" // Clear ID so a new one is generated
	event.Type = EventNATMapping
	l.LogEvent(&event)
}

// LogAuth logs an authentication event.
func (l *Logger) LogAuth(auth *AuthEvent, success bool) {
	// Create a copy of the event to avoid ID reuse
	event := auth.Event
	event.ID = "" // Clear ID so a new one is generated
	if success {
		event.Type = EventAuthSuccess
	} else {
		event.Type = EventAuthFailure
	}
	l.LogEvent(&event)
}

// LogDeviceRegistration logs a device registration event.
func (l *Logger) LogDeviceRegistration(event *Event, success bool) {
	event.ID = "" // Clear ID so a new one is generated
	if success {
		event.Type = EventDeviceRegistrationSuccess
	} else {
		event.Type = EventDeviceRegistrationFailure
	}
	l.LogEvent(event)
}

// LogAPIAccess logs an API access event.
func (l *Logger) LogAPIAccess(event *Event) {
	event.ID = "" // Clear ID so a new one is generated
	// Event type should be set by caller (APIAuthSuccess, APIAuthFailure, etc.)
	if event.Type == "" {
		event.Type = EventAPIAuthAttempt
	}
	l.LogEvent(event)
}

// LogSuspiciousActivity logs a suspicious activity event.
func (l *Logger) LogSuspiciousActivity(event *Event, threatType string, score int) {
	event.ID = "" // Clear ID so a new one is generated
	event.Type = EventSuspiciousActivity
	event.ThreatType = threatType
	event.ThreatScore = score
	l.LogEvent(event)
}

// LogBruteForce logs a brute force detection event.
func (l *Logger) LogBruteForce(event *Event, failureCount int) {
	event.ID = "" // Clear ID so a new one is generated
	event.Type = EventBruteForceDetected
	event.ThreatType = "brute_force"
	event.FailureCount = failureCount
	l.LogEvent(event)
}

// LogResourceAllocation logs a resource allocation or deallocation event.
func (l *Logger) LogResourceAllocation(event *Event, allocated bool) {
	event.ID = "" // Clear ID so a new one is generated
	if allocated {
		event.Type = EventResourceAllocated
	} else {
		event.Type = EventResourceDeallocated
	}
	l.LogEvent(event)
}

// LogConfigChange logs a configuration change event.
func (l *Logger) LogConfigChange(event *Event) {
	event.ID = "" // Clear ID so a new one is generated
	event.Type = EventConfigChange
	l.LogEvent(event)
}

// prepareEvent fills in default fields.
func (l *Logger) prepareEvent(event *Event) {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.DeviceID == "" {
		event.DeviceID = l.config.DeviceID
	}

	// Set retention
	event.RetentionDays = l.retention.GetRetention(event.Type.Category())
	event.ExpiresAt = event.Timestamp.AddDate(0, 0, event.RetentionDays)
}

// shouldLog checks if an event should be logged based on config.
func (l *Logger) shouldLog(event *Event) bool {
	// Check severity
	if event.Type.GetSeverity() < l.config.MinSeverity {
		return false
	}

	// Check category filter
	if len(l.config.EnabledCategories) > 0 {
		category := event.Type.Category()
		found := false
		for _, c := range l.config.EnabledCategories {
			if c == category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// storeAndExport stores and exports a single event.
func (l *Logger) storeAndExport(event *Event) {
	ctx := context.Background()

	// Store
	if l.storage != nil {
		if err := l.storage.Store(ctx, event); err != nil {
			l.mu.Lock()
			l.stats.StorageErrors++
			l.mu.Unlock()
			l.logger.Error("Failed to store audit event",
				zap.Error(err),
				zap.String("event_id", event.ID),
			)
		}
	}

	// Export
	l.mu.RLock()
	exporters := l.exporters
	l.mu.RUnlock()

	for _, exp := range exporters {
		if err := exp.Export(ctx, event); err != nil {
			l.mu.Lock()
			l.stats.ExportErrors++
			l.mu.Unlock()
			l.logger.Warn("Failed to export audit event",
				zap.String("exporter", exp.Name()),
				zap.Error(err),
			)
		}
	}

	l.mu.Lock()
	l.stats.EventsLogged++
	l.mu.Unlock()
}

// processEvents processes events from the channel.
func (l *Logger) processEvents() {
	defer l.wg.Done()

	for event := range l.eventChan {
		l.mu.Lock()
		l.buffer = append(l.buffer, event)
		bufLen := len(l.buffer)
		l.mu.Unlock()

		// Flush if buffer is getting full
		if bufLen >= cap(l.buffer)*80/100 {
			l.flush()
		}
	}
}

// flushLoop periodically flushes the buffer.
func (l *Logger) flushLoop() {
	defer l.wg.Done()

	ticker := time.NewTicker(l.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			l.flush()
		}
	}
}

// flush writes buffered events to storage and exporters.
func (l *Logger) flush() {
	l.mu.Lock()
	if len(l.buffer) == 0 {
		l.mu.Unlock()
		return
	}

	events := l.buffer
	l.buffer = make([]*Event, 0, 1000)
	l.mu.Unlock()

	ctx := context.Background()

	// Store batch
	if l.storage != nil {
		if err := l.storage.StoreBatch(ctx, events); err != nil {
			l.mu.Lock()
			l.stats.StorageErrors++
			l.mu.Unlock()
			l.logger.Error("Failed to store audit batch",
				zap.Error(err),
				zap.Int("count", len(events)),
			)
		}
	}

	// Export batch
	l.mu.RLock()
	exporters := l.exporters
	l.mu.RUnlock()

	for _, exp := range exporters {
		if err := exp.ExportBatch(ctx, events); err != nil {
			l.mu.Lock()
			l.stats.ExportErrors++
			l.mu.Unlock()
			l.logger.Warn("Failed to export audit batch",
				zap.String("exporter", exp.Name()),
				zap.Error(err),
			)
		} else {
			l.mu.Lock()
			l.stats.EventsExported += int64(len(events))
			l.mu.Unlock()
		}
	}

	l.mu.Lock()
	l.stats.EventsLogged += int64(len(events))
	l.mu.Unlock()
}

// retentionLoop periodically cleans up expired events.
func (l *Logger) retentionLoop() {
	defer l.wg.Done()

	// Run daily
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Initial cleanup after startup (with cancellation support)
	select {
	case <-l.ctx.Done():
		return
	case <-time.After(1 * time.Minute):
		l.cleanupExpired()
	}

	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			l.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired events.
func (l *Logger) cleanupExpired() {
	if l.storage == nil {
		return
	}

	ctx := context.Background()
	deleted, err := l.storage.DeleteExpired(ctx)
	if err != nil {
		l.logger.Error("Failed to cleanup expired events", zap.Error(err))
		return
	}

	if deleted > 0 {
		l.mu.Lock()
		l.stats.EventsExpired += deleted
		l.mu.Unlock()

		l.logger.Info("Cleaned up expired audit events",
			zap.Int64("deleted", deleted),
		)
	}
}

// Query searches for audit events.
func (l *Logger) Query(query *Query) ([]*Event, error) {
	if l.storage == nil {
		return nil, fmt.Errorf("no storage configured")
	}
	return l.storage.Query(context.Background(), query)
}

// Stats returns logger statistics.
func (l *Logger) Stats() LoggerStats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := l.stats
	stats.BufferSize = len(l.buffer)
	return stats
}

// FormatJSON formats an event as JSON.
func FormatJSON(event *Event) ([]byte, error) {
	return json.Marshal(event)
}

// FormatSyslog formats an event for syslog.
func FormatSyslog(event *Event) string {
	msg := fmt.Sprintf("[%s] device=%s type=%s",
		event.Timestamp.Format(time.RFC3339),
		event.DeviceID,
		event.Type,
	)

	if event.SubscriberID != "" {
		msg += fmt.Sprintf(" subscriber=%s", event.SubscriberID)
	}
	if event.SessionID != "" {
		msg += fmt.Sprintf(" session=%s", event.SessionID)
	}
	if event.IPv4 != nil {
		msg += fmt.Sprintf(" ipv4=%s", event.IPv4)
	}
	if event.MAC != nil {
		msg += fmt.Sprintf(" mac=%s", event.MAC)
	}
	if event.ISPID != "" {
		msg += fmt.Sprintf(" isp=%s", event.ISPID)
	}
	if event.BytesIn > 0 || event.BytesOut > 0 {
		msg += fmt.Sprintf(" bytes_in=%d bytes_out=%d", event.BytesIn, event.BytesOut)
	}
	if event.ErrorMessage != "" {
		msg += fmt.Sprintf(" error=%q", event.ErrorMessage)
	}

	// Security context fields
	if event.ActorID != "" {
		msg += fmt.Sprintf(" actor=%s", event.ActorID)
	}
	if event.ActorType != "" {
		msg += fmt.Sprintf(" actor_type=%s", event.ActorType)
	}
	if event.SourceIP != nil {
		msg += fmt.Sprintf(" source_ip=%s", event.SourceIP)
	}
	if event.APIEndpoint != "" {
		msg += fmt.Sprintf(" endpoint=%s", event.APIEndpoint)
	}
	if event.HTTPMethod != "" {
		msg += fmt.Sprintf(" method=%s", event.HTTPMethod)
	}
	if event.HTTPStatus != 0 {
		msg += fmt.Sprintf(" status=%d", event.HTTPStatus)
	}
	if event.ResourceType != "" {
		msg += fmt.Sprintf(" resource_type=%s", event.ResourceType)
	}
	if event.ResourceID != "" {
		msg += fmt.Sprintf(" resource_id=%s", event.ResourceID)
	}
	if event.ThreatType != "" {
		msg += fmt.Sprintf(" threat=%s", event.ThreatType)
	}
	if event.ThreatScore > 0 {
		msg += fmt.Sprintf(" threat_score=%d", event.ThreatScore)
	}
	if event.FailureCount > 0 {
		msg += fmt.Sprintf(" failures=%d", event.FailureCount)
	}

	return msg
}
