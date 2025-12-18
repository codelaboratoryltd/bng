package intercept

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Manager handles lawful interception warrants and delivery.
type Manager struct {
	config Config
	logger *zap.Logger

	mu sync.RWMutex

	// Active warrants indexed by ID
	warrants map[string]*Warrant

	// Active intercept sessions indexed by session ID
	sessions map[string]*InterceptSession

	// Indexes for efficient lookup
	bySubscriberID map[string][]*Warrant // subscriber_id -> warrants
	byMAC          map[string][]*Warrant // MAC -> warrants
	byIPv4         map[string][]*Warrant // IPv4 -> warrants

	// Delivery channels
	iriChan chan *InterceptRecord
	ccChan  chan *InterceptRecord

	// Exporters for different delivery methods
	exporters map[DeliveryMethod]Exporter

	// Statistics
	stats ManagerStats

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Exporter delivers intercept records to mediation devices.
type Exporter interface {
	Name() string
	DeliverIRI(ctx context.Context, record *InterceptRecord) error
	DeliverCC(ctx context.Context, record *InterceptRecord) error
	Close() error
}

// NewManager creates a new lawful intercept manager.
func NewManager(config Config, logger *zap.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		config:         config,
		logger:         logger,
		warrants:       make(map[string]*Warrant),
		sessions:       make(map[string]*InterceptSession),
		bySubscriberID: make(map[string][]*Warrant),
		byMAC:          make(map[string][]*Warrant),
		byIPv4:         make(map[string][]*Warrant),
		iriChan:        make(chan *InterceptRecord, config.DeliveryBufferSize),
		ccChan:         make(chan *InterceptRecord, config.DeliveryBufferSize),
		exporters:      make(map[DeliveryMethod]Exporter),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start begins the lawful intercept manager.
func (m *Manager) Start() error {
	if !m.config.Enabled {
		m.logger.Info("Lawful intercept disabled")
		return nil
	}

	m.logger.Info("Starting lawful intercept manager",
		zap.String("operator_id", m.config.OperatorID),
		zap.String("country_code", m.config.CountryCode),
	)

	// Start IRI delivery goroutine
	m.wg.Add(1)
	go m.deliverIRI()

	// Start CC delivery goroutine
	m.wg.Add(1)
	go m.deliverCC()

	// Start warrant expiry checker
	m.wg.Add(1)
	go m.checkWarrantExpiry()

	m.logger.Info("Lawful intercept manager started")
	return nil
}

// Stop shuts down the lawful intercept manager.
func (m *Manager) Stop() error {
	m.logger.Info("Stopping lawful intercept manager")

	m.cancel()

	// Close channels
	close(m.iriChan)
	close(m.ccChan)

	m.wg.Wait()

	// Close exporters
	for name, exp := range m.exporters {
		if err := exp.Close(); err != nil {
			m.logger.Warn("Error closing exporter",
				zap.String("exporter", string(name)),
				zap.Error(err),
			)
		}
	}

	m.logger.Info("Lawful intercept manager stopped")
	return nil
}

// AddExporter adds a delivery exporter.
func (m *Manager) AddExporter(method DeliveryMethod, exporter Exporter) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.exporters[method] = exporter
	m.logger.Info("Added LI exporter",
		zap.String("method", string(method)),
		zap.String("name", exporter.Name()),
	)
}

// AddWarrant adds a new lawful intercept warrant.
func (m *Manager) AddWarrant(warrant *Warrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate warrant
	if err := m.validateWarrant(warrant); err != nil {
		return fmt.Errorf("invalid warrant: %w", err)
	}

	// Generate ID if not set
	if warrant.ID == "" {
		warrant.ID = uuid.New().String()
	}

	warrant.CreatedAt = time.Now()
	warrant.UpdatedAt = warrant.CreatedAt

	// Check if warrant is currently valid
	now := time.Now()
	if now.Before(warrant.ValidFrom) {
		warrant.Status = WarrantStatusPending
	} else if now.After(warrant.ValidUntil) {
		warrant.Status = WarrantStatusExpired
	} else {
		warrant.Status = WarrantStatusActive
	}

	// Store warrant
	m.warrants[warrant.ID] = warrant

	// Build indexes
	m.indexWarrant(warrant)

	m.stats.ActiveWarrants++

	m.logger.Info("Added lawful intercept warrant",
		zap.String("warrant_id", warrant.ID),
		zap.String("liid", warrant.LIID),
		zap.String("type", string(warrant.Type)),
		zap.String("status", string(warrant.Status)),
		zap.String("target_subscriber", warrant.TargetSubscriberID),
	)

	return nil
}

// RemoveWarrant removes a warrant.
func (m *Manager) RemoveWarrant(warrantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	warrant, exists := m.warrants[warrantID]
	if !exists {
		return fmt.Errorf("warrant not found: %s", warrantID)
	}

	// Remove from indexes
	m.unindexWarrant(warrant)

	// Remove from main map
	delete(m.warrants, warrantID)

	m.stats.ActiveWarrants--

	m.logger.Info("Removed lawful intercept warrant",
		zap.String("warrant_id", warrantID),
	)

	return nil
}

// UpdateWarrantStatus updates the status of a warrant.
func (m *Manager) UpdateWarrantStatus(warrantID string, status WarrantStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	warrant, exists := m.warrants[warrantID]
	if !exists {
		return fmt.Errorf("warrant not found: %s", warrantID)
	}

	warrant.Status = status
	warrant.UpdatedAt = time.Now()

	m.logger.Info("Updated warrant status",
		zap.String("warrant_id", warrantID),
		zap.String("status", string(status)),
	)

	return nil
}

// GetWarrant retrieves a warrant by ID.
func (m *Manager) GetWarrant(warrantID string) (*Warrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	warrant, exists := m.warrants[warrantID]
	if !exists {
		return nil, fmt.Errorf("warrant not found: %s", warrantID)
	}

	return warrant, nil
}

// ListWarrants returns all warrants.
func (m *Manager) ListWarrants() []*Warrant {
	m.mu.RLock()
	defer m.mu.RUnlock()

	warrants := make([]*Warrant, 0, len(m.warrants))
	for _, w := range m.warrants {
		warrants = append(warrants, w)
	}
	return warrants
}

// MatchSession checks if a session should be intercepted.
func (m *Manager) MatchSession(subscriberID string, mac net.HardwareAddr, ipv4, ipv6 net.IP) []*Warrant {
	m.mu.RLock()
	defer m.mu.RUnlock()

	seen := make(map[string]bool)
	var matches []*Warrant

	// Check by subscriber ID
	if subscriberID != "" {
		for _, w := range m.bySubscriberID[subscriberID] {
			if m.isWarrantActive(w) && !seen[w.ID] {
				matches = append(matches, w)
				seen[w.ID] = true
			}
		}
	}

	// Check by MAC
	if mac != nil {
		macStr := mac.String()
		for _, w := range m.byMAC[macStr] {
			if m.isWarrantActive(w) && !seen[w.ID] {
				matches = append(matches, w)
				seen[w.ID] = true
			}
		}
	}

	// Check by IPv4
	if ipv4 != nil {
		ipStr := ipv4.String()
		for _, w := range m.byIPv4[ipStr] {
			if m.isWarrantActive(w) && !seen[w.ID] {
				matches = append(matches, w)
				seen[w.ID] = true
			}
		}
	}

	return matches
}

// RecordIRI records an Intercept Related Information event.
func (m *Manager) RecordIRI(warrant *Warrant, eventType IRIEventType, session *InterceptSession, partyInfo *PartyInfo) {
	record := &InterceptRecord{
		ID:           uuid.New().String(),
		LIID:         warrant.LIID,
		WarrantID:    warrant.ID,
		Timestamp:    time.Now(),
		RecordType:   RecordTypeIRI,
		EventType:    eventType,
		SessionID:    session.SessionID,
		SubscriberID: session.SubscriberID,
		MAC:          session.MAC,
		SourceIP:     session.IPv4,
		PartyInfo:    partyInfo,
	}

	// Update statistics
	m.mu.Lock()
	warrant.LastActivity = record.Timestamp
	warrant.SessionsMatched++
	session.IRIRecords++
	m.stats.TotalIRIRecords++
	m.mu.Unlock()

	// Queue for delivery
	select {
	case m.iriChan <- record:
	default:
		m.logger.Warn("IRI delivery buffer full, record dropped",
			zap.String("warrant_id", warrant.ID),
		)
	}
}

// RecordCC records Content of Communication (traffic).
func (m *Manager) RecordCC(warrant *Warrant, session *InterceptSession, direction Direction, srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, payload []byte) {
	if warrant.Type == WarrantIRI {
		return // IRI-only warrant, skip CC
	}

	record := &InterceptRecord{
		ID:           uuid.New().String(),
		LIID:         warrant.LIID,
		WarrantID:    warrant.ID,
		Timestamp:    time.Now(),
		RecordType:   RecordTypeCC,
		SessionID:    session.SessionID,
		SubscriberID: session.SubscriberID,
		MAC:          session.MAC,
		SourceIP:     srcIP,
		DestIP:       dstIP,
		SourcePort:   srcPort,
		DestPort:     dstPort,
		Protocol:     protocol,
		Direction:    direction,
		PayloadSize:  len(payload),
		Payload:      payload, // Deep copy would be better in production
	}

	// Update statistics
	m.mu.Lock()
	warrant.LastActivity = record.Timestamp
	warrant.BytesIntercepted += int64(len(payload))
	session.CCRecords++
	session.BytesCaptured += int64(len(payload))
	m.stats.TotalCCRecords++
	m.mu.Unlock()

	// Queue for delivery
	select {
	case m.ccChan <- record:
	default:
		m.logger.Warn("CC delivery buffer full, record dropped",
			zap.String("warrant_id", warrant.ID),
		)
	}
}

// StartInterceptSession creates a new intercept session.
func (m *Manager) StartInterceptSession(warrant *Warrant, sessionID, subscriberID string, mac net.HardwareAddr, ipv4, ipv6 net.IP) *InterceptSession {
	session := &InterceptSession{
		SessionID:    sessionID,
		WarrantID:    warrant.ID,
		LIID:         warrant.LIID,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		SubscriberID: subscriberID,
		MAC:          mac,
		IPv4:         ipv4,
		IPv6:         ipv6,
	}

	m.mu.Lock()
	m.sessions[sessionID] = session
	m.stats.ActiveInterceptions++
	m.mu.Unlock()

	// Record session start IRI
	m.RecordIRI(warrant, IRISessionStart, session, &PartyInfo{
		PartyID:     subscriberID,
		PartyType:   "subscriber",
		IPv4Address: ipv4,
		IPv6Address: ipv6,
		MACAddress:  mac,
	})

	m.logger.Debug("Started intercept session",
		zap.String("session_id", sessionID),
		zap.String("warrant_id", warrant.ID),
		zap.String("subscriber_id", subscriberID),
	)

	return session
}

// StopInterceptSession ends an intercept session.
func (m *Manager) StopInterceptSession(sessionID string) {
	m.mu.Lock()
	session, exists := m.sessions[sessionID]
	if !exists {
		m.mu.Unlock()
		return
	}
	delete(m.sessions, sessionID)
	m.stats.ActiveInterceptions--
	m.mu.Unlock()

	// Get warrant for IRI recording
	warrant, err := m.GetWarrant(session.WarrantID)
	if err != nil {
		m.logger.Warn("Warrant not found for session end",
			zap.String("session_id", sessionID),
			zap.String("warrant_id", session.WarrantID),
		)
		return
	}

	// Record session end IRI
	m.RecordIRI(warrant, IRISessionEnd, session, nil)

	m.logger.Debug("Stopped intercept session",
		zap.String("session_id", sessionID),
		zap.Int64("iri_records", session.IRIRecords),
		zap.Int64("cc_records", session.CCRecords),
		zap.Int64("bytes_captured", session.BytesCaptured),
	)
}

// GetSession retrieves an active intercept session.
func (m *Manager) GetSession(sessionID string) (*InterceptSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[sessionID]
	return session, exists
}

// Stats returns manager statistics.
func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// validateWarrant validates a warrant.
func (m *Manager) validateWarrant(warrant *Warrant) error {
	if warrant.LIID == "" {
		return fmt.Errorf("LIID required")
	}
	if warrant.Type == "" {
		return fmt.Errorf("warrant type required")
	}
	if warrant.ValidFrom.IsZero() {
		return fmt.Errorf("valid_from required")
	}
	if warrant.ValidUntil.IsZero() {
		return fmt.Errorf("valid_until required")
	}
	if warrant.ValidUntil.Before(warrant.ValidFrom) {
		return fmt.Errorf("valid_until must be after valid_from")
	}

	// At least one target identifier required
	if warrant.TargetSubscriberID == "" &&
		warrant.TargetMAC == nil &&
		warrant.TargetIPv4 == nil &&
		warrant.TargetIPv6 == nil &&
		warrant.TargetUsername == "" &&
		warrant.TargetNTEID == "" {
		return fmt.Errorf("at least one target identifier required")
	}

	return nil
}

// indexWarrant adds a warrant to the lookup indexes.
func (m *Manager) indexWarrant(warrant *Warrant) {
	if warrant.TargetSubscriberID != "" {
		m.bySubscriberID[warrant.TargetSubscriberID] = append(
			m.bySubscriberID[warrant.TargetSubscriberID], warrant)
	}
	if warrant.TargetMAC != nil {
		macStr := warrant.TargetMAC.String()
		m.byMAC[macStr] = append(m.byMAC[macStr], warrant)
	}
	if warrant.TargetIPv4 != nil {
		ipStr := warrant.TargetIPv4.String()
		m.byIPv4[ipStr] = append(m.byIPv4[ipStr], warrant)
	}
}

// unindexWarrant removes a warrant from the lookup indexes.
func (m *Manager) unindexWarrant(warrant *Warrant) {
	if warrant.TargetSubscriberID != "" {
		m.removeFromSlice(&m.bySubscriberID, warrant.TargetSubscriberID, warrant.ID)
	}
	if warrant.TargetMAC != nil {
		m.removeFromSlice(&m.byMAC, warrant.TargetMAC.String(), warrant.ID)
	}
	if warrant.TargetIPv4 != nil {
		m.removeFromSlice(&m.byIPv4, warrant.TargetIPv4.String(), warrant.ID)
	}
}

// removeFromSlice removes a warrant from an index slice.
func (m *Manager) removeFromSlice(index *map[string][]*Warrant, key, warrantID string) {
	warrants := (*index)[key]
	for i, w := range warrants {
		if w.ID == warrantID {
			(*index)[key] = append(warrants[:i], warrants[i+1:]...)
			break
		}
	}
	if len((*index)[key]) == 0 {
		delete(*index, key)
	}
}

// isWarrantActive checks if a warrant is currently active.
func (m *Manager) isWarrantActive(warrant *Warrant) bool {
	if warrant.Status != WarrantStatusActive {
		return false
	}

	now := time.Now()
	return now.After(warrant.ValidFrom) && now.Before(warrant.ValidUntil)
}

// deliverIRI handles IRI record delivery.
func (m *Manager) deliverIRI() {
	defer m.wg.Done()

	for record := range m.iriChan {
		m.deliverRecord(record, HI2)
	}
}

// deliverCC handles CC record delivery.
func (m *Manager) deliverCC() {
	defer m.wg.Done()

	for record := range m.ccChan {
		m.deliverRecord(record, HI3)
	}
}

// deliverRecord delivers a record via the appropriate exporter.
func (m *Manager) deliverRecord(record *InterceptRecord, hi HandoverInterface) {
	// Get warrant to find delivery method
	warrant, err := m.GetWarrant(record.WarrantID)
	if err != nil {
		m.logger.Warn("Cannot deliver record - warrant not found",
			zap.String("warrant_id", record.WarrantID),
		)
		return
	}

	m.mu.RLock()
	exporter, exists := m.exporters[warrant.DeliveryMethod]
	m.mu.RUnlock()

	if !exists {
		m.logger.Warn("No exporter for delivery method",
			zap.String("method", string(warrant.DeliveryMethod)),
		)
		return
	}

	ctx, cancel := context.WithTimeout(m.ctx, m.config.DeliveryTimeout)
	defer cancel()

	var deliveryErr error
	if hi == HI2 {
		deliveryErr = exporter.DeliverIRI(ctx, record)
	} else {
		deliveryErr = exporter.DeliverCC(ctx, record)
	}

	if deliveryErr != nil {
		m.mu.Lock()
		m.stats.DeliveryErrors++
		m.mu.Unlock()

		m.logger.Error("Failed to deliver record",
			zap.String("hi", string(hi)),
			zap.String("warrant_id", record.WarrantID),
			zap.Error(deliveryErr),
		)
	} else {
		m.mu.Lock()
		m.stats.TotalBytesDelivered += int64(record.PayloadSize)
		m.mu.Unlock()
	}
}

// checkWarrantExpiry periodically checks for expired warrants.
func (m *Manager) checkWarrantExpiry() {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.expireWarrants()
		}
	}
}

// expireWarrants marks expired warrants.
func (m *Manager) expireWarrants() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for _, warrant := range m.warrants {
		if warrant.Status == WarrantStatusActive && now.After(warrant.ValidUntil) {
			warrant.Status = WarrantStatusExpired
			warrant.UpdatedAt = now

			m.logger.Info("Warrant expired",
				zap.String("warrant_id", warrant.ID),
				zap.String("liid", warrant.LIID),
			)
		} else if warrant.Status == WarrantStatusPending && now.After(warrant.ValidFrom) {
			warrant.Status = WarrantStatusActive
			warrant.UpdatedAt = now

			m.logger.Info("Warrant activated",
				zap.String("warrant_id", warrant.ID),
				zap.String("liid", warrant.LIID),
			)
		}
	}
}
