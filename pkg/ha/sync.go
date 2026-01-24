package ha

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// SyncConfig contains configuration for the HA syncer.
type SyncConfig struct {
	// NodeID is this node's unique identifier.
	NodeID string

	// Role is this node's HA role (active or standby).
	Role Role

	// Partner contains information about the HA partner.
	Partner *PartnerInfo

	// ListenAddr is the address to listen on for incoming sync connections.
	// Only used by active nodes.
	ListenAddr string

	// ReconnectInterval is how long to wait before reconnecting after disconnect.
	ReconnectInterval time.Duration

	// HeartbeatInterval is how often to send heartbeat messages.
	HeartbeatInterval time.Duration

	// FullSyncInterval is how often to request a full sync (standby only).
	// Set to 0 to disable periodic full syncs.
	FullSyncInterval time.Duration

	// ConnectTimeout is the timeout for establishing connections.
	ConnectTimeout time.Duration

	// RequestTimeout is the timeout for HTTP requests.
	RequestTimeout time.Duration
}

// DefaultSyncConfig returns sensible defaults for sync configuration.
func DefaultSyncConfig() SyncConfig {
	return SyncConfig{
		ReconnectInterval: 5 * time.Second,
		HeartbeatInterval: 10 * time.Second,
		FullSyncInterval:  5 * time.Minute,
		ConnectTimeout:    10 * time.Second,
		RequestTimeout:    30 * time.Second,
	}
}

// HASyncer manages state synchronization between HA pairs.
type HASyncer struct {
	config SyncConfig
	logger *zap.Logger
	store  SessionStore
	client *http.Client
	server *http.Server

	// State
	mu          sync.RWMutex
	connected   bool
	sequenceNum uint64
	stats       SyncStats

	// Change notifications from local session manager
	pendingChanges chan *SyncMessage

	// For standby: received state from active
	receivedSessions map[string]*SessionState
	receivedMu       sync.RWMutex

	// SSE connections from standby nodes (active only)
	sseClients   map[string]chan *SyncMessage
	sseClientsMu sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewHASyncer creates a new HA syncer.
func NewHASyncer(config SyncConfig, store SessionStore, logger *zap.Logger) *HASyncer {
	ctx, cancel := context.WithCancel(context.Background())

	return &HASyncer{
		config:           config,
		logger:           logger,
		store:            store,
		client:           &http.Client{Timeout: config.RequestTimeout},
		pendingChanges:   make(chan *SyncMessage, 1000),
		receivedSessions: make(map[string]*SessionState),
		sseClients:       make(map[string]chan *SyncMessage),
		ctx:              ctx,
		cancel:           cancel,
	}
}

// Start begins the sync process.
// For active nodes: starts the HTTP server for standby connections.
// For standby nodes: connects to active and starts receiving updates.
func (s *HASyncer) Start() error {
	s.logger.Info("Starting HA syncer",
		zap.String("node_id", s.config.NodeID),
		zap.String("role", string(s.config.Role)),
	)

	switch s.config.Role {
	case RoleActive:
		return s.startActive()
	case RoleStandby:
		return s.startStandby()
	default:
		return fmt.Errorf("unknown role: %s", s.config.Role)
	}
}

// Stop shuts down the syncer gracefully.
func (s *HASyncer) Stop() error {
	s.logger.Info("Stopping HA syncer")
	s.cancel()

	// Close SSE client channels
	s.sseClientsMu.Lock()
	for _, ch := range s.sseClients {
		close(ch)
	}
	s.sseClients = make(map[string]chan *SyncMessage)
	s.sseClientsMu.Unlock()

	// Shutdown HTTP server if running
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)
	}

	s.wg.Wait()
	s.logger.Info("HA syncer stopped")
	return nil
}

// ===== Active Node Implementation =====

// startActive starts the HTTP server for standby nodes to connect.
func (s *HASyncer) startActive() error {
	if s.config.ListenAddr == "" {
		s.config.ListenAddr = ":9000"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ha/sessions", s.handleGetSessions)
	mux.HandleFunc("/ha/sessions/stream", s.handleSessionStream)
	mux.HandleFunc("/ha/health", s.handleHealth)

	s.server = &http.Server{
		Addr:    s.config.ListenAddr,
		Handler: mux,
	}

	// Start server in goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.logger.Info("Starting HA sync server", zap.String("addr", s.config.ListenAddr))
		if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
			s.logger.Error("HA sync server error", zap.Error(err))
		}
	}()

	// Start change broadcaster
	s.wg.Add(1)
	go s.broadcastLoop()

	return nil
}

// handleGetSessions returns all sessions for full sync.
// GET /ha/sessions
func (s *HASyncer) handleGetSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessions := s.store.GetAllSessions()

	msg := &SyncMessage{
		Type:        SyncTypeFull,
		Sessions:    sessions,
		Timestamp:   time.Now(),
		SequenceNum: atomic.LoadUint64(&s.sequenceNum),
		NodeID:      s.config.NodeID,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(msg); err != nil {
		s.logger.Error("Failed to encode sessions", zap.Error(err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.stats.MessagesSent++
	s.mu.Unlock()

	s.logger.Info("Sent full sync",
		zap.Int("sessions", len(sessions)),
		zap.String("client", r.RemoteAddr),
	)
}

// handleSessionStream streams session updates via Server-Sent Events.
// GET /ha/sessions/stream
func (s *HASyncer) handleSessionStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set up SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Create channel for this client
	clientID := r.RemoteAddr
	msgChan := make(chan *SyncMessage, 100)

	s.sseClientsMu.Lock()
	s.sseClients[clientID] = msgChan
	s.sseClientsMu.Unlock()

	s.logger.Info("SSE client connected", zap.String("client", clientID))

	defer func() {
		s.sseClientsMu.Lock()
		delete(s.sseClients, clientID)
		s.sseClientsMu.Unlock()
		s.logger.Info("SSE client disconnected", zap.String("client", clientID))
	}()

	// Send initial heartbeat
	s.sendSSE(w, flusher, &SyncMessage{
		Type:      SyncTypeHeartbeat,
		Timestamp: time.Now(),
		NodeID:    s.config.NodeID,
	})

	// Stream updates
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.ctx.Done():
			return
		case msg, ok := <-msgChan:
			if !ok {
				return
			}
			s.sendSSE(w, flusher, msg)
		}
	}
}

// sendSSE sends a Server-Sent Event.
func (s *HASyncer) sendSSE(w http.ResponseWriter, flusher http.Flusher, msg *SyncMessage) {
	data, err := msg.Encode()
	if err != nil {
		s.logger.Error("Failed to encode SSE message", zap.Error(err))
		return
	}

	fmt.Fprintf(w, "event: %s\n", msg.Type)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()

	s.mu.Lock()
	s.stats.MessagesSent++
	s.stats.BytesSent += uint64(len(data))
	s.mu.Unlock()
}

// handleHealth returns health status.
// GET /ha/health
func (s *HASyncer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	stats := s.stats
	s.mu.RUnlock()

	stats.SessionsSynced = s.store.GetSessionCount()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"role":    s.config.Role,
		"node_id": s.config.NodeID,
		"stats":   stats,
	})
}

// broadcastLoop sends pending changes to all connected standby nodes.
func (s *HASyncer) broadcastLoop() {
	defer s.wg.Done()

	heartbeatTicker := time.NewTicker(s.config.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return

		case msg := <-s.pendingChanges:
			s.broadcastToClients(msg)

		case <-heartbeatTicker.C:
			s.broadcastToClients(&SyncMessage{
				Type:        SyncTypeHeartbeat,
				Timestamp:   time.Now(),
				SequenceNum: atomic.LoadUint64(&s.sequenceNum),
				NodeID:      s.config.NodeID,
			})
		}
	}
}

// broadcastToClients sends a message to all connected SSE clients.
func (s *HASyncer) broadcastToClients(msg *SyncMessage) {
	s.sseClientsMu.RLock()
	defer s.sseClientsMu.RUnlock()

	for clientID, ch := range s.sseClients {
		select {
		case ch <- msg:
		default:
			s.logger.Warn("Client channel full, dropping message",
				zap.String("client", clientID),
			)
		}
	}
}

// PushChange queues a session change to be pushed to standby nodes.
// Called by the active node's session manager when state changes.
func (s *HASyncer) PushChange(changeType SyncMessageType, session *SessionState) error {
	if s.config.Role != RoleActive {
		return fmt.Errorf("PushChange can only be called on active node")
	}

	seq := atomic.AddUint64(&s.sequenceNum, 1)

	msg := &SyncMessage{
		Type:        changeType,
		Sessions:    []SessionState{*session},
		Timestamp:   time.Now(),
		SequenceNum: seq,
		NodeID:      s.config.NodeID,
	}

	select {
	case s.pendingChanges <- msg:
		return nil
	default:
		return fmt.Errorf("change queue full")
	}
}

// ===== Standby Node Implementation =====

// startStandby connects to the active node and starts receiving updates.
func (s *HASyncer) startStandby() error {
	if s.config.Partner == nil {
		return fmt.Errorf("partner info required for standby mode")
	}

	// Start the connection manager
	s.wg.Add(1)
	go s.standbyLoop()

	return nil
}

// standbyLoop manages the connection to the active node.
func (s *HASyncer) standbyLoop() {
	defer s.wg.Done()

	fullSyncTicker := time.NewTicker(s.config.FullSyncInterval)
	if s.config.FullSyncInterval == 0 {
		fullSyncTicker.Stop()
	}
	defer fullSyncTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Perform initial full sync
		if err := s.performFullSync(); err != nil {
			s.logger.Error("Full sync failed", zap.Error(err))
			s.recordError(err)
			s.waitReconnect()
			continue
		}

		// Connect to SSE stream
		if err := s.connectToStream(); err != nil {
			s.logger.Error("Stream connection failed", zap.Error(err))
			s.recordError(err)
			s.waitReconnect()
			continue
		}
	}
}

// performFullSync requests all sessions from the active node.
func (s *HASyncer) performFullSync() error {
	url := fmt.Sprintf("http://%s/ha/sessions", s.config.Partner.Endpoint)

	ctx, cancel := context.WithTimeout(s.ctx, s.config.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var msg SyncMessage
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	// Apply full sync
	s.receivedMu.Lock()
	s.receivedSessions = make(map[string]*SessionState)
	for i := range msg.Sessions {
		session := msg.Sessions[i]
		s.receivedSessions[session.SessionID] = &session
		if err := s.store.PutSession(&session); err != nil {
			s.logger.Warn("Failed to store session",
				zap.String("session_id", session.SessionID),
				zap.Error(err),
			)
		}
	}
	s.receivedMu.Unlock()

	s.mu.Lock()
	s.stats.LastSyncTime = time.Now()
	s.stats.SessionsSynced = len(msg.Sessions)
	s.stats.MessagesReceived++
	s.stats.PartnerNodeID = msg.NodeID
	s.mu.Unlock()

	s.logger.Info("Full sync completed",
		zap.Int("sessions", len(msg.Sessions)),
		zap.Uint64("sequence", msg.SequenceNum),
	)

	return nil
}

// connectToStream connects to the SSE stream from the active node.
func (s *HASyncer) connectToStream() error {
	url := fmt.Sprintf("http://%s/ha/sessions/stream", s.config.Partner.Endpoint)

	req, err := http.NewRequestWithContext(s.ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	s.mu.Lock()
	s.connected = true
	s.stats.Connected = true
	s.mu.Unlock()

	s.logger.Info("Connected to active node SSE stream",
		zap.String("partner", s.config.Partner.Endpoint),
	)

	defer func() {
		s.mu.Lock()
		s.connected = false
		s.stats.Connected = false
		s.mu.Unlock()
	}()

	// Read SSE events
	reader := bufio.NewReader(resp.Body)
	for {
		select {
		case <-s.ctx.Done():
			return nil
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF || isConnectionClosed(err) {
				return fmt.Errorf("connection closed")
			}
			return fmt.Errorf("read error: %w", err)
		}

		// Parse SSE format
		if bytes.HasPrefix([]byte(line), []byte("data: ")) {
			data := line[6 : len(line)-1] // Remove "data: " prefix and trailing newline
			if err := s.handleSSEData([]byte(data)); err != nil {
				s.logger.Warn("Failed to handle SSE data", zap.Error(err))
			}
		}
	}
}

// handleSSEData processes an incoming SSE data payload.
func (s *HASyncer) handleSSEData(data []byte) error {
	msg, err := DecodeSyncMessage(data)
	if err != nil {
		return fmt.Errorf("decode message: %w", err)
	}

	s.mu.Lock()
	s.stats.MessagesReceived++
	s.stats.BytesReceived += uint64(len(data))
	s.mu.Unlock()

	switch msg.Type {
	case SyncTypeHeartbeat:
		// Just update stats
		s.logger.Debug("Received heartbeat", zap.String("from", msg.NodeID))

	case SyncTypeAdd, SyncTypeUpdate:
		for i := range msg.Sessions {
			session := msg.Sessions[i]
			s.receivedMu.Lock()
			s.receivedSessions[session.SessionID] = &session
			s.receivedMu.Unlock()

			if err := s.store.PutSession(&session); err != nil {
				s.logger.Warn("Failed to store session",
					zap.String("session_id", session.SessionID),
					zap.Error(err),
				)
			}

			s.logger.Debug("Session synced",
				zap.String("type", string(msg.Type)),
				zap.String("session_id", session.SessionID),
				zap.String("mac", session.MAC),
				zap.String("ip", session.IP),
			)
		}

	case SyncTypeDelete:
		for i := range msg.Sessions {
			session := msg.Sessions[i]
			s.receivedMu.Lock()
			delete(s.receivedSessions, session.SessionID)
			s.receivedMu.Unlock()

			if err := s.store.DeleteSession(session.SessionID); err != nil {
				s.logger.Warn("Failed to delete session",
					zap.String("session_id", session.SessionID),
					zap.Error(err),
				)
			}

			s.logger.Debug("Session deleted",
				zap.String("session_id", session.SessionID),
			)
		}

	case SyncTypeFull:
		// Unexpected in stream, but handle gracefully
		s.receivedMu.Lock()
		s.receivedSessions = make(map[string]*SessionState)
		for i := range msg.Sessions {
			session := msg.Sessions[i]
			s.receivedSessions[session.SessionID] = &session
			s.store.PutSession(&session)
		}
		s.receivedMu.Unlock()
	}

	s.mu.Lock()
	s.stats.SessionsSynced = len(s.receivedSessions)
	s.mu.Unlock()

	return nil
}

// waitReconnect waits for the reconnect interval.
func (s *HASyncer) waitReconnect() {
	select {
	case <-s.ctx.Done():
	case <-time.After(s.config.ReconnectInterval):
	}
}

// recordError records an error in stats.
func (s *HASyncer) recordError(err error) {
	s.mu.Lock()
	s.stats.LastError = err.Error()
	s.stats.LastErrorTime = time.Now()
	s.mu.Unlock()
}

// ===== Public API =====

// Stats returns current sync statistics.
func (s *HASyncer) Stats() SyncStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := s.stats
	stats.SessionsSynced = s.store.GetSessionCount()
	return stats
}

// IsConnected returns true if connected to partner.
func (s *HASyncer) IsConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connected
}

// GetReceivedSession returns a session received from the active node (standby only).
func (s *HASyncer) GetReceivedSession(sessionID string) (*SessionState, bool) {
	s.receivedMu.RLock()
	defer s.receivedMu.RUnlock()
	session, ok := s.receivedSessions[sessionID]
	return session, ok
}

// GetAllReceivedSessions returns all sessions received from active (standby only).
func (s *HASyncer) GetAllReceivedSessions() []*SessionState {
	s.receivedMu.RLock()
	defer s.receivedMu.RUnlock()
	sessions := make([]*SessionState, 0, len(s.receivedSessions))
	for _, session := range s.receivedSessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// isConnectionClosed checks if the error indicates a closed connection.
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(*net.OpError); ok {
		return netErr.Err.Error() == "use of closed network connection"
	}
	return false
}
