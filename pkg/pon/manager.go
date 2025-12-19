package pon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/nexus"
	"go.uber.org/zap"
)

// NTEState represents the connection state of an NTE.
type NTEState int

const (
	// NTEStateUnknown - state is unknown.
	NTEStateUnknown NTEState = iota
	// NTEStateConnected - NTE is physically connected.
	NTEStateConnected
	// NTEStateDisconnected - NTE was connected but is now offline.
	NTEStateDisconnected
	// NTEStateUnconfigured - NTE is connected but not yet provisioned.
	NTEStateUnconfigured
)

func (s NTEState) String() string {
	switch s {
	case NTEStateConnected:
		return "CONNECTED"
	case NTEStateDisconnected:
		return "DISCONNECTED"
	case NTEStateUnconfigured:
		return "UNCONFIGURED"
	default:
		return "UNKNOWN"
	}
}

// DiscoveryEvent represents an NTE discovery event from the PON hardware.
type DiscoveryEvent struct {
	SerialNumber string
	PONPort      string
	Timestamp    time.Time
	State        NTEState
}

// ProvisioningResult represents the result of an NTE provisioning attempt.
type ProvisioningResult struct {
	NTEID    string
	Success  bool
	Error    error
	STag     uint16
	CTag     uint16
	Duration time.Duration
}

// ManagerConfig contains configuration for the PON manager.
type ManagerConfig struct {
	// DeviceID is this OLT's unique identifier.
	DeviceID string

	// DefaultISPID is the ISP to assign to discovered NTEs by default.
	DefaultISPID string

	// DefaultQoS is the default QoS profile for new subscribers.
	DefaultQoS QoSProfile

	// DiscoveryRetries is how many times to retry provisioning on failure.
	DiscoveryRetries int

	// DiscoveryRetryDelay is the delay between retries.
	DiscoveryRetryDelay time.Duration

	// WalledGardenEnabled enables walled garden for unprovisioned NTEs.
	WalledGardenEnabled bool
}

// QoSProfile represents default QoS settings.
type QoSProfile struct {
	DownloadBps uint64
	UploadBps   uint64
}

// DefaultManagerConfig returns sensible defaults.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		DefaultQoS: QoSProfile{
			DownloadBps: 100_000_000, // 100 Mbps
			UploadBps:   50_000_000,  // 50 Mbps
		},
		DiscoveryRetries:    3,
		DiscoveryRetryDelay: 5 * time.Second,
		WalledGardenEnabled: true,
	}
}

// Manager handles PON port management and NTE discovery for the OLT-BNG.
type Manager struct {
	config      ManagerConfig
	logger      *zap.Logger
	nexusClient *nexus.Client
	vlanAlloc   *nexus.VLANAllocator

	// Callbacks
	onNTEDiscovered   func(*DiscoveryEvent)
	onNTEProvisioned  func(*ProvisioningResult)
	onNTEDisconnected func(string)

	// Internal state
	mu          sync.RWMutex
	nteStates   map[string]NTEState
	pendingNTEs map[string]*DiscoveryEvent

	// Discovery channel for processing events
	discoveryChan chan *DiscoveryEvent

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new PON manager.
func NewManager(
	config ManagerConfig,
	nexusClient *nexus.Client,
	vlanAlloc *nexus.VLANAllocator,
	logger *zap.Logger,
) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		config:        config,
		logger:        logger,
		nexusClient:   nexusClient,
		vlanAlloc:     vlanAlloc,
		nteStates:     make(map[string]NTEState),
		pendingNTEs:   make(map[string]*DiscoveryEvent),
		discoveryChan: make(chan *DiscoveryEvent, 100),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start begins the PON manager's background operations.
func (m *Manager) Start() error {
	m.logger.Info("Starting PON manager",
		zap.String("device_id", m.config.DeviceID),
	)

	// Start discovery event processor
	m.wg.Add(1)
	go m.processDiscoveryEvents()

	// Register for NTE changes from Nexus
	m.nexusClient.OnNTEChange(m.handleNexusNTEChange)

	m.logger.Info("PON manager started")
	return nil
}

// Stop shuts down the PON manager.
func (m *Manager) Stop() error {
	m.logger.Info("Stopping PON manager")
	m.cancel()
	close(m.discoveryChan)
	m.wg.Wait()
	return nil
}

// OnNTEDiscovered registers a callback for NTE discovery events.
func (m *Manager) OnNTEDiscovered(callback func(*DiscoveryEvent)) {
	m.onNTEDiscovered = callback
}

// OnNTEProvisioned registers a callback for NTE provisioning results.
func (m *Manager) OnNTEProvisioned(callback func(*ProvisioningResult)) {
	m.onNTEProvisioned = callback
}

// OnNTEDisconnected registers a callback for NTE disconnect events.
func (m *Manager) OnNTEDisconnected(callback func(string)) {
	m.onNTEDisconnected = callback
}

// HandleDiscovery processes an NTE discovery event from PON hardware.
// This should be called when the OLT detects a new ONU/ONT.
func (m *Manager) HandleDiscovery(event *DiscoveryEvent) {
	select {
	case m.discoveryChan <- event:
	default:
		m.logger.Warn("Discovery channel full, dropping event",
			zap.String("serial", event.SerialNumber),
		)
	}
}

// processDiscoveryEvents processes NTE discovery events.
func (m *Manager) processDiscoveryEvents() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case event, ok := <-m.discoveryChan:
			if !ok {
				return
			}
			m.handleDiscoveryEvent(event)
		}
	}
}

// handleDiscoveryEvent processes a single discovery event.
func (m *Manager) handleDiscoveryEvent(event *DiscoveryEvent) {
	startTime := time.Now()

	m.logger.Info("NTE discovered",
		zap.String("serial", event.SerialNumber),
		zap.String("pon_port", event.PONPort),
	)

	// Call discovery callback
	if m.onNTEDiscovered != nil {
		m.onNTEDiscovered(event)
	}

	// Update internal state
	m.mu.Lock()
	m.nteStates[event.SerialNumber] = NTEStateUnconfigured
	m.pendingNTEs[event.SerialNumber] = event
	m.mu.Unlock()

	// Attempt provisioning with retries
	var lastErr error
	for attempt := 0; attempt <= m.config.DiscoveryRetries; attempt++ {
		if attempt > 0 {
			m.logger.Info("Retrying NTE provisioning",
				zap.String("serial", event.SerialNumber),
				zap.Int("attempt", attempt),
			)
			time.Sleep(m.config.DiscoveryRetryDelay)
		}

		result := m.provisionNTE(event)
		if result.Success {
			m.mu.Lock()
			m.nteStates[event.SerialNumber] = NTEStateConnected
			delete(m.pendingNTEs, event.SerialNumber)
			m.mu.Unlock()

			result.Duration = time.Since(startTime)
			if m.onNTEProvisioned != nil {
				m.onNTEProvisioned(result)
			}
			return
		}
		lastErr = result.Error
	}

	// All retries failed
	m.logger.Error("Failed to provision NTE after retries",
		zap.String("serial", event.SerialNumber),
		zap.Error(lastErr),
	)

	if m.onNTEProvisioned != nil {
		m.onNTEProvisioned(&ProvisioningResult{
			NTEID:    event.SerialNumber,
			Success:  false,
			Error:    lastErr,
			Duration: time.Since(startTime),
		})
	}
}

// provisionNTE attempts to provision an NTE.
func (m *Manager) provisionNTE(event *DiscoveryEvent) *ProvisioningResult {
	ctx := context.Background()

	// Check if NTE already exists in Nexus
	existingNTE, exists := m.nexusClient.GetNTEBySerial(event.SerialNumber)
	if exists && existingNTE.Provisioned {
		m.logger.Info("NTE already provisioned, updating state",
			zap.String("serial", event.SerialNumber),
		)
		existingNTE.State = "connected"
		existingNTE.LastSeen = time.Now().UTC()
		if err := m.nexusClient.SaveNTE(ctx, existingNTE); err != nil {
			return &ProvisioningResult{
				NTEID:   event.SerialNumber,
				Success: false,
				Error:   fmt.Errorf("update NTE state: %w", err),
			}
		}
		return &ProvisioningResult{
			NTEID:   event.SerialNumber,
			Success: true,
			STag:    existingNTE.STag,
			CTag:    existingNTE.CTag,
		}
	}

	// Allocate VLAN for new NTE
	vlanAlloc, err := m.vlanAlloc.Allocate(event.SerialNumber)
	if err != nil {
		return &ProvisioningResult{
			NTEID:   event.SerialNumber,
			Success: false,
			Error:   fmt.Errorf("allocate VLAN: %w", err),
		}
	}

	// Create NTE record
	nteID := fmt.Sprintf("%s-%s", m.config.DeviceID, event.SerialNumber)
	nte := &nexus.NTE{
		ID:           nteID,
		DeviceID:     m.config.DeviceID,
		SerialNumber: event.SerialNumber,
		PONPort:      event.PONPort,
		STag:         vlanAlloc.STag,
		CTag:         vlanAlloc.CTag,
		State:        "connected",
		FirstSeen:    event.Timestamp,
		LastSeen:     time.Now().UTC(),
		Provisioned:  true,
	}

	// Save NTE to Nexus
	if err := m.nexusClient.SaveNTE(ctx, nte); err != nil {
		// Rollback VLAN allocation
		m.vlanAlloc.Release(event.SerialNumber)
		return &ProvisioningResult{
			NTEID:   event.SerialNumber,
			Success: false,
			Error:   fmt.Errorf("save NTE: %w", err),
		}
	}

	// Check if subscriber exists for this NTE
	sub, exists := m.nexusClient.GetSubscriberByNTE(nteID)
	if !exists {
		// Create default subscriber
		subID := fmt.Sprintf("sub-%s", event.SerialNumber)
		sub = &nexus.Subscriber{
			ID:          subID,
			NTEID:       nteID,
			DeviceID:    m.config.DeviceID,
			STag:        vlanAlloc.STag,
			CTag:        vlanAlloc.CTag,
			ISPID:       m.config.DefaultISPID,
			State:       "active",
			RADIUSRealm: "",
		}

		if err := m.nexusClient.SaveSubscriber(ctx, sub); err != nil {
			m.logger.Warn("Failed to create default subscriber",
				zap.String("serial", event.SerialNumber),
				zap.Error(err),
			)
			// Don't fail provisioning, subscriber can be created later
		}
	}

	m.logger.Info("NTE provisioned successfully",
		zap.String("serial", event.SerialNumber),
		zap.Uint16("s_tag", vlanAlloc.STag),
		zap.Uint16("c_tag", vlanAlloc.CTag),
	)

	return &ProvisioningResult{
		NTEID:   event.SerialNumber,
		Success: true,
		STag:    vlanAlloc.STag,
		CTag:    vlanAlloc.CTag,
	}
}

// handleNexusNTEChange handles NTE changes from Nexus (CLSet sync).
func (m *Manager) handleNexusNTEChange(id string, nte *nexus.NTE, deleted bool) {
	if deleted {
		m.logger.Info("NTE deleted from Nexus", zap.String("nte_id", id))
		m.mu.Lock()
		delete(m.nteStates, nte.SerialNumber)
		m.mu.Unlock()
		m.vlanAlloc.Release(nte.SerialNumber)
		return
	}

	m.logger.Debug("NTE updated from Nexus",
		zap.String("nte_id", id),
		zap.String("state", nte.State),
	)
}

// HandleDisconnect processes an NTE disconnect event.
func (m *Manager) HandleDisconnect(serialNumber string) {
	m.logger.Info("NTE disconnected",
		zap.String("serial", serialNumber),
	)

	m.mu.Lock()
	m.nteStates[serialNumber] = NTEStateDisconnected
	m.mu.Unlock()

	// Update NTE state in Nexus
	nte, exists := m.nexusClient.GetNTEBySerial(serialNumber)
	if exists {
		nte.State = "disconnected"
		nte.LastSeen = time.Now().UTC()
		if err := m.nexusClient.SaveNTE(context.Background(), nte); err != nil {
			m.logger.Warn("Failed to update NTE disconnect state",
				zap.String("serial", serialNumber),
				zap.Error(err),
			)
		}
	}

	if m.onNTEDisconnected != nil {
		m.onNTEDisconnected(serialNumber)
	}
}

// GetNTEState returns the current state of an NTE.
func (m *Manager) GetNTEState(serialNumber string) NTEState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.nteStates[serialNumber]
	if !ok {
		return NTEStateUnknown
	}
	return state
}

// ListConnectedNTEs returns all currently connected NTEs.
func (m *Manager) ListConnectedNTEs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var ntes []string
	for serial, state := range m.nteStates {
		if state == NTEStateConnected {
			ntes = append(ntes, serial)
		}
	}
	return ntes
}

// ListPendingNTEs returns all NTEs pending provisioning.
func (m *Manager) ListPendingNTEs() []*DiscoveryEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := make([]*DiscoveryEvent, 0, len(m.pendingNTEs))
	for _, event := range m.pendingNTEs {
		events = append(events, event)
	}
	return events
}

// Stats returns PON manager statistics.
func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := ManagerStats{}
	for _, state := range m.nteStates {
		switch state {
		case NTEStateConnected:
			stats.ConnectedNTEs++
		case NTEStateDisconnected:
			stats.DisconnectedNTEs++
		case NTEStateUnconfigured:
			stats.PendingNTEs++
		}
	}
	stats.TotalNTEs = len(m.nteStates)
	return stats
}

// ManagerStats contains PON manager statistics.
type ManagerStats struct {
	TotalNTEs        int
	ConnectedNTEs    int
	DisconnectedNTEs int
	PendingNTEs      int
}
