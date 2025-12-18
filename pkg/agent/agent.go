package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Version is the agent version, set at build time.
var Version = "0.1.0"

// Config contains the full agent configuration.
type Config struct {
	Bootstrap         BootstrapConfig `yaml:"bootstrap"`
	DataDir           string          `yaml:"data_dir"`
	HeartbeatInterval time.Duration   `yaml:"heartbeat_interval"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Bootstrap:         DefaultBootstrapConfig(),
		DataDir:           "/var/lib/neelix",
		HeartbeatInterval: 30 * time.Second,
	}
}

// StateChangeHandler is called when the agent state changes.
type StateChangeHandler func(oldState, newState State)

// ConfigChangeHandler is called when configuration changes.
type ConfigChangeHandler func(change ConfigChange)

// ISPChurnHandler is called when a subscriber changes ISPs.
type ISPChurnHandler func(event ISPChurnEvent)

// Agent is the main Neelix agent that runs on each OLT.
type Agent struct {
	config       Config
	logger       *zap.Logger
	bootstrap    *Bootstrap
	deviceInfo   *DeviceInfo
	deviceConfig *DeviceConfig

	// State
	mu           sync.RWMutex
	state        State
	deviceID     string
	lastSyncTime time.Time
	startTime    time.Time

	// Subscribers cache
	subscribers   map[string]*Subscriber
	subscribersMu sync.RWMutex

	// NTEs cache
	ntes   map[string]*NTE
	ntesMu sync.RWMutex

	// Allocations cache
	allocations   map[string]*Allocation
	allocationsMu sync.RWMutex

	// Handlers
	stateChangeHandlers  []StateChangeHandler
	configChangeHandlers []ConfigChangeHandler
	ispChurnHandlers     []ISPChurnHandler

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new Agent instance.
func New(config Config, logger *zap.Logger) (*Agent, error) {
	if config.Bootstrap.NeelixServerURL == "" {
		return nil, fmt.Errorf("neelix_server_url is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	a := &Agent{
		config:      config,
		logger:      logger,
		bootstrap:   NewBootstrap(config.Bootstrap, logger),
		state:       StateBootstrap,
		startTime:   time.Now(),
		subscribers: make(map[string]*Subscriber),
		ntes:        make(map[string]*NTE),
		allocations: make(map[string]*Allocation),
		ctx:         ctx,
		cancel:      cancel,
	}

	return a, nil
}

// Start starts the agent.
func (a *Agent) Start() error {
	a.logger.Info("Starting Neelix agent", zap.String("version", Version))

	// Get device info
	var err error
	a.deviceInfo, err = a.bootstrap.GetDeviceInfo()
	if err != nil {
		return fmt.Errorf("failed to get device info: %w", err)
	}

	a.logger.Info("Device info",
		zap.String("serial", a.deviceInfo.Serial),
		zap.String("mac", a.deviceInfo.MAC),
		zap.String("model", a.deviceInfo.Model),
	)

	// Start bootstrap process
	a.wg.Add(1)
	go a.bootstrapLoop()

	return nil
}

// Stop stops the agent gracefully.
func (a *Agent) Stop() error {
	a.logger.Info("Stopping Neelix agent")
	a.cancel()
	a.wg.Wait()
	return nil
}

// State returns the current agent state.
func (a *Agent) State() State {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

// DeviceID returns the assigned device ID.
func (a *Agent) DeviceID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.deviceID
}

// DeviceConfig returns the current device configuration.
func (a *Agent) DeviceConfig() *DeviceConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.deviceConfig
}

// IsOnline returns true if the agent is connected to the CLSet mesh.
func (a *Agent) IsOnline() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state == StateConnected
}

// Uptime returns the agent uptime.
func (a *Agent) Uptime() time.Duration {
	return time.Since(a.startTime)
}

// OnStateChange registers a handler for state changes.
func (a *Agent) OnStateChange(handler StateChangeHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stateChangeHandlers = append(a.stateChangeHandlers, handler)
}

// OnConfigChange registers a handler for config changes.
func (a *Agent) OnConfigChange(handler ConfigChangeHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.configChangeHandlers = append(a.configChangeHandlers, handler)
}

// OnISPChurn registers a handler for ISP churn events.
func (a *Agent) OnISPChurn(handler ISPChurnHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ispChurnHandlers = append(a.ispChurnHandlers, handler)
}

// setState changes the agent state and notifies handlers.
func (a *Agent) setState(newState State) {
	a.mu.Lock()
	oldState := a.state
	if oldState == newState {
		a.mu.Unlock()
		return
	}
	a.state = newState
	handlers := make([]StateChangeHandler, len(a.stateChangeHandlers))
	copy(handlers, a.stateChangeHandlers)
	a.mu.Unlock()

	a.logger.Info("Agent state changed",
		zap.String("old_state", oldState.String()),
		zap.String("new_state", newState.String()),
	)

	for _, handler := range handlers {
		handler(oldState, newState)
	}
}

// bootstrapLoop handles the initial registration and state transitions.
func (a *Agent) bootstrapLoop() {
	defer a.wg.Done()

	a.logger.Info("Starting bootstrap process")

	// Attempt registration
	resp, err := a.bootstrap.RegisterWithRetry(a.ctx)
	if err != nil {
		if a.ctx.Err() != nil {
			a.logger.Info("Bootstrap cancelled")
			return
		}
		a.logger.Error("Bootstrap failed", zap.Error(err))
		return
	}

	// Store configuration
	a.mu.Lock()
	a.deviceID = resp.DeviceID
	a.deviceConfig = resp.Config
	a.mu.Unlock()

	a.logger.Info("Bootstrap complete",
		zap.String("device_id", resp.DeviceID),
		zap.Int("clset_peers", len(resp.CLSetPeers)),
	)

	// Transition to connected state
	a.setState(StateConnected)

	// Start background tasks
	a.wg.Add(1)
	go a.heartbeatLoop()

	a.wg.Add(1)
	go a.watchLoop()
}

// heartbeatLoop sends periodic heartbeats.
func (a *Agent) heartbeatLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat()
		}
	}
}

// sendHeartbeat sends a heartbeat to update device status.
func (a *Agent) sendHeartbeat() {
	a.subscribersMu.RLock()
	subCount := len(a.subscribers)
	a.subscribersMu.RUnlock()

	a.ntesMu.RLock()
	nteCount := len(a.ntes)
	a.ntesMu.RUnlock()

	hb := Heartbeat{
		DeviceID:       a.DeviceID(),
		Status:         a.State().String(),
		Timestamp:      time.Now().UTC(),
		Uptime:         int64(a.Uptime().Seconds()),
		Subscribers:    subCount,
		NTEsDiscovered: nteCount,
	}

	a.logger.Debug("Sending heartbeat",
		zap.String("status", hb.Status),
		zap.Int("subscribers", hb.Subscribers),
		zap.Int("ntes", hb.NTEsDiscovered),
	)

	// TODO: Send heartbeat to CLSet
	// For now, just log it
	_ = hb
}

// watchLoop watches for configuration changes.
func (a *Agent) watchLoop() {
	defer a.wg.Done()

	// TODO: Implement CLSet watch
	// This would watch paths like:
	// - /devices/{device-id}/config
	// - /subscribers/*
	// - /ispcos/*

	<-a.ctx.Done()
}

// GetSubscriber returns a subscriber by ID.
func (a *Agent) GetSubscriber(subscriberID string) *Subscriber {
	a.subscribersMu.RLock()
	defer a.subscribersMu.RUnlock()
	return a.subscribers[subscriberID]
}

// GetSubscriberByMAC returns a subscriber by MAC address.
func (a *Agent) GetSubscriberByMAC(mac string) *Subscriber {
	a.subscribersMu.RLock()
	defer a.subscribersMu.RUnlock()

	for _, sub := range a.subscribers {
		if sub.MACString == mac {
			return sub
		}
	}
	return nil
}

// GetSubscriberByNTE returns a subscriber by NTE (ONT) serial.
func (a *Agent) GetSubscriberByNTE(nteSerial string) *Subscriber {
	a.subscribersMu.RLock()
	defer a.subscribersMu.RUnlock()

	for _, sub := range a.subscribers {
		if sub.NTEID == nteSerial {
			return sub
		}
	}
	return nil
}

// SetSubscriber stores or updates a subscriber.
func (a *Agent) SetSubscriber(sub *Subscriber) {
	a.subscribersMu.Lock()
	defer a.subscribersMu.Unlock()

	// Check for ISP churn
	if existing, ok := a.subscribers[sub.SubscriberID]; ok {
		if existing.ISPID != sub.ISPID && existing.ISPID != "" {
			a.handleISPChurn(existing.SubscriberID, existing.ISPID, sub.ISPID)
		}
	}

	a.subscribers[sub.SubscriberID] = sub
}

// RemoveSubscriber removes a subscriber.
func (a *Agent) RemoveSubscriber(subscriberID string) {
	a.subscribersMu.Lock()
	defer a.subscribersMu.Unlock()
	delete(a.subscribers, subscriberID)
}

// GetSubscriberCount returns the number of subscribers.
func (a *Agent) GetSubscriberCount() int {
	a.subscribersMu.RLock()
	defer a.subscribersMu.RUnlock()
	return len(a.subscribers)
}

// GetSubscriberCountByISP returns subscriber counts per ISP.
func (a *Agent) GetSubscriberCountByISP() map[string]int {
	a.subscribersMu.RLock()
	defer a.subscribersMu.RUnlock()

	counts := make(map[string]int)
	for _, sub := range a.subscribers {
		counts[sub.ISPID]++
	}
	return counts
}

// handleISPChurn processes an ISP churn event.
func (a *Agent) handleISPChurn(subscriberID, oldISP, newISP string) {
	event := ISPChurnEvent{
		SubscriberID: subscriberID,
		OldISPID:     oldISP,
		NewISPID:     newISP,
		Timestamp:    time.Now().UTC(),
	}

	a.logger.Info("ISP churn detected",
		zap.String("subscriber", subscriberID),
		zap.String("old_isp", oldISP),
		zap.String("new_isp", newISP),
	)

	a.mu.RLock()
	handlers := make([]ISPChurnHandler, len(a.ispChurnHandlers))
	copy(handlers, a.ispChurnHandlers)
	a.mu.RUnlock()

	for _, handler := range handlers {
		handler(event)
	}
}

// GetNTE returns an NTE by serial.
func (a *Agent) GetNTE(serial string) *NTE {
	a.ntesMu.RLock()
	defer a.ntesMu.RUnlock()
	return a.ntes[serial]
}

// SetNTE stores or updates an NTE.
func (a *Agent) SetNTE(nte *NTE) {
	a.ntesMu.Lock()
	defer a.ntesMu.Unlock()
	a.ntes[nte.Serial] = nte
}

// RemoveNTE removes an NTE.
func (a *Agent) RemoveNTE(serial string) {
	a.ntesMu.Lock()
	defer a.ntesMu.Unlock()
	delete(a.ntes, serial)
}

// GetNTECount returns the number of discovered NTEs.
func (a *Agent) GetNTECount() int {
	a.ntesMu.RLock()
	defer a.ntesMu.RUnlock()
	return len(a.ntes)
}

// GetISPConfig returns the configuration for a specific ISP.
func (a *Agent) GetISPConfig(ispID string) *ISPConfig {
	config := a.DeviceConfig()
	if config == nil {
		return nil
	}

	for i := range config.ISPs {
		if config.ISPs[i].ISPID == ispID {
			return &config.ISPs[i]
		}
	}
	return nil
}

// Health returns the agent health status.
func (a *Agent) Health() map[string]interface{} {
	return map[string]interface{}{
		"status":         a.State().String(),
		"device_id":      a.DeviceID(),
		"uptime_seconds": int64(a.Uptime().Seconds()),
		"subscribers":    a.GetSubscriberCount(),
		"ntes":           a.GetNTECount(),
		"version":        Version,
		"online":         a.IsOnline(),
	}
}
