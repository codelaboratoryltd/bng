package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// BFDManager manages Bidirectional Forwarding Detection (BFD) sessions
// for fast failover detection with BGP neighbors.
type BFDManager struct {
	config BFDConfig
	logger *zap.Logger

	mu sync.RWMutex

	// Active BFD peers
	peers map[string]*BFDPeer

	// Callbacks
	onPeerUp   func(peerIP string)
	onPeerDown func(peerIP string)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// BFDConfig holds BFD manager configuration.
type BFDConfig struct {
	// VtyshPath is the path to the vtysh binary.
	VtyshPath string

	// VtyshSocket is the path to the vtysh socket (optional).
	VtyshSocket string

	// DefaultMinRxInterval is the minimum interval (ms) for receiving BFD packets.
	DefaultMinRxInterval int

	// DefaultMinTxInterval is the minimum interval (ms) for transmitting BFD packets.
	DefaultMinTxInterval int

	// DefaultDetectMultiplier is the number of missed packets before declaring down.
	DefaultDetectMultiplier int

	// MonitorInterval is how often to poll BFD session status.
	MonitorInterval time.Duration

	// CommandTimeout is the timeout for vtysh commands.
	CommandTimeout time.Duration

	// EnableEchoMode enables BFD echo mode for lower CPU usage.
	EnableEchoMode bool
}

// DefaultBFDConfig returns sensible defaults.
// With these settings: detection time = 100ms * 3 = 300ms
func DefaultBFDConfig() BFDConfig {
	return BFDConfig{
		VtyshPath:               "/usr/bin/vtysh",
		DefaultMinRxInterval:    100, // 100ms
		DefaultMinTxInterval:    100, // 100ms
		DefaultDetectMultiplier: 3,   // 3 missed packets
		MonitorInterval:         5 * time.Second,
		CommandTimeout:          5 * time.Second,
		EnableEchoMode:          false,
	}
}

// AggressiveBFDConfig returns aggressive timer settings for sub-second failover.
// Detection time = 50ms * 3 = 150ms
func AggressiveBFDConfig() BFDConfig {
	config := DefaultBFDConfig()
	config.DefaultMinRxInterval = 50
	config.DefaultMinTxInterval = 50
	return config
}

// BFDPeer represents a BFD peer/session.
type BFDPeer struct {
	PeerIP           net.IP        `json:"peer_ip"`
	LocalIP          net.IP        `json:"local_ip,omitempty"`
	Interface        string        `json:"interface,omitempty"`
	State            BFDState      `json:"state"`
	MinRxInterval    int           `json:"min_rx_interval"`
	MinTxInterval    int           `json:"min_tx_interval"`
	DetectMultiplier int           `json:"detect_multiplier"`
	EchoMode         bool          `json:"echo_mode"`
	Multihop         bool          `json:"multihop"`
	LinkedToBGP      bool          `json:"linked_to_bgp"`
	BGPNeighborIP    net.IP        `json:"bgp_neighbor_ip,omitempty"`
	LastStateChange  time.Time     `json:"last_state_change"`
	Uptime           time.Duration `json:"uptime"`

	// Statistics
	PacketsTx      uint64    `json:"packets_tx"`
	PacketsRx      uint64    `json:"packets_rx"`
	UpCount        uint64    `json:"up_count"`
	DownCount      uint64    `json:"down_count"`
	LastPacketRecv time.Time `json:"last_packet_recv"`
}

// BFDState represents the state of a BFD session.
type BFDState int

const (
	BFDStateAdminDown BFDState = iota
	BFDStateDown
	BFDStateInit
	BFDStateUp
)

func (s BFDState) String() string {
	switch s {
	case BFDStateAdminDown:
		return "AdminDown"
	case BFDStateDown:
		return "Down"
	case BFDStateInit:
		return "Init"
	case BFDStateUp:
		return "Up"
	default:
		return "Unknown"
	}
}

// ParseBFDState parses a BFD state string from FRR.
func ParseBFDState(s string) BFDState {
	switch strings.ToLower(s) {
	case "admindown", "admin down":
		return BFDStateAdminDown
	case "down":
		return BFDStateDown
	case "init":
		return BFDStateInit
	case "up":
		return BFDStateUp
	default:
		return BFDStateDown
	}
}

// NewBFDManager creates a new BFD manager.
func NewBFDManager(config BFDConfig, logger *zap.Logger) *BFDManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &BFDManager{
		config: config,
		logger: logger,
		peers:  make(map[string]*BFDPeer),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins the BFD manager.
func (m *BFDManager) Start() error {
	m.logger.Info("Starting BFD manager",
		zap.Int("default_min_rx", m.config.DefaultMinRxInterval),
		zap.Int("default_min_tx", m.config.DefaultMinTxInterval),
		zap.Int("detect_multiplier", m.config.DefaultDetectMultiplier),
	)

	// Verify BFD daemon is running
	if err := m.checkBFD(); err != nil {
		return fmt.Errorf("BFD daemon not available: %w", err)
	}

	// Initial peer refresh
	if err := m.refreshPeers(); err != nil {
		m.logger.Warn("Failed to refresh BFD peers on start", zap.Error(err))
	}

	// Start monitor loop
	m.wg.Add(1)
	go m.monitorLoop()

	m.logger.Info("BFD manager started")
	return nil
}

// Stop shuts down the BFD manager.
func (m *BFDManager) Stop() error {
	m.logger.Info("Stopping BFD manager")
	m.cancel()
	m.wg.Wait()
	m.logger.Info("BFD manager stopped")
	return nil
}

// OnPeerUp registers a callback for BFD peer establishment.
func (m *BFDManager) OnPeerUp(callback func(peerIP string)) {
	m.onPeerUp = callback
}

// OnPeerDown registers a callback for BFD peer failure.
func (m *BFDManager) OnPeerDown(callback func(peerIP string)) {
	m.onPeerDown = callback
}

// checkBFD verifies the BFD daemon is running.
func (m *BFDManager) checkBFD() error {
	output, err := m.vtysh("show bfd peers")
	if err != nil {
		// BFD might not be configured yet, which is OK
		if strings.Contains(err.Error(), "No BFD peers") {
			return nil
		}
		return err
	}

	m.logger.Debug("BFD check passed", zap.String("output", output))
	return nil
}

// AddPeer adds a BFD peer with default settings.
func (m *BFDManager) AddPeer(peerIP net.IP) error {
	return m.AddPeerWithOptions(peerIP, m.config.DefaultMinRxInterval, m.config.DefaultMinTxInterval, m.config.DefaultDetectMultiplier, false)
}

// AddPeerWithOptions adds a BFD peer with custom settings.
func (m *BFDManager) AddPeerWithOptions(peerIP net.IP, minRx, minTx, detectMult int, multihop bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	addr := peerIP.String()

	// Build configuration commands
	var cmds []string
	cmds = append(cmds, "configure terminal", "bfd")

	if multihop {
		cmds = append(cmds, fmt.Sprintf("peer %s multihop", addr))
	} else {
		cmds = append(cmds, fmt.Sprintf("peer %s", addr))
	}

	cmds = append(cmds,
		fmt.Sprintf("receive-interval %d", minRx),
		fmt.Sprintf("transmit-interval %d", minTx),
		fmt.Sprintf("detect-multiplier %d", detectMult),
	)

	if m.config.EnableEchoMode {
		cmds = append(cmds, "echo-mode")
	} else {
		cmds = append(cmds, "no echo-mode")
	}

	cmds = append(cmds, "exit", "exit", "end")

	_, err := m.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("add BFD peer %s: %w", addr, err)
	}

	// Update local cache
	peer := &BFDPeer{
		PeerIP:           peerIP,
		State:            BFDStateDown,
		MinRxInterval:    minRx,
		MinTxInterval:    minTx,
		DetectMultiplier: detectMult,
		Multihop:         multihop,
		LastStateChange:  time.Now(),
	}
	m.peers[addr] = peer

	m.logger.Info("Added BFD peer",
		zap.String("peer_ip", addr),
		zap.Int("min_rx", minRx),
		zap.Int("min_tx", minTx),
		zap.Int("detect_mult", detectMult),
		zap.Bool("multihop", multihop),
	)

	return nil
}

// RemovePeer removes a BFD peer.
func (m *BFDManager) RemovePeer(peerIP net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	addr := peerIP.String()

	cmds := []string{
		"configure terminal",
		"bfd",
		fmt.Sprintf("no peer %s", addr),
		"exit",
		"end",
	}

	_, err := m.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("remove BFD peer %s: %w", addr, err)
	}

	delete(m.peers, addr)

	m.logger.Info("Removed BFD peer", zap.String("peer_ip", addr))
	return nil
}

// LinkToBGPNeighbor enables BFD for a BGP neighbor.
// This causes BGP to tear down the session if BFD detects failure.
func (m *BFDManager) LinkToBGPNeighbor(bgpAS uint32, neighborIP net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	addr := neighborIP.String()

	cmds := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", bgpAS),
		fmt.Sprintf("neighbor %s bfd", addr),
		"end",
	}

	_, err := m.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("link BFD to BGP neighbor %s: %w", addr, err)
	}

	// Update local cache if peer exists
	if peer, ok := m.peers[addr]; ok {
		peer.LinkedToBGP = true
		peer.BGPNeighborIP = neighborIP
	}

	m.logger.Info("Linked BFD to BGP neighbor",
		zap.Uint32("bgp_as", bgpAS),
		zap.String("neighbor_ip", addr),
	)

	return nil
}

// UnlinkFromBGPNeighbor disables BFD for a BGP neighbor.
func (m *BFDManager) UnlinkFromBGPNeighbor(bgpAS uint32, neighborIP net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	addr := neighborIP.String()

	cmds := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", bgpAS),
		fmt.Sprintf("no neighbor %s bfd", addr),
		"end",
	}

	_, err := m.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("unlink BFD from BGP neighbor %s: %w", addr, err)
	}

	if peer, ok := m.peers[addr]; ok {
		peer.LinkedToBGP = false
	}

	m.logger.Info("Unlinked BFD from BGP neighbor",
		zap.Uint32("bgp_as", bgpAS),
		zap.String("neighbor_ip", addr),
	)

	return nil
}

// GetPeer returns a BFD peer by IP.
func (m *BFDManager) GetPeer(peerIP net.IP) (*BFDPeer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	peer, ok := m.peers[peerIP.String()]
	return peer, ok
}

// ListPeers returns all BFD peers.
func (m *BFDManager) ListPeers() []*BFDPeer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make([]*BFDPeer, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	return peers
}

// GetPeerStatus fetches current peer status from FRR.
func (m *BFDManager) GetPeerStatus() (map[string]*BFDPeer, error) {
	output, err := m.vtysh("show bfd peers json")
	if err != nil {
		return nil, fmt.Errorf("get BFD peer status: %w", err)
	}

	return m.parsePeersJSON(output)
}

// Stats returns BFD statistics.
func (m *BFDManager) Stats() BFDStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := BFDStats{
		TotalPeers: len(m.peers),
	}

	for _, peer := range m.peers {
		switch peer.State {
		case BFDStateUp:
			stats.PeersUp++
		case BFDStateDown:
			stats.PeersDown++
		case BFDStateInit:
			stats.PeersInit++
		case BFDStateAdminDown:
			stats.PeersAdminDown++
		}

		stats.TotalUpEvents += peer.UpCount
		stats.TotalDownEvents += peer.DownCount
	}

	return stats
}

// BFDStats contains BFD statistics.
type BFDStats struct {
	TotalPeers      int    `json:"total_peers"`
	PeersUp         int    `json:"peers_up"`
	PeersDown       int    `json:"peers_down"`
	PeersInit       int    `json:"peers_init"`
	PeersAdminDown  int    `json:"peers_admin_down"`
	TotalUpEvents   uint64 `json:"total_up_events"`
	TotalDownEvents uint64 `json:"total_down_events"`
}

// vtysh executes a vtysh command.
func (m *BFDManager) vtysh(command string) (string, error) {
	ctx, cancel := context.WithTimeout(m.ctx, m.config.CommandTimeout)
	defer cancel()

	args := []string{"-c", command}
	if m.config.VtyshSocket != "" {
		// Use --vty_socket to specify the VTY socket directory.
		// Note: -N is for pathspace/namespace isolation, not socket paths.
		// See: https://docs.frrouting.org/en/latest/setup.html
		args = append([]string{"--vty_socket", m.config.VtyshSocket}, args...)
	}

	cmd := exec.CommandContext(ctx, m.config.VtyshPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vtysh error: %w, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// refreshPeers updates the local peer cache from FRR.
func (m *BFDManager) refreshPeers() error {
	peers, err := m.GetPeerStatus()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for addr, newState := range peers {
		if existing, ok := m.peers[addr]; ok {
			oldState := existing.State
			existing.State = newState.State
			existing.Uptime = newState.Uptime
			existing.PacketsTx = newState.PacketsTx
			existing.PacketsRx = newState.PacketsRx
			existing.LastPacketRecv = newState.LastPacketRecv

			// Check for state changes
			if oldState != newState.State {
				existing.LastStateChange = time.Now()

				if newState.State == BFDStateUp {
					existing.UpCount++
					if m.onPeerUp != nil {
						go m.onPeerUp(addr)
					}
				} else if oldState == BFDStateUp {
					existing.DownCount++
					if m.onPeerDown != nil {
						go m.onPeerDown(addr)
					}
				}

				m.logger.Info("BFD peer state changed",
					zap.String("peer_ip", addr),
					zap.String("old_state", oldState.String()),
					zap.String("new_state", newState.State.String()),
				)
			}
		} else {
			// New peer discovered
			m.peers[addr] = newState
		}
	}

	return nil
}

// monitorLoop periodically checks peer status.
func (m *BFDManager) monitorLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.MonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.refreshPeers(); err != nil {
				m.logger.Warn("Failed to refresh BFD peers", zap.Error(err))
			}
		}
	}
}

// parsePeersJSON parses FRR's "show bfd peers json" output.
func (m *BFDManager) parsePeersJSON(jsonStr string) (map[string]*BFDPeer, error) {
	// FRR BFD JSON output structure
	var raw []struct {
		Peer              string `json:"peer"`
		Local             string `json:"local,omitempty"`
		Interface         string `json:"interface,omitempty"`
		Status            string `json:"status"`
		Uptime            int64  `json:"uptime"`
		Multihop          bool   `json:"multihop"`
		ReceiveInterval   int    `json:"receive-interval"`
		TransmitInterval  int    `json:"transmit-interval"`
		DetectMultiplier  int    `json:"detect-multiplier"`
		EchoInterval      int    `json:"echo-interval,omitempty"`
		RemoteReceiveInt  int    `json:"remote-receive-interval"`
		RemoteTransmitInt int    `json:"remote-transmit-interval"`
		RemoteEchoInt     int    `json:"remote-echo-interval,omitempty"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		// Try to handle empty output
		if strings.TrimSpace(jsonStr) == "" || strings.Contains(jsonStr, "No BFD peers") {
			return make(map[string]*BFDPeer), nil
		}
		return nil, fmt.Errorf("parse BFD peers JSON: %w", err)
	}

	peers := make(map[string]*BFDPeer)

	for _, p := range raw {
		peer := &BFDPeer{
			PeerIP:           net.ParseIP(p.Peer),
			LocalIP:          net.ParseIP(p.Local),
			Interface:        p.Interface,
			State:            ParseBFDState(p.Status),
			MinRxInterval:    p.ReceiveInterval,
			MinTxInterval:    p.TransmitInterval,
			DetectMultiplier: p.DetectMultiplier,
			Multihop:         p.Multihop,
			Uptime:           time.Duration(p.Uptime) * time.Millisecond,
		}

		peers[p.Peer] = peer
	}

	return peers, nil
}

// GenerateConfig generates FRR BFD configuration.
func (m *BFDManager) GenerateConfig() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var buf bytes.Buffer

	buf.WriteString("! BFD Configuration generated by BNG\n")
	buf.WriteString("!\n")
	buf.WriteString("bfd\n")

	for _, peer := range m.peers {
		if peer.Multihop {
			buf.WriteString(fmt.Sprintf(" peer %s multihop\n", peer.PeerIP.String()))
		} else {
			buf.WriteString(fmt.Sprintf(" peer %s\n", peer.PeerIP.String()))
		}
		buf.WriteString(fmt.Sprintf("  receive-interval %d\n", peer.MinRxInterval))
		buf.WriteString(fmt.Sprintf("  transmit-interval %d\n", peer.MinTxInterval))
		buf.WriteString(fmt.Sprintf("  detect-multiplier %d\n", peer.DetectMultiplier))
		if peer.EchoMode {
			buf.WriteString("  echo-mode\n")
		}
		buf.WriteString(" !\n")
	}

	buf.WriteString("!\n")

	return buf.String()
}

// DetectionTime returns the calculated detection time for a peer in milliseconds.
func (peer *BFDPeer) DetectionTime() int {
	return peer.MinRxInterval * peer.DetectMultiplier
}

// IsHealthy returns true if the BFD session is up.
func (peer *BFDPeer) IsHealthy() bool {
	return peer.State == BFDStateUp
}
