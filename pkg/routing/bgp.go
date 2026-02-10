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

// BGPController manages BGP configuration via FRR (vtysh).
type BGPController struct {
	config BGPConfig
	logger *zap.Logger

	mu sync.RWMutex

	// Local state cache
	neighbors     map[string]*BGPNeighbor
	announcements map[string]*BGPAnnouncement

	// Callbacks
	onNeighborUp   func(neighbor string)
	onNeighborDown func(neighbor string)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// BGPConfig holds BGP controller configuration.
type BGPConfig struct {
	// LocalAS is this router's autonomous system number.
	LocalAS uint32

	// RouterID is the BGP router ID (usually an IP address).
	RouterID net.IP

	// VtyshPath is the path to the vtysh binary.
	VtyshPath string

	// VtyshSocket is the path to the vtysh socket (optional).
	VtyshSocket string

	// MonitorInterval is how often to poll neighbor status.
	MonitorInterval time.Duration

	// CommandTimeout is the timeout for vtysh commands.
	CommandTimeout time.Duration
}

// DefaultBGPConfig returns sensible defaults.
func DefaultBGPConfig() BGPConfig {
	return BGPConfig{
		VtyshPath:       "/usr/bin/vtysh",
		MonitorInterval: 10 * time.Second,
		CommandTimeout:  5 * time.Second,
	}
}

// BGPNeighbor represents a BGP neighbor/peer.
type BGPNeighbor struct {
	Address         net.IP        `json:"address"`
	RemoteAS        uint32        `json:"remote_as"`
	Description     string        `json:"description"`
	State           BGPState      `json:"state"`
	Uptime          time.Duration `json:"uptime"`
	PrefixesRecv    int           `json:"prefixes_received"`
	PrefixesSent    int           `json:"prefixes_sent"`
	LastError       string        `json:"last_error,omitempty"`
	BFDEnabled      bool          `json:"bfd_enabled"`
	RouteMapIn      string        `json:"route_map_in,omitempty"`
	RouteMapOut     string        `json:"route_map_out,omitempty"`
	UpdateSource    net.IP        `json:"update_source,omitempty"`
	NextHopSelf     bool          `json:"next_hop_self"`
	RouteTableID    int           `json:"route_table_id,omitempty"` // For multi-ISP routing
	LastStateChange time.Time     `json:"last_state_change"`
}

// BGPState represents the state of a BGP session.
type BGPState int

const (
	BGPStateIdle BGPState = iota
	BGPStateConnect
	BGPStateActive
	BGPStateOpenSent
	BGPStateOpenConfirm
	BGPStateEstablished
)

func (s BGPState) String() string {
	switch s {
	case BGPStateIdle:
		return "Idle"
	case BGPStateConnect:
		return "Connect"
	case BGPStateActive:
		return "Active"
	case BGPStateOpenSent:
		return "OpenSent"
	case BGPStateOpenConfirm:
		return "OpenConfirm"
	case BGPStateEstablished:
		return "Established"
	default:
		return "Unknown"
	}
}

// ParseBGPState parses a state string from FRR.
func ParseBGPState(s string) BGPState {
	switch strings.ToLower(s) {
	case "idle":
		return BGPStateIdle
	case "connect":
		return BGPStateConnect
	case "active":
		return BGPStateActive
	case "opensent":
		return BGPStateOpenSent
	case "openconfirm":
		return BGPStateOpenConfirm
	case "established":
		return BGPStateEstablished
	default:
		return BGPStateIdle
	}
}

// BGPAnnouncement represents an announced prefix.
type BGPAnnouncement struct {
	Prefix    *net.IPNet `json:"prefix"`
	NextHop   net.IP     `json:"next_hop,omitempty"`
	Community string     `json:"community,omitempty"`
	LocalPref uint32     `json:"local_pref,omitempty"`
	MED       uint32     `json:"med,omitempty"`
}

// NewBGPController creates a new BGP controller.
func NewBGPController(config BGPConfig, logger *zap.Logger) *BGPController {
	ctx, cancel := context.WithCancel(context.Background())

	return &BGPController{
		config:        config,
		logger:        logger,
		neighbors:     make(map[string]*BGPNeighbor),
		announcements: make(map[string]*BGPAnnouncement),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start begins the BGP controller.
func (b *BGPController) Start() error {
	b.logger.Info("Starting BGP controller",
		zap.Uint32("local_as", b.config.LocalAS),
		zap.String("router_id", b.config.RouterID.String()),
	)

	// Verify FRR is available
	if err := b.checkFRR(); err != nil {
		return fmt.Errorf("FRR not available: %w", err)
	}

	// Initial neighbor refresh
	if err := b.refreshNeighbors(); err != nil {
		b.logger.Warn("Failed to refresh neighbors on start", zap.Error(err))
	}

	// Start monitor loop
	b.wg.Add(1)
	go b.monitorLoop()

	b.logger.Info("BGP controller started")
	return nil
}

// Stop shuts down the BGP controller.
func (b *BGPController) Stop() error {
	b.logger.Info("Stopping BGP controller")
	b.cancel()
	b.wg.Wait()
	return nil
}

// OnNeighborUp registers a callback for neighbor establishment.
func (b *BGPController) OnNeighborUp(callback func(neighbor string)) {
	b.onNeighborUp = callback
}

// OnNeighborDown registers a callback for neighbor failure.
func (b *BGPController) OnNeighborDown(callback func(neighbor string)) {
	b.onNeighborDown = callback
}

// checkFRR verifies FRR is running and accessible.
func (b *BGPController) checkFRR() error {
	output, err := b.vtysh("show version")
	if err != nil {
		return err
	}

	if !strings.Contains(output, "FRRouting") {
		return fmt.Errorf("unexpected vtysh output: %s", output)
	}

	b.logger.Debug("FRR version check passed", zap.String("output", output))
	return nil
}

// AddNeighbor adds a BGP neighbor.
func (b *BGPController) AddNeighbor(neighbor *BGPNeighbor) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	addr := neighbor.Address.String()

	// Build configuration commands
	cmds := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", b.config.LocalAS),
		fmt.Sprintf("neighbor %s remote-as %d", addr, neighbor.RemoteAS),
	}

	if neighbor.Description != "" {
		cmds = append(cmds, fmt.Sprintf("neighbor %s description %s", addr, neighbor.Description))
	}

	if neighbor.UpdateSource != nil {
		cmds = append(cmds, fmt.Sprintf("neighbor %s update-source %s", addr, neighbor.UpdateSource.String()))
	}

	if neighbor.RouteMapIn != "" {
		cmds = append(cmds, fmt.Sprintf("neighbor %s route-map %s in", addr, neighbor.RouteMapIn))
	}

	if neighbor.RouteMapOut != "" {
		cmds = append(cmds, fmt.Sprintf("neighbor %s route-map %s out", addr, neighbor.RouteMapOut))
	}

	if neighbor.NextHopSelf {
		cmds = append(cmds, fmt.Sprintf("neighbor %s next-hop-self", addr))
	}

	if neighbor.BFDEnabled {
		cmds = append(cmds, fmt.Sprintf("neighbor %s bfd", addr))
	}

	cmds = append(cmds, "end")

	// Execute configuration
	_, err := b.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("add neighbor %s: %w", addr, err)
	}

	// Update local cache
	neighbor.State = BGPStateIdle
	neighbor.LastStateChange = time.Now()
	b.neighbors[addr] = neighbor

	b.logger.Info("Added BGP neighbor",
		zap.String("address", addr),
		zap.Uint32("remote_as", neighbor.RemoteAS),
	)

	return nil
}

// RemoveNeighbor removes a BGP neighbor.
func (b *BGPController) RemoveNeighbor(address net.IP) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	addr := address.String()

	cmds := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", b.config.LocalAS),
		fmt.Sprintf("no neighbor %s", addr),
		"end",
	}

	_, err := b.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("remove neighbor %s: %w", addr, err)
	}

	delete(b.neighbors, addr)

	b.logger.Info("Removed BGP neighbor", zap.String("address", addr))
	return nil
}

// GetNeighbor returns a neighbor by address.
func (b *BGPController) GetNeighbor(address net.IP) (*BGPNeighbor, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n, ok := b.neighbors[address.String()]
	return n, ok
}

// ListNeighbors returns all neighbors.
func (b *BGPController) ListNeighbors() []*BGPNeighbor {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*BGPNeighbor, 0, len(b.neighbors))
	for _, n := range b.neighbors {
		result = append(result, n)
	}
	return result
}

// AnnouncePrefix advertises a prefix via BGP.
func (b *BGPController) AnnouncePrefix(prefix *net.IPNet) error {
	return b.AnnouncePrefixWithOptions(prefix, nil)
}

// AnnouncePrefixWithOptions advertises a prefix with additional options.
func (b *BGPController) AnnouncePrefixWithOptions(prefix *net.IPNet, opts *BGPAnnouncement) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	prefixStr := prefix.String()

	cmds := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", b.config.LocalAS),
		"address-family ipv4 unicast",
		fmt.Sprintf("network %s", prefixStr),
		"exit-address-family",
		"end",
	}

	_, err := b.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("announce prefix %s: %w", prefixStr, err)
	}

	// Update local cache
	announcement := &BGPAnnouncement{Prefix: prefix}
	if opts != nil {
		announcement.NextHop = opts.NextHop
		announcement.Community = opts.Community
		announcement.LocalPref = opts.LocalPref
		announcement.MED = opts.MED
	}
	b.announcements[prefixStr] = announcement

	b.logger.Info("Announced BGP prefix", zap.String("prefix", prefixStr))
	return nil
}

// WithdrawPrefix removes a prefix advertisement.
func (b *BGPController) WithdrawPrefix(prefix *net.IPNet) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	prefixStr := prefix.String()

	cmds := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", b.config.LocalAS),
		"address-family ipv4 unicast",
		fmt.Sprintf("no network %s", prefixStr),
		"exit-address-family",
		"end",
	}

	_, err := b.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("withdraw prefix %s: %w", prefixStr, err)
	}

	delete(b.announcements, prefixStr)

	b.logger.Info("Withdrew BGP prefix", zap.String("prefix", prefixStr))
	return nil
}

// ListAnnouncements returns all announced prefixes.
func (b *BGPController) ListAnnouncements() []*BGPAnnouncement {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*BGPAnnouncement, 0, len(b.announcements))
	for _, a := range b.announcements {
		result = append(result, a)
	}
	return result
}

// GetNeighborStatus fetches current neighbor status from FRR.
func (b *BGPController) GetNeighborStatus() (map[string]*BGPNeighbor, error) {
	output, err := b.vtysh("show bgp neighbors json")
	if err != nil {
		return nil, fmt.Errorf("get neighbor status: %w", err)
	}

	return b.parseNeighborsJSON(output)
}

// GetSummary returns a BGP summary.
func (b *BGPController) GetSummary() (*BGPSummary, error) {
	output, err := b.vtysh("show bgp summary json")
	if err != nil {
		return nil, fmt.Errorf("get summary: %w", err)
	}

	return b.parseSummaryJSON(output)
}

// BGPSummary contains BGP summary information.
type BGPSummary struct {
	RouterID       net.IP `json:"router_id"`
	LocalAS        uint32 `json:"local_as"`
	TotalNeighbors int    `json:"total_neighbors"`
	EstablishedNbr int    `json:"established_neighbors"`
	TotalPrefixes  int    `json:"total_prefixes"`
}

// EnableMaxPaths enables ECMP with the specified number of paths.
func (b *BGPController) EnableMaxPaths(maxPaths int) error {
	cmds := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", b.config.LocalAS),
		"address-family ipv4 unicast",
		fmt.Sprintf("maximum-paths %d", maxPaths),
		"exit-address-family",
		"end",
	}

	_, err := b.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("enable max-paths: %w", err)
	}

	b.logger.Info("Enabled ECMP", zap.Int("max_paths", maxPaths))
	return nil
}

// ConfigureBFD enables BFD for a neighbor.
func (b *BGPController) ConfigureBFD(address net.IP, minRx, minTx, multiplier int) error {
	addr := address.String()

	cmds := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", b.config.LocalAS),
		fmt.Sprintf("neighbor %s bfd", addr),
		"end",
		"configure terminal",
		"bfd",
		fmt.Sprintf("peer %s", addr),
		fmt.Sprintf("receive-interval %d", minRx),
		fmt.Sprintf("transmit-interval %d", minTx),
		fmt.Sprintf("detect-multiplier %d", multiplier),
		"end",
	}

	_, err := b.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("configure BFD for %s: %w", addr, err)
	}

	b.mu.Lock()
	if n, ok := b.neighbors[addr]; ok {
		n.BFDEnabled = true
	}
	b.mu.Unlock()

	b.logger.Info("Configured BFD for neighbor",
		zap.String("address", addr),
		zap.Int("min_rx", minRx),
		zap.Int("min_tx", minTx),
		zap.Int("multiplier", multiplier),
	)

	return nil
}

// CreateRouteMap creates a route-map for policy routing.
func (b *BGPController) CreateRouteMap(name string, seq int, action string, matchClauses, setClauses []string) error {
	cmds := []string{
		"configure terminal",
		fmt.Sprintf("route-map %s %s %d", name, action, seq),
	}

	for _, match := range matchClauses {
		cmds = append(cmds, fmt.Sprintf("match %s", match))
	}

	for _, set := range setClauses {
		cmds = append(cmds, fmt.Sprintf("set %s", set))
	}

	cmds = append(cmds, "end")

	_, err := b.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("create route-map %s: %w", name, err)
	}

	b.logger.Info("Created route-map", zap.String("name", name))
	return nil
}

// SetNeighborRouteTable configures a neighbor to use a specific routing table.
// This is useful for multi-ISP setups where each ISP's routes go to a different table.
func (b *BGPController) SetNeighborRouteTable(address net.IP, tableID int) error {
	addr := address.String()
	routeMapName := fmt.Sprintf("SET-TABLE-%d", tableID)

	// Create route-map to set table
	cmds := []string{
		"configure terminal",
		fmt.Sprintf("route-map %s permit 10", routeMapName),
		fmt.Sprintf("set table %d", tableID),
		"end",
		"configure terminal",
		fmt.Sprintf("router bgp %d", b.config.LocalAS),
		fmt.Sprintf("neighbor %s route-map %s in", addr, routeMapName),
		"end",
	}

	_, err := b.vtysh(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("set route table for %s: %w", addr, err)
	}

	b.mu.Lock()
	if n, ok := b.neighbors[addr]; ok {
		n.RouteTableID = tableID
		n.RouteMapIn = routeMapName
	}
	b.mu.Unlock()

	b.logger.Info("Set neighbor route table",
		zap.String("address", addr),
		zap.Int("table_id", tableID),
	)

	return nil
}

// vtysh executes a vtysh command.
func (b *BGPController) vtysh(command string) (string, error) {
	ctx, cancel := context.WithTimeout(b.ctx, b.config.CommandTimeout)
	defer cancel()

	args := []string{"-c", command}
	if b.config.VtyshSocket != "" {
		// Use --vty_socket to specify the VTY socket directory.
		// Note: -N is for pathspace/namespace isolation, not socket paths.
		// See: https://docs.frrouting.org/en/latest/setup.html
		args = append([]string{"--vty_socket", b.config.VtyshSocket}, args...)
	}

	cmd := exec.CommandContext(ctx, b.config.VtyshPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vtysh error: %w, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// refreshNeighbors updates the local neighbor cache from FRR.
func (b *BGPController) refreshNeighbors() error {
	neighbors, err := b.GetNeighborStatus()
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for addr, newState := range neighbors {
		if existing, ok := b.neighbors[addr]; ok {
			oldState := existing.State
			existing.State = newState.State
			existing.Uptime = newState.Uptime
			existing.PrefixesRecv = newState.PrefixesRecv
			existing.PrefixesSent = newState.PrefixesSent
			existing.LastError = newState.LastError

			// Check for state changes
			if oldState != newState.State {
				existing.LastStateChange = time.Now()

				if newState.State == BGPStateEstablished && b.onNeighborUp != nil {
					go b.onNeighborUp(addr)
				} else if oldState == BGPStateEstablished && b.onNeighborDown != nil {
					go b.onNeighborDown(addr)
				}
			}
		} else {
			// New neighbor discovered
			b.neighbors[addr] = newState
		}
	}

	return nil
}

// monitorLoop periodically checks neighbor status.
func (b *BGPController) monitorLoop() {
	defer b.wg.Done()

	ticker := time.NewTicker(b.config.MonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			if err := b.refreshNeighbors(); err != nil {
				b.logger.Warn("Failed to refresh neighbors", zap.Error(err))
			}
		}
	}
}

// parseNeighborsJSON parses FRR's "show bgp neighbors json" output.
func (b *BGPController) parseNeighborsJSON(jsonStr string) (map[string]*BGPNeighbor, error) {
	// FRR outputs neighbors as a map keyed by IP address
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("parse neighbors JSON: %w", err)
	}

	neighbors := make(map[string]*BGPNeighbor)

	for addr, data := range raw {
		// Skip non-neighbor keys
		if addr == "default" || strings.HasPrefix(addr, "table") {
			continue
		}

		var nbrData struct {
			RemoteAS             uint32 `json:"remoteAs"`
			LocalAS              uint32 `json:"localAs"`
			BgpState             string `json:"bgpState"`
			NeighborCapabilities struct {
				FourOctetAs bool `json:"4byteAs"`
			} `json:"neighborCapabilities"`
			BgpTimerUpMsec       int64  `json:"bgpTimerUpMsec"`
			BgpTimerLastRead     int64  `json:"bgpTimerLastRead"`
			BgpTimerLastWrite    int64  `json:"bgpTimerLastWrite"`
			LastErrorCodeSubcode string `json:"lastErrorCodeSubcode,omitempty"`
			AddressFamilyInfo    map[string]struct {
				PrefixCounter int `json:"acceptedPrefixCounter"`
			} `json:"addressFamilyInfo"`
		}

		if err := json.Unmarshal(data, &nbrData); err != nil {
			b.logger.Warn("Failed to parse neighbor", zap.String("addr", addr), zap.Error(err))
			continue
		}

		neighbor := &BGPNeighbor{
			Address:   net.ParseIP(addr),
			RemoteAS:  nbrData.RemoteAS,
			State:     ParseBGPState(nbrData.BgpState),
			Uptime:    time.Duration(nbrData.BgpTimerUpMsec) * time.Millisecond,
			LastError: nbrData.LastErrorCodeSubcode,
		}

		// Get prefix counts from address family info
		if afi, ok := nbrData.AddressFamilyInfo["ipv4Unicast"]; ok {
			neighbor.PrefixesRecv = afi.PrefixCounter
		}

		neighbors[addr] = neighbor
	}

	return neighbors, nil
}

// parseSummaryJSON parses FRR's "show bgp summary json" output.
func (b *BGPController) parseSummaryJSON(jsonStr string) (*BGPSummary, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("parse summary JSON: %w", err)
	}

	summary := &BGPSummary{}

	// Parse IPv4 unicast section
	if ipv4Data, ok := raw["ipv4Unicast"]; ok {
		var ipv4Summary struct {
			RouterID string `json:"routerId"`
			AS       uint32 `json:"as"`
			Peers    map[string]struct {
				State  string `json:"state"`
				PfxRcd int    `json:"pfxRcd"`
			} `json:"peers"`
		}

		if err := json.Unmarshal(ipv4Data, &ipv4Summary); err == nil {
			summary.RouterID = net.ParseIP(ipv4Summary.RouterID)
			summary.LocalAS = ipv4Summary.AS
			summary.TotalNeighbors = len(ipv4Summary.Peers)

			for _, peer := range ipv4Summary.Peers {
				if strings.EqualFold(peer.State, "established") {
					summary.EstablishedNbr++
				}
				summary.TotalPrefixes += peer.PfxRcd
			}
		}
	}

	return summary, nil
}

// Stats returns BGP statistics.
func (b *BGPController) Stats() BGPStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	stats := BGPStats{
		TotalNeighbors:     len(b.neighbors),
		TotalAnnouncements: len(b.announcements),
	}

	for _, n := range b.neighbors {
		if n.State == BGPStateEstablished {
			stats.EstablishedNeighbors++
		}
		stats.TotalPrefixesRecv += n.PrefixesRecv
	}

	return stats
}

// BGPStats contains BGP statistics.
type BGPStats struct {
	TotalNeighbors       int
	EstablishedNeighbors int
	TotalAnnouncements   int
	TotalPrefixesRecv    int
}

// GenerateConfig generates a complete FRR BGP configuration.
func (b *BGPController) GenerateConfig() string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var buf bytes.Buffer

	buf.WriteString("! BGP Configuration generated by BNG\n")
	buf.WriteString("!\n")
	buf.WriteString(fmt.Sprintf("router bgp %d\n", b.config.LocalAS))

	if b.config.RouterID != nil {
		buf.WriteString(fmt.Sprintf(" bgp router-id %s\n", b.config.RouterID.String()))
	}

	buf.WriteString(" no bgp default ipv4-unicast\n")
	buf.WriteString(" bgp bestpath as-path multipath-relax\n")
	buf.WriteString("!\n")

	// Neighbors
	for _, n := range b.neighbors {
		addr := n.Address.String()
		buf.WriteString(fmt.Sprintf(" neighbor %s remote-as %d\n", addr, n.RemoteAS))
		if n.Description != "" {
			buf.WriteString(fmt.Sprintf(" neighbor %s description %s\n", addr, n.Description))
		}
		if n.BFDEnabled {
			buf.WriteString(fmt.Sprintf(" neighbor %s bfd\n", addr))
		}
	}

	buf.WriteString("!\n")
	buf.WriteString(" address-family ipv4 unicast\n")

	// Announce prefixes
	for _, a := range b.announcements {
		buf.WriteString(fmt.Sprintf("  network %s\n", a.Prefix.String()))
	}

	// Activate neighbors
	for _, n := range b.neighbors {
		addr := n.Address.String()
		buf.WriteString(fmt.Sprintf("  neighbor %s activate\n", addr))
		if n.NextHopSelf {
			buf.WriteString(fmt.Sprintf("  neighbor %s next-hop-self\n", addr))
		}
		if n.RouteMapIn != "" {
			buf.WriteString(fmt.Sprintf("  neighbor %s route-map %s in\n", addr, n.RouteMapIn))
		}
		if n.RouteMapOut != "" {
			buf.WriteString(fmt.Sprintf("  neighbor %s route-map %s out\n", addr, n.RouteMapOut))
		}
	}

	buf.WriteString(" exit-address-family\n")
	buf.WriteString("!\n")

	return buf.String()
}

// WriteConfig writes the BGP configuration to FRR.
func (b *BGPController) WriteConfig() error {
	_, err := b.vtysh("write memory")
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	b.logger.Info("Wrote BGP configuration to FRR")
	return nil
}

// ClearNeighbor clears (resets) a BGP neighbor session.
func (b *BGPController) ClearNeighbor(address net.IP, soft bool) error {
	cmd := fmt.Sprintf("clear bgp %s", address.String())
	if soft {
		cmd += " soft"
	}

	_, err := b.vtysh(cmd)
	if err != nil {
		return fmt.Errorf("clear neighbor %s: %w", address.String(), err)
	}

	b.logger.Info("Cleared BGP neighbor",
		zap.String("address", address.String()),
		zap.Bool("soft", soft),
	)

	return nil
}
