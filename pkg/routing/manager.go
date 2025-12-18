package routing

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Manager handles routing configuration for the BNG.
// It manages upstream interfaces, route tables, and policy routing.
type Manager struct {
	config Config
	logger *zap.Logger

	mu sync.RWMutex

	// Upstream interfaces
	upstreams map[string]*Upstream

	// Route tables (table ID -> routes)
	tables map[int]*RouteTable

	// Policy rules
	rules []*PolicyRule

	// Health checker
	healthChecker *HealthChecker

	// Callbacks
	onUpstreamDown func(name string)
	onUpstreamUp   func(name string)

	// Platform-specific implementation
	platform RoutingPlatform

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds routing manager configuration.
type Config struct {
	// DefaultTable is the main routing table ID (usually 254 for "main").
	DefaultTable int

	// HealthCheckInterval is how often to check upstream health.
	HealthCheckInterval time.Duration

	// HealthCheckTimeout is the timeout for health checks.
	HealthCheckTimeout time.Duration

	// EnableECMP enables equal-cost multi-path routing.
	EnableECMP bool

	// EnablePolicyRouting enables policy-based routing.
	EnablePolicyRouting bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		DefaultTable:        254, // Main table
		HealthCheckInterval: 5 * time.Second,
		HealthCheckTimeout:  2 * time.Second,
		EnableECMP:          true,
		EnablePolicyRouting: true,
	}
}

// Upstream represents an upstream interface/gateway.
type Upstream struct {
	Name        string    `json:"name"`
	Interface   string    `json:"interface"`
	Gateway     net.IP    `json:"gateway"`
	Weight      int       `json:"weight"`   // For ECMP load balancing
	Priority    int       `json:"priority"` // Lower = preferred
	State       LinkState `json:"state"`
	LastSeen    time.Time `json:"last_seen"`
	HealthCheck string    `json:"health_check"` // IP/host to ping for health
	Enabled     bool      `json:"enabled"`

	// Statistics
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
	PacketsTx uint64 `json:"packets_tx"`
	PacketsRx uint64 `json:"packets_rx"`
}

// LinkState represents the state of an upstream link.
type LinkState int

const (
	LinkStateUnknown LinkState = iota
	LinkStateUp
	LinkStateDown
	LinkStateDegraded
)

func (s LinkState) String() string {
	switch s {
	case LinkStateUp:
		return "UP"
	case LinkStateDown:
		return "DOWN"
	case LinkStateDegraded:
		return "DEGRADED"
	default:
		return "UNKNOWN"
	}
}

// Route represents a routing table entry.
type Route struct {
	Destination *net.IPNet `json:"destination"`
	Gateway     net.IP     `json:"gateway"`
	Interface   string     `json:"interface"`
	Metric      int        `json:"metric"`
	Table       int        `json:"table"`
	Protocol    int        `json:"protocol"` // RTPROT_STATIC, RTPROT_BGP, etc.
	Scope       int        `json:"scope"`
	Source      net.IP     `json:"source,omitempty"`
	MTU         int        `json:"mtu,omitempty"`

	// For ECMP
	NextHops []NextHop `json:"next_hops,omitempty"`
}

// NextHop represents a single next-hop in an ECMP route.
type NextHop struct {
	Gateway   net.IP `json:"gateway"`
	Interface string `json:"interface"`
	Weight    int    `json:"weight"`
}

// RouteTable represents a routing table.
type RouteTable struct {
	ID     int      `json:"id"`
	Name   string   `json:"name"`
	Routes []*Route `json:"routes"`
}

// PolicyRule represents a policy routing rule.
type PolicyRule struct {
	Priority    int        `json:"priority"`
	Table       int        `json:"table"`
	Source      *net.IPNet `json:"source,omitempty"`
	Destination *net.IPNet `json:"destination,omitempty"`
	IIF         string     `json:"iif,omitempty"` // Input interface
	OIF         string     `json:"oif,omitempty"` // Output interface
	FwMark      uint32     `json:"fwmark,omitempty"`
	Description string     `json:"description,omitempty"`
}

// RoutingPlatform abstracts platform-specific routing operations.
type RoutingPlatform interface {
	// Route operations
	AddRoute(route *Route) error
	DeleteRoute(route *Route) error
	GetRoutes(table int) ([]*Route, error)
	FlushTable(table int) error

	// Policy rule operations
	AddRule(rule *PolicyRule) error
	DeleteRule(rule *PolicyRule) error
	GetRules() ([]*PolicyRule, error)

	// Interface operations
	GetInterfaceByName(name string) (*InterfaceInfo, error)
	SetInterfaceUp(name string) error
	SetInterfaceDown(name string) error

	// Health check
	Ping(target net.IP, timeout time.Duration) (time.Duration, error)
}

// InterfaceInfo holds interface information.
type InterfaceInfo struct {
	Name      string
	Index     int
	MTU       int
	HWAddr    net.HardwareAddr
	Flags     net.Flags
	Addresses []net.IPNet
	OperState string
}

// NewManager creates a new routing manager.
func NewManager(config Config, logger *zap.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:    config,
		logger:    logger,
		upstreams: make(map[string]*Upstream),
		tables:    make(map[int]*RouteTable),
		rules:     make([]*PolicyRule, 0),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Initialize default table
	m.tables[config.DefaultTable] = &RouteTable{
		ID:     config.DefaultTable,
		Name:   "main",
		Routes: make([]*Route, 0),
	}

	return m
}

// SetPlatform sets the platform-specific implementation.
func (m *Manager) SetPlatform(platform RoutingPlatform) {
	m.platform = platform
}

// Start begins the routing manager.
func (m *Manager) Start() error {
	m.logger.Info("Starting routing manager",
		zap.Int("default_table", m.config.DefaultTable),
		zap.Bool("ecmp", m.config.EnableECMP),
		zap.Bool("policy_routing", m.config.EnablePolicyRouting),
	)

	// Start health checker
	m.healthChecker = NewHealthChecker(m.config.HealthCheckInterval, m.config.HealthCheckTimeout, m.logger)
	m.healthChecker.OnStateChange(m.handleUpstreamStateChange)

	m.wg.Add(1)
	go m.healthCheckLoop()

	m.logger.Info("Routing manager started")
	return nil
}

// Stop shuts down the routing manager.
func (m *Manager) Stop() error {
	m.logger.Info("Stopping routing manager")
	m.cancel()
	m.wg.Wait()
	return nil
}

// OnUpstreamDown registers a callback for upstream failure.
func (m *Manager) OnUpstreamDown(callback func(name string)) {
	m.onUpstreamDown = callback
}

// OnUpstreamUp registers a callback for upstream recovery.
func (m *Manager) OnUpstreamUp(callback func(name string)) {
	m.onUpstreamUp = callback
}

// AddUpstream adds an upstream gateway.
func (m *Manager) AddUpstream(upstream *Upstream) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.upstreams[upstream.Name]; exists {
		return fmt.Errorf("upstream %s already exists", upstream.Name)
	}

	upstream.State = LinkStateUnknown
	upstream.Enabled = true
	m.upstreams[upstream.Name] = upstream

	// Add health check target
	if upstream.HealthCheck != "" {
		target := net.ParseIP(upstream.HealthCheck)
		if target == nil {
			// Try to resolve hostname
			addrs, err := net.LookupIP(upstream.HealthCheck)
			if err != nil || len(addrs) == 0 {
				m.logger.Warn("Invalid health check target",
					zap.String("upstream", upstream.Name),
					zap.String("target", upstream.HealthCheck),
				)
			} else {
				target = addrs[0]
			}
		}
		if target != nil {
			m.healthChecker.AddTarget(upstream.Name, target)
		}
	}

	m.logger.Info("Added upstream",
		zap.String("name", upstream.Name),
		zap.String("interface", upstream.Interface),
		zap.String("gateway", upstream.Gateway.String()),
	)

	return nil
}

// RemoveUpstream removes an upstream gateway.
func (m *Manager) RemoveUpstream(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	upstream, exists := m.upstreams[name]
	if !exists {
		return fmt.Errorf("upstream %s not found", name)
	}

	// Remove routes using this upstream
	if err := m.removeUpstreamRoutes(upstream); err != nil {
		m.logger.Warn("Failed to remove upstream routes",
			zap.String("upstream", name),
			zap.Error(err),
		)
	}

	m.healthChecker.RemoveTarget(name)
	delete(m.upstreams, name)

	m.logger.Info("Removed upstream", zap.String("name", name))
	return nil
}

// GetUpstream returns an upstream by name.
func (m *Manager) GetUpstream(name string) (*Upstream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.upstreams[name]
	return u, ok
}

// ListUpstreams returns all upstreams.
func (m *Manager) ListUpstreams() []*Upstream {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Upstream, 0, len(m.upstreams))
	for _, u := range m.upstreams {
		result = append(result, u)
	}
	return result
}

// SetDefaultGateway sets the default route.
func (m *Manager) SetDefaultGateway(gateway net.IP, iface string) error {
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")

	route := &Route{
		Destination: defaultNet,
		Gateway:     gateway,
		Interface:   iface,
		Table:       m.config.DefaultTable,
		Metric:      100,
	}

	return m.AddRoute(route)
}

// SetDefaultGatewayECMP sets a default route with multiple next-hops.
func (m *Manager) SetDefaultGatewayECMP(nexthops []NextHop) error {
	if !m.config.EnableECMP {
		return fmt.Errorf("ECMP is not enabled")
	}

	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")

	route := &Route{
		Destination: defaultNet,
		Table:       m.config.DefaultTable,
		NextHops:    nexthops,
	}

	return m.AddRoute(route)
}

// AddRoute adds a route to a routing table.
func (m *Manager) AddRoute(route *Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if route.Table == 0 {
		route.Table = m.config.DefaultTable
	}

	// Ensure table exists
	if _, exists := m.tables[route.Table]; !exists {
		m.tables[route.Table] = &RouteTable{
			ID:     route.Table,
			Routes: make([]*Route, 0),
		}
	}

	// Add to platform if available
	if m.platform != nil {
		if err := m.platform.AddRoute(route); err != nil {
			return fmt.Errorf("platform add route: %w", err)
		}
	}

	// Add to local state
	m.tables[route.Table].Routes = append(m.tables[route.Table].Routes, route)

	m.logger.Debug("Added route",
		zap.String("destination", route.Destination.String()),
		zap.String("gateway", route.Gateway.String()),
		zap.Int("table", route.Table),
	)

	return nil
}

// DeleteRoute removes a route from a routing table.
func (m *Manager) DeleteRoute(route *Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if route.Table == 0 {
		route.Table = m.config.DefaultTable
	}

	table, exists := m.tables[route.Table]
	if !exists {
		return fmt.Errorf("table %d not found", route.Table)
	}

	// Remove from platform if available
	if m.platform != nil {
		if err := m.platform.DeleteRoute(route); err != nil {
			return fmt.Errorf("platform delete route: %w", err)
		}
	}

	// Remove from local state
	for i, r := range table.Routes {
		if r.Destination.String() == route.Destination.String() &&
			r.Gateway.Equal(route.Gateway) {
			table.Routes = append(table.Routes[:i], table.Routes[i+1:]...)
			break
		}
	}

	m.logger.Debug("Deleted route",
		zap.String("destination", route.Destination.String()),
		zap.String("gateway", route.Gateway.String()),
	)

	return nil
}

// GetRoutes returns all routes in a table.
func (m *Manager) GetRoutes(tableID int) []*Route {
	m.mu.RLock()
	defer m.mu.RUnlock()

	table, exists := m.tables[tableID]
	if !exists {
		return nil
	}

	return table.Routes
}

// AddPolicyRule adds a policy routing rule.
func (m *Manager) AddPolicyRule(rule *PolicyRule) error {
	if !m.config.EnablePolicyRouting {
		return fmt.Errorf("policy routing is not enabled")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to platform if available
	if m.platform != nil {
		if err := m.platform.AddRule(rule); err != nil {
			return fmt.Errorf("platform add rule: %w", err)
		}
	}

	m.rules = append(m.rules, rule)

	m.logger.Debug("Added policy rule",
		zap.Int("priority", rule.Priority),
		zap.Int("table", rule.Table),
		zap.String("description", rule.Description),
	)

	return nil
}

// DeletePolicyRule removes a policy routing rule.
func (m *Manager) DeletePolicyRule(rule *PolicyRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from platform if available
	if m.platform != nil {
		if err := m.platform.DeleteRule(rule); err != nil {
			return fmt.Errorf("platform delete rule: %w", err)
		}
	}

	// Remove from local state
	for i, r := range m.rules {
		if r.Priority == rule.Priority && r.Table == rule.Table {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			break
		}
	}

	return nil
}

// GetPolicyRules returns all policy rules.
func (m *Manager) GetPolicyRules() []*PolicyRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rules
}

// CreateISPTable creates a routing table for an ISP.
func (m *Manager) CreateISPTable(ispID string, tableID int, gateway net.IP, iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create table
	m.tables[tableID] = &RouteTable{
		ID:     tableID,
		Name:   ispID,
		Routes: make([]*Route, 0),
	}

	// Add default route for this ISP
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	route := &Route{
		Destination: defaultNet,
		Gateway:     gateway,
		Interface:   iface,
		Table:       tableID,
	}

	if m.platform != nil {
		if err := m.platform.AddRoute(route); err != nil {
			return fmt.Errorf("add ISP default route: %w", err)
		}
	}

	m.tables[tableID].Routes = append(m.tables[tableID].Routes, route)

	m.logger.Info("Created ISP routing table",
		zap.String("isp", ispID),
		zap.Int("table", tableID),
		zap.String("gateway", gateway.String()),
	)

	return nil
}

// RouteSubscriberToISP creates a policy rule to route a subscriber's traffic via an ISP table.
func (m *Manager) RouteSubscriberToISP(subscriberIP net.IP, tableID int) error {
	mask := net.CIDRMask(32, 32)
	source := &net.IPNet{IP: subscriberIP, Mask: mask}

	rule := &PolicyRule{
		Priority:    100, // Higher priority than default
		Table:       tableID,
		Source:      source,
		Description: fmt.Sprintf("subscriber %s -> table %d", subscriberIP, tableID),
	}

	return m.AddPolicyRule(rule)
}

// removeUpstreamRoutes removes all routes using an upstream.
func (m *Manager) removeUpstreamRoutes(upstream *Upstream) error {
	for _, table := range m.tables {
		var remaining []*Route
		for _, route := range table.Routes {
			if route.Gateway.Equal(upstream.Gateway) || route.Interface == upstream.Interface {
				if m.platform != nil {
					m.platform.DeleteRoute(route)
				}
			} else {
				remaining = append(remaining, route)
			}
		}
		table.Routes = remaining
	}
	return nil
}

// handleUpstreamStateChange handles upstream state changes from health checker.
func (m *Manager) handleUpstreamStateChange(name string, up bool) {
	m.mu.Lock()
	upstream, exists := m.upstreams[name]
	if !exists {
		m.mu.Unlock()
		return
	}

	oldState := upstream.State
	if up {
		upstream.State = LinkStateUp
		upstream.LastSeen = time.Now()
	} else {
		upstream.State = LinkStateDown
	}
	m.mu.Unlock()

	if oldState != upstream.State {
		m.logger.Info("Upstream state changed",
			zap.String("name", name),
			zap.String("old_state", oldState.String()),
			zap.String("new_state", upstream.State.String()),
		)

		if up && m.onUpstreamUp != nil {
			m.onUpstreamUp(name)
		} else if !up && m.onUpstreamDown != nil {
			m.onUpstreamDown(name)
		}
	}
}

// healthCheckLoop runs periodic health checks.
func (m *Manager) healthCheckLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.healthChecker.CheckAll(m.platform)
		}
	}
}

// Stats returns routing statistics.
func (m *Manager) Stats() RoutingStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := RoutingStats{
		UpstreamsTotal: len(m.upstreams),
		TablesTotal:    len(m.tables),
		RulesTotal:     len(m.rules),
	}

	for _, u := range m.upstreams {
		if u.State == LinkStateUp {
			stats.UpstreamsUp++
		}
	}

	for _, t := range m.tables {
		stats.RoutesTotal += len(t.Routes)
	}

	return stats
}

// RoutingStats contains routing statistics.
type RoutingStats struct {
	UpstreamsTotal int
	UpstreamsUp    int
	TablesTotal    int
	RoutesTotal    int
	RulesTotal     int
}
