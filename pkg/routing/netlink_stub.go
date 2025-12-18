//go:build !linux

package routing

import (
	"fmt"
	"net"
	"time"
)

// StubPlatform is a no-op implementation for non-Linux systems.
// It stores routes and rules in memory for testing purposes.
type StubPlatform struct {
	routes map[int][]*Route
	rules  []*PolicyRule
}

// NewNetlinkPlatform returns a stub platform on non-Linux systems.
func NewNetlinkPlatform() (*StubPlatform, error) {
	return &StubPlatform{
		routes: make(map[int][]*Route),
		rules:  make([]*PolicyRule, 0),
	}, nil
}

// Close is a no-op on stub platforms.
func (p *StubPlatform) Close() {}

// AddRoute stores a route in memory.
func (p *StubPlatform) AddRoute(route *Route) error {
	table := route.Table
	if table == 0 {
		table = 254 // Default table
	}

	if p.routes[table] == nil {
		p.routes[table] = make([]*Route, 0)
	}

	// Check for duplicate
	for _, r := range p.routes[table] {
		if r.Destination.String() == route.Destination.String() &&
			r.Gateway.Equal(route.Gateway) {
			// Replace existing
			*r = *route
			return nil
		}
	}

	p.routes[table] = append(p.routes[table], route)
	return nil
}

// DeleteRoute removes a route from memory.
func (p *StubPlatform) DeleteRoute(route *Route) error {
	table := route.Table
	if table == 0 {
		table = 254
	}

	routes := p.routes[table]
	for i, r := range routes {
		if r.Destination.String() == route.Destination.String() &&
			r.Gateway.Equal(route.Gateway) {
			p.routes[table] = append(routes[:i], routes[i+1:]...)
			return nil
		}
	}

	return nil // Not found is not an error
}

// GetRoutes returns all routes in a table.
func (p *StubPlatform) GetRoutes(table int) ([]*Route, error) {
	return p.routes[table], nil
}

// FlushTable removes all routes from a table.
func (p *StubPlatform) FlushTable(table int) error {
	p.routes[table] = make([]*Route, 0)
	return nil
}

// AddRule stores a rule in memory.
func (p *StubPlatform) AddRule(rule *PolicyRule) error {
	// Check for duplicate
	for _, r := range p.rules {
		if r.Priority == rule.Priority && r.Table == rule.Table {
			// Replace existing
			*r = *rule
			return nil
		}
	}

	p.rules = append(p.rules, rule)
	return nil
}

// DeleteRule removes a rule from memory.
func (p *StubPlatform) DeleteRule(rule *PolicyRule) error {
	for i, r := range p.rules {
		if r.Priority == rule.Priority && r.Table == rule.Table {
			p.rules = append(p.rules[:i], p.rules[i+1:]...)
			return nil
		}
	}
	return nil
}

// GetRules returns all policy rules.
func (p *StubPlatform) GetRules() ([]*PolicyRule, error) {
	return p.rules, nil
}

// GetInterfaceByName returns interface information.
func (p *StubPlatform) GetInterfaceByName(name string) (*InterfaceInfo, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", name, err)
	}

	info := &InterfaceInfo{
		Name:      iface.Name,
		Index:     iface.Index,
		MTU:       iface.MTU,
		HWAddr:    iface.HardwareAddr,
		Flags:     iface.Flags,
		OperState: "unknown",
	}

	// Get addresses
	addrs, err := iface.Addrs()
	if err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				info.Addresses = append(info.Addresses, *ipNet)
			}
		}
	}

	return info, nil
}

// SetInterfaceUp is a no-op on stub platforms.
func (p *StubPlatform) SetInterfaceUp(name string) error {
	return fmt.Errorf("interface management not supported on this platform")
}

// SetInterfaceDown is a no-op on stub platforms.
func (p *StubPlatform) SetInterfaceDown(name string) error {
	return fmt.Errorf("interface management not supported on this platform")
}

// Ping performs a simulated ping (always succeeds with fake RTT).
func (p *StubPlatform) Ping(target net.IP, timeout time.Duration) (time.Duration, error) {
	// Simulate a successful ping with ~10ms RTT
	return 10 * time.Millisecond, nil
}
