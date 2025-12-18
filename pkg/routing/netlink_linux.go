//go:build linux

package routing

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// NetlinkPlatform implements RoutingPlatform using Linux netlink.
type NetlinkPlatform struct {
	// Handle for netlink operations
	handle *netlink.Handle
}

// NewNetlinkPlatform creates a new Linux netlink routing platform.
func NewNetlinkPlatform() (*NetlinkPlatform, error) {
	handle, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("create netlink handle: %w", err)
	}

	return &NetlinkPlatform{
		handle: handle,
	}, nil
}

// Close releases the netlink handle.
func (p *NetlinkPlatform) Close() {
	if p.handle != nil {
		p.handle.Close()
	}
}

// AddRoute adds a route to the routing table.
func (p *NetlinkPlatform) AddRoute(route *Route) error {
	nlRoute, err := p.routeToNetlink(route)
	if err != nil {
		return err
	}

	if err := p.handle.RouteAdd(nlRoute); err != nil {
		// Check if route already exists
		if strings.Contains(err.Error(), "file exists") {
			// Replace existing route
			return p.handle.RouteReplace(nlRoute)
		}
		return fmt.Errorf("add route: %w", err)
	}

	return nil
}

// DeleteRoute removes a route from the routing table.
func (p *NetlinkPlatform) DeleteRoute(route *Route) error {
	nlRoute, err := p.routeToNetlink(route)
	if err != nil {
		return err
	}

	if err := p.handle.RouteDel(nlRoute); err != nil {
		// Ignore "no such process" which means route doesn't exist
		if strings.Contains(err.Error(), "no such process") {
			return nil
		}
		return fmt.Errorf("delete route: %w", err)
	}

	return nil
}

// GetRoutes returns all routes in a table.
func (p *NetlinkPlatform) GetRoutes(table int) ([]*Route, error) {
	// Get routes from the specified table
	filter := &netlink.Route{
		Table: table,
	}

	nlRoutes, err := p.handle.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}

	routes := make([]*Route, 0, len(nlRoutes))
	for _, nlRoute := range nlRoutes {
		route := p.netlinkToRoute(&nlRoute, table)
		routes = append(routes, route)
	}

	return routes, nil
}

// FlushTable removes all routes from a table.
func (p *NetlinkPlatform) FlushTable(table int) error {
	routes, err := p.GetRoutes(table)
	if err != nil {
		return err
	}

	for _, route := range routes {
		if err := p.DeleteRoute(route); err != nil {
			// Log but continue
			continue
		}
	}

	return nil
}

// AddRule adds a policy routing rule.
func (p *NetlinkPlatform) AddRule(rule *PolicyRule) error {
	nlRule := p.ruleToNetlink(rule)

	if err := p.handle.RuleAdd(nlRule); err != nil {
		// Check if rule already exists
		if strings.Contains(err.Error(), "file exists") {
			return nil
		}
		return fmt.Errorf("add rule: %w", err)
	}

	return nil
}

// DeleteRule removes a policy routing rule.
func (p *NetlinkPlatform) DeleteRule(rule *PolicyRule) error {
	nlRule := p.ruleToNetlink(rule)

	if err := p.handle.RuleDel(nlRule); err != nil {
		// Ignore "no such process" which means rule doesn't exist
		if strings.Contains(err.Error(), "no such process") {
			return nil
		}
		return fmt.Errorf("delete rule: %w", err)
	}

	return nil
}

// GetRules returns all policy routing rules.
func (p *NetlinkPlatform) GetRules() ([]*PolicyRule, error) {
	nlRules, err := p.handle.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}

	rules := make([]*PolicyRule, 0, len(nlRules))
	for _, nlRule := range nlRules {
		rule := p.netlinkToRule(&nlRule)
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetInterfaceByName returns interface information.
func (p *NetlinkPlatform) GetInterfaceByName(name string) (*InterfaceInfo, error) {
	link, err := p.handle.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("get link %s: %w", name, err)
	}

	attrs := link.Attrs()

	info := &InterfaceInfo{
		Name:      attrs.Name,
		Index:     attrs.Index,
		MTU:       attrs.MTU,
		HWAddr:    attrs.HardwareAddr,
		Flags:     attrs.Flags,
		OperState: attrs.OperState.String(),
	}

	// Get addresses
	addrs, err := p.handle.AddrList(link, netlink.FAMILY_V4)
	if err == nil {
		for _, addr := range addrs {
			if addr.IPNet != nil {
				info.Addresses = append(info.Addresses, *addr.IPNet)
			}
		}
	}

	return info, nil
}

// SetInterfaceUp brings an interface up.
func (p *NetlinkPlatform) SetInterfaceUp(name string) error {
	link, err := p.handle.LinkByName(name)
	if err != nil {
		return fmt.Errorf("get link %s: %w", name, err)
	}

	if err := p.handle.LinkSetUp(link); err != nil {
		return fmt.Errorf("set link up: %w", err)
	}

	return nil
}

// SetInterfaceDown brings an interface down.
func (p *NetlinkPlatform) SetInterfaceDown(name string) error {
	link, err := p.handle.LinkByName(name)
	if err != nil {
		return fmt.Errorf("get link %s: %w", name, err)
	}

	if err := p.handle.LinkSetDown(link); err != nil {
		return fmt.Errorf("set link down: %w", err)
	}

	return nil
}

// Ping sends an ICMP echo request and returns the RTT.
func (p *NetlinkPlatform) Ping(target net.IP, timeout time.Duration) (time.Duration, error) {
	// Try ICMP ping first (requires root or CAP_NET_RAW)
	rtt, err := p.icmpPing(target, timeout)
	if err == nil {
		return rtt, nil
	}

	// Fallback to using system ping command
	return p.cmdPing(target, timeout)
}

// icmpPing sends a raw ICMP ping.
func (p *NetlinkPlatform) icmpPing(target net.IP, timeout time.Duration) (time.Duration, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, fmt.Errorf("listen ICMP: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("BNG-HEALTH-CHECK"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("marshal ICMP: %w", err)
	}

	start := time.Now()

	if _, err := conn.WriteTo(msgBytes, &net.IPAddr{IP: target}); err != nil {
		return 0, fmt.Errorf("send ICMP: %w", err)
	}

	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return 0, fmt.Errorf("recv ICMP: %w", err)
	}

	rtt := time.Since(start)

	// Parse reply
	parsedMsg, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return 0, fmt.Errorf("parse ICMP reply: %w", err)
	}

	switch parsedMsg.Type {
	case ipv4.ICMPTypeEchoReply:
		return rtt, nil
	default:
		return 0, fmt.Errorf("unexpected ICMP type: %v", parsedMsg.Type)
	}
}

// cmdPing uses the system ping command as a fallback.
func (p *NetlinkPlatform) cmdPing(target net.IP, timeout time.Duration) (time.Duration, error) {
	timeoutSec := int(timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	cmd := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeoutSec), target.String())
	start := time.Now()

	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("ping command failed: %w", err)
	}

	return time.Since(start), nil
}

// routeToNetlink converts our Route to netlink.Route.
func (p *NetlinkPlatform) routeToNetlink(route *Route) (*netlink.Route, error) {
	nlRoute := &netlink.Route{
		Dst:      route.Destination,
		Gw:       route.Gateway,
		Table:    route.Table,
		Protocol: netlink.RouteProtocol(route.Protocol),
		Scope:    netlink.Scope(route.Scope),
		Src:      route.Source,
	}

	if route.Metric > 0 {
		nlRoute.Priority = route.Metric
	}

	if route.MTU > 0 {
		nlRoute.MTU = route.MTU
	}

	// Set interface index if specified
	if route.Interface != "" {
		link, err := p.handle.LinkByName(route.Interface)
		if err != nil {
			return nil, fmt.Errorf("get interface %s: %w", route.Interface, err)
		}
		nlRoute.LinkIndex = link.Attrs().Index
	}

	// Handle ECMP multi-path routes
	if len(route.NextHops) > 0 {
		nlRoute.MultiPath = make([]*netlink.NexthopInfo, 0, len(route.NextHops))
		for _, nh := range route.NextHops {
			nhInfo := &netlink.NexthopInfo{
				Gw: nh.Gateway,
			}

			if nh.Interface != "" {
				link, err := p.handle.LinkByName(nh.Interface)
				if err != nil {
					return nil, fmt.Errorf("get interface %s: %w", nh.Interface, err)
				}
				nhInfo.LinkIndex = link.Attrs().Index
			}

			nlRoute.MultiPath = append(nlRoute.MultiPath, nhInfo)
		}
	}

	return nlRoute, nil
}

// netlinkToRoute converts netlink.Route to our Route.
func (p *NetlinkPlatform) netlinkToRoute(nlRoute *netlink.Route, table int) *Route {
	route := &Route{
		Destination: nlRoute.Dst,
		Gateway:     nlRoute.Gw,
		Metric:      nlRoute.Priority,
		Table:       table,
		Protocol:    int(nlRoute.Protocol),
		Scope:       int(nlRoute.Scope),
		Source:      nlRoute.Src,
		MTU:         nlRoute.MTU,
	}

	// Get interface name
	if nlRoute.LinkIndex > 0 {
		link, err := p.handle.LinkByIndex(nlRoute.LinkIndex)
		if err == nil {
			route.Interface = link.Attrs().Name
		}
	}

	// Handle ECMP multi-path routes
	if len(nlRoute.MultiPath) > 0 {
		route.NextHops = make([]NextHop, 0, len(nlRoute.MultiPath))
		for _, nh := range nlRoute.MultiPath {
			nextHop := NextHop{
				Gateway: nh.Gw,
			}

			if nh.LinkIndex > 0 {
				link, err := p.handle.LinkByIndex(nh.LinkIndex)
				if err == nil {
					nextHop.Interface = link.Attrs().Name
				}
			}

			route.NextHops = append(route.NextHops, nextHop)
		}
	}

	return route
}

// ruleToNetlink converts our PolicyRule to netlink.Rule.
func (p *NetlinkPlatform) ruleToNetlink(rule *PolicyRule) *netlink.Rule {
	nlRule := netlink.NewRule()
	nlRule.Priority = rule.Priority
	nlRule.Table = rule.Table

	if rule.Source != nil {
		nlRule.Src = rule.Source
	}

	if rule.Destination != nil {
		nlRule.Dst = rule.Destination
	}

	if rule.IIF != "" {
		nlRule.IifName = rule.IIF
	}

	if rule.OIF != "" {
		nlRule.OifName = rule.OIF
	}

	if rule.FwMark > 0 {
		nlRule.Mark = rule.FwMark
	}

	return nlRule
}

// netlinkToRule converts netlink.Rule to our PolicyRule.
func (p *NetlinkPlatform) netlinkToRule(nlRule *netlink.Rule) *PolicyRule {
	return &PolicyRule{
		Priority:    nlRule.Priority,
		Table:       nlRule.Table,
		Source:      nlRule.Src,
		Destination: nlRule.Dst,
		IIF:         nlRule.IifName,
		OIF:         nlRule.OifName,
		FwMark:      nlRule.Mark,
	}
}
