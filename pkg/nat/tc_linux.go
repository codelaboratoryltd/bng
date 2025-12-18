//go:build linux

package nat

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// attachTCPrograms attaches NAT eBPF programs to TC on Linux
func (m *Manager) attachTCPrograms(coll *ebpf.Collection) error {
	// Get interface
	iface, err := netlink.LinkByName(m.iface)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", m.iface, err)
	}

	// Ensure clsact qdisc exists
	if err := m.ensureClsactQdisc(iface); err != nil {
		return fmt.Errorf("failed to setup qdisc: %w", err)
	}

	// Get programs
	egressProg := coll.Programs["nat44_egress"]
	if egressProg == nil {
		return fmt.Errorf("nat44_egress program not found")
	}

	ingressProg := coll.Programs["nat44_ingress"]
	if ingressProg == nil {
		return fmt.Errorf("nat44_ingress program not found")
	}

	// Attach egress filter (SNAT)
	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    2, // Different handle than QoS
			Priority:  2, // Lower priority (runs after QoS)
			Protocol:  3, // ETH_P_ALL
		},
		Fd:           egressProg.FD(),
		Name:         "nat44_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(egressFilter); err != nil {
		m.logger.Warn("Failed to add NAT egress filter (may already exist)")
	}

	// Attach ingress filter (DNAT)
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    2,
			Priority:  2,
			Protocol:  3, // ETH_P_ALL
		},
		Fd:           ingressProg.FD(),
		Name:         "nat44_ingress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		m.logger.Warn("Failed to add NAT ingress filter (may already exist)")
	}

	return nil
}

// ensureClsactQdisc ensures the clsact qdisc is attached
func (m *Manager) ensureClsactQdisc(iface netlink.Link) error {
	// Check if clsact qdisc already exists
	qdiscs, err := netlink.QdiscList(iface)
	if err != nil {
		return err
	}

	for _, qdisc := range qdiscs {
		if _, ok := qdisc.(*netlink.GenericQdisc); ok {
			if qdisc.Attrs().Parent == netlink.HANDLE_CLSACT {
				return nil // Already exists
			}
		}
	}

	// Add clsact qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	return netlink.QdiscAdd(qdisc)
}
