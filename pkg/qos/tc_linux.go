//go:build linux

package qos

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// attachTCPrograms attaches eBPF programs to TC on Linux
func (m *Manager) attachTCPrograms(egressProg, ingressProg *ebpf.Program) error {
	// Get interface
	iface, err := netlink.LinkByName(m.iface)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", m.iface, err)
	}

	// Ensure clsact qdisc exists
	if err := m.ensureClsactQdisc(iface); err != nil {
		return fmt.Errorf("failed to setup qdisc: %w", err)
	}

	// Attach egress filter
	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Priority:  1,
			Protocol:  3, // ETH_P_ALL
		},
		Fd:           egressProg.FD(),
		Name:         "qos_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(egressFilter); err != nil {
		m.logger.Warn("Failed to add egress filter (may already exist)")
	}

	// Attach ingress filter
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Priority:  1,
			Protocol:  3, // ETH_P_ALL
		},
		Fd:           ingressProg.FD(),
		Name:         "qos_ingress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		m.logger.Warn("Failed to add ingress filter (may already exist)")
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
