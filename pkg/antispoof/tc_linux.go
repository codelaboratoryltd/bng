//go:build linux

package antispoof

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// attachTCProgram attaches the anti-spoofing eBPF program to TC on Linux
func (m *Manager) attachTCProgram(coll *ebpf.Collection) error {
	// Get interface
	iface, err := netlink.LinkByName(m.iface)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", m.iface, err)
	}

	// Ensure clsact qdisc exists
	if err := m.ensureClsactQdisc(iface); err != nil {
		return fmt.Errorf("failed to setup qdisc: %w", err)
	}

	// Get program
	prog := coll.Programs["antispoof_ingress"]
	if prog == nil {
		return fmt.Errorf("antispoof_ingress program not found")
	}

	// Attach ingress filter (validate incoming packets from subscribers)
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    3, // Different handle than QoS and NAT
			Priority:  0, // Highest priority - check first!
			Protocol:  3, // ETH_P_ALL
		},
		Fd:           prog.FD(),
		Name:         "antispoof",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		m.logger.Warn("Failed to add anti-spoof filter (may already exist)")
	}

	return nil
}

// ensureClsactQdisc ensures the clsact qdisc is attached
func (m *Manager) ensureClsactQdisc(iface netlink.Link) error {
	qdiscs, err := netlink.QdiscList(iface)
	if err != nil {
		return err
	}

	for _, qdisc := range qdiscs {
		if _, ok := qdisc.(*netlink.GenericQdisc); ok {
			if qdisc.Attrs().Parent == netlink.HANDLE_CLSACT {
				return nil
			}
		}
	}

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
