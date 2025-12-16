package ebpf

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// Loader handles loading and managing eBPF programs
type Loader struct {
	iface  string
	logger *zap.Logger

	// eBPF resources
	collection *ebpf.Collection
	xdpLink    link.Link
}

// NewLoader creates a new eBPF program loader
func NewLoader(iface string, logger *zap.Logger) (*Loader, error) {
	if iface == "" {
		return nil, fmt.Errorf("interface name is required")
	}

	return &Loader{
		iface:  iface,
		logger: logger,
	}, nil
}

// Load loads the eBPF program and attaches it to the interface
func (l *Loader) Load(ctx context.Context) error {
	l.logger.Info("Loading eBPF program",
		zap.String("interface", l.iface),
	)

	// TODO Phase 3: Load actual eBPF program
	// For Phase 2, just log that we would load it

	// Get interface
	iface, err := net.InterfaceByName(l.iface)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", l.iface, err)
	}

	l.logger.Info("Interface found",
		zap.String("name", iface.Name),
		zap.Int("index", iface.Index),
		zap.String("mac", iface.HardwareAddr.String()),
	)

	// TODO Phase 3: Actual eBPF program loading
	//
	// // Load compiled eBPF program
	// spec, err := ebpf.LoadCollectionSpec("bpf/dhcp_fastpath.bpf.o")
	// if err != nil {
	// 	return fmt.Errorf("failed to load eBPF spec: %w", err)
	// }
	//
	// // Create collection
	// coll, err := ebpf.NewCollection(spec)
	// if err != nil {
	// 	return fmt.Errorf("failed to create eBPF collection: %w", err)
	// }
	// l.collection = coll
	//
	// // Get XDP program
	// prog := coll.Programs["dhcp_fastpath_prog"]
	// if prog == nil {
	// 	return fmt.Errorf("XDP program not found in collection")
	// }
	//
	// // Attach XDP program to interface
	// xdpLink, err := link.AttachXDP(link.XDPOptions{
	// 	Program:   prog,
	// 	Interface: iface.Index,
	// })
	// if err != nil {
	// 	return fmt.Errorf("failed to attach XDP program: %w", err)
	// }
	// l.xdpLink = xdpLink
	//
	// l.logger.Info("XDP program attached successfully")

	l.logger.Info("eBPF program load complete (stub implementation)")
	return nil
}

// Close detaches the eBPF program and cleans up resources
func (l *Loader) Close() error {
	l.logger.Info("Cleaning up eBPF resources")

	if l.xdpLink != nil {
		if err := l.xdpLink.Close(); err != nil {
			l.logger.Error("Failed to detach XDP program", zap.Error(err))
		}
	}

	if l.collection != nil {
		if err := l.collection.Close(); err != nil {
			l.logger.Error("Failed to close eBPF collection", zap.Error(err))
		}
	}

	l.logger.Info("eBPF resources cleaned up")
	return nil
}

// GetMaps returns the eBPF maps for userspace access
func (l *Loader) GetMaps() *ebpf.Collection {
	return l.collection
}
