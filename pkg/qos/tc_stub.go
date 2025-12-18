//go:build !linux

package qos

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
)

// attachTCPrograms is a stub for non-Linux platforms
func (m *Manager) attachTCPrograms(egressProg, ingressProg *ebpf.Program) error {
	return fmt.Errorf("TC program attachment not supported on %s (Linux required)", runtime.GOOS)
}
