//go:build !linux

package antispoof

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
)

// attachTCProgram is a stub for non-Linux platforms
func (m *Manager) attachTCProgram(coll *ebpf.Collection) error {
	return fmt.Errorf("anti-spoofing TC program attachment not supported on %s (Linux required)", runtime.GOOS)
}
