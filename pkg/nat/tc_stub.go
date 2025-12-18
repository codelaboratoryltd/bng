//go:build !linux

package nat

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
)

// attachTCPrograms is a stub for non-Linux platforms
func (m *Manager) attachTCPrograms(coll *ebpf.Collection) error {
	return fmt.Errorf("NAT TC program attachment not supported on %s (Linux required)", runtime.GOOS)
}
