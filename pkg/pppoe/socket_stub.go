//go:build !linux

package pppoe

import (
	"fmt"
	"net"
	"runtime"
)

// stubRawSocket is a stub for non-Linux platforms
type stubRawSocket struct{}

// newRawSocket creates a stub raw socket for non-Linux platforms
func newRawSocket() rawSocket {
	return &stubRawSocket{}
}

// open returns an error on non-Linux platforms
func (s *stubRawSocket) open(iface string, etherType uint16) error {
	return fmt.Errorf("raw sockets not supported on %s (Linux required for PPPoE)", runtime.GOOS)
}

// close is a no-op on non-Linux platforms
func (s *stubRawSocket) close() error {
	return nil
}

// recv returns an error on non-Linux platforms
func (s *stubRawSocket) recv(buf []byte) (int, error) {
	return 0, fmt.Errorf("raw sockets not supported on %s", runtime.GOOS)
}

// send returns an error on non-Linux platforms
func (s *stubRawSocket) send(iface string, dstMAC net.HardwareAddr, etherType uint16, data []byte) error {
	return fmt.Errorf("raw sockets not supported on %s", runtime.GOOS)
}
