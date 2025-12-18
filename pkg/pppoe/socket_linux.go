//go:build linux

package pppoe

import (
	"net"
	"syscall"
)

// linuxRawSocket implements rawSocket using AF_PACKET
type linuxRawSocket struct {
	fd int
}

// newRawSocket creates a new platform-specific raw socket
func newRawSocket() rawSocket {
	return &linuxRawSocket{}
}

// open opens the raw socket and binds to the interface
func (s *linuxRawSocket) open(iface string, etherType uint16) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherType)))
	if err != nil {
		return err
	}
	s.fd = fd

	// Get interface index
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		syscall.Close(fd)
		return err
	}

	// Bind to interface
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(etherType),
		Ifindex:  netIface.Index,
	}

	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return err
	}

	// Set receive timeout
	tv := syscall.Timeval{Sec: 1, Usec: 0}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	return nil
}

// close closes the raw socket
func (s *linuxRawSocket) close() error {
	if s.fd != 0 {
		return syscall.Close(s.fd)
	}
	return nil
}

// recv receives a packet from the socket
func (s *linuxRawSocket) recv(buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(s.fd, buf, 0)
	return n, err
}

// send sends a packet on the socket
func (s *linuxRawSocket) send(iface string, dstMAC net.HardwareAddr, etherType uint16, data []byte) error {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(etherType),
		Ifindex:  netIface.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], dstMAC)

	return syscall.Sendto(s.fd, data, 0, &addr)
}
