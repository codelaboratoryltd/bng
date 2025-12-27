//go:build !linux

// Package ztp provides Zero Touch Provisioning client functionality for OLT-BNG devices.
// This stub is for non-Linux platforms where the DHCP client is not available.
package ztp

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Result contains the ZTP DHCP response with Nexus configuration.
type Result struct {
	IP        net.IP
	Mask      net.IPMask
	Gateway   net.IP
	DNS       []net.IP
	NexusURL  string
	LeaseTime time.Duration
}

// Client is a ZTP DHCP client for OLT-BNG devices.
type Client struct {
	iface string
}

// NewClient creates a new ZTP client.
func NewClient(iface string) *Client {
	return &Client{iface: iface}
}

// Discover performs DHCP discovery (not supported on this platform).
func (c *Client) Discover(ctx context.Context) (*Result, error) {
	return nil, fmt.Errorf("ZTP DHCP discovery not supported on this platform (Linux only)")
}

// Configure applies the ZTP result to the network interface.
func (c *Client) Configure(result *Result) error {
	return fmt.Errorf("ZTP network configuration not supported on this platform")
}
