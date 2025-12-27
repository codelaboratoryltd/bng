//go:build linux

// Package ztp provides Zero Touch Provisioning client functionality for OLT-BNG devices.
// It handles obtaining management IP and Nexus URL via DHCP.
package ztp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
)

// Result contains the ZTP DHCP response with Nexus configuration.
type Result struct {
	// Assigned management IP
	IP net.IP

	// Subnet mask
	Mask net.IPMask

	// Gateway
	Gateway net.IP

	// DNS servers
	DNS []net.IP

	// Nexus URL from DHCP option 224 or vendor option 43
	NexusURL string

	// Lease duration
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

// Discover performs DHCP discovery and extracts Nexus URL.
// Returns the assigned IP, network config, and Nexus URL.
func (c *Client) Discover(ctx context.Context) (*Result, error) {
	// Get interface
	iface, err := net.InterfaceByName(c.iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", c.iface, err)
	}

	// Create DHCP client
	client, err := nclient4.New(c.iface,
		nclient4.WithHWAddr(iface.HardwareAddr),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCP client: %w", err)
	}
	defer client.Close()

	// Perform DHCP exchange with context timeout
	lease, err := client.Request(ctx)
	if err != nil {
		return nil, fmt.Errorf("DHCP request failed: %w", err)
	}

	// Extract result
	result := &Result{
		IP: lease.ACK.YourIPAddr,
	}

	// Subnet mask
	if mask := lease.ACK.SubnetMask(); mask != nil {
		result.Mask = mask
	}

	// Gateway/router
	if routers := lease.ACK.Router(); len(routers) > 0 {
		result.Gateway = routers[0]
	}

	// DNS servers
	result.DNS = lease.ACK.DNS()

	// Lease time
	if lt := lease.ACK.IPAddressLeaseTime(24 * time.Hour); lt > 0 {
		result.LeaseTime = lt
	}

	// Extract Nexus URL from options
	result.NexusURL = extractNexusURL(lease.ACK)

	return result, nil
}

// extractNexusURL extracts the Nexus URL from DHCP options.
// Checks Option 224 (simple) first, then Option 43 (vendor-specific).
func extractNexusURL(ack *dhcpv4.DHCPv4) string {
	// Try Option 224 (private use, simple string)
	if opt224 := ack.Options.Get(dhcpv4.GenericOptionCode(224)); opt224 != nil {
		return string(opt224)
	}

	// Try Option 43 (vendor-specific information)
	// Format: Type(1) Length(1) Value(n)
	// Type 1 = Nexus URL
	if opt43 := ack.Options.Get(dhcpv4.GenericOptionCode(43)); opt43 != nil {
		return parseVendorOptions(opt43)
	}

	return ""
}

// parseVendorOptions parses vendor-specific option 43 data.
// Format: Type(1) Length(1) Value(n)
// Type 1 = Nexus URL
func parseVendorOptions(data []byte) string {
	i := 0
	for i+2 <= len(data) {
		optType := data[i]
		optLen := int(data[i+1])
		i += 2

		if i+optLen > len(data) {
			break
		}

		if optType == 1 {
			// Type 1 = Nexus URL
			return string(data[i : i+optLen])
		}

		i += optLen
	}
	return ""
}

// Configure applies the ZTP result to the network interface.
func (c *Client) Configure(result *Result) error {
	// This would typically use netlink to configure the interface.
	// For now, just log what would be done.
	// In production, you'd use:
	// - github.com/vishvananda/netlink for Linux
	// - os/exec to run "ip addr add" / "ip route add"

	fmt.Printf("ZTP: Would configure %s:\n", c.iface)
	fmt.Printf("  IP:      %s/%d\n", result.IP, maskSize(result.Mask))
	fmt.Printf("  Gateway: %s\n", result.Gateway)
	fmt.Printf("  DNS:     %v\n", result.DNS)
	fmt.Printf("  Nexus:   %s\n", result.NexusURL)

	return nil
}

func maskSize(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}
