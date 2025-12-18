package slaac

import (
	"net"
	"time"
)

// RouterConfig holds configuration for the RA daemon.
type RouterConfig struct {
	// Interface to send RAs on
	Interface string `json:"interface"`

	// Prefixes to advertise
	Prefixes []PrefixAdvertisement `json:"prefixes"`

	// Link MTU (0 = don't advertise)
	MTU uint32 `json:"mtu"`

	// RA timing
	MinRAInterval time.Duration `json:"min_ra_interval"`
	MaxRAInterval time.Duration `json:"max_ra_interval"`

	// Router lifetime (0 = not a default router)
	DefaultLifetime time.Duration `json:"default_lifetime"`

	// Hop limit for RA packets
	CurHopLimit uint8 `json:"cur_hop_limit"`

	// Reachable time for NUD (ms)
	ReachableTime uint32 `json:"reachable_time"`

	// Retransmit timer for NUD (ms)
	RetransTimer uint32 `json:"retrans_timer"`

	// Flags
	Managed bool `json:"managed"` // M flag - use DHCPv6 for addresses
	Other   bool `json:"other"`   // O flag - use DHCPv6 for other config

	// DNS configuration
	DNSServers []net.IP `json:"dns_servers"`
	DNSDomains []string `json:"dns_domains"`
}

// PrefixAdvertisement holds configuration for an advertised prefix.
type PrefixAdvertisement struct {
	// The prefix to advertise
	Prefix *net.IPNet `json:"prefix"`

	// Flags
	OnLink     bool `json:"on_link"`    // L flag - prefix is on-link
	Autonomous bool `json:"autonomous"` // A flag - use SLAAC

	// Lifetimes in seconds
	ValidLifetime     uint32 `json:"valid_lifetime"`
	PreferredLifetime uint32 `json:"preferred_lifetime"`
}

// DefaultRouterConfig returns sensible defaults per RFC 4861.
func DefaultRouterConfig() RouterConfig {
	return RouterConfig{
		MinRAInterval:   200 * time.Second,
		MaxRAInterval:   600 * time.Second,
		DefaultLifetime: 30 * time.Minute,
		CurHopLimit:     64,
		ReachableTime:   0, // Unspecified
		RetransTimer:    0, // Unspecified
		Managed:         false,
		Other:           false,
	}
}

// DefaultPrefixAdvertisement returns defaults for a prefix.
func DefaultPrefixAdvertisement(prefix *net.IPNet) PrefixAdvertisement {
	return PrefixAdvertisement{
		Prefix:            prefix,
		OnLink:            true,
		Autonomous:        true,
		ValidLifetime:     2592000, // 30 days
		PreferredLifetime: 604800,  // 7 days
	}
}

// Stats holds RA daemon statistics.
type Stats struct {
	RAsSent          uint64 `json:"ras_sent"`
	RSsReceived      uint64 `json:"rss_received"`
	UnicastRAsSent   uint64 `json:"unicast_ras_sent"`
	MulticastRAsSent uint64 `json:"multicast_ras_sent"`
	ErrorCount       uint64 `json:"error_count"`
}

// Interface represents a network interface for SLAAC.
type Interface struct {
	Name         string           `json:"name"`
	Index        int              `json:"index"`
	MTU          int              `json:"mtu"`
	HardwareAddr net.HardwareAddr `json:"hardware_addr"`
	IPv6Addrs    []net.IP         `json:"ipv6_addrs"`
}

// NeighborEntry represents a neighbor cache entry.
type NeighborEntry struct {
	IP            net.IP           `json:"ip"`
	MAC           net.HardwareAddr `json:"mac"`
	State         NeighborState    `json:"state"`
	LastSeen      time.Time        `json:"last_seen"`
	IsRouter      bool             `json:"is_router"`
	ReachableTime time.Duration    `json:"reachable_time"`
}

// NeighborState represents the state of a neighbor entry.
type NeighborState string

const (
	NeighborStateIncomplete NeighborState = "INCOMPLETE"
	NeighborStateReachable  NeighborState = "REACHABLE"
	NeighborStateStale      NeighborState = "STALE"
	NeighborStateDelay      NeighborState = "DELAY"
	NeighborStateProbe      NeighborState = "PROBE"
)

// GenerateSLAACAddress generates a SLAAC address from a prefix and MAC.
// Uses modified EUI-64 format.
func GenerateSLAACAddress(prefix *net.IPNet, mac net.HardwareAddr) net.IP {
	if len(mac) != 6 {
		return nil
	}

	// Modified EUI-64: insert ff:fe in the middle and flip bit 6
	eui64 := make([]byte, 8)
	eui64[0] = mac[0] ^ 0x02 // Flip universal/local bit
	eui64[1] = mac[1]
	eui64[2] = mac[2]
	eui64[3] = 0xff
	eui64[4] = 0xfe
	eui64[5] = mac[3]
	eui64[6] = mac[4]
	eui64[7] = mac[5]

	// Combine prefix with EUI-64
	ip := make(net.IP, 16)
	copy(ip[:8], prefix.IP.To16()[:8])
	copy(ip[8:], eui64)

	return ip
}

// GenerateStablePrivacyAddress generates a stable privacy address per RFC 7217.
// This is a simplified version - production should use cryptographic hash.
func GenerateStablePrivacyAddress(prefix *net.IPNet, interfaceID, secretKey []byte) net.IP {
	// Simplified: just XOR components together
	// Real implementation should use SHA-256
	ip := make(net.IP, 16)
	copy(ip[:8], prefix.IP.To16()[:8])

	for i := 0; i < 8 && i < len(interfaceID); i++ {
		ip[8+i] = interfaceID[i]
	}
	for i := 0; i < 8 && i < len(secretKey); i++ {
		ip[8+i] ^= secretKey[i]
	}

	// Clear the universal/local bit (RFC 7217)
	ip[8] &^= 0x02

	return ip
}

// IsLinkLocal returns true if the IP is a link-local address.
func IsLinkLocal(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}
	return ip.IsLinkLocalUnicast()
}

// IsGlobalUnicast returns true if the IP is a global unicast address.
func IsGlobalUnicast(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}
