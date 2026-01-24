// Package agent implements the Nexus agent for OLT-BNG devices.
// The agent handles device registration, CLSet synchronization,
// configuration management, and offline operation.
package agent

import (
	"net"
	"time"
)

// State represents the agent's current operational state.
type State int

const (
	// StateBootstrap is the initial state when the device has no configuration.
	StateBootstrap State = iota
	// StateConnected indicates the agent is online and syncing with CLSet mesh.
	StateConnected
	// StatePartitioned indicates the agent is offline but operating from cache.
	StatePartitioned
	// StateRecovering indicates the agent is reconnecting and merging changes.
	StateRecovering
)

// String returns a human-readable state name.
func (s State) String() string {
	switch s {
	case StateBootstrap:
		return "bootstrap"
	case StateConnected:
		return "connected"
	case StatePartitioned:
		return "partitioned"
	case StateRecovering:
		return "recovering"
	default:
		return "unknown"
	}
}

// DeviceInfo contains hardware information about this OLT device.
type DeviceInfo struct {
	Serial       string   `json:"serial"`
	MAC          string   `json:"mac"`
	Model        string   `json:"model"`
	Firmware     string   `json:"firmware"`
	AgentVersion string   `json:"agent_version"`
	Capabilities []string `json:"capabilities"`
}

// RegistrationRequest is sent to the Nexus server during bootstrap.
type RegistrationRequest struct {
	DeviceInfo
	Timestamp time.Time `json:"timestamp"`
}

// RegistrationResponse is returned by the Nexus server.
type RegistrationResponse struct {
	Status     string        `json:"status"` // "approved", "pending", "rejected"
	DeviceID   string        `json:"device_id,omitempty"`
	Config     *DeviceConfig `json:"config,omitempty"`
	CLSetPeers []string      `json:"clset_peers,omitempty"`
	Message    string        `json:"message,omitempty"`

	// HA (High Availability) configuration
	// When this device is part of an HA pair, these fields describe the HA setup.
	HARole    string     `json:"ha_role,omitempty"`    // "active", "standby", or empty if not in HA pair
	HAPartner *HAPartner `json:"ha_partner,omitempty"` // Partner device info (if in HA pair)
}

// HAPartner contains information about the HA partner device.
// This is used for P2P state synchronization between active/standby BNGs.
type HAPartner struct {
	// NodeID is the partner's unique device identifier.
	NodeID string `json:"node_id"`

	// Endpoint is the partner's HA sync endpoint (e.g., "10.0.0.1:9000").
	// The standby connects to this endpoint to receive state updates.
	Endpoint string `json:"endpoint"`
}

// DeviceConfig contains the full configuration for this OLT device.
type DeviceConfig struct {
	DeviceID string `json:"device_id"`
	NetCoID  string `json:"netco_id"`
	Image    string `json:"image"`

	Network      NetworkConfig      `json:"network"`
	PON          PONConfig          `json:"pon"`
	Pools        PoolsConfig        `json:"pools"`
	ISPs         []ISPConfig        `json:"isps"`
	QoS          QoSConfig          `json:"qos"`
	WalledGarden WalledGardenConfig `json:"walled_garden"`
}

// NetworkConfig contains network interface configuration.
type NetworkConfig struct {
	ManagementVLAN    uint16   `json:"management_vlan"`
	ManagementIP      string   `json:"management_ip"`
	ManagementGateway string   `json:"management_gateway"`
	UplinkInterface   string   `json:"uplink_interface"`
	PONInterfaces     []string `json:"pon_interfaces"`
}

// PONConfig contains PON-specific settings.
type PONConfig struct {
	Ports      int    `json:"ports"`
	Technology string `json:"technology"` // "gpon", "xgs-pon"
	SplitRatio int    `json:"split_ratio"`
}

// PoolsConfig references IP and VLAN pools available to this device.
type PoolsConfig struct {
	IPv4  []string `json:"ipv4"`
	IPv6  []string `json:"ipv6"`
	VLANs []string `json:"vlans"`
}

// ISPConfig contains configuration for a specific ISP.
type ISPConfig struct {
	ISPID       string       `json:"isp_id"`
	Name        string       `json:"name"`
	RADIUS      RADIUSConfig `json:"radius"`
	Pools       PoolsConfig  `json:"pools"`
	QoSPolicies []string     `json:"qos_policies"`
	ControlVLAN uint16       `json:"control_vlan"`
}

// RADIUSConfig contains RADIUS server configuration for an ISP.
type RADIUSConfig struct {
	Servers   []string `json:"servers"`
	SecretRef string   `json:"secret_ref"` // Reference to vault
	Secret    string   `json:"-"`          // Resolved secret (not serialized)
	Realm     string   `json:"realm"`      // e.g., "@ispa.com"
	TimeoutMS int      `json:"timeout_ms"`
	Retries   int      `json:"retries"`
}

// QoSConfig contains default QoS settings.
type QoSConfig struct {
	DefaultDownMbps uint64  `json:"default_down_mbps"`
	DefaultUpMbps   uint64  `json:"default_up_mbps"`
	BurstAllowance  float64 `json:"burst_allowance"`
}

// WalledGardenConfig contains captive portal settings.
type WalledGardenConfig struct {
	Enabled      bool     `json:"enabled"`
	PortalIP     string   `json:"portal_ip"`
	PortalPort   uint16   `json:"portal_port"`
	AllowedDNS   []string `json:"allowed_dns"`
	AllowedHosts []string `json:"allowed_hosts"`
}

// Subscriber represents a subscriber's configuration and state.
type Subscriber struct {
	SubscriberID string `json:"subscriber_id"`

	// Physical layer (NetCo) - stable
	NTEID    string `json:"nte_id"`
	DeviceID string `json:"device_id"`
	VLAN     string `json:"vlan"` // "s-tag:c-tag"
	NetCoID  string `json:"netco_id"`

	// Service layer (ISPCo) - can change
	ISPID       string `json:"isp_id"`
	RADIUSRealm string `json:"radius_realm"`
	ServiceTier string `json:"service_tier"`
	QoSPolicy   string `json:"qos_policy"`

	// Session state
	MAC           net.HardwareAddr `json:"-"`
	MACString     string           `json:"mac"`
	IPv4          net.IP           `json:"-"`
	IPv4String    string           `json:"ipv4"`
	IPv6Prefix    string           `json:"ipv6_prefix"`
	Authenticated bool             `json:"authenticated"`
	SessionStart  time.Time        `json:"session_start,omitempty"`
}

// NTE represents a discovered Network Terminating Equipment (ONU/ONT).
type NTE struct {
	Serial       string    `json:"serial"`
	DeviceID     string    `json:"device_id"`
	Port         int       `json:"port"`
	Status       string    `json:"status"` // "discovered", "provisioned", "active"
	Vendor       string    `json:"vendor"`
	Model        string    `json:"model"`
	Firmware     string    `json:"firmware"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Pool represents an IP or VLAN allocation pool.
type Pool struct {
	Name         string `json:"name"`
	Type         string `json:"type"` // "ipv4", "ipv6", "vlan"
	Range        string `json:"range"`
	Owner        string `json:"owner"` // netco_id or ispco_id
	DeviceFilter string `json:"device_filter"`
}

// Allocation represents a resource allocation (IP or VLAN).
type Allocation struct {
	Pool         string    `json:"pool"`
	Value        string    `json:"value"` // IP address or VLAN tag
	SubscriberID string    `json:"subscriber_id"`
	AllocatedAt  time.Time `json:"allocated_at"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

// Heartbeat is sent periodically to update device status.
type Heartbeat struct {
	DeviceID       string    `json:"device_id"`
	Status         string    `json:"status"`
	Timestamp      time.Time `json:"timestamp"`
	Uptime         int64     `json:"uptime_seconds"`
	Subscribers    int       `json:"subscribers_active"`
	NTEsDiscovered int       `json:"ntes_discovered"`
	CLSetLagMS     int64     `json:"clset_lag_ms"`
}

// ConfigChange represents a configuration change notification.
type ConfigChange struct {
	Path      string      `json:"path"`
	Operation string      `json:"operation"` // "put", "delete"
	Value     interface{} `json:"value,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// ISPChurnEvent represents a subscriber changing ISPs.
type ISPChurnEvent struct {
	SubscriberID string    `json:"subscriber_id"`
	OldISPID     string    `json:"old_isp_id"`
	NewISPID     string    `json:"new_isp_id"`
	Timestamp    time.Time `json:"timestamp"`
}
