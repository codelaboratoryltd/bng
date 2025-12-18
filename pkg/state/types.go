package state

import (
	"net"
	"time"
)

// Subscriber represents a subscriber in the BNG system.
type Subscriber struct {
	// Core identification
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Hardware identification
	MAC     net.HardwareAddr `json:"mac"`
	NTEID   string           `json:"nte_id,omitempty"`   // Network Termination Equipment ID
	ONUID   string           `json:"onu_id,omitempty"`   // ONU ID for PON
	PONPort string           `json:"pon_port,omitempty"` // PON port

	// VLAN identification
	STag uint16 `json:"s_tag,omitempty"` // Service VLAN
	CTag uint16 `json:"c_tag,omitempty"` // Customer VLAN

	// ISP assignment
	ISPID       string `json:"isp_id"`
	RADIUSRealm string `json:"radius_realm,omitempty"`

	// Classification
	Class       SubscriberClass `json:"class"`
	ServicePlan string          `json:"service_plan,omitempty"`
	ContractID  string          `json:"contract_id,omitempty"`

	// QoS settings
	DownloadRateBps uint64 `json:"download_rate_bps,omitempty"`
	UploadRateBps   uint64 `json:"upload_rate_bps,omitempty"`
	QoSPolicyID     string `json:"qos_policy_id,omitempty"`

	// Pool assignment
	IPv4PoolID string `json:"ipv4_pool_id,omitempty"`
	IPv6PoolID string `json:"ipv6_pool_id,omitempty"`

	// Authentication
	AuthMethod    AuthMethod `json:"auth_method"`
	Username      string     `json:"username,omitempty"` // For PPPoE
	Authenticated bool       `json:"authenticated"`

	// Status
	Status       SubscriberStatus `json:"status"`
	StatusReason string           `json:"status_reason,omitempty"`
	WalledGarden bool             `json:"walled_garden"`
	WalledReason string           `json:"walled_reason,omitempty"`

	// Metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SubscriberClass represents the class of subscriber.
type SubscriberClass string

const (
	ClassResidential SubscriberClass = "residential"
	ClassBusiness    SubscriberClass = "business"
	ClassWholesale   SubscriberClass = "wholesale"
	ClassInternal    SubscriberClass = "internal"
)

// SubscriberStatus represents the status of a subscriber.
type SubscriberStatus string

const (
	StatusActive    SubscriberStatus = "active"
	StatusSuspended SubscriberStatus = "suspended"
	StatusDisabled  SubscriberStatus = "disabled"
	StatusPending   SubscriberStatus = "pending"
)

// AuthMethod represents the authentication method.
type AuthMethod string

const (
	AuthNone   AuthMethod = "none"
	AuthMAC    AuthMethod = "mac"    // MAC-based (IPoE)
	AuthPPPoE  AuthMethod = "pppoe"  // PPPoE with RADIUS
	AuthDot1X  AuthMethod = "802.1x" // 802.1X
	AuthRADIUS AuthMethod = "radius" // Direct RADIUS
)

// Lease represents an IP address lease.
type Lease struct {
	// Core identification
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Lease target
	SubscriberID string           `json:"subscriber_id"`
	MAC          net.HardwareAddr `json:"mac"`
	SessionID    string           `json:"session_id,omitempty"`

	// IP assignment
	IPv4       net.IP     `json:"ipv4,omitempty"`
	IPv6       net.IP     `json:"ipv6,omitempty"`
	IPv6Prefix *net.IPNet `json:"ipv6_prefix,omitempty"` // Delegated prefix

	// Pool context
	PoolID   string `json:"pool_id"`
	PoolName string `json:"pool_name,omitempty"`

	// DHCP options
	SubnetMask net.IPMask `json:"subnet_mask,omitempty"`
	Gateway    net.IP     `json:"gateway,omitempty"`
	DNSServers []net.IP   `json:"dns_servers,omitempty"`
	NTPServers []net.IP   `json:"ntp_servers,omitempty"`
	DomainName string     `json:"domain_name,omitempty"`

	// Timing
	LeaseTime  time.Duration `json:"lease_time"`
	RenewTime  time.Duration `json:"renew_time"`  // T1
	RebindTime time.Duration `json:"rebind_time"` // T2
	ExpiresAt  time.Time     `json:"expires_at"`

	// State
	State    LeaseState `json:"state"`
	Hostname string     `json:"hostname,omitempty"`
	ClientID string     `json:"client_id,omitempty"`

	// Statistics
	RenewCount   int       `json:"renew_count"`
	LastRenewAt  time.Time `json:"last_renew_at,omitempty"`
	LastActivity time.Time `json:"last_activity"`
}

// LeaseState represents the state of a lease.
type LeaseState string

const (
	LeaseStateOffered   LeaseState = "offered"   // DHCP OFFER sent
	LeaseStateBound     LeaseState = "bound"     // DHCP ACK sent
	LeaseStateRenewing  LeaseState = "renewing"  // T1 passed, renewing
	LeaseStateRebinding LeaseState = "rebinding" // T2 passed, rebinding
	LeaseStateExpired   LeaseState = "expired"   // Lease expired
	LeaseStateReleased  LeaseState = "released"  // Client released
)

// Pool represents an IP address pool.
type Pool struct {
	// Core identification
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Pool type
	Type    PoolType `json:"type"`
	Version int      `json:"version"` // 4 or 6

	// Network range
	Network    net.IPNet  `json:"network"`  // e.g., 10.0.0.0/24
	StartIP    net.IP     `json:"start_ip"` // First allocatable IP
	EndIP      net.IP     `json:"end_ip"`   // Last allocatable IP
	Gateway    net.IP     `json:"gateway"`  // Default gateway
	SubnetMask net.IPMask `json:"subnet_mask"`

	// DHCP options
	DNSServers []net.IP      `json:"dns_servers,omitempty"`
	NTPServers []net.IP      `json:"ntp_servers,omitempty"`
	DomainName string        `json:"domain_name,omitempty"`
	LeaseTime  time.Duration `json:"lease_time"`

	// Assignment rules
	ISPIDs          []string          `json:"isp_ids,omitempty"`          // ISPs that can use this pool
	SubscriberClass []SubscriberClass `json:"subscriber_class,omitempty"` // Classes that can use this pool
	Priority        int               `json:"priority"`                   // Higher = preferred

	// Capacity
	TotalAddresses     int `json:"total_addresses"`
	AllocatedAddresses int `json:"allocated_addresses"`
	ReservedAddresses  int `json:"reserved_addresses"`

	// Status
	Enabled bool   `json:"enabled"`
	Status  string `json:"status,omitempty"`

	// Metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PoolType represents the type of pool.
type PoolType string

const (
	PoolTypePublic    PoolType = "public"    // Public IP addresses
	PoolTypePrivate   PoolType = "private"   // RFC1918 addresses
	PoolTypeCGNAT     PoolType = "cgnat"     // CGNAT range (100.64.0.0/10)
	PoolTypeDelegated PoolType = "delegated" // IPv6 prefix delegation
)

// Session represents an active subscriber session.
type Session struct {
	// Core identification
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Links
	SubscriberID string `json:"subscriber_id"`
	LeaseID      string `json:"lease_id,omitempty"`

	// Session type
	Type SessionType `json:"type"`

	// Network identification
	MAC  net.HardwareAddr `json:"mac"`
	IPv4 net.IP           `json:"ipv4,omitempty"`
	IPv6 net.IP           `json:"ipv6,omitempty"`
	STag uint16           `json:"s_tag,omitempty"`
	CTag uint16           `json:"c_tag,omitempty"`

	// ISP context
	ISPID       string `json:"isp_id"`
	RADIUSRealm string `json:"radius_realm,omitempty"`

	// PPPoE context (if applicable)
	PPPoESessionID uint16 `json:"pppoe_session_id,omitempty"`
	LCPState       string `json:"lcp_state,omitempty"`
	NCPState       string `json:"ncp_state,omitempty"`

	// Authentication
	Username        string     `json:"username,omitempty"`
	AuthMethod      AuthMethod `json:"auth_method"`
	Authenticated   bool       `json:"authenticated"`
	RADIUSSessionID string     `json:"radius_session_id,omitempty"`

	// State
	State       SessionState `json:"state"`
	StateReason string       `json:"state_reason,omitempty"`

	// Timing
	StartTime      time.Time     `json:"start_time"`
	LastActivity   time.Time     `json:"last_activity"`
	SessionTimeout time.Duration `json:"session_timeout,omitempty"`
	IdleTimeout    time.Duration `json:"idle_timeout,omitempty"`

	// Traffic statistics
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`

	// QoS applied
	QoSPolicyID     string `json:"qos_policy_id,omitempty"`
	DownloadRateBps uint64 `json:"download_rate_bps,omitempty"`
	UploadRateBps   uint64 `json:"upload_rate_bps,omitempty"`

	// NAT context
	NATPoolID    string `json:"nat_pool_id,omitempty"`
	NATPublicIP  net.IP `json:"nat_public_ip,omitempty"`
	NATPortStart uint16 `json:"nat_port_start,omitempty"`
	NATPortEnd   uint16 `json:"nat_port_end,omitempty"`

	// Metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SessionType represents the type of session.
type SessionType string

const (
	SessionTypeIPoE  SessionType = "ipoe"
	SessionTypePPPoE SessionType = "pppoe"
)

// SessionState represents the state of a session.
type SessionState string

const (
	SessionStateInit           SessionState = "init"           // Session initializing
	SessionStateAuthenticating SessionState = "authenticating" // Waiting for auth
	SessionStateEstablishing   SessionState = "establishing"   // Setting up
	SessionStateActive         SessionState = "active"         // Fully active
	SessionStateTerminating    SessionState = "terminating"    // Shutting down
	SessionStateTerminated     SessionState = "terminated"     // Ended
)

// NATBinding represents a NAT port mapping.
type NATBinding struct {
	// Core identification
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`

	// Session context
	SessionID    string `json:"session_id"`
	SubscriberID string `json:"subscriber_id"`

	// Original (private) address
	PrivateIP   net.IP `json:"private_ip"`
	PrivatePort uint16 `json:"private_port"`

	// Translated (public) address
	PublicIP   net.IP `json:"public_ip"`
	PublicPort uint16 `json:"public_port"`

	// Protocol
	Protocol uint8 `json:"protocol"` // TCP=6, UDP=17, ICMP=1

	// Destination (for full cone NAT)
	DestIP   net.IP `json:"dest_ip,omitempty"`
	DestPort uint16 `json:"dest_port,omitempty"`

	// Timing
	ExpiresAt    time.Time `json:"expires_at"`
	LastActivity time.Time `json:"last_activity"`

	// Statistics
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

// StoreStats holds state store statistics.
type StoreStats struct {
	Subscribers    int `json:"subscribers"`
	ActiveSessions int `json:"active_sessions"`
	Leases         int `json:"leases"`
	Pools          int `json:"pools"`
	NATBindings    int `json:"nat_bindings"`

	// Operations
	Reads   int64 `json:"reads"`
	Writes  int64 `json:"writes"`
	Deletes int64 `json:"deletes"`
}
