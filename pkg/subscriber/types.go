package subscriber

import (
	"net"
	"time"
)

// SessionRequest represents a request to create a new session.
type SessionRequest struct {
	// Identification
	MAC     net.HardwareAddr
	NTEID   string // Network Termination Equipment ID
	ONUID   string // ONU ID for PON
	PONPort string

	// VLAN context
	STag uint16 // Service VLAN
	CTag uint16 // Customer VLAN

	// Session type
	Type SessionType

	// PPPoE context (if applicable)
	Username string
	Password string

	// DHCP context (if applicable)
	RequestedIP net.IP
	Hostname    string
	ClientID    string
	VendorClass string
	UserClass   string
	CircuitID   string // Option 82 Circuit ID
	RemoteID    string // Option 82 Remote ID

	// Interface
	InterfaceName string
	InterfaceID   int
}

// SessionType represents the type of subscriber session.
type SessionType string

const (
	SessionTypeIPoE  SessionType = "ipoe"
	SessionTypePPPoE SessionType = "pppoe"
)

// SessionState represents the state of a session.
type SessionState string

const (
	StateInit           SessionState = "init"
	StateAuthenticating SessionState = "authenticating"
	StateAddressAssign  SessionState = "address_assign"
	StateEstablishing   SessionState = "establishing"
	StateActive         SessionState = "active"
	StateWalledGarden   SessionState = "walled_garden"
	StateTerminating    SessionState = "terminating"
	StateTerminated     SessionState = "terminated"
)

// Session represents an active subscriber session.
type Session struct {
	// Core identification
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Subscriber link
	SubscriberID string `json:"subscriber_id"`

	// Hardware identification
	MAC     net.HardwareAddr `json:"mac"`
	NTEID   string           `json:"nte_id,omitempty"`
	ONUID   string           `json:"onu_id,omitempty"`
	PONPort string           `json:"pon_port,omitempty"`

	// VLAN context
	STag uint16 `json:"s_tag,omitempty"`
	CTag uint16 `json:"c_tag,omitempty"`

	// Session type
	Type SessionType `json:"type"`

	// ISP context
	ISPID       string `json:"isp_id"`
	RADIUSRealm string `json:"radius_realm,omitempty"`

	// Network assignment
	IPv4       net.IP     `json:"ipv4,omitempty"`
	IPv6       net.IP     `json:"ipv6,omitempty"`
	IPv6Prefix *net.IPNet `json:"ipv6_prefix,omitempty"` // Delegated prefix
	Gateway    net.IP     `json:"gateway,omitempty"`
	SubnetMask net.IPMask `json:"subnet_mask,omitempty"`
	DNSServers []net.IP   `json:"dns_servers,omitempty"`
	LeaseID    string     `json:"lease_id,omitempty"`

	// PPPoE context
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

	// Walled garden
	WalledGarden bool   `json:"walled_garden"`
	WalledReason string `json:"walled_reason,omitempty"`

	// QoS
	QoSPolicyID     string `json:"qos_policy_id,omitempty"`
	DownloadRateBps uint64 `json:"download_rate_bps,omitempty"`
	UploadRateBps   uint64 `json:"upload_rate_bps,omitempty"`

	// NAT context
	NATPoolID    string `json:"nat_pool_id,omitempty"`
	NATPublicIP  net.IP `json:"nat_public_ip,omitempty"`
	NATPortStart uint16 `json:"nat_port_start,omitempty"`
	NATPortEnd   uint16 `json:"nat_port_end,omitempty"`

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

	// Interface
	InterfaceName string `json:"interface_name,omitempty"`
	InterfaceID   int    `json:"interface_id,omitempty"`

	// Metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// AuthMethod represents the authentication method used.
type AuthMethod string

const (
	AuthNone   AuthMethod = "none"
	AuthMAC    AuthMethod = "mac"    // MAC-based (IPoE)
	AuthPPPoE  AuthMethod = "pppoe"  // PPPoE with RADIUS
	AuthDot1X  AuthMethod = "802.1x" // 802.1X
	AuthRADIUS AuthMethod = "radius" // Direct RADIUS
)

// AuthResult represents the result of an authentication attempt.
type AuthResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`

	// Subscriber info
	SubscriberID string `json:"subscriber_id,omitempty"`
	ISPID        string `json:"isp_id,omitempty"`
	Username     string `json:"username,omitempty"`

	// Session attributes
	SessionTimeout time.Duration `json:"session_timeout,omitempty"`
	IdleTimeout    time.Duration `json:"idle_timeout,omitempty"`

	// QoS attributes
	DownloadRateBps uint64 `json:"download_rate_bps,omitempty"`
	UploadRateBps   uint64 `json:"upload_rate_bps,omitempty"`
	QoSPolicyID     string `json:"qos_policy_id,omitempty"`

	// IP assignment
	FramedIPAddress     net.IP `json:"framed_ip_address,omitempty"`
	FramedIPNetmask     net.IP `json:"framed_ip_netmask,omitempty"`
	FramedIPv6Prefix    string `json:"framed_ipv6_prefix,omitempty"`
	DelegatedIPv6Prefix string `json:"delegated_ipv6_prefix,omitempty"`
	IPv4PoolID          string `json:"ipv4_pool_id,omitempty"`
	IPv6PoolID          string `json:"ipv6_pool_id,omitempty"`

	// RADIUS context
	RADIUSSessionID string            `json:"radius_session_id,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`

	// Walled garden
	WalledGarden bool   `json:"walled_garden"`
	WalledReason string `json:"walled_reason,omitempty"`
}

// SessionEvent represents an event in the session lifecycle.
type SessionEvent struct {
	Type      SessionEventType `json:"type"`
	SessionID string           `json:"session_id"`
	Timestamp time.Time        `json:"timestamp"`
	OldState  SessionState     `json:"old_state,omitempty"`
	NewState  SessionState     `json:"new_state,omitempty"`
	Reason    string           `json:"reason,omitempty"`
	Details   map[string]any   `json:"details,omitempty"`
}

// SessionEventType represents the type of session event.
type SessionEventType string

const (
	EventSessionCreate    SessionEventType = "session_create"
	EventSessionAuth      SessionEventType = "session_auth"
	EventSessionAuthFail  SessionEventType = "session_auth_fail"
	EventSessionActivate  SessionEventType = "session_activate"
	EventSessionUpdate    SessionEventType = "session_update"
	EventSessionWalled    SessionEventType = "session_walled"
	EventSessionUnwalled  SessionEventType = "session_unwalled"
	EventSessionTerminate SessionEventType = "session_terminate"
	EventSessionTimeout   SessionEventType = "session_timeout"
	EventSessionAcct      SessionEventType = "session_acct"
)

// TerminateReason represents the reason for session termination.
type TerminateReason string

const (
	TerminateUserRequest    TerminateReason = "user_request"
	TerminateAdminReset     TerminateReason = "admin_reset"
	TerminateSessionTimeout TerminateReason = "session_timeout"
	TerminateIdleTimeout    TerminateReason = "idle_timeout"
	TerminateLostCarrier    TerminateReason = "lost_carrier"
	TerminatePortError      TerminateReason = "port_error"
	TerminateNASRequest     TerminateReason = "nas_request"
	TerminateNASReboot      TerminateReason = "nas_reboot"
	TerminateAuthFailed     TerminateReason = "auth_failed"
)

// ManagerConfig holds session manager configuration.
type ManagerConfig struct {
	// Cleanup intervals
	CleanupInterval time.Duration `json:"cleanup_interval"`

	// Default timeouts
	DefaultSessionTimeout time.Duration `json:"default_session_timeout"`
	DefaultIdleTimeout    time.Duration `json:"default_idle_timeout"`

	// Auth settings
	AuthTimeout     time.Duration `json:"auth_timeout"`
	MaxAuthAttempts int           `json:"max_auth_attempts"`

	// Walled garden
	WalledGardenDNS     []net.IP `json:"walled_garden_dns,omitempty"`
	WalledGardenDomains []string `json:"walled_garden_domains,omitempty"`

	// Capacity limits
	MaxSessions int `json:"max_sessions"`

	// QoS defaults
	DefaultDownloadRateBps uint64 `json:"default_download_rate_bps"`
	DefaultUploadRateBps   uint64 `json:"default_upload_rate_bps"`
}

// DefaultManagerConfig returns sensible defaults.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		CleanupInterval:        30 * time.Second,
		DefaultSessionTimeout:  24 * time.Hour,
		DefaultIdleTimeout:     30 * time.Minute,
		AuthTimeout:            30 * time.Second,
		MaxAuthAttempts:        3,
		MaxSessions:            100000,
		DefaultDownloadRateBps: 100_000_000, // 100 Mbps
		DefaultUploadRateBps:   50_000_000,  // 50 Mbps
	}
}

// ManagerStats holds session manager statistics.
type ManagerStats struct {
	ActiveSessions       int   `json:"active_sessions"`
	WalledGardenSessions int   `json:"walled_garden_sessions"`
	TotalSessionsCreated int64 `json:"total_sessions_created"`
	TotalSessionsEnded   int64 `json:"total_sessions_ended"`
	AuthSuccesses        int64 `json:"auth_successes"`
	AuthFailures         int64 `json:"auth_failures"`
	TotalBytesIn         int64 `json:"total_bytes_in"`
	TotalBytesOut        int64 `json:"total_bytes_out"`
}
