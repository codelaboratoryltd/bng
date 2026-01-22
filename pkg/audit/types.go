package audit

import (
	"net"
	"time"
)

// EventType represents the type of audit event.
type EventType string

const (
	// Session events
	EventSessionStart   EventType = "SESSION_START"
	EventSessionStop    EventType = "SESSION_STOP"
	EventSessionUpdate  EventType = "SESSION_UPDATE"
	EventSessionTimeout EventType = "SESSION_TIMEOUT"

	// Authentication events
	EventAuthSuccess EventType = "AUTH_SUCCESS"
	EventAuthFailure EventType = "AUTH_FAILURE"
	EventAuthReject  EventType = "AUTH_REJECT"

	// DHCP events
	EventDHCPDiscover EventType = "DHCP_DISCOVER"
	EventDHCPOffer    EventType = "DHCP_OFFER"
	EventDHCPRequest  EventType = "DHCP_REQUEST"
	EventDHCPAck      EventType = "DHCP_ACK"
	EventDHCPNak      EventType = "DHCP_NAK"
	EventDHCPRelease  EventType = "DHCP_RELEASE"
	EventDHCPDecline  EventType = "DHCP_DECLINE"

	// NAT events
	EventNATMapping EventType = "NAT_MAPPING"
	EventNATExpiry  EventType = "NAT_EXPIRY"

	// Policy events
	EventPolicyApply     EventType = "POLICY_APPLY"
	EventPolicyViolation EventType = "POLICY_VIOLATION"

	// Walled garden events
	EventWalledGardenAdd     EventType = "WALLED_GARDEN_ADD"
	EventWalledGardenRelease EventType = "WALLED_GARDEN_RELEASE"
	EventWalledGardenBlock   EventType = "WALLED_GARDEN_BLOCK"

	// Admin events
	EventConfigChange EventType = "CONFIG_CHANGE"
	EventAdminAction  EventType = "ADMIN_ACTION"

	// System events
	EventSystemStart EventType = "SYSTEM_START"
	EventSystemStop  EventType = "SYSTEM_STOP"
	EventSystemError EventType = "SYSTEM_ERROR"

	// Device registration events
	EventDeviceRegistrationAttempt EventType = "DEVICE_REGISTRATION_ATTEMPT"
	EventDeviceRegistrationSuccess EventType = "DEVICE_REGISTRATION_SUCCESS"
	EventDeviceRegistrationFailure EventType = "DEVICE_REGISTRATION_FAILURE"
	EventDeviceDeregistration      EventType = "DEVICE_DEREGISTRATION"

	// API security events
	EventAPIAuthAttempt  EventType = "API_AUTH_ATTEMPT"
	EventAPIAuthSuccess  EventType = "API_AUTH_SUCCESS"
	EventAPIAuthFailure  EventType = "API_AUTH_FAILURE"
	EventAPIAccessDenied EventType = "API_ACCESS_DENIED"
	EventAPIRateLimited  EventType = "API_RATE_LIMITED"

	// Suspicious activity events
	EventSuspiciousActivity    EventType = "SUSPICIOUS_ACTIVITY"
	EventBruteForceDetected    EventType = "BRUTE_FORCE_DETECTED"
	EventUnauthorizedAccess    EventType = "UNAUTHORIZED_ACCESS"
	EventMACSpoof              EventType = "MAC_SPOOF_DETECTED"
	EventIPSpoof               EventType = "IP_SPOOF_DETECTED"
	EventDHCPStarvationAttempt EventType = "DHCP_STARVATION_ATTEMPT"

	// Resource events (allocation/deallocation)
	EventResourceAllocated   EventType = "RESOURCE_ALLOCATED"
	EventResourceDeallocated EventType = "RESOURCE_DEALLOCATED"
	EventResourceExhausted   EventType = "RESOURCE_EXHAUSTED"
)

// Event represents a single audit event.
type Event struct {
	// Core fields
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	DeviceID  string    `json:"device_id"`

	// Subscriber identification
	SubscriberID string           `json:"subscriber_id,omitempty"`
	MAC          net.HardwareAddr `json:"mac,omitempty"`
	NTEID        string           `json:"nte_id,omitempty"`

	// Network identifiers
	IPv4 net.IP `json:"ipv4,omitempty"`
	IPv6 net.IP `json:"ipv6,omitempty"`
	STag uint16 `json:"s_tag,omitempty"`
	CTag uint16 `json:"c_tag,omitempty"`

	// ISP context
	ISPID       string `json:"isp_id,omitempty"`
	RADIUSRealm string `json:"radius_realm,omitempty"`

	// Session context
	SessionID string        `json:"session_id,omitempty"`
	Duration  time.Duration `json:"duration,omitempty"`

	// Traffic statistics
	BytesIn    uint64 `json:"bytes_in,omitempty"`
	BytesOut   uint64 `json:"bytes_out,omitempty"`
	PacketsIn  uint64 `json:"packets_in,omitempty"`
	PacketsOut uint64 `json:"packets_out,omitempty"`

	// NAT context (for NAT mapping events)
	NATPublicIP    net.IP `json:"nat_public_ip,omitempty"`
	NATPublicPort  uint16 `json:"nat_public_port,omitempty"`
	NATPrivateIP   net.IP `json:"nat_private_ip,omitempty"`
	NATPrivatePort uint16 `json:"nat_private_port,omitempty"`
	NATProtocol    uint8  `json:"nat_protocol,omitempty"`

	// DHCP context
	DHCPLeaseTime time.Duration `json:"dhcp_lease_time,omitempty"`
	DHCPServerID  net.IP        `json:"dhcp_server_id,omitempty"`

	// Authentication context
	AuthMethod   string `json:"auth_method,omitempty"`
	AuthUsername string `json:"auth_username,omitempty"`
	AuthReason   string `json:"auth_reason,omitempty"`

	// Policy context
	PolicyID   string `json:"policy_id,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`

	// Error context
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`

	// Admin context
	AdminUser   string `json:"admin_user,omitempty"`
	AdminAction string `json:"admin_action,omitempty"`

	// Security context (for API and access events)
	ActorID      string `json:"actor_id,omitempty"`      // User or service ID that initiated the action
	ActorType    string `json:"actor_type,omitempty"`    // "user", "service", "device", "system"
	SourceIP     net.IP `json:"source_ip,omitempty"`     // IP address of the request origin
	UserAgent    string `json:"user_agent,omitempty"`    // HTTP user agent or client identifier
	RequestID    string `json:"request_id,omitempty"`    // Unique request identifier for tracing
	APIEndpoint  string `json:"api_endpoint,omitempty"`  // API endpoint accessed
	HTTPMethod   string `json:"http_method,omitempty"`   // HTTP method used
	HTTPStatus   int    `json:"http_status,omitempty"`   // HTTP response status code
	ResourceType string `json:"resource_type,omitempty"` // Type of resource affected (pool, allocation, etc.)
	ResourceID   string `json:"resource_id,omitempty"`   // ID of the resource affected

	// Suspicious activity context
	ThreatType   string    `json:"threat_type,omitempty"`   // Type of threat detected
	ThreatScore  int       `json:"threat_score,omitempty"`  // Risk score 0-100
	FailureCount int       `json:"failure_count,omitempty"` // Number of failures for brute force detection
	BlockedUntil time.Time `json:"blocked_until,omitempty"` // Time until which the actor is blocked

	// Additional metadata
	Metadata map[string]string `json:"metadata,omitempty"`

	// Retention
	RetentionDays int       `json:"retention_days,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
}

// SessionEvent represents a subscriber session lifecycle event.
type SessionEvent struct {
	Event

	// Session details
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`
	TermCause string    `json:"term_cause,omitempty"`

	// QoS applied
	QoSPolicyID      string `json:"qos_policy_id,omitempty"`
	DownloadLimitBps uint64 `json:"download_limit_bps,omitempty"`
	UploadLimitBps   uint64 `json:"upload_limit_bps,omitempty"`

	// Connection type
	ConnectionType string `json:"connection_type,omitempty"` // "IPoE", "PPPoE"
	PONPort        string `json:"pon_port,omitempty"`
}

// NATEvent represents a NAT translation event.
type NATEvent struct {
	Event

	// Translation details
	TranslationType string    `json:"translation_type"` // "SNAT", "DNAT"
	DestIP          net.IP    `json:"dest_ip,omitempty"`
	DestPort        uint16    `json:"dest_port,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
}

// AuthEvent represents an authentication event.
type AuthEvent struct {
	Event

	// RADIUS details
	RADIUSServer    string `json:"radius_server,omitempty"`
	RADIUSReplyCode int    `json:"radius_reply_code,omitempty"`
	RADIUSReplyMsg  string `json:"radius_reply_msg,omitempty"`

	// Session attributes from RADIUS
	FramedIP       net.IP        `json:"framed_ip,omitempty"`
	FramedIPMask   net.IPMask    `json:"framed_ip_mask,omitempty"`
	SessionTimeout time.Duration `json:"session_timeout,omitempty"`
	IdleTimeout    time.Duration `json:"idle_timeout,omitempty"`
}

// Severity represents the severity of an event for filtering/alerting.
type Severity int

const (
	SeverityDebug Severity = iota
	SeverityInfo
	SeverityNotice
	SeverityWarning
	SeverityError
	SeverityCritical
	SeverityAlert
	SeverityEmergency
)

func (s Severity) String() string {
	switch s {
	case SeverityDebug:
		return "DEBUG"
	case SeverityInfo:
		return "INFO"
	case SeverityNotice:
		return "NOTICE"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	case SeverityAlert:
		return "ALERT"
	case SeverityEmergency:
		return "EMERGENCY"
	default:
		return "UNKNOWN"
	}
}

// GetSeverity returns the severity for an event type.
func (e EventType) GetSeverity() Severity {
	switch e {
	case EventAuthFailure, EventAuthReject, EventPolicyViolation:
		return SeverityWarning
	case EventSystemError:
		return SeverityError
	case EventSessionStart, EventSessionStop, EventAuthSuccess:
		return SeverityInfo
	case EventNATMapping, EventNATExpiry:
		return SeverityDebug
	// Device registration events
	case EventDeviceRegistrationSuccess:
		return SeverityInfo
	case EventDeviceRegistrationAttempt:
		return SeverityInfo
	case EventDeviceRegistrationFailure:
		return SeverityWarning
	case EventDeviceDeregistration:
		return SeverityNotice
	// API security events
	case EventAPIAuthAttempt:
		return SeverityInfo
	case EventAPIAuthSuccess:
		return SeverityInfo
	case EventAPIAuthFailure:
		return SeverityWarning
	case EventAPIAccessDenied:
		return SeverityWarning
	case EventAPIRateLimited:
		return SeverityWarning
	// Suspicious activity events (high severity)
	case EventSuspiciousActivity:
		return SeverityWarning
	case EventBruteForceDetected:
		return SeverityAlert
	case EventUnauthorizedAccess:
		return SeverityAlert
	case EventMACSpoof:
		return SeverityCritical
	case EventIPSpoof:
		return SeverityCritical
	case EventDHCPStarvationAttempt:
		return SeverityAlert
	// Resource events
	case EventResourceAllocated, EventResourceDeallocated:
		return SeverityInfo
	case EventResourceExhausted:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// Category returns the category for an event type.
func (e EventType) Category() string {
	switch e {
	case EventSessionStart, EventSessionStop, EventSessionUpdate, EventSessionTimeout:
		return "session"
	case EventAuthSuccess, EventAuthFailure, EventAuthReject:
		return "auth"
	case EventDHCPDiscover, EventDHCPOffer, EventDHCPRequest, EventDHCPAck, EventDHCPNak, EventDHCPRelease, EventDHCPDecline:
		return "dhcp"
	case EventNATMapping, EventNATExpiry:
		return "nat"
	case EventPolicyApply, EventPolicyViolation:
		return "policy"
	case EventWalledGardenAdd, EventWalledGardenRelease, EventWalledGardenBlock:
		return "walledgarden"
	case EventConfigChange, EventAdminAction:
		return "admin"
	case EventSystemStart, EventSystemStop, EventSystemError:
		return "system"
	case EventDeviceRegistrationAttempt, EventDeviceRegistrationSuccess, EventDeviceRegistrationFailure, EventDeviceDeregistration:
		return "device"
	case EventAPIAuthAttempt, EventAPIAuthSuccess, EventAPIAuthFailure, EventAPIAccessDenied, EventAPIRateLimited:
		return "api"
	case EventSuspiciousActivity, EventBruteForceDetected, EventUnauthorizedAccess, EventMACSpoof, EventIPSpoof, EventDHCPStarvationAttempt:
		return "security"
	case EventResourceAllocated, EventResourceDeallocated, EventResourceExhausted:
		return "resource"
	default:
		return "other"
	}
}
