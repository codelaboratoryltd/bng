package intercept

import (
	"net"
	"time"
)

// ETSI LI (Lawful Interception) standard implementation.
// References:
// - ETSI TS 102 232-1: Handover specification for IP delivery
// - ETSI TS 102 232-2: IP delivery for email
// - ETSI TS 102 232-3: IP delivery for internet access
// - ETSI TS 102 232-4: IP delivery for VoIP
// - ETSI ES 201 671: Handover interface

// WarrantType represents the type of lawful intercept warrant.
type WarrantType string

const (
	// WarrantIRI intercept-related information only (metadata).
	WarrantIRI WarrantType = "IRI"
	// WarrantCC content of communication (full traffic).
	WarrantCC WarrantType = "CC"
	// WarrantIRICC both IRI and CC.
	WarrantIRICC WarrantType = "IRI+CC"
)

// WarrantStatus represents the status of a warrant.
type WarrantStatus string

const (
	WarrantStatusPending   WarrantStatus = "PENDING"
	WarrantStatusActive    WarrantStatus = "ACTIVE"
	WarrantStatusSuspended WarrantStatus = "SUSPENDED"
	WarrantStatusExpired   WarrantStatus = "EXPIRED"
	WarrantStatusRevoked   WarrantStatus = "REVOKED"
)

// Warrant represents a lawful intercept warrant.
type Warrant struct {
	// Core identification
	ID        string    `json:"id"`
	LIID      string    `json:"liid"` // Lawful Interception ID (from LEA)
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Warrant details
	Type         WarrantType   `json:"type"`
	Status       WarrantStatus `json:"status"`
	AuthorityRef string        `json:"authority_ref"` // Reference to authorizing document
	IssuingBody  string        `json:"issuing_body"`  // Law enforcement agency

	// Target identification (one or more must be set)
	TargetSubscriberID string           `json:"target_subscriber_id,omitempty"`
	TargetMAC          net.HardwareAddr `json:"target_mac,omitempty"`
	TargetIPv4         net.IP           `json:"target_ipv4,omitempty"`
	TargetIPv6         net.IP           `json:"target_ipv6,omitempty"`
	TargetUsername     string           `json:"target_username,omitempty"` // RADIUS username
	TargetPhoneNumber  string           `json:"target_phone_number,omitempty"`
	TargetNTEID        string           `json:"target_nte_id,omitempty"`

	// Validity period
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`

	// Delivery configuration
	DeliveryMethod   DeliveryMethod `json:"delivery_method"`
	MediationAddress string         `json:"mediation_address"` // Address of mediation device
	MediationPort    int            `json:"mediation_port"`

	// Filtering (optional)
	FilterSourcePorts []int    `json:"filter_source_ports,omitempty"`
	FilterDestPorts   []int    `json:"filter_dest_ports,omitempty"`
	FilterProtocols   []uint8  `json:"filter_protocols,omitempty"` // IP protocols
	FilterDestIPs     []net.IP `json:"filter_dest_ips,omitempty"`

	// Internal tracking
	SessionsMatched  int64     `json:"sessions_matched"`
	BytesIntercepted int64     `json:"bytes_intercepted"`
	LastActivity     time.Time `json:"last_activity,omitempty"`
}

// DeliveryMethod specifies how intercepted data is delivered.
type DeliveryMethod string

const (
	DeliveryETSI      DeliveryMethod = "ETSI"       // ETSI standard handover
	DeliveryPCAP      DeliveryMethod = "PCAP"       // PCAP file delivery
	DeliverySyslog    DeliveryMethod = "SYSLOG"     // Syslog (IRI only)
	DeliveryJSONHTTPS DeliveryMethod = "JSON_HTTPS" // JSON over HTTPS
)

// InterceptRecord represents intercepted data or metadata.
type InterceptRecord struct {
	// Core identification
	ID        string    `json:"id"`
	LIID      string    `json:"liid"`
	WarrantID string    `json:"warrant_id"`
	Timestamp time.Time `json:"timestamp"`

	// Record type
	RecordType RecordType `json:"record_type"`

	// Target identification
	SubscriberID string           `json:"subscriber_id,omitempty"`
	MAC          net.HardwareAddr `json:"mac,omitempty"`
	SourceIP     net.IP           `json:"source_ip,omitempty"`
	DestIP       net.IP           `json:"dest_ip,omitempty"`
	SourcePort   uint16           `json:"source_port,omitempty"`
	DestPort     uint16           `json:"dest_port,omitempty"`
	Protocol     uint8            `json:"protocol,omitempty"`

	// Session context
	SessionID string `json:"session_id,omitempty"`

	// IRI-specific fields
	EventType    IRIEventType `json:"event_type,omitempty"`
	LocationInfo string       `json:"location_info,omitempty"`
	PartyInfo    *PartyInfo   `json:"party_info,omitempty"`

	// CC-specific fields (content)
	Direction   Direction `json:"direction,omitempty"`
	PayloadSize int       `json:"payload_size,omitempty"`
	Payload     []byte    `json:"-"` // Not serialized in JSON for security

	// NAT context (if applicable)
	PreNATSourceIP    net.IP `json:"pre_nat_source_ip,omitempty"`
	PreNATSourcePort  uint16 `json:"pre_nat_source_port,omitempty"`
	PostNATSourceIP   net.IP `json:"post_nat_source_ip,omitempty"`
	PostNATSourcePort uint16 `json:"post_nat_source_port,omitempty"`
}

// RecordType specifies the type of intercept record.
type RecordType string

const (
	RecordTypeIRI RecordType = "IRI" // Intercept Related Information
	RecordTypeCC  RecordType = "CC"  // Content of Communication
)

// IRIEventType specifies the type of IRI event.
type IRIEventType string

const (
	// Session events
	IRISessionStart  IRIEventType = "SESSION_START"
	IRISessionEnd    IRIEventType = "SESSION_END"
	IRISessionModify IRIEventType = "SESSION_MODIFY"

	// Network events
	IRIDHCPAllocate IRIEventType = "DHCP_ALLOCATE"
	IRIDHCPRelease  IRIEventType = "DHCP_RELEASE"
	IRINATMapping   IRIEventType = "NAT_MAPPING"
	IRINATExpiry    IRIEventType = "NAT_EXPIRY"

	// Authentication events
	IRIAuthSuccess IRIEventType = "AUTH_SUCCESS"
	IRIAuthFailure IRIEventType = "AUTH_FAILURE"

	// Policy events
	IRIPolicyApply     IRIEventType = "POLICY_APPLY"
	IRIPolicyViolation IRIEventType = "POLICY_VIOLATION"
)

// Direction specifies the direction of traffic.
type Direction string

const (
	DirectionUplink   Direction = "UPLINK"   // Subscriber → Network
	DirectionDownlink Direction = "DOWNLINK" // Network → Subscriber
)

// PartyInfo contains information about a communication party.
type PartyInfo struct {
	PartyID     string           `json:"party_id,omitempty"`
	PartyType   string           `json:"party_type,omitempty"` // "subscriber", "remote"
	IPv4Address net.IP           `json:"ipv4_address,omitempty"`
	IPv6Address net.IP           `json:"ipv6_address,omitempty"`
	Port        uint16           `json:"port,omitempty"`
	MACAddress  net.HardwareAddr `json:"mac_address,omitempty"`
}

// HandoverInterface represents an ETSI HI interface.
type HandoverInterface string

const (
	// HI1 is the administrative interface between LEA and CSP.
	HI1 HandoverInterface = "HI1"
	// HI2 delivers Intercept Related Information (metadata).
	HI2 HandoverInterface = "HI2"
	// HI3 delivers Content of Communication (actual traffic).
	HI3 HandoverInterface = "HI3"
)

// ETSIHeader represents the ETSI PDU header.
type ETSIHeader struct {
	Version      uint8             `json:"version"`
	HandoverType HandoverInterface `json:"handover_type"`
	LIID         string            `json:"liid"`
	CIN          string            `json:"cin"` // Communication Identity Number
	SequenceNum  uint64            `json:"sequence_num"`
	Timestamp    time.Time         `json:"timestamp"`
	CountryCode  string            `json:"country_code"` // ISO 3166-1 alpha-2
}

// InterceptSession tracks an active interception for a session.
type InterceptSession struct {
	// Session identification
	SessionID    string    `json:"session_id"`
	WarrantID    string    `json:"warrant_id"`
	LIID         string    `json:"liid"`
	StartTime    time.Time `json:"start_time"`
	LastActivity time.Time `json:"last_activity"`

	// Target info
	SubscriberID string           `json:"subscriber_id"`
	MAC          net.HardwareAddr `json:"mac,omitempty"`
	IPv4         net.IP           `json:"ipv4,omitempty"`
	IPv6         net.IP           `json:"ipv6,omitempty"`

	// Statistics
	IRIRecords    int64 `json:"iri_records"`
	CCRecords     int64 `json:"cc_records"`
	BytesCaptured int64 `json:"bytes_captured"`
}

// ManagerStats holds lawful intercept manager statistics.
type ManagerStats struct {
	ActiveWarrants      int   `json:"active_warrants"`
	ActiveInterceptions int   `json:"active_interceptions"`
	TotalIRIRecords     int64 `json:"total_iri_records"`
	TotalCCRecords      int64 `json:"total_cc_records"`
	TotalBytesDelivered int64 `json:"total_bytes_delivered"`
	DeliveryErrors      int64 `json:"delivery_errors"`
}

// Config holds lawful intercept configuration.
type Config struct {
	// Enable/disable LI
	Enabled bool `json:"enabled"`

	// Operator identification
	OperatorID  string `json:"operator_id"`
	CountryCode string `json:"country_code"` // ISO 3166-1 alpha-2

	// Default mediation settings
	DefaultMediationAddress string `json:"default_mediation_address,omitempty"`
	DefaultMediationPort    int    `json:"default_mediation_port,omitempty"`

	// Delivery settings
	DeliveryBufferSize int           `json:"delivery_buffer_size"`
	DeliveryTimeout    time.Duration `json:"delivery_timeout"`
	RetryAttempts      int           `json:"retry_attempts"`
	RetryInterval      time.Duration `json:"retry_interval"`

	// Security
	RequireTLS bool   `json:"require_tls"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	CAFile     string `json:"ca_file,omitempty"`

	// Storage
	StoreRecords     bool          `json:"store_records"`
	StorageRetention time.Duration `json:"storage_retention"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:            false, // Disabled by default
		CountryCode:        "GB",
		DeliveryBufferSize: 10000,
		DeliveryTimeout:    30 * time.Second,
		RetryAttempts:      3,
		RetryInterval:      5 * time.Second,
		RequireTLS:         true,
		StoreRecords:       true,
		StorageRetention:   90 * 24 * time.Hour, // 90 days
	}
}
