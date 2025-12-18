package dns

import (
	"net"
	"time"
)

// Config holds DNS server configuration.
type Config struct {
	// Listener configuration
	ListenAddress string // Address to listen on (e.g., "0.0.0.0:53")
	EnableTCP     bool   // Enable TCP (default: true)
	EnableUDP     bool   // Enable UDP (default: true)

	// Upstream resolvers
	Upstreams []Upstream

	// Cache configuration
	CacheEnabled     bool          `json:"cache_enabled"`
	CacheSize        int           `json:"cache_size"`         // Max cache entries
	CacheMinTTL      time.Duration `json:"cache_min_ttl"`      // Minimum TTL
	CacheMaxTTL      time.Duration `json:"cache_max_ttl"`      // Maximum TTL
	CacheNegativeTTL time.Duration `json:"cache_negative_ttl"` // TTL for NXDOMAIN

	// EDNS configuration
	EDNSBufferSize uint16 `json:"edns_buffer_size"`

	// DNS64 configuration
	DNS64Enabled bool      `json:"dns64_enabled"`
	DNS64Prefix  net.IPNet `json:"dns64_prefix"` // Well-known prefix 64:ff9b::/96

	// Rate limiting
	RateLimitEnabled bool `json:"rate_limit_enabled"`
	RateLimitQPS     int  `json:"rate_limit_qps"` // Queries per second per client

	// Walled garden integration
	WalledGardenEnabled    bool   `json:"walled_garden_enabled"`
	WalledGardenRedirectIP net.IP `json:"walled_garden_redirect_ip"`

	// Query logging
	QueryLogging bool `json:"query_logging"`
}

// Upstream represents an upstream DNS resolver.
type Upstream struct {
	Address  string        `json:"address"`  // IP:port
	Protocol string        `json:"protocol"` // "udp", "tcp", "tls", "https"
	Timeout  time.Duration `json:"timeout"`
	Weight   int           `json:"weight"` // For load balancing

	// TLS configuration (for DoT)
	TLSServerName string `json:"tls_server_name,omitempty"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddress: "0.0.0.0:53",
		EnableTCP:     true,
		EnableUDP:     true,
		Upstreams: []Upstream{
			{Address: "8.8.8.8:53", Protocol: "udp", Timeout: 5 * time.Second, Weight: 1},
			{Address: "8.8.4.4:53", Protocol: "udp", Timeout: 5 * time.Second, Weight: 1},
		},
		CacheEnabled:     true,
		CacheSize:        10000,
		CacheMinTTL:      60 * time.Second,
		CacheMaxTTL:      24 * time.Hour,
		CacheNegativeTTL: 5 * time.Minute,
		EDNSBufferSize:   4096,
		DNS64Enabled:     false,
		DNS64Prefix:      net.IPNet{IP: net.ParseIP("64:ff9b::"), Mask: net.CIDRMask(96, 128)},
		RateLimitEnabled: true,
		RateLimitQPS:     100,
		QueryLogging:     true,
	}
}

// Query represents a DNS query.
type Query struct {
	Name   string // Domain name
	Type   uint16 // Query type (A, AAAA, MX, etc.)
	Class  uint16 // Query class (IN, CH, etc.)
	Source net.IP // Client IP
}

// Response represents a DNS response.
type Response struct {
	Query       *Query
	Answers     []Record
	Authorities []Record
	Additionals []Record
	Rcode       int           // Response code
	FromCache   bool          // Whether from cache
	Latency     time.Duration // Query latency
}

// Record represents a DNS resource record.
type Record struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte

	// Parsed data fields
	IPv4   net.IP // For A records
	IPv6   net.IP // For AAAA records
	Target string // For CNAME, MX, NS, PTR
	MXPref uint16 // For MX records
	TXT    string // For TXT records
}

// CacheEntry represents a cached DNS response.
type CacheEntry struct {
	Key       string
	Records   []Record
	ExpiresAt time.Time
	Negative  bool // NXDOMAIN response
	CreatedAt time.Time
	HitCount  int64
}

// CacheStats holds cache statistics.
type CacheStats struct {
	Size      int   `json:"size"`
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	Evictions int64 `json:"evictions"`
}

// ServerStats holds DNS server statistics.
type ServerStats struct {
	QueriesReceived    int64            `json:"queries_received"`
	QueriesForwarded   int64            `json:"queries_forwarded"`
	QueriesFromCache   int64            `json:"queries_from_cache"`
	QueriesBlocked     int64            `json:"queries_blocked"`
	QueriesRateLimited int64            `json:"queries_rate_limited"`
	DNS64Translations  int64            `json:"dns64_translations"`
	Errors             int64            `json:"errors"`
	AvgLatencyMS       float64          `json:"avg_latency_ms"`
	QueryTypeStats     map[uint16]int64 `json:"query_type_stats"`
	Cache              CacheStats       `json:"cache"`
}

// Standard DNS record types.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeOPT   uint16 = 41
	TypeANY   uint16 = 255
)

// Standard DNS response codes.
const (
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3 // NXDOMAIN
	RcodeNotImplemented = 4
	RcodeRefused        = 5
)

// TypeString returns the string name for a DNS type.
func TypeString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	case TypeANY:
		return "ANY"
	default:
		return "UNKNOWN"
	}
}

// RcodeString returns the string name for a response code.
func RcodeString(rcode int) string {
	switch rcode {
	case RcodeSuccess:
		return "NOERROR"
	case RcodeFormatError:
		return "FORMERR"
	case RcodeServerFailure:
		return "SERVFAIL"
	case RcodeNameError:
		return "NXDOMAIN"
	case RcodeNotImplemented:
		return "NOTIMP"
	case RcodeRefused:
		return "REFUSED"
	default:
		return "UNKNOWN"
	}
}

// InterceptRule defines a DNS interception rule.
type InterceptRule struct {
	// Match criteria
	Domain       string // Domain to match (supports wildcards)
	DomainSuffix string // Match domain suffix (e.g., ".example.com")
	Exact        bool   // Exact match only

	// Action
	Action      InterceptAction
	RedirectIP  net.IP // For redirect action
	CNAME       string // For CNAME override
	BlockReason string // For logging
}

// InterceptAction defines what to do when a rule matches.
type InterceptAction int

const (
	// ActionAllow allows the query to proceed normally.
	ActionAllow InterceptAction = iota
	// ActionBlock returns NXDOMAIN.
	ActionBlock
	// ActionRedirect returns a different IP.
	ActionRedirect
	// ActionCNAME returns a CNAME record.
	ActionCNAME
)

// WalledGardenClient represents a client in the walled garden.
type WalledGardenClient struct {
	IP           net.IP
	MAC          net.HardwareAddr
	SubscriberID string
	Reason       string // Why in walled garden
	AddedAt      time.Time
}
