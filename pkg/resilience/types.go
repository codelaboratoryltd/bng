// Package resilience provides network partition handling and recovery mechanisms
// for the OLT-BNG system. It handles graceful degradation during network partitions,
// IP pool exhaustion, duplicate IP detection, and RADIUS reconnection.
package resilience

import (
	"net"
	"sync"
	"time"
)

// PartitionState represents the current network partition state.
type PartitionState int

const (
	// StateOnline indicates normal operation with full connectivity.
	StateOnline PartitionState = iota
	// StatePartitioned indicates connectivity to Nexus/RADIUS is lost.
	StatePartitioned
	// StateRecovering indicates partition is healing and reconciliation is in progress.
	StateRecovering
)

// String returns a human-readable state name.
func (s PartitionState) String() string {
	switch s {
	case StateOnline:
		return "online"
	case StatePartitioned:
		return "partitioned"
	case StateRecovering:
		return "recovering"
	default:
		return "unknown"
	}
}

// PoolUtilizationLevel represents the severity of pool utilization.
type PoolUtilizationLevel int

const (
	// LevelNormal indicates normal pool utilization (<80%).
	LevelNormal PoolUtilizationLevel = iota
	// LevelWarning indicates elevated utilization (80-90%).
	LevelWarning
	// LevelCritical indicates critical utilization (90-95%).
	LevelCritical
	// LevelExhausted indicates pool is exhausted (>95% or no IPs available).
	LevelExhausted
)

// String returns a human-readable level name.
func (l PoolUtilizationLevel) String() string {
	switch l {
	case LevelNormal:
		return "normal"
	case LevelWarning:
		return "warning"
	case LevelCritical:
		return "critical"
	case LevelExhausted:
		return "exhausted"
	default:
		return "unknown"
	}
}

// PartitionConfig holds configuration for partition handling.
type PartitionConfig struct {
	// Health check settings
	HealthCheckInterval time.Duration `yaml:"health_check_interval"`
	HealthCheckTimeout  time.Duration `yaml:"health_check_timeout"`
	HealthCheckRetries  int           `yaml:"health_check_retries"`

	// Pool thresholds
	PoolWarningThreshold   float64 `yaml:"pool_warning_threshold"`   // Default: 0.80
	PoolCriticalThreshold  float64 `yaml:"pool_critical_threshold"`  // Default: 0.90
	PoolExhaustedThreshold float64 `yaml:"pool_exhausted_threshold"` // Default: 0.95

	// Short lease mode settings
	ShortLeaseEnabled   bool          `yaml:"short_lease_enabled"`
	ShortLeaseDuration  time.Duration `yaml:"short_lease_duration"`  // Default: 5 minutes
	ShortLeaseThreshold float64       `yaml:"short_lease_threshold"` // Default: 0.90

	// Request queue settings
	RequestQueueSize    int           `yaml:"request_queue_size"`    // Default: 1000
	RequestQueueTimeout time.Duration `yaml:"request_queue_timeout"` // Default: 30 seconds

	// Recovery settings
	ReconciliationTimeout   time.Duration `yaml:"reconciliation_timeout"`     // Default: 60 seconds
	ReauthRateLimit         int           `yaml:"reauth_rate_limit"`          // Default: 100/sec
	AccountingSyncBatchSize int           `yaml:"accounting_sync_batch_size"` // Default: 100
	AccountingBufferSize    int           `yaml:"accounting_buffer_size"`     // Default: 100000

	// RADIUS settings
	RADIUSPartitionMode RADIUSPartitionMode `yaml:"radius_partition_mode"` // deny, cached, queue
	CachedProfileTTL    time.Duration       `yaml:"cached_profile_ttl"`    // Default: 24h
}

// RADIUSPartitionMode defines behavior when RADIUS is unreachable.
type RADIUSPartitionMode string

const (
	// RADIUSModeDeny rejects all new authentications during partition.
	RADIUSModeDeny RADIUSPartitionMode = "deny"
	// RADIUSModeCached uses cached profiles for authentication during partition.
	RADIUSModeCached RADIUSPartitionMode = "cached"
	// RADIUSModeQueue queues authentication requests until partition heals.
	RADIUSModeQueue RADIUSPartitionMode = "queue"
)

// DefaultPartitionConfig returns sensible defaults.
func DefaultPartitionConfig() PartitionConfig {
	return PartitionConfig{
		HealthCheckInterval:     10 * time.Second,
		HealthCheckTimeout:      5 * time.Second,
		HealthCheckRetries:      3,
		PoolWarningThreshold:    0.80,
		PoolCriticalThreshold:   0.90,
		PoolExhaustedThreshold:  0.95,
		ShortLeaseEnabled:       true,
		ShortLeaseDuration:      5 * time.Minute,
		ShortLeaseThreshold:     0.90,
		RequestQueueSize:        1000,
		RequestQueueTimeout:     30 * time.Second,
		ReconciliationTimeout:   60 * time.Second,
		ReauthRateLimit:         100,
		AccountingSyncBatchSize: 100,
		AccountingBufferSize:    100000,
		RADIUSPartitionMode:     RADIUSModeCached,
		CachedProfileTTL:        24 * time.Hour,
	}
}

// PartitionEvent represents a partition state change event.
type PartitionEvent struct {
	OldState  PartitionState `json:"old_state"`
	NewState  PartitionState `json:"new_state"`
	Timestamp time.Time      `json:"timestamp"`
	Reason    string         `json:"reason,omitempty"`
	Duration  time.Duration  `json:"duration,omitempty"` // Duration if recovering from partition
}

// PoolStatus represents the current status of an IP pool.
type PoolStatus struct {
	PoolID           string               `json:"pool_id"`
	PoolName         string               `json:"pool_name"`
	Total            int                  `json:"total"`
	Allocated        int                  `json:"allocated"`
	Available        int                  `json:"available"`
	Reserved         int                  `json:"reserved"`
	Utilization      float64              `json:"utilization"`
	Level            PoolUtilizationLevel `json:"level"`
	ShortLeaseActive bool                 `json:"short_lease_active"`
	AllocationRate   float64              `json:"allocation_rate"` // Allocations per minute
	EstimatedTTL     time.Duration        `json:"estimated_ttl"`   // Time until exhaustion at current rate
}

// QueuedRequest represents a DHCP or RADIUS request queued during partition.
type QueuedRequest struct {
	ID           string           `json:"id"`
	Type         RequestType      `json:"type"`
	MAC          net.HardwareAddr `json:"mac"`
	SubscriberID string           `json:"subscriber_id,omitempty"`
	RequestedIP  net.IP           `json:"requested_ip,omitempty"`
	QueuedAt     time.Time        `json:"queued_at"`
	ExpiresAt    time.Time        `json:"expires_at"`
	Retries      int              `json:"retries"`
	Data         interface{}      `json:"data,omitempty"` // Original request data
}

// RequestType identifies the type of queued request.
type RequestType string

const (
	RequestTypeDHCPDiscover RequestType = "dhcp_discover"
	RequestTypeDHCPRequest  RequestType = "dhcp_request"
	RequestTypeRADIUSAuth   RequestType = "radius_auth"
	RequestTypeRADIUSAcct   RequestType = "radius_acct"
)

// IPAllocation represents an IP allocation record for conflict detection.
type IPAllocation struct {
	IP           net.IP           `json:"ip"`
	MAC          net.HardwareAddr `json:"mac"`
	SubscriberID string           `json:"subscriber_id"`
	PoolID       string           `json:"pool_id"`
	AllocatedAt  time.Time        `json:"allocated_at"`
	SiteID       string           `json:"site_id"`
	IsPartition  bool             `json:"is_partition"` // Allocated during partition
}

// AllocationConflict represents a detected IP allocation conflict.
type AllocationConflict struct {
	IP          net.IP             `json:"ip"`
	LocalAlloc  IPAllocation       `json:"local_allocation"`
	RemoteAlloc IPAllocation       `json:"remote_allocation"`
	DetectedAt  time.Time          `json:"detected_at"`
	Resolution  ConflictResolution `json:"resolution"`
	ResolvedAt  time.Time          `json:"resolved_at,omitempty"`
	AffectedMAC net.HardwareAddr   `json:"affected_mac,omitempty"`
}

// ConflictResolution indicates how a conflict was resolved.
type ConflictResolution string

const (
	// ResolutionPending indicates conflict is not yet resolved.
	ResolutionPending ConflictResolution = "pending"
	// ResolutionLocalWins indicates local allocation was kept.
	ResolutionLocalWins ConflictResolution = "local_wins"
	// ResolutionRemoteWins indicates remote allocation was kept.
	ResolutionRemoteWins ConflictResolution = "remote_wins"
	// ResolutionBothReallocate indicates both parties got new IPs.
	ResolutionBothReallocate ConflictResolution = "both_reallocate"
)

// DegradedSession represents a session authenticated in degraded mode.
type DegradedSession struct {
	SessionID       string           `json:"session_id"`
	MAC             net.HardwareAddr `json:"mac"`
	SubscriberID    string           `json:"subscriber_id,omitempty"`
	AuthenticatedAt time.Time        `json:"authenticated_at"`
	CachedProfile   *CachedProfile   `json:"cached_profile,omitempty"`
	NeedsReauth     bool             `json:"needs_reauth"`
	ReauthAttempts  int              `json:"reauth_attempts"`
	IPv4            net.IP           `json:"ipv4,omitempty"`
}

// CachedProfile represents a cached subscriber profile for degraded mode authentication.
type CachedProfile struct {
	SubscriberID    string        `json:"subscriber_id"`
	ISPID           string        `json:"isp_id"`
	RADIUSRealm     string        `json:"radius_realm"`
	QoSPolicyID     string        `json:"qos_policy_id,omitempty"`
	DownloadRateBps uint64        `json:"download_rate_bps"`
	UploadRateBps   uint64        `json:"upload_rate_bps"`
	IPv4PoolID      string        `json:"ipv4_pool_id,omitempty"`
	IPv6PoolID      string        `json:"ipv6_pool_id,omitempty"`
	SessionTimeout  time.Duration `json:"session_timeout"`
	IdleTimeout     time.Duration `json:"idle_timeout"`
	CachedAt        time.Time     `json:"cached_at"`
	LastVerified    time.Time     `json:"last_verified"`
}

// BufferedAcctRecord represents a RADIUS accounting record buffered during partition.
type BufferedAcctRecord struct {
	ID             string           `json:"id"`
	SessionID      string           `json:"session_id"`
	MAC            net.HardwareAddr `json:"mac"`
	FramedIP       net.IP           `json:"framed_ip"`
	StatusType     int              `json:"status_type"` // Start, Stop, Interim-Update
	Timestamp      time.Time        `json:"timestamp"`
	InputOctets    uint64           `json:"input_octets"`
	OutputOctets   uint64           `json:"output_octets"`
	SessionTime    uint32           `json:"session_time"`
	TerminateCause uint32           `json:"terminate_cause,omitempty"`
	SyncAttempts   int              `json:"sync_attempts"`
	LastAttempt    time.Time        `json:"last_attempt,omitempty"`
}

// PartitionStats holds statistics about partition handling.
type PartitionStats struct {
	mu sync.RWMutex

	// Partition info
	CurrentState       PartitionState `json:"current_state"`
	PartitionStartTime time.Time      `json:"partition_start_time,omitempty"`
	TotalPartitions    int64          `json:"total_partitions"`
	TotalPartitionTime time.Duration  `json:"total_partition_time"`
	LastPartitionTime  time.Time      `json:"last_partition_time,omitempty"`

	// Pool stats
	PoolWarnings      int64 `json:"pool_warnings"`
	PoolCriticals     int64 `json:"pool_criticals"`
	PoolExhaustions   int64 `json:"pool_exhaustions"`
	ShortLeasesIssued int64 `json:"short_leases_issued"`

	// Queue stats
	RequestsQueued     int64 `json:"requests_queued"`
	RequestsDequeued   int64 `json:"requests_dequeued"`
	RequestsExpired    int64 `json:"requests_expired"`
	QueueHighWaterMark int   `json:"queue_high_water_mark"`

	// Conflict stats
	ConflictsDetected int64 `json:"conflicts_detected"`
	ConflictsResolved int64 `json:"conflicts_resolved"`
	LocalWins         int64 `json:"local_wins"`
	RemoteWins        int64 `json:"remote_wins"`

	// RADIUS stats
	DegradedAuthsIssued int64 `json:"degraded_auths_issued"`
	ReauthsCompleted    int64 `json:"reauths_completed"`
	ReauthsFailed       int64 `json:"reauths_failed"`
	AcctRecordsBuffered int64 `json:"acct_records_buffered"`
	AcctRecordsSynced   int64 `json:"acct_records_synced"`
	AcctRecordsDropped  int64 `json:"acct_records_dropped"`
	AcctBufferHighWater int   `json:"acct_buffer_high_water"`
}

// PartitionEventHandler is called when partition state changes.
type PartitionEventHandler func(event PartitionEvent)

// PoolAlertHandler is called when pool utilization crosses thresholds.
type PoolAlertHandler func(pool PoolStatus, level PoolUtilizationLevel)

// ConflictHandler is called when an IP allocation conflict is detected.
type ConflictHandler func(conflict AllocationConflict)

// ReconciliationResult holds the result of partition reconciliation.
type ReconciliationResult struct {
	StartedAt         time.Time            `json:"started_at"`
	CompletedAt       time.Time            `json:"completed_at"`
	Duration          time.Duration        `json:"duration"`
	ConflictsFound    int                  `json:"conflicts_found"`
	ConflictsResolved int                  `json:"conflicts_resolved"`
	ReauthsQueued     int                  `json:"reauths_queued"`
	ReauthsCompleted  int                  `json:"reauths_completed"`
	AcctRecordsSynced int                  `json:"acct_records_synced"`
	Errors            []string             `json:"errors,omitempty"`
	Conflicts         []AllocationConflict `json:"conflicts,omitempty"`
}
