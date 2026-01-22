// Package direct provides RADIUS-less operation mode where subscriber identity
// is derived directly from ONT/OLT provisioning rather than RADIUS authentication.
//
// Benefits of RADIUS-less mode:
//   - Simpler architecture, fewer moving parts
//   - No RADIUS server dependency
//   - ONT identity already established via provisioning
//   - BSS already has subscriber to ONT mapping
//   - Reduced latency for session establishment
//
// The ONT serial number or DHCP Option 82 circuit ID is used to look up the
// subscriber directly in the BSS/Nexus instead of authenticating via RADIUS.
package direct

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/nexus"
	"github.com/codelaboratoryltd/bng/pkg/subscriber"
	"go.uber.org/zap"
)

// AuthMode defines the authentication mode
type AuthMode string

const (
	// AuthModeRADIUS uses traditional RADIUS authentication
	AuthModeRADIUS AuthMode = "radius"
	// AuthModeDirect uses direct ONT identity lookup (RADIUS-less)
	AuthModeDirect AuthMode = "direct"
	// AuthModeHybrid supports both RADIUS and direct modes
	AuthModeHybrid AuthMode = "hybrid"
)

// Config holds configuration for the direct authenticator
type Config struct {
	// Mode is the authentication mode (radius, direct, hybrid)
	Mode AuthMode `json:"mode"`

	// DefaultISPID is the default ISP ID when not specified in ONT mapping
	DefaultISPID string `json:"default_isp_id"`

	// DefaultQoSPolicy is the default QoS policy name
	DefaultQoSPolicy string `json:"default_qos_policy"`

	// DefaultSessionTimeout is the default session timeout
	DefaultSessionTimeout time.Duration `json:"default_session_timeout"`

	// DefaultIdleTimeout is the default idle timeout
	DefaultIdleTimeout time.Duration `json:"default_idle_timeout"`

	// DefaultDownloadRateBps is the default download rate in bits per second
	DefaultDownloadRateBps uint64 `json:"default_download_rate_bps"`

	// DefaultUploadRateBps is the default upload rate in bits per second
	DefaultUploadRateBps uint64 `json:"default_upload_rate_bps"`

	// BSS integration settings
	BSSWebhookURL    string `json:"bss_webhook_url,omitempty"`
	BSSWebhookSecret string `json:"bss_webhook_secret,omitempty"`
}

// DefaultConfig returns sensible defaults for direct authentication
func DefaultConfig() Config {
	return Config{
		Mode:                   AuthModeDirect,
		DefaultSessionTimeout:  24 * time.Hour,
		DefaultIdleTimeout:     30 * time.Minute,
		DefaultDownloadRateBps: 100_000_000, // 100 Mbps
		DefaultUploadRateBps:   50_000_000,  // 50 Mbps
		DefaultQoSPolicy:       "residential-default",
	}
}

// Authenticator provides RADIUS-less authentication using direct ONT identity lookup
type Authenticator struct {
	config      Config
	nexusClient *nexus.Client
	logger      *zap.Logger
	bssClient   BSSClient

	// Local cache for fast lookups
	mu             sync.RWMutex
	ontCache       map[string]*ONTMapping // ONT serial -> mapping
	circuitIDCache map[string]*ONTMapping // Circuit ID -> mapping
}

// ONTMapping represents the BSS-provided mapping from ONT to subscriber
type ONTMapping struct {
	// ONT identification
	ONTSerial   string `json:"ont_serial"`
	CircuitID   string `json:"circuit_id,omitempty"`
	PONPort     string `json:"pon_port,omitempty"`
	OLTDeviceID string `json:"olt_device_id,omitempty"`

	// Subscriber info
	SubscriberID string `json:"subscriber_id"`
	ISPID        string `json:"isp_id,omitempty"`

	// Service parameters
	ServiceClass string `json:"service_class,omitempty"` // residential, business, etc.
	QoSPolicy    string `json:"qos_policy,omitempty"`
	DownloadBps  uint64 `json:"download_bps,omitempty"`
	UploadBps    uint64 `json:"upload_bps,omitempty"`

	// IP assignment (pre-allocated)
	IPv4Pool   string `json:"ipv4_pool,omitempty"`
	IPv4Addr   string `json:"ipv4_addr,omitempty"`
	IPv6Pool   string `json:"ipv6_pool,omitempty"`
	IPv6Prefix string `json:"ipv6_prefix,omitempty"`

	// VLAN context (for QinQ)
	STag uint16 `json:"s_tag,omitempty"`
	CTag uint16 `json:"c_tag,omitempty"`

	// State
	Status        string    `json:"status"` // active, suspended, disconnected
	ProvisionedAt time.Time `json:"provisioned_at"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
}

// BSSClient is the interface for BSS (Business Support System) integration
type BSSClient interface {
	// GetONTMapping retrieves the subscriber mapping for an ONT
	GetONTMapping(ctx context.Context, ontSerial string) (*ONTMapping, error)

	// GetONTMappingByCircuitID retrieves mapping by DHCP Option 82 circuit ID
	GetONTMappingByCircuitID(ctx context.Context, circuitID string) (*ONTMapping, error)

	// ReportBinding notifies BSS of a DHCP binding event
	ReportBinding(ctx context.Context, event *BindingEvent) error

	// SyncMappings retrieves all ONT mappings (for cache population)
	SyncMappings(ctx context.Context) ([]*ONTMapping, error)
}

// BindingEvent represents a DHCP binding event to report to BSS
type BindingEvent struct {
	EventType    BindingEventType `json:"event_type"`
	Timestamp    time.Time        `json:"timestamp"`
	ONTSerial    string           `json:"ont_serial"`
	SubscriberID string           `json:"subscriber_id"`
	MAC          string           `json:"mac"`
	IPv4Addr     string           `json:"ipv4_addr,omitempty"`
	IPv6Addr     string           `json:"ipv6_addr,omitempty"`
	LeaseExpiry  time.Time        `json:"lease_expiry,omitempty"`
	SessionID    string           `json:"session_id,omitempty"`
}

// BindingEventType represents the type of binding event
type BindingEventType string

const (
	BindingEventAssign  BindingEventType = "assign"  // IP assigned
	BindingEventRenew   BindingEventType = "renew"   // Lease renewed
	BindingEventRelease BindingEventType = "release" // IP released
	BindingEventExpire  BindingEventType = "expire"  // Lease expired
)

// NewAuthenticator creates a new direct authenticator
func NewAuthenticator(config Config, nexusClient *nexus.Client, logger *zap.Logger) *Authenticator {
	return &Authenticator{
		config:         config,
		nexusClient:    nexusClient,
		logger:         logger,
		ontCache:       make(map[string]*ONTMapping),
		circuitIDCache: make(map[string]*ONTMapping),
	}
}

// SetBSSClient sets the BSS integration client
func (a *Authenticator) SetBSSClient(client BSSClient) {
	a.bssClient = client
}

// Authenticate implements the subscriber.Authenticator interface
// It performs RADIUS-less authentication by looking up the ONT identity
func (a *Authenticator) Authenticate(ctx context.Context, req *subscriber.SessionRequest) (*subscriber.AuthResult, error) {
	a.logger.Debug("Direct authentication request",
		zap.String("mac", req.MAC.String()),
		zap.String("circuit_id", req.CircuitID),
		zap.String("remote_id", req.RemoteID),
		zap.String("ont_uid", req.ONUID),
	)

	// Try to find ONT mapping
	mapping, err := a.lookupONTMapping(ctx, req)
	if err != nil {
		a.logger.Warn("ONT mapping lookup failed",
			zap.Error(err),
			zap.String("mac", req.MAC.String()),
		)
		return &subscriber.AuthResult{
			Success: false,
			Error:   fmt.Sprintf("ONT not found: %v", err),
		}, nil
	}

	// Check subscriber status
	if mapping.Status != "active" && mapping.Status != "" {
		a.logger.Warn("Subscriber not active",
			zap.String("subscriber_id", mapping.SubscriberID),
			zap.String("status", mapping.Status),
		)
		return &subscriber.AuthResult{
			Success:      false,
			Error:        "subscriber not active",
			WalledGarden: mapping.Status == "suspended",
			WalledReason: fmt.Sprintf("Account %s", mapping.Status),
		}, nil
	}

	// Build successful auth result
	result := &subscriber.AuthResult{
		Success:      true,
		SubscriberID: mapping.SubscriberID,
		ISPID:        mapping.ISPID,

		// Session attributes
		SessionTimeout: a.config.DefaultSessionTimeout,
		IdleTimeout:    a.config.DefaultIdleTimeout,

		// QoS attributes
		QoSPolicyID:     mapping.QoSPolicy,
		DownloadRateBps: mapping.DownloadBps,
		UploadRateBps:   mapping.UploadBps,

		// IP assignment
		IPv4PoolID: mapping.IPv4Pool,
	}

	// Apply defaults if not specified
	if result.ISPID == "" {
		result.ISPID = a.config.DefaultISPID
	}
	if result.QoSPolicyID == "" {
		result.QoSPolicyID = a.config.DefaultQoSPolicy
	}
	if result.DownloadRateBps == 0 {
		result.DownloadRateBps = a.config.DefaultDownloadRateBps
	}
	if result.UploadRateBps == 0 {
		result.UploadRateBps = a.config.DefaultUploadRateBps
	}

	// Pre-allocated IP from BSS
	if mapping.IPv4Addr != "" {
		result.FramedIPAddress = net.ParseIP(mapping.IPv4Addr)
	}

	a.logger.Info("Direct authentication successful",
		zap.String("subscriber_id", mapping.SubscriberID),
		zap.String("ont_serial", mapping.ONTSerial),
		zap.String("ip", mapping.IPv4Addr),
	)

	return result, nil
}

// lookupONTMapping attempts to find the ONT mapping using various identifiers
func (a *Authenticator) lookupONTMapping(ctx context.Context, req *subscriber.SessionRequest) (*ONTMapping, error) {
	// Try local cache first

	// 1. Try circuit ID (Option 82)
	if req.CircuitID != "" {
		if mapping := a.getCachedByCircuitID(req.CircuitID); mapping != nil {
			return mapping, nil
		}
	}

	// 2. Try ONT UID / Remote ID
	ontSerial := req.ONUID
	if ontSerial == "" {
		ontSerial = req.RemoteID
	}
	if ontSerial == "" {
		ontSerial = req.NTEID
	}

	if ontSerial != "" {
		if mapping := a.getCachedBySerial(ontSerial); mapping != nil {
			return mapping, nil
		}
	}

	// 3. Try BSS lookup
	if a.bssClient != nil {
		// Try circuit ID first
		if req.CircuitID != "" {
			mapping, err := a.bssClient.GetONTMappingByCircuitID(ctx, req.CircuitID)
			if err == nil && mapping != nil {
				a.cacheMapping(mapping)
				return mapping, nil
			}
		}

		// Try ONT serial
		if ontSerial != "" {
			mapping, err := a.bssClient.GetONTMapping(ctx, ontSerial)
			if err == nil && mapping != nil {
				a.cacheMapping(mapping)
				return mapping, nil
			}
		}
	}

	// 4. Try Nexus lookup
	if a.nexusClient != nil {
		// Try to find NTE by serial
		if ontSerial != "" {
			if nte, ok := a.nexusClient.GetNTEBySerial(ontSerial); ok {
				// Found NTE, look for associated subscriber
				if sub, ok := a.nexusClient.GetSubscriberByNTE(nte.ID); ok {
					mapping := &ONTMapping{
						ONTSerial:    nte.SerialNumber,
						SubscriberID: sub.ID,
						ISPID:        sub.ISPID,
						IPv4Pool:     sub.IPv4Pool,
						IPv4Addr:     sub.IPv4Addr,
						STag:         sub.STag,
						CTag:         sub.CTag,
						Status:       sub.State,
					}
					a.cacheMapping(mapping)
					return mapping, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no ONT mapping found for circuit_id=%s, serial=%s", req.CircuitID, ontSerial)
}

// getCachedBySerial returns a cached mapping by ONT serial
func (a *Authenticator) getCachedBySerial(serial string) *ONTMapping {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ontCache[serial]
}

// getCachedByCircuitID returns a cached mapping by circuit ID
func (a *Authenticator) getCachedByCircuitID(circuitID string) *ONTMapping {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.circuitIDCache[circuitID]
}

// cacheMapping adds a mapping to the local cache
func (a *Authenticator) cacheMapping(mapping *ONTMapping) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if mapping.ONTSerial != "" {
		a.ontCache[mapping.ONTSerial] = mapping
	}
	if mapping.CircuitID != "" {
		a.circuitIDCache[mapping.CircuitID] = mapping
	}
}

// InvalidateCache removes a mapping from the cache
func (a *Authenticator) InvalidateCache(ontSerial, circuitID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ontSerial != "" {
		delete(a.ontCache, ontSerial)
	}
	if circuitID != "" {
		delete(a.circuitIDCache, circuitID)
	}
}

// SyncFromBSS synchronizes the local cache from BSS
func (a *Authenticator) SyncFromBSS(ctx context.Context) error {
	if a.bssClient == nil {
		return fmt.Errorf("BSS client not configured")
	}

	mappings, err := a.bssClient.SyncMappings(ctx)
	if err != nil {
		return fmt.Errorf("sync mappings from BSS: %w", err)
	}

	a.mu.Lock()
	// Clear existing cache
	a.ontCache = make(map[string]*ONTMapping)
	a.circuitIDCache = make(map[string]*ONTMapping)

	// Populate from BSS
	for _, mapping := range mappings {
		if mapping.ONTSerial != "" {
			a.ontCache[mapping.ONTSerial] = mapping
		}
		if mapping.CircuitID != "" {
			a.circuitIDCache[mapping.CircuitID] = mapping
		}
	}
	a.mu.Unlock()

	a.logger.Info("Synced ONT mappings from BSS",
		zap.Int("count", len(mappings)),
	)

	return nil
}

// ReportBindingEvent reports a binding event to BSS
func (a *Authenticator) ReportBindingEvent(ctx context.Context, event *BindingEvent) error {
	if a.bssClient == nil {
		return nil // BSS not configured, silently ignore
	}

	event.Timestamp = time.Now().UTC()

	if err := a.bssClient.ReportBinding(ctx, event); err != nil {
		a.logger.Warn("Failed to report binding event to BSS",
			zap.String("event_type", string(event.EventType)),
			zap.String("subscriber_id", event.SubscriberID),
			zap.Error(err),
		)
		return err
	}

	a.logger.Debug("Reported binding event to BSS",
		zap.String("event_type", string(event.EventType)),
		zap.String("subscriber_id", event.SubscriberID),
		zap.String("ipv4", event.IPv4Addr),
	)

	return nil
}

// GetConfig returns the current configuration
func (a *Authenticator) GetConfig() Config {
	return a.config
}

// Stats returns authenticator statistics
func (a *Authenticator) Stats() AuthStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return AuthStats{
		CachedONTMappings:       len(a.ontCache),
		CachedCircuitIDMappings: len(a.circuitIDCache),
	}
}

// AuthStats holds authenticator statistics
type AuthStats struct {
	CachedONTMappings       int `json:"cached_ont_mappings"`
	CachedCircuitIDMappings int `json:"cached_circuit_id_mappings"`
}
