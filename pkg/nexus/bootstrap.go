// Package nexus provides client functionality for the Nexus central coordination service.
// This file implements the Bootstrap API client for Zero Touch Provisioning (ZTP).
package nexus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// BootstrapClient handles device bootstrap registration with the Nexus server.
// It supports the "pending" status for devices awaiting site assignment.
type BootstrapClient struct {
	baseURL    string
	httpClient *http.Client
	serial     string
	mac        string
	model      string
	firmware   string
	logger     *zap.Logger
}

// BootstrapRequest is sent to the Nexus bootstrap API.
type BootstrapRequest struct {
	Serial    string `json:"serial"`
	MAC       string `json:"mac"`
	Model     string `json:"model"`
	Firmware  string `json:"firmware"`
	PublicKey string `json:"public_key,omitempty"`
}

// BootstrapResponse is returned by the Nexus bootstrap API.
type BootstrapResponse struct {
	// NodeID is the unique identifier assigned to this device.
	NodeID string `json:"node_id"`

	// Status indicates the bootstrap state: "pending" or "configured".
	Status string `json:"status"`

	// SiteID is the site this device is assigned to (only when configured).
	SiteID string `json:"site_id,omitempty"`

	// Role is the HA role: "primary", "standby", or empty for standalone.
	Role string `json:"role,omitempty"`

	// Partner contains information about the HA partner (only when configured with HA).
	Partner *PartnerInfo `json:"partner,omitempty"`

	// Pools contains IP pool assignments for this device.
	Pools []PoolInfo `json:"pools,omitempty"`

	// RetryAfter indicates how many seconds to wait before retrying (when pending).
	RetryAfter int `json:"retry_after,omitempty"`

	// Message contains a human-readable status message.
	Message string `json:"message,omitempty"`
}

// PartnerInfo contains information about an HA partner device.
type PartnerInfo struct {
	// NodeID is the partner's unique identifier.
	NodeID string `json:"node_id"`

	// Endpoint is the partner's API/sync endpoint (host:port).
	Endpoint string `json:"endpoint"`
}

// PoolInfo contains information about an IP pool assigned to this device.
type PoolInfo struct {
	// ID is the pool's unique identifier.
	ID string `json:"id"`

	// CIDR is the IP range in CIDR notation.
	CIDR string `json:"cidr"`

	// Gateway is the gateway IP for this pool.
	Gateway string `json:"gateway,omitempty"`

	// DNS contains DNS server addresses for this pool.
	DNS []string `json:"dns,omitempty"`
}

// BootstrapClientConfig contains configuration for the BootstrapClient.
type BootstrapClientConfig struct {
	// NexusURL is the base URL of the Nexus server.
	NexusURL string

	// Serial is the device serial number.
	Serial string

	// MAC is the device MAC address.
	MAC string

	// Model is the device model/product name.
	Model string

	// Firmware is the device firmware version.
	Firmware string

	// HTTPClient is an optional custom HTTP client.
	// If nil, a default client with 30s timeout is used.
	HTTPClient *http.Client

	// Logger is an optional logger.
	// If nil, a no-op logger is used.
	Logger *zap.Logger
}

// NewBootstrapClient creates a new BootstrapClient.
func NewBootstrapClient(config BootstrapClientConfig) *BootstrapClient {
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &BootstrapClient{
		baseURL:    config.NexusURL,
		httpClient: httpClient,
		serial:     config.Serial,
		mac:        config.MAC,
		model:      config.Model,
		firmware:   config.Firmware,
		logger:     logger,
	}
}

// Bootstrap registers with Nexus and waits for configuration.
// This method blocks until the device is configured or the context is cancelled.
//
// The method handles two states:
//   - "pending": Device is registered but not yet assigned to a site.
//     The method will poll at the interval specified by RetryAfter.
//   - "configured": Device has been assigned to a site and has full config.
//     The method returns successfully with the configuration.
//
// Returns the bootstrap response with full configuration, or an error if
// the context is cancelled or an unrecoverable error occurs.
func (c *BootstrapClient) Bootstrap(ctx context.Context) (*BootstrapResponse, error) {
	req := BootstrapRequest{
		Serial:   c.serial,
		MAC:      c.mac,
		Model:    c.model,
		Firmware: c.firmware,
	}

	c.logger.Info("Starting bootstrap process",
		zap.String("serial", c.serial),
		zap.String("mac", c.mac),
		zap.String("model", c.model),
	)

	for {
		resp, err := c.doBootstrap(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("bootstrap request failed: %w", err)
		}

		if resp.Status == "configured" {
			c.logger.Info("Device configured successfully",
				zap.String("node_id", resp.NodeID),
				zap.String("site_id", resp.SiteID),
				zap.String("role", resp.Role),
			)
			return resp, nil
		}

		if resp.Status == "rejected" {
			return nil, fmt.Errorf("bootstrap rejected: %s", resp.Message)
		}

		// Status is "pending" - wait and retry
		retryAfter := time.Duration(resp.RetryAfter) * time.Second
		if retryAfter <= 0 {
			retryAfter = 60 * time.Second // default retry interval
		}

		c.logger.Info("Device pending configuration, waiting to retry",
			zap.String("node_id", resp.NodeID),
			zap.String("message", resp.Message),
			zap.Duration("retry_after", retryAfter),
		)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryAfter):
			// Continue to next iteration
		}
	}
}

// BootstrapOnce performs a single bootstrap request without polling.
// Use this when you want to check the current status without waiting.
func (c *BootstrapClient) BootstrapOnce(ctx context.Context) (*BootstrapResponse, error) {
	req := BootstrapRequest{
		Serial:   c.serial,
		MAC:      c.mac,
		Model:    c.model,
		Firmware: c.firmware,
	}

	return c.doBootstrap(ctx, req)
}

// doBootstrap performs the actual HTTP request to the bootstrap API.
func (c *BootstrapClient) doBootstrap(ctx context.Context, req BootstrapRequest) (*BootstrapResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.baseURL + "/api/v1/bootstrap"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "olt-bng-bootstrap/1.0")

	c.logger.Debug("Sending bootstrap request",
		zap.String("url", url),
		zap.String("serial", req.Serial),
	)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle error status codes
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		// Success - parse response
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("authentication failed: %s", string(respBody))
	case http.StatusForbidden:
		return nil, fmt.Errorf("device not authorized: %s", string(respBody))
	case http.StatusBadRequest:
		return nil, fmt.Errorf("invalid request: %s", string(respBody))
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("service unavailable: %s", string(respBody))
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var bootstrapResp BootstrapResponse
	if err := json.Unmarshal(respBody, &bootstrapResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &bootstrapResp, nil
}

// IsPending returns true if the response indicates the device is pending configuration.
func (r *BootstrapResponse) IsPending() bool {
	return r.Status == "pending"
}

// IsConfigured returns true if the response indicates the device is fully configured.
func (r *BootstrapResponse) IsConfigured() bool {
	return r.Status == "configured"
}

// HasHAPartner returns true if the device has an HA partner assigned.
func (r *BootstrapResponse) HasHAPartner() bool {
	return r.Partner != nil && r.Partner.NodeID != ""
}

// IsPrimary returns true if the device has the "primary" HA role.
func (r *BootstrapResponse) IsPrimary() bool {
	return r.Role == "primary"
}

// IsStandby returns true if the device has the "standby" HA role.
func (r *BootstrapResponse) IsStandby() bool {
	return r.Role == "standby"
}
