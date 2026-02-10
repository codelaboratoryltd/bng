//go:build linux

// Package ztp provides Zero Touch Provisioning for OLT-BNG devices.
package ztp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// BootstrapConfig holds configuration for the bootstrap client.
type BootstrapConfig struct {
	// NexusURL is the base URL of the Nexus server.
	NexusURL string

	// Interface is the management interface name.
	Interface string

	// Serial is the device serial number (auto-detected if empty).
	Serial string

	// TLSConfig is optional TLS configuration for mTLS.
	TLSConfig *tls.Config

	// Logger is the logger to use (defaults to no-op).
	Logger *zap.Logger

	// MaxRetries is the maximum number of retries for pending state (0 = unlimited).
	MaxRetries int

	// InitialBackoff is the initial backoff duration (default: 5s).
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration (default: 5m).
	MaxBackoff time.Duration
}

// BootstrapRequest is sent to Nexus to register a device.
type BootstrapRequest struct {
	Serial    string `json:"serial"`
	MAC       string `json:"mac"`
	Model     string `json:"model,omitempty"`
	Firmware  string `json:"firmware,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

// PartnerInfo contains information about an HA partner device.
type PartnerInfo struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address,omitempty"`
	Status  string `json:"status,omitempty"`
}

// PoolAssignment represents a pool assigned to this device.
type PoolAssignment struct {
	PoolID  string   `json:"pool_id"`
	CIDR    string   `json:"cidr"`
	Subnets []string `json:"subnets,omitempty"`
}

// ClusterInfo contains information about the Nexus cluster.
type ClusterInfo struct {
	Peers        []string `json:"peers,omitempty"`
	SyncEndpoint string   `json:"sync_endpoint,omitempty"`
}

// BootstrapResponse is returned by Nexus after registration.
type BootstrapResponse struct {
	NodeID     string           `json:"node_id"`
	Status     string           `json:"status"` // "pending" or "configured"
	SiteID     string           `json:"site_id,omitempty"`
	Role       string           `json:"role,omitempty"` // "active" or "standby"
	Partner    *PartnerInfo     `json:"partner,omitempty"`
	Pools      []PoolAssignment `json:"pools,omitempty"`
	Cluster    *ClusterInfo     `json:"cluster,omitempty"`
	RetryAfter int              `json:"retry_after,omitempty"`
	Message    string           `json:"message,omitempty"`
}

// DeviceConfig represents the complete device configuration.
type DeviceConfig struct {
	NodeID    string           `json:"node_id"`
	SiteID    string           `json:"site_id"`
	Role      string           `json:"role"`
	Partner   *PartnerInfo     `json:"partner,omitempty"`
	Pools     []PoolAssignment `json:"pools"`
	Cluster   *ClusterInfo     `json:"cluster,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

// BootstrapClient handles device registration and configuration with Nexus.
type BootstrapClient struct {
	config     BootstrapConfig
	httpClient *http.Client
	logger     *zap.Logger
}

// NewBootstrapClient creates a new bootstrap client.
func NewBootstrapClient(cfg BootstrapConfig) (*BootstrapClient, error) {
	if cfg.NexusURL == "" {
		return nil, fmt.Errorf("nexus URL is required")
	}

	// Set defaults
	if cfg.InitialBackoff == 0 {
		cfg.InitialBackoff = 5 * time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: cfg.TLSConfig,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &BootstrapClient{
		config:     cfg,
		httpClient: client,
		logger:     cfg.Logger,
	}, nil
}

// Bootstrap performs the full bootstrap flow:
// 1. Detect system info (serial, MAC)
// 2. Register with Nexus
// 3. Poll until configured (if pending)
// 4. Return device configuration
func (c *BootstrapClient) Bootstrap(ctx context.Context) (*DeviceConfig, error) {
	// Detect system info
	info, err := c.detectSystemInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to detect system info: %w", err)
	}

	c.logger.Info("Starting bootstrap",
		zap.String("serial", info.Serial),
		zap.String("mac", info.MAC),
		zap.String("nexus_url", c.config.NexusURL),
	)

	// Register and poll until configured
	return c.registerAndWait(ctx, info)
}

// SystemInfo contains detected device information.
type SystemInfo struct {
	Serial   string
	MAC      string
	Model    string
	Firmware string
}

// detectSystemInfo detects the device's serial number and MAC address.
func (c *BootstrapClient) detectSystemInfo() (*SystemInfo, error) {
	info := &SystemInfo{}

	// Use configured serial or detect
	if c.config.Serial != "" {
		info.Serial = c.config.Serial
	} else {
		serial, err := detectSerial()
		if err != nil {
			return nil, fmt.Errorf("failed to detect serial: %w", err)
		}
		info.Serial = serial
	}

	// Get MAC from interface
	if c.config.Interface != "" {
		mac, err := getMACAddress(c.config.Interface)
		if err != nil {
			return nil, fmt.Errorf("failed to get MAC address: %w", err)
		}
		info.MAC = mac
	} else {
		// Try to find a suitable interface
		mac, err := findPrimaryMAC()
		if err != nil {
			return nil, fmt.Errorf("failed to find MAC address: %w", err)
		}
		info.MAC = mac
	}

	// Detect model and firmware (best effort)
	info.Model = detectModel()
	info.Firmware = detectFirmware()

	return info, nil
}

// registerAndWait registers with Nexus and waits until configured.
func (c *BootstrapClient) registerAndWait(ctx context.Context, info *SystemInfo) (*DeviceConfig, error) {
	req := &BootstrapRequest{
		Serial:   info.Serial,
		MAC:      info.MAC,
		Model:    info.Model,
		Firmware: info.Firmware,
	}

	backoff := c.config.InitialBackoff
	retries := 0

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := c.register(ctx, req)
		if err != nil {
			c.logger.Warn("Registration failed, retrying",
				zap.Error(err),
				zap.Duration("backoff", backoff),
			)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}

			backoff = min(backoff*2, c.config.MaxBackoff)
			continue
		}

		c.logger.Info("Registration response",
			zap.String("node_id", resp.NodeID),
			zap.String("status", resp.Status),
			zap.String("message", resp.Message),
		)

		if resp.Status == "configured" {
			// Device is configured, return config
			return &DeviceConfig{
				NodeID:    resp.NodeID,
				SiteID:    resp.SiteID,
				Role:      resp.Role,
				Partner:   resp.Partner,
				Pools:     resp.Pools,
				Cluster:   resp.Cluster,
				Timestamp: time.Now(),
			}, nil
		}

		// Device is pending, wait and retry
		retries++
		if c.config.MaxRetries > 0 && retries >= c.config.MaxRetries {
			return nil, fmt.Errorf("max retries (%d) exceeded while waiting for configuration", c.config.MaxRetries)
		}

		waitTime := time.Duration(resp.RetryAfter) * time.Second
		if waitTime == 0 {
			waitTime = backoff
		}

		c.logger.Info("Device pending, waiting for configuration",
			zap.Int("retry", retries),
			zap.Duration("wait_time", waitTime),
		)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(waitTime):
		}

		// Reset backoff after successful registration
		backoff = c.config.InitialBackoff
	}
}

// register sends a registration request to Nexus.
func (c *BootstrapClient) register(ctx context.Context, req *BootstrapRequest) (*BootstrapResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := strings.TrimSuffix(c.config.NexusURL, "/") + "/api/v1/bootstrap"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var bootstrapResp BootstrapResponse
	if err := json.Unmarshal(respBody, &bootstrapResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &bootstrapResp, nil
}

// detectSerial attempts to detect the device serial number.
func detectSerial() (string, error) {
	// Try DMI/SMBIOS first
	paths := []string{
		"/sys/class/dmi/id/product_serial",
		"/sys/class/dmi/id/board_serial",
		"/sys/class/dmi/id/chassis_serial",
	}

	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			serial := strings.TrimSpace(string(data))
			if serial != "" && serial != "None" && serial != "Not Specified" {
				return serial, nil
			}
		}
	}

	// Try machine-id as fallback
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		machineID := strings.TrimSpace(string(data))
		if machineID != "" {
			return "machine-" + machineID[:16], nil
		}
	}

	return "", fmt.Errorf("unable to detect serial number")
}

// getMACAddress gets the MAC address of a specific interface.
func getMACAddress(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}

	if len(iface.HardwareAddr) == 0 {
		return "", fmt.Errorf("interface %s has no MAC address", ifaceName)
	}

	return iface.HardwareAddr.String(), nil
}

// findPrimaryMAC finds the MAC address of the first non-loopback interface.
func findPrimaryMAC() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		// Skip loopback and interfaces without MAC
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		// Skip virtual interfaces
		if strings.HasPrefix(iface.Name, "veth") ||
			strings.HasPrefix(iface.Name, "docker") ||
			strings.HasPrefix(iface.Name, "br-") {
			continue
		}

		return iface.HardwareAddr.String(), nil
	}

	return "", fmt.Errorf("no suitable network interface found")
}

// detectModel attempts to detect the device model.
func detectModel() string {
	paths := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/board_name",
	}

	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			model := strings.TrimSpace(string(data))
			if model != "" && model != "None" && model != "Not Specified" {
				return model
			}
		}
	}

	return ""
}

// detectFirmware attempts to detect the firmware/BIOS version.
func detectFirmware() string {
	paths := []string{
		"/sys/class/dmi/id/bios_version",
	}

	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			version := strings.TrimSpace(string(data))
			if version != "" && version != "None" && version != "Not Specified" {
				return version
			}
		}
	}

	return ""
}

// BootstrapOnce performs a single bootstrap attempt without polling.
// Returns the response regardless of pending/configured status.
func (c *BootstrapClient) BootstrapOnce(ctx context.Context) (*BootstrapResponse, error) {
	info, err := c.detectSystemInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to detect system info: %w", err)
	}

	req := &BootstrapRequest{
		Serial:   info.Serial,
		MAC:      info.MAC,
		Model:    info.Model,
		Firmware: info.Firmware,
	}

	return c.register(ctx, req)
}

// Healthcheck checks if Nexus is reachable.
func (c *BootstrapClient) Healthcheck(ctx context.Context) error {
	url := strings.TrimSuffix(c.config.NexusURL, "/") + "/health"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status %d", resp.StatusCode)
	}

	return nil
}
