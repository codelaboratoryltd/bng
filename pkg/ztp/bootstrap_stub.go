//go:build !linux

// Package ztp provides Zero Touch Provisioning for OLT-BNG devices.
// This stub is for non-Linux platforms where the bootstrap client is not available.
package ztp

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// BootstrapConfig holds configuration for the bootstrap client.
type BootstrapConfig struct {
	NexusURL       string
	Interface      string
	Serial         string
	TLSConfig      *tls.Config
	Logger         *zap.Logger
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
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
	Status     string           `json:"status"`
	SiteID     string           `json:"site_id,omitempty"`
	Role       string           `json:"role,omitempty"`
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

// SystemInfo contains detected device information.
type SystemInfo struct {
	Serial   string
	MAC      string
	Model    string
	Firmware string
}

// BootstrapClient handles device registration and configuration with Nexus.
type BootstrapClient struct {
	config BootstrapConfig
}

// NewBootstrapClient creates a new bootstrap client.
func NewBootstrapClient(cfg BootstrapConfig) (*BootstrapClient, error) {
	if cfg.NexusURL == "" {
		return nil, fmt.Errorf("nexus URL is required")
	}
	return &BootstrapClient{config: cfg}, nil
}

// Bootstrap performs the full bootstrap flow (not supported on this platform).
func (c *BootstrapClient) Bootstrap(ctx context.Context) (*DeviceConfig, error) {
	return nil, fmt.Errorf("bootstrap not supported on this platform (Linux only)")
}

// BootstrapOnce performs a single bootstrap attempt (not supported on this platform).
func (c *BootstrapClient) BootstrapOnce(ctx context.Context) (*BootstrapResponse, error) {
	return nil, fmt.Errorf("bootstrap not supported on this platform (Linux only)")
}

// Healthcheck checks if Nexus is reachable (not supported on this platform).
func (c *BootstrapClient) Healthcheck(ctx context.Context) error {
	return fmt.Errorf("healthcheck not supported on this platform (Linux only)")
}

// register sends a registration request to Nexus (stub for testing).
func (c *BootstrapClient) register(ctx context.Context, req *BootstrapRequest) (*BootstrapResponse, error) {
	return nil, fmt.Errorf("register not supported on this platform (Linux only)")
}

// registerAndWait registers with Nexus and waits until configured (stub for testing).
func (c *BootstrapClient) registerAndWait(ctx context.Context, info *SystemInfo) (*DeviceConfig, error) {
	return nil, fmt.Errorf("registerAndWait not supported on this platform (Linux only)")
}

// detectSystemInfo detects the device's system information (stub).
func (c *BootstrapClient) detectSystemInfo() (*SystemInfo, error) {
	return nil, fmt.Errorf("detectSystemInfo not supported on this platform (Linux only)")
}

// Helper functions (stubs for non-Linux)
func detectSerial() (string, error) {
	return "", fmt.Errorf("detectSerial not supported on this platform")
}

func getMACAddress(ifaceName string) (string, error) {
	return "", fmt.Errorf("getMACAddress not supported on this platform")
}

func findPrimaryMAC() (string, error) {
	return "", fmt.Errorf("findPrimaryMAC not supported on this platform")
}

func detectModel() string {
	return ""
}

func detectFirmware() string {
	return ""
}
