package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/deviceauth"
	"github.com/codelaboratoryltd/bng/pkg/ztp"
)

// BootstrapConfig contains settings for the bootstrap process.
type BootstrapConfig struct {
	// NexusServerURL is the URL of the Nexus server bootstrap API.
	// If empty and ZTPEnabled=true, this will be discovered via DHCP.
	NexusServerURL string `yaml:"nexus_server_url"`

	// ZTPEnabled enables Zero Touch Provisioning via DHCP.
	// When enabled, the management IP and Nexus URL are obtained from DHCP.
	ZTPEnabled bool `yaml:"ztp_enabled"`

	// ZTPInterface is the management interface for ZTP DHCP discovery.
	ZTPInterface string `yaml:"ztp_interface"`

	// SerialOverride allows overriding the hardware serial (for testing).
	SerialOverride string `yaml:"serial_override,omitempty"`

	// RetryInterval is how long to wait between registration attempts.
	RetryInterval time.Duration `yaml:"retry_interval"`

	// MaxRetries is the maximum number of registration attempts (0 = infinite).
	MaxRetries int `yaml:"max_retries"`

	// Auth contains device authentication configuration.
	Auth deviceauth.Config `yaml:"auth"`
}

// DefaultBootstrapConfig returns sensible defaults.
func DefaultBootstrapConfig() BootstrapConfig {
	return BootstrapConfig{
		ZTPInterface:  "eth0",
		RetryInterval: 30 * time.Second,
		MaxRetries:    0, // Infinite retries
		Auth:          deviceauth.DefaultConfig(),
	}
}

// Bootstrap handles the initial device registration process.
type Bootstrap struct {
	config        BootstrapConfig
	logger        *zap.Logger
	client        *http.Client
	authenticator deviceauth.Authenticator
}

// NewBootstrap creates a new Bootstrap instance.
func NewBootstrap(config BootstrapConfig, logger *zap.Logger) *Bootstrap {
	return &Bootstrap{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewBootstrapWithAuth creates a new Bootstrap instance with device authentication.
func NewBootstrapWithAuth(config BootstrapConfig, logger *zap.Logger) (*Bootstrap, error) {
	b := &Bootstrap{
		config: config,
		logger: logger,
	}

	// Initialize authenticator based on config
	if config.Auth.Mode != deviceauth.AuthModeNone {
		// Validate auth config
		if err := deviceauth.ValidateConfig(config.Auth); err != nil {
			return nil, fmt.Errorf("invalid auth config: %w", err)
		}

		// Get device info for authenticator options
		info, err := b.GetDeviceInfo()
		if err != nil {
			logger.Warn("Failed to get device info for auth", zap.Error(err))
		}

		opts := []deviceauth.AuthenticatorOption{}
		if info != nil {
			opts = append(opts, deviceauth.WithSerial(info.Serial))
			opts = append(opts, deviceauth.WithMAC(info.MAC))
		}

		// Create authenticator
		auth, err := deviceauth.NewAuthenticator(config.Auth, logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create authenticator: %w", err)
		}
		b.authenticator = auth

		// Configure HTTP client with TLS
		tlsConfig := auth.GetTLSConfig()
		if tlsConfig != nil {
			b.client = &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}
		} else {
			b.client = &http.Client{
				Timeout: 30 * time.Second,
			}
		}

		logger.Info("Device authentication initialized",
			zap.String("mode", string(auth.Mode())),
			zap.String("device_id", auth.Identity().DeviceID),
		)
	} else {
		b.client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return b, nil
}

// Authenticator returns the device authenticator (if any).
func (b *Bootstrap) Authenticator() deviceauth.Authenticator {
	return b.authenticator
}

// Close releases resources held by the bootstrap instance.
func (b *Bootstrap) Close() error {
	if b.authenticator != nil {
		return b.authenticator.Close()
	}
	return nil
}

// GetDeviceInfo reads hardware information from the system.
func (b *Bootstrap) GetDeviceInfo() (*DeviceInfo, error) {
	info := &DeviceInfo{
		AgentVersion: Version,
		Capabilities: []string{},
	}

	// Get serial number
	var err error
	if b.config.SerialOverride != "" {
		info.Serial = b.config.SerialOverride
	} else {
		info.Serial, err = b.readSerial()
		if err != nil {
			return nil, fmt.Errorf("failed to read serial: %w", err)
		}
	}

	// Get MAC address of management interface
	info.MAC, err = b.readMAC()
	if err != nil {
		b.logger.Warn("Failed to read MAC address", zap.Error(err))
		info.MAC = "00:00:00:00:00:00"
	}

	// Get model/product name
	info.Model, err = b.readModel()
	if err != nil {
		b.logger.Warn("Failed to read model", zap.Error(err))
		info.Model = "unknown"
	}

	// Get firmware/kernel version
	info.Firmware, err = b.readFirmware()
	if err != nil {
		b.logger.Warn("Failed to read firmware version", zap.Error(err))
		info.Firmware = "unknown"
	}

	// Detect capabilities
	info.Capabilities = b.detectCapabilities()

	return info, nil
}

// readSerial reads the system serial number from DMI/SMBIOS.
func (b *Bootstrap) readSerial() (string, error) {
	// Try multiple sources for serial number

	// 1. DMI product serial
	paths := []string{
		"/sys/class/dmi/id/product_serial",
		"/sys/class/dmi/id/board_serial",
		"/sys/class/dmi/id/chassis_serial",
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			serial := strings.TrimSpace(string(data))
			if serial != "" && serial != "None" && serial != "To Be Filled By O.E.M." {
				return serial, nil
			}
		}
	}

	// 2. Try machine-id as fallback
	data, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		machineID := strings.TrimSpace(string(data))
		if machineID != "" {
			// Truncate to reasonable length
			if len(machineID) > 32 {
				machineID = machineID[:32]
			}
			return "MID-" + machineID, nil
		}
	}

	return "", fmt.Errorf("no serial number found")
}

// readMAC reads the MAC address of the first suitable interface.
func (b *Bootstrap) readMAC() (string, error) {
	// Prefer management interfaces
	interfaceNames := []string{"eth0", "eno1", "enp0s3", "mgmt0"}

	for _, name := range interfaceNames {
		path := fmt.Sprintf("/sys/class/net/%s/address", name)
		data, err := os.ReadFile(path)
		if err == nil {
			mac := strings.TrimSpace(string(data))
			if mac != "" && mac != "00:00:00:00:00:00" {
				return mac, nil
			}
		}
	}

	// Fall back to any interface with a valid MAC
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if entry.Name() == "lo" {
			continue
		}
		path := fmt.Sprintf("/sys/class/net/%s/address", entry.Name())
		data, err := os.ReadFile(path)
		if err == nil {
			mac := strings.TrimSpace(string(data))
			if mac != "" && mac != "00:00:00:00:00:00" {
				return mac, nil
			}
		}
	}

	return "", fmt.Errorf("no MAC address found")
}

// readModel reads the product/model name.
func (b *Bootstrap) readModel() (string, error) {
	paths := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/board_name",
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			model := strings.TrimSpace(string(data))
			if model != "" && model != "None" && model != "To Be Filled By O.E.M." {
				return model, nil
			}
		}
	}

	return "unknown", nil
}

// readFirmware reads the firmware/kernel version.
func (b *Bootstrap) readFirmware() (string, error) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", err
	}

	// Extract kernel version from /proc/version
	// Format: "Linux version X.Y.Z ..."
	parts := strings.Fields(string(data))
	if len(parts) >= 3 {
		return parts[2], nil
	}

	return strings.TrimSpace(string(data)), nil
}

// detectCapabilities detects what this device can do.
func (b *Bootstrap) detectCapabilities() []string {
	caps := []string{}

	// Check for network interfaces that might be PON ports
	// This is hardware-specific and would need to be adapted
	entries, _ := os.ReadDir("/sys/class/net")
	for _, entry := range entries {
		name := entry.Name()
		// Look for PON-like interfaces
		if strings.HasPrefix(name, "pon") || strings.HasPrefix(name, "gpon") {
			caps = append(caps, "gpon")
		}
		if strings.HasPrefix(name, "xgs") {
			caps = append(caps, "xgs-pon")
		}
	}

	// Check for high-speed uplinks
	for _, name := range []string{"eth0", "sfp0", "sfp1"} {
		speedPath := fmt.Sprintf("/sys/class/net/%s/speed", name)
		data, err := os.ReadFile(speedPath)
		if err == nil {
			speed := strings.TrimSpace(string(data))
			switch speed {
			case "10000":
				caps = append(caps, "10g-uplink")
			case "25000":
				caps = append(caps, "25g-uplink")
			case "100000":
				caps = append(caps, "100g-uplink")
			}
		}
	}

	// Check for eBPF support
	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		caps = append(caps, "ebpf")
	}

	// Default capabilities if none detected
	if len(caps) == 0 {
		caps = []string{"generic"}
	}

	return caps
}

// Register attempts to register this device with the Nexus server.
func (b *Bootstrap) Register(ctx context.Context) (*RegistrationResponse, error) {
	info, err := b.GetDeviceInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}

	req := RegistrationRequest{
		DeviceInfo: *info,
		Timestamp:  time.Now().UTC(),
	}

	b.logger.Info("Registering device",
		zap.String("serial", info.Serial),
		zap.String("mac", info.MAC),
		zap.String("model", info.Model),
		zap.Strings("capabilities", info.Capabilities),
	)

	return b.sendRegistration(ctx, &req)
}

// RegisterWithRetry attempts registration with retries until success or context cancellation.
func (b *Bootstrap) RegisterWithRetry(ctx context.Context) (*RegistrationResponse, error) {
	attempt := 0

	for {
		attempt++

		resp, err := b.Register(ctx)
		if err == nil {
			if resp.Status == "approved" {
				b.logger.Info("Device registration approved",
					zap.String("device_id", resp.DeviceID),
				)
				return resp, nil
			}

			if resp.Status == "pending" {
				b.logger.Info("Device registration pending approval",
					zap.String("message", resp.Message),
				)
			} else if resp.Status == "rejected" {
				return nil, fmt.Errorf("registration rejected: %s", resp.Message)
			}
		} else {
			b.logger.Warn("Registration attempt failed",
				zap.Int("attempt", attempt),
				zap.Error(err),
			)
		}

		// Check if we've exceeded max retries
		if b.config.MaxRetries > 0 && attempt >= b.config.MaxRetries {
			return nil, fmt.Errorf("max registration attempts (%d) exceeded", b.config.MaxRetries)
		}

		// Wait before retrying
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(b.config.RetryInterval):
			// Continue to next attempt
		}
	}
}

// sendRegistration sends the registration request to the server.
func (b *Bootstrap) sendRegistration(ctx context.Context, req *RegistrationRequest) (*RegistrationResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := b.config.NexusServerURL + "/api/v1/devices/register"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "olt-bng/"+Version)

	// Add authentication headers if authenticator is configured
	if b.authenticator != nil {
		// Perform authentication check
		authResult, err := b.authenticator.Authenticate()
		if err != nil {
			return nil, fmt.Errorf("device authentication failed: %w", err)
		}
		if !authResult.Success {
			return nil, fmt.Errorf("device authentication failed: %s", authResult.Error)
		}

		// Add authentication headers
		for key, value := range b.authenticator.GetHTTPHeaders() {
			httpReq.Header.Set(key, value)
		}

		// Add auth mode header for server to know how to verify
		httpReq.Header.Set("X-Auth-Mode", string(b.authenticator.Mode()))
	}

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication rejected by server: %s", string(respBody))
	}

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("device not authorized: %s", string(respBody))
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var regResp RegistrationResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &regResp, nil
}

// DiscoverNexusURL uses ZTP DHCP to discover the Nexus server URL.
// This also obtains and configures the management IP address.
func (b *Bootstrap) DiscoverNexusURL(ctx context.Context) (string, error) {
	if !b.config.ZTPEnabled {
		if b.config.NexusServerURL == "" {
			return "", fmt.Errorf("ZTP not enabled and no Nexus URL configured")
		}
		return b.config.NexusServerURL, nil
	}

	b.logger.Info("Starting ZTP discovery",
		zap.String("interface", b.config.ZTPInterface),
	)

	ztpClient := ztp.NewClient(b.config.ZTPInterface)

	// Perform DHCP discovery with timeout
	discoverCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := ztpClient.Discover(discoverCtx)
	if err != nil {
		return "", fmt.Errorf("ZTP DHCP discovery failed: %w", err)
	}

	if result.NexusURL == "" {
		return "", fmt.Errorf("ZTP DHCP response did not contain Nexus URL")
	}

	b.logger.Info("ZTP discovery successful",
		zap.String("ip", result.IP.String()),
		zap.String("nexus_url", result.NexusURL),
	)

	// Configure the network interface
	if err := ztpClient.Configure(result); err != nil {
		b.logger.Warn("Failed to configure network interface", zap.Error(err))
		// Continue anyway - interface may already be configured
	}

	// Update the config with discovered URL
	b.config.NexusServerURL = result.NexusURL

	return result.NexusURL, nil
}

// BootstrapWithZTP performs the full bootstrap process including ZTP discovery.
func (b *Bootstrap) BootstrapWithZTP(ctx context.Context) (*RegistrationResponse, error) {
	// Step 1: Discover Nexus URL via ZTP DHCP (if enabled)
	nexusURL, err := b.DiscoverNexusURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover Nexus: %w", err)
	}

	b.logger.Info("Using Nexus server", zap.String("url", nexusURL))

	// Step 2: Register with Nexus
	return b.RegisterWithRetry(ctx)
}
