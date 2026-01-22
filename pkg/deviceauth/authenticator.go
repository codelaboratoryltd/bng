package deviceauth

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// NewAuthenticator creates an Authenticator based on the config mode.
func NewAuthenticator(config Config, logger *zap.Logger, opts ...AuthenticatorOption) (Authenticator, error) {
	switch config.Mode {
	case AuthModeNone:
		return NewNoneAuthenticator(logger, opts...)

	case AuthModePSK:
		if config.PSK == nil {
			return nil, fmt.Errorf("PSK config is required for PSK mode")
		}
		return NewPSKAuthenticator(config.PSK, logger, opts...)

	case AuthModeMTLS:
		if config.MTLS == nil {
			return nil, fmt.Errorf("mTLS config is required for mTLS mode")
		}
		return NewMTLSAuthenticator(config.MTLS, logger, opts...)

	case AuthModeTPM:
		return nil, fmt.Errorf("TPM authentication not yet implemented")

	default:
		return nil, fmt.Errorf("unknown authentication mode: %s", config.Mode)
	}
}

// NoneAuthenticator provides a pass-through authenticator for testing.
type NoneAuthenticator struct {
	logger   *zap.Logger
	options  authenticatorOptions
	identity *DeviceIdentity
}

// NewNoneAuthenticator creates an authenticator that doesn't perform auth.
// WARNING: This is insecure and should only be used for testing!
func NewNoneAuthenticator(logger *zap.Logger, opts ...AuthenticatorOption) (*NoneAuthenticator, error) {
	options := authenticatorOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	auth := &NoneAuthenticator{
		logger:  logger,
		options: options,
	}

	auth.buildIdentity()

	logger.Warn("Using no-auth mode - THIS IS INSECURE!")
	return auth, nil
}

func (a *NoneAuthenticator) buildIdentity() {
	deviceID := a.options.deviceID
	if deviceID == "" && a.options.serial != "" {
		deviceID = "device-" + a.options.serial
	}
	if deviceID == "" {
		deviceID = "device-noauth"
	}

	a.identity = &DeviceIdentity{
		DeviceID:  deviceID,
		Serial:    a.options.serial,
		MAC:       a.options.mac,
		CreatedAt: time.Now().UTC(),
	}
}

// Authenticate always succeeds for NoneAuthenticator.
func (a *NoneAuthenticator) Authenticate() (*AuthResult, error) {
	return &AuthResult{
		Success:   true,
		DeviceID:  a.identity.DeviceID,
		Mode:      AuthModeNone,
		Timestamp: time.Now().UTC(),
	}, nil
}

// GetTLSConfig returns a basic TLS config.
func (a *NoneAuthenticator) GetTLSConfig() *tls.Config {
	if a.options.tlsConfig != nil {
		return a.options.tlsConfig.Clone()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// GetHTTPHeaders returns device identity headers.
func (a *NoneAuthenticator) GetHTTPHeaders() map[string]string {
	headers := make(map[string]string)
	if a.identity != nil {
		headers["X-Device-ID"] = a.identity.DeviceID
		if a.identity.Serial != "" {
			headers["X-Device-Serial"] = a.identity.Serial
		}
	}
	return headers
}

// Identity returns the device identity.
func (a *NoneAuthenticator) Identity() *DeviceIdentity {
	if a.identity == nil {
		return nil
	}
	identCopy := *a.identity
	return &identCopy
}

// Mode returns AuthModeNone.
func (a *NoneAuthenticator) Mode() AuthMode {
	return AuthModeNone
}

// Close does nothing.
func (a *NoneAuthenticator) Close() error {
	return nil
}

// ReadDeviceIdentity reads device identity from the system.
// This collects serial number, MAC address, and other hardware info.
func ReadDeviceIdentity() (*DeviceIdentity, error) {
	identity := &DeviceIdentity{
		CreatedAt: time.Now().UTC(),
	}

	// Read serial number
	serial, err := readSerial()
	if err == nil {
		identity.Serial = serial
	}

	// Read MAC address
	mac, err := readMAC()
	if err == nil {
		identity.MAC = mac
	}

	// Generate device ID from available info
	identity.DeviceID = generateDeviceID(serial, mac)

	return identity, nil
}

// readSerial reads the system serial number from various sources.
func readSerial() (string, error) {
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

	// Try machine-id as fallback
	data, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		machineID := strings.TrimSpace(string(data))
		if machineID != "" {
			if len(machineID) > 32 {
				machineID = machineID[:32]
			}
			return "MID-" + machineID, nil
		}
	}

	return "", fmt.Errorf("no serial number found")
}

// readMAC reads the MAC address of the first suitable network interface.
func readMAC() (string, error) {
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

// generateDeviceID generates a device ID from available hardware info.
func generateDeviceID(serial, mac string) string {
	// Prefer serial number
	if serial != "" {
		return "olt-" + sanitizeID(serial)
	}

	// Fall back to MAC-based ID
	if mac != "" {
		return "olt-" + strings.ReplaceAll(mac, ":", "")
	}

	// Last resort: generate from random data
	h := sha256.New()
	h.Write([]byte(time.Now().String()))
	return "olt-" + hex.EncodeToString(h.Sum(nil)[:8])
}

// sanitizeID removes characters that shouldn't be in an ID.
func sanitizeID(s string) string {
	var result strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// ValidateConfig validates an authentication configuration.
func ValidateConfig(config Config) error {
	switch config.Mode {
	case AuthModeNone:
		// No validation needed
		return nil

	case AuthModePSK:
		if config.PSK == nil {
			return fmt.Errorf("PSK config is required for PSK mode")
		}
		if config.PSK.Key == "" && config.PSK.KeyFile == "" {
			return fmt.Errorf("PSK key or key_file is required")
		}
		return nil

	case AuthModeMTLS:
		if config.MTLS == nil {
			return fmt.Errorf("mTLS config is required for mTLS mode")
		}
		if config.MTLS.CertFile == "" {
			return fmt.Errorf("mTLS cert_file is required")
		}
		if config.MTLS.KeyFile == "" {
			return fmt.Errorf("mTLS key_file is required")
		}
		if config.MTLS.CAFile == "" && !config.MTLS.InsecureSkipVerify {
			return fmt.Errorf("mTLS ca_file is required (or set insecure_skip_verify)")
		}
		return nil

	case AuthModeTPM:
		return fmt.Errorf("TPM mode not yet implemented")

	default:
		return fmt.Errorf("unknown authentication mode: %s", config.Mode)
	}
}
