// Package deviceauth implements device authentication mechanisms for OLT-BNG devices.
// It supports multiple authentication modes:
// - mTLS with device certificates (recommended for production)
// - Pre-shared keys (for simpler deployments/testing)
// - TPM-based attestation (future, for hardware-rooted trust)
package deviceauth

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

// AuthMode represents the device authentication mode.
type AuthMode string

const (
	// AuthModeNone disables device authentication (insecure, for testing only).
	AuthModeNone AuthMode = "none"

	// AuthModePSK uses pre-shared key authentication.
	// Simpler but less secure - suitable for dev/test environments.
	AuthModePSK AuthMode = "psk"

	// AuthModeMTLS uses mutual TLS with device certificates.
	// Recommended for production deployments.
	AuthModeMTLS AuthMode = "mtls"

	// AuthModeTPM uses TPM 2.0 attestation (future implementation).
	// Provides hardware-rooted trust.
	AuthModeTPM AuthMode = "tpm"
)

// Config contains device authentication configuration.
type Config struct {
	// Mode specifies the authentication mode.
	Mode AuthMode `yaml:"mode"`

	// DeviceID is the unique identifier for this device.
	// If empty, it will be derived from hardware (serial number, MAC, etc.)
	DeviceID string `yaml:"device_id,omitempty"`

	// PSK contains pre-shared key configuration (when Mode = AuthModePSK).
	PSK *PSKConfig `yaml:"psk,omitempty"`

	// MTLS contains mTLS configuration (when Mode = AuthModeMTLS).
	MTLS *MTLSConfig `yaml:"mtls,omitempty"`

	// TPM contains TPM attestation configuration (when Mode = AuthModeTPM).
	TPM *TPMConfig `yaml:"tpm,omitempty"`
}

// DefaultConfig returns sensible defaults with no authentication.
func DefaultConfig() Config {
	return Config{
		Mode: AuthModeNone,
	}
}

// PSKConfig contains pre-shared key authentication settings.
type PSKConfig struct {
	// Key is the pre-shared secret key.
	// In production, this should be loaded from a secure source (vault, env var).
	Key string `yaml:"key"`

	// KeyFile is an alternative path to load the key from a file.
	KeyFile string `yaml:"key_file,omitempty"`

	// HeaderName is the HTTP header name for transmitting the PSK.
	// Default: "X-Device-PSK"
	HeaderName string `yaml:"header_name,omitempty"`
}

// MTLSConfig contains mutual TLS authentication settings.
type MTLSConfig struct {
	// CertFile is the path to the device certificate (PEM format).
	CertFile string `yaml:"cert_file"`

	// KeyFile is the path to the device private key (PEM format).
	KeyFile string `yaml:"key_file"`

	// CAFile is the path to the CA certificate bundle for server verification.
	CAFile string `yaml:"ca_file"`

	// ServerName is the expected server hostname (for TLS verification).
	// If empty, extracted from the connection URL.
	ServerName string `yaml:"server_name,omitempty"`

	// InsecureSkipVerify disables server certificate verification.
	// NEVER use in production!
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty"`

	// CertificateRotation enables automatic certificate rotation.
	CertificateRotation bool `yaml:"certificate_rotation,omitempty"`

	// RotationCheckInterval is how often to check for certificate renewal.
	RotationCheckInterval time.Duration `yaml:"rotation_check_interval,omitempty"`

	// RotationThreshold is how long before expiry to trigger renewal.
	// Default: 30 days
	RotationThreshold time.Duration `yaml:"rotation_threshold,omitempty"`
}

// TPMConfig contains TPM 2.0 attestation settings (future implementation).
type TPMConfig struct {
	// DevicePath is the path to the TPM device.
	// Default: /dev/tpmrm0 (resource manager)
	DevicePath string `yaml:"device_path,omitempty"`

	// UseSimulator enables the software TPM simulator (for testing).
	UseSimulator bool `yaml:"use_simulator,omitempty"`

	// PCRs is the list of PCR indices to include in attestation.
	// These typically include measurements of firmware and boot components.
	PCRs []int `yaml:"pcrs,omitempty"`

	// AttestationKeyHandle is the handle of the attestation key in TPM.
	AttestationKeyHandle uint32 `yaml:"ak_handle,omitempty"`
}

// DeviceIdentity represents the cryptographic identity of this device.
type DeviceIdentity struct {
	// DeviceID is the unique device identifier.
	DeviceID string `json:"device_id"`

	// Serial is the hardware serial number.
	Serial string `json:"serial"`

	// MAC is the primary MAC address.
	MAC string `json:"mac"`

	// Certificate is the device's X.509 certificate (for mTLS).
	Certificate *x509.Certificate `json:"-"`

	// CertificatePEM is the PEM-encoded certificate.
	CertificatePEM string `json:"certificate_pem,omitempty"`

	// CertificateExpiry is when the certificate expires.
	CertificateExpiry time.Time `json:"certificate_expiry,omitempty"`

	// TPMPublicKey is the TPM endorsement key (for TPM mode).
	TPMPublicKey []byte `json:"tpm_public_key,omitempty"`

	// CreatedAt is when this identity was established.
	CreatedAt time.Time `json:"created_at"`
}

// CertificateRenewalRequest is sent to Nexus to request a new certificate.
type CertificateRenewalRequest struct {
	// DeviceID is the device requesting renewal.
	DeviceID string `json:"device_id"`

	// CSR is the Certificate Signing Request (PEM encoded).
	CSR string `json:"csr"`

	// CurrentCertSerial is the serial of the current certificate.
	CurrentCertSerial string `json:"current_cert_serial,omitempty"`

	// Reason for renewal (optional).
	Reason string `json:"reason,omitempty"`
}

// CertificateRenewalResponse is returned by Nexus with the new certificate.
type CertificateRenewalResponse struct {
	// Certificate is the new device certificate (PEM encoded).
	Certificate string `json:"certificate"`

	// Chain contains intermediate CA certificates (PEM encoded).
	Chain string `json:"chain,omitempty"`

	// ExpiresAt is when the new certificate expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthResult contains the result of a device authentication attempt.
type AuthResult struct {
	// Success indicates if authentication succeeded.
	Success bool `json:"success"`

	// DeviceID is the authenticated device ID.
	DeviceID string `json:"device_id,omitempty"`

	// Mode is the authentication mode used.
	Mode AuthMode `json:"mode"`

	// Error contains the error message if authentication failed.
	Error string `json:"error,omitempty"`

	// Timestamp is when authentication was attempted.
	Timestamp time.Time `json:"timestamp"`
}

// Authenticator is the interface for device authentication.
type Authenticator interface {
	// Authenticate performs device authentication.
	// Returns the authenticated device identity or an error.
	Authenticate() (*AuthResult, error)

	// GetTLSConfig returns the TLS configuration for authenticated connections.
	// Returns nil if no TLS is required (e.g., PSK mode).
	GetTLSConfig() *tls.Config

	// GetHTTPHeaders returns additional HTTP headers for authentication.
	// Used for PSK mode and additional device identity headers.
	GetHTTPHeaders() map[string]string

	// Identity returns the current device identity.
	Identity() *DeviceIdentity

	// Mode returns the current authentication mode.
	Mode() AuthMode

	// Close releases any resources held by the authenticator.
	Close() error
}

// AuthenticatorOption is a functional option for configuring authenticators.
type AuthenticatorOption func(*authenticatorOptions)

type authenticatorOptions struct {
	deviceID  string
	serial    string
	mac       string
	tlsConfig *tls.Config
}

// WithDeviceID sets the device ID explicitly.
func WithDeviceID(id string) AuthenticatorOption {
	return func(o *authenticatorOptions) {
		o.deviceID = id
	}
}

// WithSerial sets the device serial number.
func WithSerial(serial string) AuthenticatorOption {
	return func(o *authenticatorOptions) {
		o.serial = serial
	}
}

// WithMAC sets the device MAC address.
func WithMAC(mac string) AuthenticatorOption {
	return func(o *authenticatorOptions) {
		o.mac = mac
	}
}

// WithTLSConfig allows providing a pre-configured TLS config.
func WithTLSConfig(cfg *tls.Config) AuthenticatorOption {
	return func(o *authenticatorOptions) {
		o.tlsConfig = cfg
	}
}
