package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// TLSConfig contains TLS settings for secure connections.
type TLSConfig struct {
	// Enabled controls whether TLS verification is enforced.
	// Default: true. Setting to false is INSECURE and should only be used for testing.
	Enabled bool `yaml:"enabled"`

	// CACertFile is the path to a PEM file containing trusted CA certificates.
	// If empty, the system root CAs are used.
	CACertFile string `yaml:"ca_cert_file,omitempty"`

	// CACertPEM contains PEM-encoded CA certificates directly in the config.
	// This is useful for embedding certificates or receiving them via environment.
	CACertPEM string `yaml:"ca_cert_pem,omitempty"`

	// CertFile is the path to the client certificate file (for mTLS).
	CertFile string `yaml:"cert_file,omitempty"`

	// KeyFile is the path to the client private key file (for mTLS).
	KeyFile string `yaml:"key_file,omitempty"`

	// PinnedCerts contains SHA256 fingerprints of pinned certificates.
	// Format: hex-encoded SHA256 hash of the DER-encoded certificate.
	// If set, the server certificate must match one of these fingerprints.
	PinnedCerts []string `yaml:"pinned_certs,omitempty"`

	// ServerName overrides the server name for certificate validation.
	// Useful when connecting via IP address but validating against a hostname.
	ServerName string `yaml:"server_name,omitempty"`

	// MinVersion is the minimum TLS version to accept.
	// Valid values: "1.2", "1.3". Default: "1.2"
	MinVersion string `yaml:"min_version,omitempty"`

	// InsecureSkipVerify disables certificate verification.
	// WARNING: This makes the connection vulnerable to man-in-the-middle attacks.
	// Only use for testing. This option will log a warning when enabled.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty"`
}

// DefaultTLSConfig returns a secure default TLS configuration.
func DefaultTLSConfig() TLSConfig {
	return TLSConfig{
		Enabled:    true,
		MinVersion: "1.2",
	}
}

// BuildTLSConfig creates a *tls.Config from the TLSConfig settings.
// Returns nil if TLS is disabled (which uses Go's default TLS config).
func (c *TLSConfig) BuildTLSConfig() (*tls.Config, error) {
	if !c.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Set minimum TLS version
	switch c.MinVersion {
	case "1.3":
		tlsConfig.MinVersion = tls.VersionTLS13
	case "1.2", "":
		tlsConfig.MinVersion = tls.VersionTLS12
	default:
		return nil, fmt.Errorf("invalid TLS min_version: %s (use '1.2' or '1.3')", c.MinVersion)
	}

	// Configure CA certificates
	if c.CACertFile != "" || c.CACertPEM != "" {
		certPool := x509.NewCertPool()

		// Load from file
		if c.CACertFile != "" {
			caCert, err := os.ReadFile(c.CACertFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA cert file %s: %w", c.CACertFile, err)
			}
			if !certPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificates from %s", c.CACertFile)
			}
		}

		// Load from PEM string
		if c.CACertPEM != "" {
			if !certPool.AppendCertsFromPEM([]byte(c.CACertPEM)) {
				return nil, fmt.Errorf("failed to parse CA certificates from PEM config")
			}
		}

		tlsConfig.RootCAs = certPool
	}

	// Configure client certificate (mTLS)
	if c.CertFile != "" && c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Set server name override
	if c.ServerName != "" {
		tlsConfig.ServerName = c.ServerName
	}

	// Handle insecure skip verify (with warning built into the config)
	if c.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	// Configure certificate pinning
	if len(c.PinnedCerts) > 0 {
		pinnedFingerprints := make(map[string]bool)
		for _, fp := range c.PinnedCerts {
			// Normalize fingerprint: lowercase, no colons or spaces
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fp, ":", ""), " ", ""))
			pinnedFingerprints[normalized] = true
		}

		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates presented by server")
			}

			// Check the leaf certificate
			leafCert := rawCerts[0]
			fingerprint := sha256.Sum256(leafCert)
			fingerprintHex := hex.EncodeToString(fingerprint[:])

			if !pinnedFingerprints[fingerprintHex] {
				return fmt.Errorf("certificate fingerprint %s does not match any pinned certificates", fingerprintHex)
			}

			return nil
		}
	}

	return tlsConfig, nil
}

// ValidateTLSConfig checks the TLS configuration for common issues.
func ValidateTLSConfig(c TLSConfig) error {
	if !c.Enabled {
		return nil
	}

	// Check that cert and key are both specified or both empty
	if (c.CertFile != "" && c.KeyFile == "") || (c.CertFile == "" && c.KeyFile != "") {
		return fmt.Errorf("both cert_file and key_file must be specified for mTLS, or neither")
	}

	// Validate pinned cert format
	for i, fp := range c.PinnedCerts {
		normalized := strings.ReplaceAll(strings.ReplaceAll(fp, ":", ""), " ", "")
		if len(normalized) != 64 {
			return fmt.Errorf("pinned_cert[%d] is invalid: expected 64 hex characters (SHA256), got %d", i, len(normalized))
		}
		if _, err := hex.DecodeString(normalized); err != nil {
			return fmt.Errorf("pinned_cert[%d] is invalid: not valid hex: %w", i, err)
		}
	}

	// Check file existence if specified
	if c.CACertFile != "" {
		if _, err := os.Stat(c.CACertFile); err != nil {
			return fmt.Errorf("ca_cert_file not accessible: %w", err)
		}
	}

	if c.CertFile != "" {
		if _, err := os.Stat(c.CertFile); err != nil {
			return fmt.Errorf("cert_file not accessible: %w", err)
		}
	}

	if c.KeyFile != "" {
		if _, err := os.Stat(c.KeyFile); err != nil {
			return fmt.Errorf("key_file not accessible: %w", err)
		}
	}

	return nil
}

// GetCertFingerprint returns the SHA256 fingerprint of a certificate file.
// This is useful for generating pinned certificate values.
func GetCertFingerprint(certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("failed to read certificate: %w", err)
	}

	// Parse the PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Calculate SHA256 fingerprint of the DER-encoded certificate
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:]), nil
}
