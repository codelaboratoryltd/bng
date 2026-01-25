// Package ztp provides Zero Touch Provisioning client functionality for OLT-BNG devices.
// This file implements TLS certificate validation for secure ZTP bootstrap connections.
package ztp

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// TLSConfig contains TLS settings for secure ZTP connections to Nexus.
type TLSConfig struct {
	// Enabled controls whether TLS is used for Nexus connections.
	// Default: true. Must be true for production.
	Enabled bool `yaml:"enabled"`

	// CACertFile is the path to a PEM file containing trusted CA certificates.
	// If empty and CACertPEM is also empty, the system root CAs are used.
	CACertFile string `yaml:"ca_cert_file,omitempty"`

	// CACertPEM contains PEM-encoded CA certificates directly in the config.
	// This is useful for bootstrap scenarios where certs are provided via DHCP.
	CACertPEM string `yaml:"ca_cert_pem,omitempty"`

	// PinnedCerts contains SHA256 fingerprints of pinned certificates.
	// Format: hex-encoded SHA256 hash of the DER-encoded certificate.
	// If set, the server certificate must match one of these fingerprints.
	// This provides TOFU (Trust On First Use) or explicit pinning for bootstrap.
	PinnedCerts []string `yaml:"pinned_certs,omitempty"`

	// ServerName overrides the server name for certificate validation.
	// Useful when Nexus URL uses an IP address but the cert has a hostname.
	ServerName string `yaml:"server_name,omitempty"`

	// MinVersion is the minimum TLS version to accept.
	// Valid values: "1.2", "1.3". Default: "1.2"
	MinVersion string `yaml:"min_version,omitempty"`

	// InsecureSkipVerify disables certificate verification.
	// WARNING: This makes the connection vulnerable to MITM attacks.
	// Only use for development/testing. Never use in production.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty"`

	// CertExpiryWarningDays triggers warnings when certs expire within this many days.
	// Default: 30 days.
	CertExpiryWarningDays int `yaml:"cert_expiry_warning_days,omitempty"`

	// RequireValidChain requires a complete valid certificate chain.
	// Default: true. Setting to false allows self-signed certificates
	// (only when combined with certificate pinning).
	RequireValidChain bool `yaml:"require_valid_chain,omitempty"`
}

// DefaultTLSConfig returns a secure default TLS configuration for ZTP.
func DefaultTLSConfig() TLSConfig {
	return TLSConfig{
		Enabled:               true,
		MinVersion:            "1.2",
		CertExpiryWarningDays: 30,
		RequireValidChain:     true,
	}
}

// TLSValidationResult contains the result of TLS certificate validation.
type TLSValidationResult struct {
	// Valid indicates if the certificate passed all validation checks.
	Valid bool

	// ServerName is the server name used for validation.
	ServerName string

	// CertificateChain contains details about the certificate chain.
	CertificateChain []CertificateInfo

	// PinningVerified indicates if certificate pinning was verified.
	PinningVerified bool

	// Warnings contains non-fatal validation warnings.
	Warnings []string

	// Errors contains validation errors (if Valid is false).
	Errors []string
}

// CertificateInfo contains information about a certificate in the chain.
type CertificateInfo struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	Fingerprint  string
	IsCA         bool
	DNSNames     []string
	IPAddresses  []net.IP
}

// CertificateValidationError represents a certificate validation error.
type CertificateValidationError struct {
	Reason      string
	Certificate *CertificateInfo
	Underlying  error
}

func (e *CertificateValidationError) Error() string {
	if e.Certificate != nil {
		return fmt.Sprintf("certificate validation failed for %s: %s", e.Certificate.Subject, e.Reason)
	}
	return fmt.Sprintf("certificate validation failed: %s", e.Reason)
}

func (e *CertificateValidationError) Unwrap() error {
	return e.Underlying
}

// BuildTLSConfig creates a *tls.Config from the TLSConfig settings.
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

	// Set server name override
	if c.ServerName != "" {
		tlsConfig.ServerName = c.ServerName
	}

	// Handle insecure skip verify (with warning)
	if c.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	// Configure certificate pinning
	if len(c.PinnedCerts) > 0 {
		pinnedFingerprints := make(map[string]bool)
		for _, fp := range c.PinnedCerts {
			// Normalize fingerprint: lowercase, no colons or spaces
			normalized := normalizeFingerprint(fp)
			pinnedFingerprints[normalized] = true
		}

		expiryDays := c.CertExpiryWarningDays
		if expiryDays == 0 {
			expiryDays = 30
		}

		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return c.verifyPeerCertificate(rawCerts, verifiedChains, pinnedFingerprints, expiryDays)
		}
	} else if c.CertExpiryWarningDays > 0 && !c.InsecureSkipVerify {
		// Even without pinning, verify expiry
		expiryDays := c.CertExpiryWarningDays
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return c.checkCertificateExpiry(rawCerts, expiryDays)
		}
	}

	return tlsConfig, nil
}

// verifyPeerCertificate performs certificate verification including pinning.
func (c *TLSConfig) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, pinnedFingerprints map[string]bool, expiryDays int) error {
	if len(rawCerts) == 0 {
		return &CertificateValidationError{
			Reason: "no certificates presented by server",
		}
	}

	// Check the leaf certificate against pinned certs
	leafCert := rawCerts[0]
	fingerprint := sha256.Sum256(leafCert)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	if !pinnedFingerprints[fingerprintHex] {
		return &CertificateValidationError{
			Reason: fmt.Sprintf("certificate fingerprint %s does not match any pinned certificates", fingerprintHex),
		}
	}

	// Check certificate expiry
	return c.checkCertificateExpiry(rawCerts, expiryDays)
}

// checkCertificateExpiry verifies certificates are not expired or expiring soon.
func (c *TLSConfig) checkCertificateExpiry(rawCerts [][]byte, expiryWarningDays int) error {
	if len(rawCerts) == 0 {
		return nil
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return &CertificateValidationError{
			Reason:     "failed to parse server certificate",
			Underlying: err,
		}
	}

	now := time.Now()

	// Check if certificate has expired
	if now.After(cert.NotAfter) {
		return &CertificateValidationError{
			Reason: fmt.Sprintf("certificate expired on %s", cert.NotAfter.Format(time.RFC3339)),
			Certificate: &CertificateInfo{
				Subject:   cert.Subject.String(),
				NotAfter:  cert.NotAfter,
				NotBefore: cert.NotBefore,
			},
		}
	}

	// Check if certificate is not yet valid
	if now.Before(cert.NotBefore) {
		return &CertificateValidationError{
			Reason: fmt.Sprintf("certificate not valid until %s", cert.NotBefore.Format(time.RFC3339)),
			Certificate: &CertificateInfo{
				Subject:   cert.Subject.String(),
				NotAfter:  cert.NotAfter,
				NotBefore: cert.NotBefore,
			},
		}
	}

	// Note: Expiry warning is informational only and doesn't cause failure
	// Logging would be done by the caller

	return nil
}

// ValidateTLSConfig checks the TLS configuration for common issues.
func ValidateTLSConfig(c TLSConfig) error {
	if !c.Enabled {
		return nil
	}

	// Validate minimum version
	switch c.MinVersion {
	case "", "1.2", "1.3":
		// Valid
	default:
		return fmt.Errorf("invalid min_version: %s (use '1.2' or '1.3')", c.MinVersion)
	}

	// Validate pinned cert format
	for i, fp := range c.PinnedCerts {
		normalized := normalizeFingerprint(fp)
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

	// Warn about insecure configurations
	if c.InsecureSkipVerify && len(c.PinnedCerts) == 0 {
		return fmt.Errorf("insecure_skip_verify is enabled without certificate pinning - this is dangerous")
	}

	return nil
}

// ValidateCertificate performs comprehensive validation of a certificate.
func ValidateCertificate(certPEM []byte, config *TLSConfig) (*TLSValidationResult, error) {
	result := &TLSValidationResult{
		Valid:            true,
		CertificateChain: make([]CertificateInfo, 0),
		Warnings:         make([]string, 0),
		Errors:           make([]string, 0),
	}

	// Parse certificates from PEM
	var certs []*x509.Certificate
	rest := certPEM
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("failed to parse certificate: %v", err))
			continue
		}
		certs = append(certs, cert)

		// Build certificate info
		fingerprint := sha256.Sum256(cert.Raw)
		info := CertificateInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			Fingerprint:  hex.EncodeToString(fingerprint[:]),
			IsCA:         cert.IsCA,
			DNSNames:     cert.DNSNames,
			IPAddresses:  cert.IPAddresses,
		}
		result.CertificateChain = append(result.CertificateChain, info)
	}

	if len(certs) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "no valid certificates found in PEM data")
		return result, nil
	}

	// Validate each certificate
	now := time.Now()
	expiryWarningDays := 30
	if config != nil && config.CertExpiryWarningDays > 0 {
		expiryWarningDays = config.CertExpiryWarningDays
	}

	for i, cert := range certs {
		// Check expiry
		if now.After(cert.NotAfter) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("certificate[%d] (%s) expired on %s", i, cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339)))
		} else if now.Before(cert.NotBefore) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("certificate[%d] (%s) not valid until %s", i, cert.Subject.CommonName, cert.NotBefore.Format(time.RFC3339)))
		}

		// Check approaching expiry
		daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysUntilExpiry <= expiryWarningDays && daysUntilExpiry > 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("certificate[%d] (%s) expires in %d days", i, cert.Subject.CommonName, daysUntilExpiry))
		}

		// Check key usage for CA certificates
		if cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("certificate[%d] (%s) is marked as CA but cannot sign certificates", i, cert.Subject.CommonName))
		}
	}

	// Validate chain if required
	if config != nil && config.RequireValidChain && len(certs) > 1 {
		if err := validateChain(certs); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("certificate chain validation failed: %v", err))
		}
	}

	// Check certificate pinning if configured
	if config != nil && len(config.PinnedCerts) > 0 && len(result.CertificateChain) > 0 {
		leafFingerprint := result.CertificateChain[0].Fingerprint
		pinned := false
		for _, fp := range config.PinnedCerts {
			if normalizeFingerprint(fp) == leafFingerprint {
				pinned = true
				break
			}
		}
		result.PinningVerified = pinned
		if !pinned {
			result.Valid = false
			result.Errors = append(result.Errors, "certificate fingerprint does not match any pinned certificates")
		}
	}

	return result, nil
}

// validateChain validates the certificate chain.
func validateChain(certs []*x509.Certificate) error {
	if len(certs) < 2 {
		return nil // Single cert, no chain to validate
	}

	// Build intermediate pool
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	// Verify the leaf certificate
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	// Try to find a valid chain
	_, err := certs[0].Verify(opts)
	if err != nil {
		// Check if it's just a self-signed root issue
		var certErr x509.UnknownAuthorityError
		if errors.As(err, &certErr) {
			// Check if the last cert is self-signed (root)
			lastCert := certs[len(certs)-1]
			if lastCert.Issuer.String() == lastCert.Subject.String() {
				// Add root to trusted
				roots := x509.NewCertPool()
				roots.AddCert(lastCert)
				opts.Roots = roots
				_, err = certs[0].Verify(opts)
			}
		}
	}

	return err
}

// GetCertFingerprint returns the SHA256 fingerprint of a certificate file.
func GetCertFingerprint(certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:]), nil
}

// GetCertFingerprintFromPEM returns the SHA256 fingerprint of a PEM-encoded certificate.
func GetCertFingerprintFromPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:]), nil
}

// normalizeFingerprint normalizes a certificate fingerprint to lowercase hex without separators.
func normalizeFingerprint(fp string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fp, ":", ""), " ", ""))
}

// IsCertificateExpiringSoon checks if a certificate is expiring within the given duration.
func IsCertificateExpiringSoon(certPEM []byte, within time.Duration) (bool, time.Duration, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, 0, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, 0, fmt.Errorf("failed to parse certificate: %w", err)
	}

	timeUntilExpiry := time.Until(cert.NotAfter)
	return timeUntilExpiry <= within, timeUntilExpiry, nil
}

// ExtractServerNameFromURL extracts the server name from a URL for TLS validation.
func ExtractServerNameFromURL(urlStr string) string {
	// Remove protocol prefix
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Remove path
	if idx := strings.Index(urlStr, "/"); idx != -1 {
		urlStr = urlStr[:idx]
	}

	// Remove port
	if host, _, err := net.SplitHostPort(urlStr); err == nil {
		return host
	}

	return urlStr
}
