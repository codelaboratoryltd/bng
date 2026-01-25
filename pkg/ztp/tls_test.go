package ztp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCACert creates a self-signed CA certificate for testing.
func generateTestCACert(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// generateTestServerCert creates a server certificate signed by the CA.
func generateTestServerCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, notBefore, notAfter time.Time, dnsNames []string, ipAddrs []net.IP) (certPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   "test.example.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM
}

// parseCertAndKey parses PEM-encoded certificate and key.
func parseCertAndKey(t *testing.T, certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	block, _ = pem.Decode(keyPEM)
	require.NotNil(t, block)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)

	return cert, key
}

func TestDefaultTLSConfig(t *testing.T) {
	cfg := DefaultTLSConfig()

	assert.True(t, cfg.Enabled, "TLS should be enabled by default")
	assert.Equal(t, "1.2", cfg.MinVersion)
	assert.Equal(t, 30, cfg.CertExpiryWarningDays)
	assert.True(t, cfg.RequireValidChain)
	assert.False(t, cfg.InsecureSkipVerify)
}

func TestBuildTLSConfig_Disabled(t *testing.T) {
	cfg := TLSConfig{Enabled: false}

	tlsCfg, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	assert.Nil(t, tlsCfg, "Expected nil TLS config when disabled")
}

func TestBuildTLSConfig_Default(t *testing.T) {
	cfg := DefaultTLSConfig()

	tlsCfg, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
	assert.False(t, tlsCfg.InsecureSkipVerify)
}

func TestBuildTLSConfig_TLS13(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		MinVersion: "1.3",
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.Equal(t, uint16(tls.VersionTLS13), tlsCfg.MinVersion)
}

func TestBuildTLSConfig_InvalidMinVersion(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		MinVersion: "1.0",
	}

	_, err := cfg.BuildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TLS min_version")
}

func TestBuildTLSConfig_ServerName(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		ServerName: "nexus.example.com",
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	require.NoError(t, err)

	assert.Equal(t, "nexus.example.com", tlsCfg.ServerName)
}

func TestBuildTLSConfig_CACertPEM(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now(), time.Now().Add(24*time.Hour))

	cfg := TLSConfig{
		Enabled:   true,
		CACertPEM: string(caCertPEM),
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.NotNil(t, tlsCfg.RootCAs)
}

func TestBuildTLSConfig_CACertFile(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now(), time.Now().Add(24*time.Hour))

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	err := os.WriteFile(caFile, caCertPEM, 0644)
	require.NoError(t, err)

	cfg := TLSConfig{
		Enabled:    true,
		CACertFile: caFile,
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.NotNil(t, tlsCfg.RootCAs)
}

func TestBuildTLSConfig_PinnedCerts(t *testing.T) {
	cfg := TLSConfig{
		Enabled: true,
		PinnedCerts: []string{
			"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.NotNil(t, tlsCfg.VerifyPeerCertificate, "Expected VerifyPeerCertificate to be set for pinning")
}

func TestBuildTLSConfig_InsecureSkipVerify(t *testing.T) {
	cfg := TLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.True(t, tlsCfg.InsecureSkipVerify)
}

func TestValidateTLSConfig_Valid(t *testing.T) {
	cfg := DefaultTLSConfig()
	err := ValidateTLSConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateTLSConfig_InvalidMinVersion(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		MinVersion: "1.0",
	}

	err := ValidateTLSConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid min_version")
}

func TestValidateTLSConfig_InvalidPinnedCert(t *testing.T) {
	tests := []struct {
		name   string
		pinned string
	}{
		{"too short", "abc123"},
		{"invalid hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{"extra characters", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2xxxx"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := TLSConfig{
				Enabled:     true,
				PinnedCerts: []string{tt.pinned},
			}

			err := ValidateTLSConfig(cfg)
			assert.Error(t, err)
		})
	}
}

func TestValidateTLSConfig_InsecureWithoutPinning(t *testing.T) {
	cfg := TLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
		PinnedCerts:        nil, // No pinning
	}

	err := ValidateTLSConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insecure_skip_verify")
}

func TestValidateTLSConfig_InsecureWithPinning(t *testing.T) {
	cfg := TLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
		PinnedCerts: []string{
			"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
	}

	// With pinning, insecure is acceptable
	err := ValidateTLSConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateTLSConfig_Disabled(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    false,
		MinVersion: "invalid", // Should be ignored when disabled
	}

	err := ValidateTLSConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateCertificate_Valid(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	result, err := ValidateCertificate(caCertPEM, nil)
	require.NoError(t, err)

	assert.True(t, result.Valid)
	assert.Len(t, result.CertificateChain, 1)
	assert.Empty(t, result.Errors)
	assert.Contains(t, result.CertificateChain[0].Subject, "Test CA")
}

func TestValidateCertificate_Expired(t *testing.T) {
	// Generate an expired certificate
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	result, err := ValidateCertificate(caCertPEM, nil)
	require.NoError(t, err)

	assert.False(t, result.Valid)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "expired")
}

func TestValidateCertificate_NotYetValid(t *testing.T) {
	// Generate a certificate that's not yet valid
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))

	result, err := ValidateCertificate(caCertPEM, nil)
	require.NoError(t, err)

	assert.False(t, result.Valid)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "not valid until")
}

func TestValidateCertificate_ExpiringSoon(t *testing.T) {
	// Generate a certificate expiring in 15 days
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(15*24*time.Hour))

	config := &TLSConfig{
		CertExpiryWarningDays: 30, // Warn within 30 days
	}

	result, err := ValidateCertificate(caCertPEM, config)
	require.NoError(t, err)

	assert.True(t, result.Valid)
	assert.Len(t, result.Warnings, 1)
	assert.Contains(t, result.Warnings[0], "expires in")
}

func TestValidateCertificate_WithPinning(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	// Get the fingerprint
	fingerprint, err := GetCertFingerprintFromPEM(caCertPEM)
	require.NoError(t, err)

	// Test with matching pin
	config := &TLSConfig{
		PinnedCerts: []string{fingerprint},
	}

	result, err := ValidateCertificate(caCertPEM, config)
	require.NoError(t, err)

	assert.True(t, result.Valid)
	assert.True(t, result.PinningVerified)
}

func TestValidateCertificate_PinningMismatch(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	// Test with non-matching pin
	config := &TLSConfig{
		PinnedCerts: []string{
			"0000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	result, err := ValidateCertificate(caCertPEM, config)
	require.NoError(t, err)

	assert.False(t, result.Valid)
	assert.False(t, result.PinningVerified)
	assert.Contains(t, result.Errors[0], "pinned certificates")
}

func TestValidateCertificate_InvalidPEM(t *testing.T) {
	result, err := ValidateCertificate([]byte("not a certificate"), nil)
	require.NoError(t, err)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Errors[0], "no valid certificates")
}

func TestValidateCertificate_ChainValidation(t *testing.T) {
	// Generate CA
	caCertPEM, caKeyPEM := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	caCert, caKey := parseCertAndKey(t, caCertPEM, caKeyPEM)

	// Generate server cert signed by CA
	serverCertPEM := generateTestServerCert(t, caCert, caKey,
		time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour),
		[]string{"test.example.com"}, nil)

	// Combine certs in chain (leaf first, then CA)
	chainPEM := append(serverCertPEM, caCertPEM...)

	config := &TLSConfig{
		RequireValidChain: true,
	}

	result, err := ValidateCertificate(chainPEM, config)
	require.NoError(t, err)

	assert.True(t, result.Valid)
	assert.Len(t, result.CertificateChain, 2)
}

func TestGetCertFingerprint(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now(), time.Now().Add(24*time.Hour))

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	err := os.WriteFile(certFile, caCertPEM, 0644)
	require.NoError(t, err)

	fingerprint, err := GetCertFingerprint(certFile)
	require.NoError(t, err)

	// Fingerprint should be 64 hex characters (256 bits / 4 bits per char)
	assert.Len(t, fingerprint, 64)
	_, err = hex.DecodeString(fingerprint)
	assert.NoError(t, err, "Fingerprint should be valid hex")
}

func TestGetCertFingerprintFromPEM(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now(), time.Now().Add(24*time.Hour))

	fingerprint, err := GetCertFingerprintFromPEM(caCertPEM)
	require.NoError(t, err)

	assert.Len(t, fingerprint, 64)
	_, err = hex.DecodeString(fingerprint)
	assert.NoError(t, err)
}

func TestNormalizeFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "abcd1234", "abcd1234"},
		{"uppercase", "ABCD1234", "abcd1234"},
		{"with colons", "AB:CD:12:34", "abcd1234"},
		{"with spaces", "AB CD 12 34", "abcd1234"},
		{"mixed", "AB:cd 12:34", "abcd1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeFingerprint(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsCertificateExpiringSoon(t *testing.T) {
	tests := []struct {
		name           string
		expiresIn      time.Duration
		checkWithin    time.Duration
		expectExpiring bool
	}{
		{"expires soon", 10 * 24 * time.Hour, 30 * 24 * time.Hour, true},
		{"not expiring", 60 * 24 * time.Hour, 30 * 24 * time.Hour, false},
		{"exactly at threshold", 30 * 24 * time.Hour, 30 * 24 * time.Hour, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caCertPEM, _ := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(tt.expiresIn))

			expiring, remaining, err := IsCertificateExpiringSoon(caCertPEM, tt.checkWithin)
			require.NoError(t, err)

			assert.Equal(t, tt.expectExpiring, expiring)
			assert.Greater(t, remaining, time.Duration(0))
		})
	}
}

func TestExtractServerNameFromURL(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://nexus.example.com", "nexus.example.com"},
		{"https://nexus.example.com:9000", "nexus.example.com"},
		{"https://nexus.example.com/api/v1", "nexus.example.com"},
		{"https://nexus.example.com:9000/api/v1", "nexus.example.com"},
		{"http://nexus.local:8080", "nexus.local"},
		{"nexus.example.com:443", "nexus.example.com"},
		{"nexus.example.com", "nexus.example.com"},
		{"192.168.1.1:9000", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := ExtractServerNameFromURL(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCertificateValidationError(t *testing.T) {
	err := &CertificateValidationError{
		Reason: "certificate expired",
		Certificate: &CertificateInfo{
			Subject: "CN=test.example.com",
		},
	}

	assert.Contains(t, err.Error(), "certificate expired")
	assert.Contains(t, err.Error(), "CN=test.example.com")
}

func TestCertificateValidationError_NoCert(t *testing.T) {
	err := &CertificateValidationError{
		Reason: "no certificates presented",
	}

	assert.Contains(t, err.Error(), "no certificates presented")
}

func TestCertificateInfo(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	result, err := ValidateCertificate(caCertPEM, nil)
	require.NoError(t, err)
	require.Len(t, result.CertificateChain, 1)

	certInfo := result.CertificateChain[0]
	assert.Contains(t, certInfo.Subject, "Test CA")
	assert.NotEmpty(t, certInfo.Fingerprint)
	assert.True(t, certInfo.IsCA)
	assert.False(t, certInfo.NotBefore.IsZero())
	assert.False(t, certInfo.NotAfter.IsZero())
}

func TestBuildTLSConfig_WithExpiryCheck(t *testing.T) {
	cfg := TLSConfig{
		Enabled:               true,
		CertExpiryWarningDays: 30,
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	// VerifyPeerCertificate should be set for expiry checking
	assert.NotNil(t, tlsCfg.VerifyPeerCertificate)
}

func TestVerifyPeerCertificate_NoCerts(t *testing.T) {
	cfg := TLSConfig{
		Enabled: true,
		PinnedCerts: []string{
			"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
	}

	pinnedFingerprints := map[string]bool{
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2": true,
	}

	err := cfg.verifyPeerCertificate([][]byte{}, nil, pinnedFingerprints, 30)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates presented")
}

func TestVerifyPeerCertificate_PinningMatch(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	// Get the DER-encoded certificate
	block, _ := pem.Decode(caCertPEM)
	require.NotNil(t, block)

	// Calculate fingerprint
	fingerprint := sha256.Sum256(block.Bytes)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	cfg := TLSConfig{Enabled: true}
	pinnedFingerprints := map[string]bool{
		fingerprintHex: true,
	}

	err := cfg.verifyPeerCertificate([][]byte{block.Bytes}, nil, pinnedFingerprints, 30)
	assert.NoError(t, err)
}

func TestVerifyPeerCertificate_PinningMismatch(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	block, _ := pem.Decode(caCertPEM)
	require.NotNil(t, block)

	cfg := TLSConfig{Enabled: true}
	pinnedFingerprints := map[string]bool{
		"0000000000000000000000000000000000000000000000000000000000000000": true,
	}

	err := cfg.verifyPeerCertificate([][]byte{block.Bytes}, nil, pinnedFingerprints, 30)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any pinned certificates")
}

func TestCheckCertificateExpiry_ExpiredCert(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	block, _ := pem.Decode(caCertPEM)
	require.NotNil(t, block)

	cfg := TLSConfig{Enabled: true}
	err := cfg.checkCertificateExpiry([][]byte{block.Bytes}, 30)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestCheckCertificateExpiry_NotYetValid(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))

	block, _ := pem.Decode(caCertPEM)
	require.NotNil(t, block)

	cfg := TLSConfig{Enabled: true}
	err := cfg.checkCertificateExpiry([][]byte{block.Bytes}, 30)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not valid until")
}

func TestCheckCertificateExpiry_ValidCert(t *testing.T) {
	caCertPEM, _ := generateTestCACert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	block, _ := pem.Decode(caCertPEM)
	require.NotNil(t, block)

	cfg := TLSConfig{Enabled: true}
	err := cfg.checkCertificateExpiry([][]byte{block.Bytes}, 30)
	assert.NoError(t, err)
}

func TestValidateTLSConfig_MissingCAFile(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		CACertFile: "/nonexistent/path/to/ca.pem",
	}

	err := ValidateTLSConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ca_cert_file not accessible")
}

func TestBuildTLSConfig_InvalidCACertFile(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		CACertFile: "/nonexistent/path/to/ca.pem",
	}

	_, err := cfg.BuildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA cert file")
}

func TestBuildTLSConfig_InvalidCACertPEM(t *testing.T) {
	cfg := TLSConfig{
		Enabled:   true,
		CACertPEM: "not a valid certificate",
	}

	_, err := cfg.BuildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificates")
}
