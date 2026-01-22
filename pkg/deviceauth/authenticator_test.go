package deviceauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNoneAuthenticator(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	auth, err := NewNoneAuthenticator(logger,
		WithDeviceID("test-device"),
		WithSerial("TEST-SERIAL-123"),
		WithMAC("00:11:22:33:44:55"),
	)
	if err != nil {
		t.Fatalf("Failed to create NoneAuthenticator: %v", err)
	}
	defer auth.Close()

	// Test Mode
	if auth.Mode() != AuthModeNone {
		t.Errorf("Expected mode %s, got %s", AuthModeNone, auth.Mode())
	}

	// Test Identity
	identity := auth.Identity()
	if identity == nil {
		t.Fatal("Identity should not be nil")
	}
	if identity.DeviceID != "test-device" {
		t.Errorf("Expected device ID 'test-device', got '%s'", identity.DeviceID)
	}
	if identity.Serial != "TEST-SERIAL-123" {
		t.Errorf("Expected serial 'TEST-SERIAL-123', got '%s'", identity.Serial)
	}
	if identity.MAC != "00:11:22:33:44:55" {
		t.Errorf("Expected MAC '00:11:22:33:44:55', got '%s'", identity.MAC)
	}

	// Test Authenticate (should always succeed for None mode)
	result, err := auth.Authenticate()
	if err != nil {
		t.Fatalf("Authenticate should not return error: %v", err)
	}
	if !result.Success {
		t.Error("Authenticate should always succeed for NoneAuthenticator")
	}
	if result.DeviceID != "test-device" {
		t.Errorf("Expected device ID 'test-device' in result, got '%s'", result.DeviceID)
	}

	// Test GetHTTPHeaders
	headers := auth.GetHTTPHeaders()
	if headers["X-Device-ID"] != "test-device" {
		t.Errorf("Expected X-Device-ID header 'test-device', got '%s'", headers["X-Device-ID"])
	}
	if headers["X-Device-Serial"] != "TEST-SERIAL-123" {
		t.Errorf("Expected X-Device-Serial header 'TEST-SERIAL-123', got '%s'", headers["X-Device-Serial"])
	}

	// Test GetTLSConfig
	tlsConfig := auth.GetTLSConfig()
	if tlsConfig == nil {
		t.Error("TLSConfig should not be nil")
	}
}

func TestPSKAuthenticator(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create a temp file for PSK
	tmpDir := t.TempDir()
	pskFile := filepath.Join(tmpDir, "device.psk")
	if err := os.WriteFile(pskFile, []byte("my-secret-psk-key-123"), 0600); err != nil {
		t.Fatalf("Failed to write PSK file: %v", err)
	}

	t.Run("with inline key", func(t *testing.T) {
		config := &PSKConfig{
			Key: "my-inline-psk-key-123",
		}

		auth, err := NewPSKAuthenticator(config, logger,
			WithDeviceID("psk-device"),
		)
		if err != nil {
			t.Fatalf("Failed to create PSKAuthenticator: %v", err)
		}
		defer auth.Close()

		if auth.Mode() != AuthModePSK {
			t.Errorf("Expected mode %s, got %s", AuthModePSK, auth.Mode())
		}

		result, err := auth.Authenticate()
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}
		if !result.Success {
			t.Error("Authentication should succeed")
		}
	})

	t.Run("with key file", func(t *testing.T) {
		config := &PSKConfig{
			KeyFile: pskFile,
		}

		auth, err := NewPSKAuthenticator(config, logger,
			WithSerial("PSK-SERIAL"),
		)
		if err != nil {
			t.Fatalf("Failed to create PSKAuthenticator: %v", err)
		}
		defer auth.Close()

		identity := auth.Identity()
		if identity == nil {
			t.Fatal("Identity should not be nil")
		}
		// Device ID should be derived from serial
		if identity.DeviceID != "device-PSK-SERIAL" {
			t.Errorf("Expected device ID derived from serial, got '%s'", identity.DeviceID)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		config := &PSKConfig{}

		_, err := NewPSKAuthenticator(config, logger)
		if err == nil {
			t.Error("Expected error for missing PSK")
		}
	})

	t.Run("signature verification", func(t *testing.T) {
		config := &PSKConfig{
			Key: "verification-test-key",
		}

		auth, err := NewPSKAuthenticator(config, logger,
			WithDeviceID("verify-device"),
		)
		if err != nil {
			t.Fatalf("Failed to create PSKAuthenticator: %v", err)
		}
		defer auth.Close()

		// Get headers (which include signature)
		headers := auth.GetHTTPHeaders()
		deviceID := headers["X-Device-ID"]
		timestamp := headers[PSKTimestampHeader]
		signature := headers[PSKSignatureHeader]

		// Verify the signature
		err = auth.VerifySignature(deviceID, timestamp, signature)
		if err != nil {
			t.Errorf("Signature verification failed: %v", err)
		}

		// Test with wrong signature
		err = auth.VerifySignature(deviceID, timestamp, "wrong-signature")
		if err == nil {
			t.Error("Expected error for wrong signature")
		}

		// Test with old timestamp
		oldTime := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
		err = auth.VerifySignature(deviceID, oldTime, signature)
		if err == nil {
			t.Error("Expected error for old timestamp")
		}
	})
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "none mode - valid",
			config:  Config{Mode: AuthModeNone},
			wantErr: false,
		},
		{
			name: "psk mode - valid with key",
			config: Config{
				Mode: AuthModePSK,
				PSK:  &PSKConfig{Key: "test-key"},
			},
			wantErr: false,
		},
		{
			name: "psk mode - valid with key file",
			config: Config{
				Mode: AuthModePSK,
				PSK:  &PSKConfig{KeyFile: "/path/to/key"},
			},
			wantErr: false,
		},
		{
			name: "psk mode - missing config",
			config: Config{
				Mode: AuthModePSK,
			},
			wantErr: true,
		},
		{
			name: "psk mode - missing key",
			config: Config{
				Mode: AuthModePSK,
				PSK:  &PSKConfig{},
			},
			wantErr: true,
		},
		{
			name: "mtls mode - valid",
			config: Config{
				Mode: AuthModeMTLS,
				MTLS: &MTLSConfig{
					CertFile: "/path/to/cert",
					KeyFile:  "/path/to/key",
					CAFile:   "/path/to/ca",
				},
			},
			wantErr: false,
		},
		{
			name: "mtls mode - missing config",
			config: Config{
				Mode: AuthModeMTLS,
			},
			wantErr: true,
		},
		{
			name: "mtls mode - missing cert",
			config: Config{
				Mode: AuthModeMTLS,
				MTLS: &MTLSConfig{
					KeyFile: "/path/to/key",
					CAFile:  "/path/to/ca",
				},
			},
			wantErr: true,
		},
		{
			name: "mtls mode - missing key",
			config: Config{
				Mode: AuthModeMTLS,
				MTLS: &MTLSConfig{
					CertFile: "/path/to/cert",
					CAFile:   "/path/to/ca",
				},
			},
			wantErr: true,
		},
		{
			name: "mtls mode - missing ca (allowed with insecure)",
			config: Config{
				Mode: AuthModeMTLS,
				MTLS: &MTLSConfig{
					CertFile:           "/path/to/cert",
					KeyFile:            "/path/to/key",
					InsecureSkipVerify: true,
				},
			},
			wantErr: false,
		},
		{
			name: "tpm mode - not implemented",
			config: Config{
				Mode: AuthModeTPM,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewAuthenticator(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("none mode", func(t *testing.T) {
		config := Config{Mode: AuthModeNone}
		auth, err := NewAuthenticator(config, logger)
		if err != nil {
			t.Fatalf("NewAuthenticator failed: %v", err)
		}
		defer auth.Close()

		if auth.Mode() != AuthModeNone {
			t.Errorf("Expected mode %s, got %s", AuthModeNone, auth.Mode())
		}
	})

	t.Run("psk mode", func(t *testing.T) {
		config := Config{
			Mode: AuthModePSK,
			PSK:  &PSKConfig{Key: "test-key-1234567"},
		}
		auth, err := NewAuthenticator(config, logger)
		if err != nil {
			t.Fatalf("NewAuthenticator failed: %v", err)
		}
		defer auth.Close()

		if auth.Mode() != AuthModePSK {
			t.Errorf("Expected mode %s, got %s", AuthModePSK, auth.Mode())
		}
	})
}

// Helper function to generate test certificates
func generateTestCert(t *testing.T, tmpDir string) (certFile, keyFile, caFile string) {
	t.Helper()

	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Generate CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	// Generate device key
	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate device key: %v", err)
	}

	// Generate device certificate
	deviceTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-device"},
		DNSNames:     []string{"test-device"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	caCert, _ := x509.ParseCertificate(caCertDER)
	deviceCertDER, err := x509.CreateCertificate(rand.Reader, deviceTemplate, caCert, &deviceKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create device certificate: %v", err)
	}

	// Write CA cert
	caFile = filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}

	// Write device cert
	certFile = filepath.Join(tmpDir, "device.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: deviceCertDER})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write device cert: %v", err)
	}

	// Write device key
	keyFile = filepath.Join(tmpDir, "device-key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(deviceKey)})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write device key: %v", err)
	}

	return certFile, keyFile, caFile
}

func TestMTLSAuthenticator(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	tmpDir := t.TempDir()

	certFile, keyFile, caFile := generateTestCert(t, tmpDir)

	t.Run("valid config", func(t *testing.T) {
		config := &MTLSConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		}

		auth, err := NewMTLSAuthenticator(config, logger)
		if err != nil {
			t.Fatalf("Failed to create MTLSAuthenticator: %v", err)
		}
		defer auth.Close()

		if auth.Mode() != AuthModeMTLS {
			t.Errorf("Expected mode %s, got %s", AuthModeMTLS, auth.Mode())
		}

		// Test identity extraction
		identity := auth.Identity()
		if identity == nil {
			t.Fatal("Identity should not be nil")
		}
		if identity.DeviceID != "test-device" {
			t.Errorf("Expected device ID 'test-device', got '%s'", identity.DeviceID)
		}

		// Test authentication
		result, err := auth.Authenticate()
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}
		if !result.Success {
			t.Error("Authentication should succeed")
		}

		// Test TLS config
		tlsConfig := auth.GetTLSConfig()
		if tlsConfig == nil {
			t.Fatal("TLSConfig should not be nil")
		}
		if len(tlsConfig.Certificates) == 0 {
			t.Error("TLSConfig should have certificates")
		}

		// Test HTTP headers
		headers := auth.GetHTTPHeaders()
		if headers["X-Device-ID"] != "test-device" {
			t.Errorf("Expected X-Device-ID 'test-device', got '%s'", headers["X-Device-ID"])
		}
	})

	t.Run("certificate expiry check", func(t *testing.T) {
		config := &MTLSConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		}

		auth, err := NewMTLSAuthenticator(config, logger)
		if err != nil {
			t.Fatalf("Failed to create MTLSAuthenticator: %v", err)
		}
		defer auth.Close()

		// Certificate expires within 48 hours (our test cert is 24h)
		if !auth.CertificateExpiresWithin(48 * time.Hour) {
			t.Error("Certificate should expire within 48 hours")
		}

		// Certificate doesn't expire within 1 hour
		if auth.CertificateExpiresWithin(1 * time.Hour) {
			t.Error("Certificate should not expire within 1 hour")
		}
	})

	t.Run("missing cert file", func(t *testing.T) {
		config := &MTLSConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  keyFile,
			CAFile:   caFile,
		}

		_, err := NewMTLSAuthenticator(config, logger)
		if err == nil {
			t.Error("Expected error for missing cert file")
		}
	})

	t.Run("missing key file", func(t *testing.T) {
		config := &MTLSConfig{
			CertFile: certFile,
			KeyFile:  "/nonexistent/key.pem",
			CAFile:   caFile,
		}

		_, err := NewMTLSAuthenticator(config, logger)
		if err == nil {
			t.Error("Expected error for missing key file")
		}
	})
}

func TestReadDeviceIdentity(t *testing.T) {
	// This test may not work on all systems, but should not panic
	identity, err := ReadDeviceIdentity()
	if err != nil {
		// Expected on systems without DMI info
		t.Logf("ReadDeviceIdentity returned error (expected on some systems): %v", err)
	}
	if identity == nil {
		t.Error("Identity should not be nil even on error")
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with-dash", "with-dash"},
		{"with_underscore", "with_underscore"},
		{"MixedCase123", "MixedCase123"},
		{"with spaces", "withspaces"},
		{"special!@#$%chars", "specialchars"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeID(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
