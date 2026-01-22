package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCA creates a self-signed CA certificate for testing
func generateTestCA(t *testing.T) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM
}

func TestDefaultTLSConfig(t *testing.T) {
	cfg := DefaultTLSConfig()

	if !cfg.Enabled {
		t.Error("TLS should be enabled by default")
	}

	if cfg.MinVersion != "1.2" {
		t.Errorf("MinVersion = %s, want 1.2", cfg.MinVersion)
	}

	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
}

func TestBuildTLSConfig_Disabled(t *testing.T) {
	cfg := TLSConfig{Enabled: false}

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig failed: %v", err)
	}

	if tlsCfg != nil {
		t.Error("Expected nil TLS config when disabled")
	}
}

func TestBuildTLSConfig_Default(t *testing.T) {
	cfg := DefaultTLSConfig()

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig failed: %v", err)
	}

	if tlsCfg == nil {
		t.Fatal("Expected non-nil TLS config")
	}

	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", tlsCfg.MinVersion, tls.VersionTLS12)
	}

	if tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false")
	}
}

func TestBuildTLSConfig_TLS13(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		MinVersion: "1.3",
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig failed: %v", err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d", tlsCfg.MinVersion, tls.VersionTLS13)
	}
}

func TestBuildTLSConfig_InvalidMinVersion(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		MinVersion: "1.0",
	}

	_, err := cfg.BuildTLSConfig()
	if err == nil {
		t.Error("Expected error for invalid MinVersion")
	}
}

func TestBuildTLSConfig_InsecureSkipVerify(t *testing.T) {
	cfg := TLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig failed: %v", err)
	}

	if !tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestBuildTLSConfig_ServerName(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		ServerName: "nexus.example.com",
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig failed: %v", err)
	}

	if tlsCfg.ServerName != "nexus.example.com" {
		t.Errorf("ServerName = %s, want nexus.example.com", tlsCfg.ServerName)
	}
}

func TestBuildTLSConfig_CACertPEM(t *testing.T) {
	// Generate a valid test CA certificate
	testCACert := generateTestCA(t)

	cfg := TLSConfig{
		Enabled:   true,
		CACertPEM: string(testCACert),
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig failed: %v", err)
	}

	if tlsCfg.RootCAs == nil {
		t.Error("Expected RootCAs to be set")
	}
}

func TestBuildTLSConfig_CACertFile(t *testing.T) {
	// Generate a valid test CA certificate
	testCACert := generateTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caFile, testCACert, 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	cfg := TLSConfig{
		Enabled:    true,
		CACertFile: caFile,
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig failed: %v", err)
	}

	if tlsCfg.RootCAs == nil {
		t.Error("Expected RootCAs to be set")
	}
}

func TestBuildTLSConfig_PinnedCerts(t *testing.T) {
	cfg := TLSConfig{
		Enabled: true,
		PinnedCerts: []string{
			"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
	}

	tlsCfg, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig failed: %v", err)
	}

	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("Expected VerifyPeerCertificate to be set for pinning")
	}
}

func TestValidateTLSConfig_Valid(t *testing.T) {
	cfg := DefaultTLSConfig()

	if err := ValidateTLSConfig(cfg); err != nil {
		t.Errorf("ValidateTLSConfig failed: %v", err)
	}
}

func TestValidateTLSConfig_MismatchedCertKey(t *testing.T) {
	cfg := TLSConfig{
		Enabled:  true,
		CertFile: "/path/to/cert.pem",
		// KeyFile missing
	}

	err := ValidateTLSConfig(cfg)
	if err == nil {
		t.Error("Expected error for mismatched cert/key")
	}
}

func TestValidateTLSConfig_InvalidPinnedCert(t *testing.T) {
	tests := []struct {
		name   string
		pinned string
	}{
		{"too short", "abc123"},
		{"invalid hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := TLSConfig{
				Enabled:     true,
				PinnedCerts: []string{tt.pinned},
			}

			err := ValidateTLSConfig(cfg)
			if err == nil {
				t.Error("Expected error for invalid pinned cert")
			}
		})
	}
}

func TestValidateTLSConfig_Disabled(t *testing.T) {
	cfg := TLSConfig{Enabled: false}

	if err := ValidateTLSConfig(cfg); err != nil {
		t.Errorf("ValidateTLSConfig should pass for disabled config: %v", err)
	}
}
