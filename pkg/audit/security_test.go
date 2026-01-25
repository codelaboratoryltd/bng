package audit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// generateTestCert creates a test certificate for testing.
func generateTestCert(t *testing.T, notBefore, notAfter time.Time, isCA bool) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              []string{"test.example.com", "localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestExtractCertInfo(t *testing.T) {
	cert := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), false)

	info := audit.ExtractCertInfo(cert)
	require.NotNil(t, info)

	assert.Contains(t, info.Subject, "test.example.com")
	assert.Contains(t, info.Issuer, "test.example.com")
	assert.NotEmpty(t, info.Serial)
	assert.NotEmpty(t, info.Fingerprint)
	assert.Len(t, info.Fingerprint, 64) // SHA256 = 64 hex chars
	assert.False(t, info.NotBefore.IsZero())
	assert.False(t, info.NotAfter.IsZero())
	assert.Greater(t, info.DaysRemaining, 0)
	assert.Contains(t, info.DNSNames, "test.example.com")
	assert.False(t, info.IsCA)
}

func TestExtractCertInfo_Nil(t *testing.T) {
	info := audit.ExtractCertInfo(nil)
	assert.Nil(t, info)
}

func TestExtractCertInfo_ExpiredCert(t *testing.T) {
	cert := generateTestCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), false)

	info := audit.ExtractCertInfo(cert)
	require.NotNil(t, info)

	assert.Equal(t, 0, info.DaysRemaining)
}

func TestLogTLSHandshake_Success(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.DeviceID = "test-device"
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	tlsEvent := &audit.TLSEvent{
		TLSVersion:      "TLS 1.3",
		CipherSuite:     "TLS_AES_256_GCM_SHA384",
		ServerName:      "nexus.example.com",
		PeerAddress:     "192.168.1.100:443",
		CertSubject:     "CN=nexus.example.com",
		CertFingerprint: "abc123",
	}

	auditLogger.LogTLSHandshake(tlsEvent, true)

	// Query for the event
	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventTLSHandshakeSuccess},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, "TLS 1.3", events[0].TLSVersion)
	assert.Equal(t, "TLS_AES_256_GCM_SHA384", events[0].TLSCipherSuite)
	assert.Equal(t, "nexus.example.com", events[0].TLSServerName)
}

func TestLogTLSHandshake_Failure(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	tlsEvent := &audit.TLSEvent{
		PeerAddress:    "192.168.1.100:443",
		HandshakeError: "certificate expired",
	}

	auditLogger.LogTLSHandshake(tlsEvent, false)

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventTLSHandshakeFailure},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, "certificate expired", events[0].TLSError)
}

func TestLogCertificateExpiring(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	cert := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(15*24*time.Hour), false)
	certInfo := audit.ExtractCertInfo(cert)

	auditLogger.LogCertificateExpiring(certInfo, "nexus_client")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventCertificateExpiring},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Contains(t, events[0].CertSubject, "test.example.com")
	assert.Equal(t, "nexus_client", events[0].Metadata["source"])
}

func TestLogCertificateExpired(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	cert := generateTestCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), false)
	certInfo := audit.ExtractCertInfo(cert)

	auditLogger.LogCertificateExpired(certInfo, "device_cert")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventCertificateExpired},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, 0, events[0].CertDaysRemaining)
}

func TestLogCertificateInvalid(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	cert := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), false)
	certInfo := audit.ExtractCertInfo(cert)

	auditLogger.LogCertificateInvalid(certInfo, "hostname mismatch")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventCertificateInvalid},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Contains(t, events[0].ErrorMessage, "hostname mismatch")
}

func TestLogCertificatePinFailed(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	cert := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), false)
	certInfo := audit.ExtractCertInfo(cert)

	expectedPins := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"1111111111111111111111111111111111111111111111111111111111111111",
	}

	auditLogger.LogCertificatePinFailed(certInfo, expectedPins, "192.168.1.100:443")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventCertificatePinFailed},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, "certificate_pin_mismatch", events[0].ThreatType)
	assert.Equal(t, 90, events[0].ThreatScore)
	assert.Equal(t, "192.168.1.100:443", events[0].PeerAddress)
}

func TestLogCertificateRenewed(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	oldCert := generateTestCert(t, time.Now().Add(-365*24*time.Hour), time.Now().Add(-time.Hour), false)
	newCert := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), false)

	oldInfo := audit.ExtractCertInfo(oldCert)
	newInfo := audit.ExtractCertInfo(newCert)

	auditLogger.LogCertificateRenewed(oldInfo, newInfo)

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventCertificateRenewed},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.NotEmpty(t, events[0].Metadata["old_fingerprint"])
	assert.NotEmpty(t, events[0].CertFingerprint)
}

func TestLogMTLSAuth_Success(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	cert := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), false)
	certInfo := audit.ExtractCertInfo(cert)

	auditLogger.LogMTLSAuth(certInfo, true, "192.168.1.50:12345", "")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventMTLSAuthSuccess},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, "mTLS", events[0].AuthMethod)
	assert.Equal(t, "192.168.1.50:12345", events[0].PeerAddress)
}

func TestLogMTLSAuth_Failure(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	cert := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), false)
	certInfo := audit.ExtractCertInfo(cert)

	auditLogger.LogMTLSAuth(certInfo, false, "192.168.1.50:12345", "client certificate not trusted")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventMTLSAuthFailure},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Contains(t, events[0].AuthReason, "not trusted")
}

func TestLogZTPStart(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	auditLogger.LogZTPStart("eth0")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventZTPBootstrapStart},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, "eth0", events[0].ZTPInterface)
	assert.Equal(t, "dhcp", events[0].Metadata["stage"])
}

func TestLogZTPSuccess(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	auditLogger.LogZTPSuccess("eth0", "https://nexus.example.com:9000")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventZTPBootstrapSuccess},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, "eth0", events[0].ZTPInterface)
	assert.Equal(t, "https://nexus.example.com:9000", events[0].ZTPNexusURL)
}

func TestLogZTPFailure(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	auditLogger.LogZTPFailure("eth0", "tls", "certificate validation failed")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventZTPBootstrapFailure},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, "tls", events[0].Metadata["stage"])
	assert.Contains(t, events[0].ErrorMessage, "certificate validation failed")
}

func TestLogZTPConfigReceived(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	auditLogger.LogZTPConfigReceived("eth0", "https://nexus.example.com:9000", "sha256:abc123")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventZTPConfigReceived},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, "sha256:abc123", events[0].ZTPConfigHash)
}

func TestLogZTPConfigRejected(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	auditLogger.LogZTPConfigRejected("eth0", "https://nexus.example.com:9000", "signature verification failed")

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventZTPConfigRejected},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Contains(t, events[0].ErrorMessage, "signature verification failed")
}

func TestSecurityAlert(t *testing.T) {
	logger := zap.NewNop()
	config := audit.DefaultConfig()
	config.SyncWrites = true

	storage := audit.NewMemoryStorage()
	auditLogger := audit.NewLogger(config, storage, logger)

	require.NoError(t, auditLogger.Start())
	defer auditLogger.Stop()

	auditLogger.SecurityAlert(
		audit.EventSuspiciousActivity,
		"repeated_auth_failures",
		75,
		map[string]string{
			"source_ip":     "192.168.1.100",
			"failure_count": "15",
		},
	)

	events, err := storage.Query(context.Background(), &audit.Query{
		Types: []audit.EventType{audit.EventSuspiciousActivity},
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, "repeated_auth_failures", events[0].ThreatType)
	assert.Equal(t, 75, events[0].ThreatScore)
	assert.Equal(t, "192.168.1.100", events[0].Metadata["source_ip"])
}

func TestTLSEventTypes_Category(t *testing.T) {
	tlsEvents := []audit.EventType{
		audit.EventTLSHandshakeSuccess,
		audit.EventTLSHandshakeFailure,
		audit.EventCertificateExpiring,
		audit.EventCertificateExpired,
		audit.EventCertificateInvalid,
		audit.EventCertificatePinFailed,
		audit.EventCertificateRenewed,
		audit.EventCertificateRevoked,
		audit.EventMTLSAuthSuccess,
		audit.EventMTLSAuthFailure,
	}

	for _, et := range tlsEvents {
		assert.Equal(t, "tls", et.Category(), "Event %s should be in 'tls' category", et)
	}
}

func TestZTPEventTypes_Category(t *testing.T) {
	ztpEvents := []audit.EventType{
		audit.EventZTPBootstrapStart,
		audit.EventZTPBootstrapSuccess,
		audit.EventZTPBootstrapFailure,
		audit.EventZTPConfigReceived,
		audit.EventZTPConfigRejected,
	}

	for _, et := range ztpEvents {
		assert.Equal(t, "ztp", et.Category(), "Event %s should be in 'ztp' category", et)
	}
}

func TestTLSEventTypes_Severity(t *testing.T) {
	tests := []struct {
		eventType        audit.EventType
		expectedSeverity audit.Severity
	}{
		{audit.EventTLSHandshakeSuccess, audit.SeverityInfo},
		{audit.EventTLSHandshakeFailure, audit.SeverityWarning},
		{audit.EventCertificateExpiring, audit.SeverityWarning},
		{audit.EventCertificateExpired, audit.SeverityError},
		{audit.EventCertificateInvalid, audit.SeverityError},
		{audit.EventCertificatePinFailed, audit.SeverityCritical},
		{audit.EventCertificateRenewed, audit.SeverityInfo},
		{audit.EventCertificateRevoked, audit.SeverityCritical},
		{audit.EventMTLSAuthSuccess, audit.SeverityInfo},
		{audit.EventMTLSAuthFailure, audit.SeverityWarning},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expectedSeverity, tt.eventType.GetSeverity(),
			"Event %s should have severity %s", tt.eventType, tt.expectedSeverity)
	}
}
