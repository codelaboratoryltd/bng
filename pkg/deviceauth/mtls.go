package deviceauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// MTLSAuthenticator implements device authentication using mutual TLS.
type MTLSAuthenticator struct {
	config  *MTLSConfig
	logger  *zap.Logger
	options authenticatorOptions

	mu          sync.RWMutex
	identity    *DeviceIdentity
	tlsConfig   *tls.Config
	certificate tls.Certificate
	certPool    *x509.CertPool

	// Certificate rotation
	ctx        context.Context
	cancel     context.CancelFunc
	rotationWg sync.WaitGroup
}

// NewMTLSAuthenticator creates a new mTLS authenticator.
func NewMTLSAuthenticator(config *MTLSConfig, logger *zap.Logger, opts ...AuthenticatorOption) (*MTLSAuthenticator, error) {
	if config == nil {
		return nil, fmt.Errorf("mTLS config is required")
	}

	// Apply options
	options := authenticatorOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.Background())

	auth := &MTLSAuthenticator{
		config:  config,
		logger:  logger,
		options: options,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Load certificates
	if err := auth.loadCertificates(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	// Build TLS config
	if err := auth.buildTLSConfig(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	// Extract identity from certificate
	if err := auth.extractIdentity(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to extract identity: %w", err)
	}

	// Start certificate rotation if enabled
	if config.CertificateRotation {
		auth.startRotationWatcher()
	}

	return auth, nil
}

// loadCertificates loads the device certificate, key, and CA bundle.
func (a *MTLSAuthenticator) loadCertificates() error {
	// Load device certificate and key
	cert, err := tls.LoadX509KeyPair(a.config.CertFile, a.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate/key pair: %w", err)
	}
	a.certificate = cert

	// Parse the certificate for later use
	if len(cert.Certificate) > 0 {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		// Store for identity extraction
		a.certificate.Leaf = parsed
	}

	// Load CA certificate pool
	a.certPool = x509.NewCertPool()
	if a.config.CAFile != "" {
		caData, err := os.ReadFile(a.config.CAFile)
		if err != nil {
			return fmt.Errorf("failed to read CA file: %w", err)
		}
		if !a.certPool.AppendCertsFromPEM(caData) {
			return fmt.Errorf("failed to parse CA certificates")
		}
	}

	a.logger.Info("Loaded mTLS certificates",
		zap.String("cert_file", a.config.CertFile),
		zap.String("ca_file", a.config.CAFile),
	)

	return nil
}

// buildTLSConfig creates the TLS configuration.
func (a *MTLSAuthenticator) buildTLSConfig() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Use provided TLS config as base, or create new one
	if a.options.tlsConfig != nil {
		a.tlsConfig = a.options.tlsConfig.Clone()
	} else {
		a.tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	// Set client certificate
	a.tlsConfig.Certificates = []tls.Certificate{a.certificate}

	// Set CA pool for server verification
	a.tlsConfig.RootCAs = a.certPool

	// Set server name if specified
	if a.config.ServerName != "" {
		a.tlsConfig.ServerName = a.config.ServerName
	}

	// Handle insecure mode (for testing only!)
	if a.config.InsecureSkipVerify {
		a.logger.Warn("TLS server verification disabled - THIS IS INSECURE!")
		a.tlsConfig.InsecureSkipVerify = true
	}

	return nil
}

// extractIdentity extracts device identity from the certificate.
func (a *MTLSAuthenticator) extractIdentity() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	cert := a.certificate.Leaf
	if cert == nil {
		return fmt.Errorf("no parsed certificate available")
	}

	// Extract device ID from certificate
	// Priority: explicit option > CN > first DNS SAN > serial number
	deviceID := a.options.deviceID
	if deviceID == "" {
		deviceID = cert.Subject.CommonName
	}
	if deviceID == "" && len(cert.DNSNames) > 0 {
		deviceID = cert.DNSNames[0]
	}
	if deviceID == "" {
		deviceID = cert.SerialNumber.String()
	}

	// Build identity
	a.identity = &DeviceIdentity{
		DeviceID:          deviceID,
		Serial:            a.options.serial,
		MAC:               a.options.mac,
		Certificate:       cert,
		CertificatePEM:    encodeCertPEM(cert.Raw),
		CertificateExpiry: cert.NotAfter,
		CreatedAt:         time.Now().UTC(),
	}

	a.logger.Info("Device identity established",
		zap.String("device_id", deviceID),
		zap.String("cert_serial", cert.SerialNumber.String()),
		zap.Time("cert_expiry", cert.NotAfter),
	)

	return nil
}

// Authenticate performs device authentication.
func (a *MTLSAuthenticator) Authenticate() (*AuthResult, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := &AuthResult{
		Mode:      AuthModeMTLS,
		Timestamp: time.Now().UTC(),
	}

	// Check if certificate is valid
	if a.identity == nil || a.identity.Certificate == nil {
		result.Error = "no valid certificate loaded"
		return result, fmt.Errorf("%s", result.Error)
	}

	// Check certificate expiry
	now := time.Now()
	cert := a.identity.Certificate
	if now.Before(cert.NotBefore) {
		result.Error = "certificate not yet valid"
		return result, fmt.Errorf("%s", result.Error)
	}
	if now.After(cert.NotAfter) {
		result.Error = "certificate expired"
		return result, fmt.Errorf("%s", result.Error)
	}

	// Certificate is valid
	result.Success = true
	result.DeviceID = a.identity.DeviceID

	a.logger.Debug("mTLS authentication successful",
		zap.String("device_id", result.DeviceID),
	)

	return result, nil
}

// GetTLSConfig returns the TLS configuration.
func (a *MTLSAuthenticator) GetTLSConfig() *tls.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.tlsConfig.Clone()
}

// GetHTTPHeaders returns additional HTTP headers for authentication.
func (a *MTLSAuthenticator) GetHTTPHeaders() map[string]string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	headers := make(map[string]string)
	if a.identity != nil {
		headers["X-Device-ID"] = a.identity.DeviceID
		if a.identity.Serial != "" {
			headers["X-Device-Serial"] = a.identity.Serial
		}
	}
	return headers
}

// Identity returns the current device identity.
func (a *MTLSAuthenticator) Identity() *DeviceIdentity {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.identity == nil {
		return nil
	}
	// Return a copy
	identCopy := *a.identity
	return &identCopy
}

// Mode returns the authentication mode.
func (a *MTLSAuthenticator) Mode() AuthMode {
	return AuthModeMTLS
}

// Close releases resources.
func (a *MTLSAuthenticator) Close() error {
	a.cancel()
	a.rotationWg.Wait()
	return nil
}

// startRotationWatcher starts the certificate rotation monitoring.
func (a *MTLSAuthenticator) startRotationWatcher() {
	interval := a.config.RotationCheckInterval
	if interval == 0 {
		interval = 24 * time.Hour // Default: check daily
	}

	threshold := a.config.RotationThreshold
	if threshold == 0 {
		threshold = 30 * 24 * time.Hour // Default: 30 days
	}

	a.rotationWg.Add(1)
	go func() {
		defer a.rotationWg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-a.ctx.Done():
				return
			case <-ticker.C:
				a.checkCertificateExpiry(threshold)
			}
		}
	}()

	a.logger.Info("Certificate rotation watcher started",
		zap.Duration("check_interval", interval),
		zap.Duration("renewal_threshold", threshold),
	)
}

// checkCertificateExpiry checks if the certificate needs renewal.
func (a *MTLSAuthenticator) checkCertificateExpiry(threshold time.Duration) {
	a.mu.RLock()
	cert := a.identity.Certificate
	a.mu.RUnlock()

	if cert == nil {
		return
	}

	timeUntilExpiry := time.Until(cert.NotAfter)
	if timeUntilExpiry < threshold {
		a.logger.Warn("Certificate approaching expiry",
			zap.Duration("time_until_expiry", timeUntilExpiry),
			zap.Time("expiry", cert.NotAfter),
		)
		// TODO: Trigger certificate renewal via Nexus
		// This would call a RenewCertificate method
	}
}

// ReloadCertificates reloads certificates from disk (for rotation).
func (a *MTLSAuthenticator) ReloadCertificates() error {
	if err := a.loadCertificates(); err != nil {
		return fmt.Errorf("failed to reload certificates: %w", err)
	}
	if err := a.buildTLSConfig(); err != nil {
		return fmt.Errorf("failed to rebuild TLS config: %w", err)
	}
	if err := a.extractIdentity(); err != nil {
		return fmt.Errorf("failed to re-extract identity: %w", err)
	}

	a.logger.Info("Certificates reloaded successfully")
	return nil
}

// GenerateCSR generates a Certificate Signing Request for renewal.
func (a *MTLSAuthenticator) GenerateCSR() ([]byte, error) {
	a.mu.RLock()
	identity := a.identity
	a.mu.RUnlock()

	if identity == nil {
		return nil, fmt.Errorf("no device identity available")
	}

	// Generate a new key pair for the CSR
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   identity.DeviceID,
			Organization: []string{"OLT-BNG"},
		},
		DNSNames: []string{identity.DeviceID},
	}

	// Create the CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Encode to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

// CertificateExpiresWithin returns true if the cert expires within duration.
func (a *MTLSAuthenticator) CertificateExpiresWithin(d time.Duration) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.identity == nil || a.identity.Certificate == nil {
		return true // No cert = needs renewal
	}

	return time.Until(a.identity.Certificate.NotAfter) < d
}

// Helper function to encode certificate to PEM.
func encodeCertPEM(certDER []byte) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	return string(pem.EncodeToMemory(block))
}
