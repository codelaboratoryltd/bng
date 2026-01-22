package deviceauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// DefaultPSKHeaderName is the default HTTP header for PSK transmission.
	DefaultPSKHeaderName = "X-Device-PSK"

	// PSKTimestampHeader contains the request timestamp for replay protection.
	PSKTimestampHeader = "X-Device-Timestamp"

	// PSKSignatureHeader contains the HMAC signature.
	PSKSignatureHeader = "X-Device-Signature"

	// MaxTimestampSkew is the maximum allowed time difference for requests.
	MaxTimestampSkew = 5 * time.Minute
)

// PSKAuthenticator implements device authentication using pre-shared keys.
// While simpler than mTLS, it provides reasonable security for dev/test
// environments when combined with HTTPS transport.
type PSKAuthenticator struct {
	config  *PSKConfig
	logger  *zap.Logger
	options authenticatorOptions

	mu       sync.RWMutex
	identity *DeviceIdentity
	psk      []byte
}

// NewPSKAuthenticator creates a new PSK authenticator.
func NewPSKAuthenticator(config *PSKConfig, logger *zap.Logger, opts ...AuthenticatorOption) (*PSKAuthenticator, error) {
	if config == nil {
		return nil, fmt.Errorf("PSK config is required")
	}

	// Apply options
	options := authenticatorOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	auth := &PSKAuthenticator{
		config:  config,
		logger:  logger,
		options: options,
	}

	// Load PSK
	if err := auth.loadPSK(); err != nil {
		return nil, fmt.Errorf("failed to load PSK: %w", err)
	}

	// Build identity
	auth.buildIdentity()

	return auth, nil
}

// loadPSK loads the pre-shared key from config or file.
func (a *PSKAuthenticator) loadPSK() error {
	var psk string

	// Try loading from file first
	if a.config.KeyFile != "" {
		data, err := os.ReadFile(a.config.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to read PSK file: %w", err)
		}
		psk = strings.TrimSpace(string(data))
	} else {
		psk = a.config.Key
	}

	if psk == "" {
		return fmt.Errorf("PSK is required")
	}

	// Validate PSK minimum length.
	// We warn instead of erroring for PSKs < 16 chars to maintain backwards
	// compatibility and allow for dev/test scenarios with simpler keys.
	// For production use, RotatePSK() enforces the 16-char minimum.
	// Consider using mTLS (AuthModeMTLS) for production deployments.
	if len(psk) < 16 {
		a.logger.Warn("PSK is shorter than recommended 16 characters",
			zap.Int("length", len(psk)),
			zap.String("recommendation", "use at least 16 characters for production"))
	}

	a.psk = []byte(psk)

	a.logger.Info("PSK loaded",
		zap.Int("length", len(psk)),
		zap.Bool("from_file", a.config.KeyFile != ""),
	)

	return nil
}

// buildIdentity constructs the device identity for PSK mode.
func (a *PSKAuthenticator) buildIdentity() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Generate device ID from options or derive from PSK hash
	deviceID := a.options.deviceID
	if deviceID == "" && a.options.serial != "" {
		deviceID = "device-" + a.options.serial
	}
	if deviceID == "" && a.options.mac != "" {
		// Derive from MAC address
		deviceID = "device-" + strings.ReplaceAll(a.options.mac, ":", "")
	}
	if deviceID == "" {
		// Derive from PSK hash as last resort
		h := sha256.Sum256(a.psk)
		deviceID = "device-" + hex.EncodeToString(h[:8])
	}

	a.identity = &DeviceIdentity{
		DeviceID:  deviceID,
		Serial:    a.options.serial,
		MAC:       a.options.mac,
		CreatedAt: time.Now().UTC(),
	}

	a.logger.Info("PSK device identity established",
		zap.String("device_id", deviceID),
	)
}

// Authenticate performs device authentication.
func (a *PSKAuthenticator) Authenticate() (*AuthResult, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := &AuthResult{
		Mode:      AuthModePSK,
		Timestamp: time.Now().UTC(),
	}

	// Check if PSK is loaded
	if len(a.psk) == 0 {
		result.Error = "no PSK configured"
		return result, fmt.Errorf("%s", result.Error)
	}

	// Check if identity is available
	if a.identity == nil {
		result.Error = "no device identity"
		return result, fmt.Errorf("%s", result.Error)
	}

	// PSK is valid
	result.Success = true
	result.DeviceID = a.identity.DeviceID

	a.logger.Debug("PSK authentication successful",
		zap.String("device_id", result.DeviceID),
	)

	return result, nil
}

// GetTLSConfig returns nil as PSK doesn't use client certificates.
// The connection should still use HTTPS with server verification.
func (a *PSKAuthenticator) GetTLSConfig() *tls.Config {
	// Return a basic TLS config for server verification
	if a.options.tlsConfig != nil {
		return a.options.tlsConfig.Clone()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// GetHTTPHeaders returns the authentication headers for requests.
func (a *PSKAuthenticator) GetHTTPHeaders() map[string]string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	headers := make(map[string]string)

	// Add device identity headers
	if a.identity != nil {
		headers["X-Device-ID"] = a.identity.DeviceID
		if a.identity.Serial != "" {
			headers["X-Device-Serial"] = a.identity.Serial
		}
		if a.identity.MAC != "" {
			headers["X-Device-MAC"] = a.identity.MAC
		}
	}

	// Add timestamp for replay protection
	timestamp := time.Now().UTC().Format(time.RFC3339)
	headers[PSKTimestampHeader] = timestamp

	// Generate HMAC signature over device ID and timestamp
	message := fmt.Sprintf("%s:%s", a.identity.DeviceID, timestamp)
	signature := a.signMessage(message)
	headers[PSKSignatureHeader] = signature

	// Use configured header name or default
	headerName := a.config.HeaderName
	if headerName == "" {
		headerName = DefaultPSKHeaderName
	}
	// Don't send raw PSK - send signature instead
	// The server should derive the same signature using shared PSK

	return headers
}

// Identity returns the current device identity.
func (a *PSKAuthenticator) Identity() *DeviceIdentity {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.identity == nil {
		return nil
	}
	identCopy := *a.identity
	return &identCopy
}

// Mode returns the authentication mode.
func (a *PSKAuthenticator) Mode() AuthMode {
	return AuthModePSK
}

// Close releases resources.
func (a *PSKAuthenticator) Close() error {
	// Clear PSK from memory
	a.mu.Lock()
	for i := range a.psk {
		a.psk[i] = 0
	}
	a.psk = nil
	a.mu.Unlock()
	return nil
}

// signMessage creates an HMAC-SHA256 signature.
func (a *PSKAuthenticator) signMessage(message string) string {
	mac := hmac.New(sha256.New, a.psk)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifies a signature from a request.
// This is used server-side to validate incoming requests.
func (a *PSKAuthenticator) VerifySignature(deviceID, timestamp, signature string) error {
	// Check timestamp freshness
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp format: %w", err)
	}

	skew := time.Since(ts)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxTimestampSkew {
		return fmt.Errorf("timestamp skew too large: %v", skew)
	}

	// Verify signature
	message := fmt.Sprintf("%s:%s", deviceID, timestamp)
	expectedSig := a.signMessage(message)

	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) != 1 {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

// RotatePSK rotates the pre-shared key.
func (a *PSKAuthenticator) RotatePSK(newPSK string) error {
	if len(newPSK) < 16 {
		return fmt.Errorf("new PSK must be at least 16 characters")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear old PSK
	for i := range a.psk {
		a.psk[i] = 0
	}

	// Set new PSK
	a.psk = []byte(newPSK)

	a.logger.Info("PSK rotated successfully")
	return nil
}
