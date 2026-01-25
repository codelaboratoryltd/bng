package audit

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"
)

// TLSEvent represents a TLS/certificate-related audit event.
type TLSEvent struct {
	Event

	// TLS connection details
	TLSVersion     string `json:"tls_version,omitempty"`
	CipherSuite    string `json:"cipher_suite,omitempty"`
	ServerName     string `json:"server_name,omitempty"`
	PeerAddress    string `json:"peer_address,omitempty"`
	HandshakeError string `json:"handshake_error,omitempty"`

	// Certificate details (for the peer certificate)
	CertSubject       string    `json:"cert_subject,omitempty"`
	CertIssuer        string    `json:"cert_issuer,omitempty"`
	CertSerial        string    `json:"cert_serial,omitempty"`
	CertFingerprint   string    `json:"cert_fingerprint,omitempty"`
	CertNotBefore     time.Time `json:"cert_not_before,omitempty"`
	CertNotAfter      time.Time `json:"cert_not_after,omitempty"`
	CertDaysRemaining int       `json:"cert_days_remaining,omitempty"`
	CertDNSNames      []string  `json:"cert_dns_names,omitempty"`

	// Chain validation
	ChainLength int    `json:"chain_length,omitempty"`
	ChainValid  bool   `json:"chain_valid,omitempty"`
	ChainError  string `json:"chain_error,omitempty"`
}

// ZTPEvent represents a ZTP-related audit event.
type ZTPEvent struct {
	Event

	// ZTP details
	Interface  string `json:"interface,omitempty"`
	NexusURL   string `json:"nexus_url,omitempty"`
	ConfigHash string `json:"config_hash,omitempty"`
	Stage      string `json:"stage,omitempty"` // "dhcp", "tls", "config", "complete"
}

// CertificateInfo extracts audit information from an x509 certificate.
type CertificateInfo struct {
	Subject       string
	Issuer        string
	Serial        string
	Fingerprint   string
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int
	DNSNames      []string
	IsCA          bool
	KeyUsage      x509.KeyUsage
}

// ExtractCertInfo extracts audit-relevant information from a certificate.
func ExtractCertInfo(cert *x509.Certificate) *CertificateInfo {
	if cert == nil {
		return nil
	}

	fingerprint := sha256.Sum256(cert.Raw)
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysRemaining < 0 {
		daysRemaining = 0
	}

	return &CertificateInfo{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		Serial:        cert.SerialNumber.String(),
		Fingerprint:   hex.EncodeToString(fingerprint[:]),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		DaysRemaining: daysRemaining,
		DNSNames:      cert.DNSNames,
		IsCA:          cert.IsCA,
		KeyUsage:      cert.KeyUsage,
	}
}

// LogTLSHandshake logs a TLS handshake event.
func (l *Logger) LogTLSHandshake(tlsEvent *TLSEvent, success bool) {
	// Create a copy of the event to avoid ID reuse
	event := tlsEvent.Event
	event.ID = "" // Clear ID so a new one is generated

	if success {
		event.Type = EventTLSHandshakeSuccess
	} else {
		event.Type = EventTLSHandshakeFailure
	}

	// Copy TLS-specific fields to the event
	event.TLSVersion = tlsEvent.TLSVersion
	event.TLSCipherSuite = tlsEvent.CipherSuite
	event.TLSServerName = tlsEvent.ServerName
	event.PeerAddress = tlsEvent.PeerAddress
	event.TLSError = tlsEvent.HandshakeError
	event.CertSubject = tlsEvent.CertSubject
	event.CertIssuer = tlsEvent.CertIssuer
	event.CertSerial = tlsEvent.CertSerial
	event.CertFingerprint = tlsEvent.CertFingerprint
	event.CertNotBefore = tlsEvent.CertNotBefore
	event.CertNotAfter = tlsEvent.CertNotAfter
	event.CertDaysRemaining = tlsEvent.CertDaysRemaining

	l.LogEvent(&event)
}

// LogCertificateExpiring logs a certificate expiration warning event.
func (l *Logger) LogCertificateExpiring(certInfo *CertificateInfo, source string) {
	event := &Event{
		Type:              EventCertificateExpiring,
		CertSubject:       certInfo.Subject,
		CertIssuer:        certInfo.Issuer,
		CertSerial:        certInfo.Serial,
		CertFingerprint:   certInfo.Fingerprint,
		CertNotBefore:     certInfo.NotBefore,
		CertNotAfter:      certInfo.NotAfter,
		CertDaysRemaining: certInfo.DaysRemaining,
		Metadata: map[string]string{
			"source": source,
		},
	}
	l.LogEvent(event)
}

// LogCertificateExpired logs a certificate expiration event.
func (l *Logger) LogCertificateExpired(certInfo *CertificateInfo, source string) {
	event := &Event{
		Type:              EventCertificateExpired,
		CertSubject:       certInfo.Subject,
		CertIssuer:        certInfo.Issuer,
		CertSerial:        certInfo.Serial,
		CertFingerprint:   certInfo.Fingerprint,
		CertNotBefore:     certInfo.NotBefore,
		CertNotAfter:      certInfo.NotAfter,
		CertDaysRemaining: 0,
		Metadata: map[string]string{
			"source": source,
		},
	}
	l.LogEvent(event)
}

// LogCertificateInvalid logs a certificate validation failure event.
func (l *Logger) LogCertificateInvalid(certInfo *CertificateInfo, reason string) {
	event := &Event{
		Type:         EventCertificateInvalid,
		ErrorMessage: reason,
		Metadata: map[string]string{
			"reason": reason,
		},
	}
	if certInfo != nil {
		event.CertSubject = certInfo.Subject
		event.CertIssuer = certInfo.Issuer
		event.CertSerial = certInfo.Serial
		event.CertFingerprint = certInfo.Fingerprint
		event.CertNotBefore = certInfo.NotBefore
		event.CertNotAfter = certInfo.NotAfter
	}
	l.LogEvent(event)
}

// LogCertificatePinFailed logs a certificate pinning failure event.
func (l *Logger) LogCertificatePinFailed(certInfo *CertificateInfo, expectedFingerprints []string, peerAddress string) {
	event := &Event{
		Type:        EventCertificatePinFailed,
		PeerAddress: peerAddress,
		ThreatType:  "certificate_pin_mismatch",
		ThreatScore: 90, // High threat score for pin failure
	}
	if certInfo != nil {
		event.CertSubject = certInfo.Subject
		event.CertFingerprint = certInfo.Fingerprint
	}
	event.Metadata = map[string]string{
		"actual_fingerprint": event.CertFingerprint,
	}
	// Add expected fingerprints to metadata
	for i, fp := range expectedFingerprints {
		if i < 5 { // Limit to first 5 expected fingerprints
			event.Metadata["expected_fingerprint_"+string(rune('0'+i))] = fp
		}
	}
	l.LogEvent(event)
}

// LogCertificateRenewed logs a successful certificate renewal event.
func (l *Logger) LogCertificateRenewed(oldCert, newCert *CertificateInfo) {
	event := &Event{
		Type:              EventCertificateRenewed,
		CertSubject:       newCert.Subject,
		CertIssuer:        newCert.Issuer,
		CertSerial:        newCert.Serial,
		CertFingerprint:   newCert.Fingerprint,
		CertNotBefore:     newCert.NotBefore,
		CertNotAfter:      newCert.NotAfter,
		CertDaysRemaining: newCert.DaysRemaining,
		Metadata:          map[string]string{},
	}
	if oldCert != nil {
		event.Metadata["old_fingerprint"] = oldCert.Fingerprint
		event.Metadata["old_serial"] = oldCert.Serial
		event.Metadata["old_expiry"] = oldCert.NotAfter.Format(time.RFC3339)
	}
	l.LogEvent(event)
}

// LogMTLSAuth logs an mTLS authentication event.
func (l *Logger) LogMTLSAuth(certInfo *CertificateInfo, success bool, peerAddress string, reason string) {
	event := &Event{
		PeerAddress: peerAddress,
		AuthMethod:  "mTLS",
	}
	if success {
		event.Type = EventMTLSAuthSuccess
	} else {
		event.Type = EventMTLSAuthFailure
		event.AuthReason = reason
		event.ErrorMessage = reason
	}
	if certInfo != nil {
		event.CertSubject = certInfo.Subject
		event.CertIssuer = certInfo.Issuer
		event.CertSerial = certInfo.Serial
		event.CertFingerprint = certInfo.Fingerprint
	}
	l.LogEvent(event)
}

// LogZTPBootstrap logs a ZTP bootstrap event.
func (l *Logger) LogZTPBootstrap(ztpEvent *ZTPEvent, eventType EventType) {
	// Create a copy of the event to avoid ID reuse
	event := ztpEvent.Event
	event.ID = "" // Clear ID so a new one is generated
	event.Type = eventType

	// Copy ZTP-specific fields
	event.ZTPInterface = ztpEvent.Interface
	event.ZTPNexusURL = ztpEvent.NexusURL
	event.ZTPConfigHash = ztpEvent.ConfigHash

	if ztpEvent.Stage != "" {
		if event.Metadata == nil {
			event.Metadata = make(map[string]string)
		}
		event.Metadata["stage"] = ztpEvent.Stage
	}

	l.LogEvent(&event)
}

// LogZTPStart logs the start of a ZTP bootstrap process.
func (l *Logger) LogZTPStart(iface string) {
	event := &Event{
		Type:         EventZTPBootstrapStart,
		ZTPInterface: iface,
		Metadata: map[string]string{
			"stage": "dhcp",
		},
	}
	l.LogEvent(event)
}

// LogZTPSuccess logs successful ZTP bootstrap completion.
func (l *Logger) LogZTPSuccess(iface, nexusURL string) {
	event := &Event{
		Type:         EventZTPBootstrapSuccess,
		ZTPInterface: iface,
		ZTPNexusURL:  nexusURL,
		Metadata: map[string]string{
			"stage": "complete",
		},
	}
	l.LogEvent(event)
}

// LogZTPFailure logs a ZTP bootstrap failure.
func (l *Logger) LogZTPFailure(iface, stage, reason string) {
	event := &Event{
		Type:         EventZTPBootstrapFailure,
		ZTPInterface: iface,
		ErrorMessage: reason,
		Metadata: map[string]string{
			"stage": stage,
		},
	}
	l.LogEvent(event)
}

// LogZTPConfigReceived logs reception of configuration via ZTP.
func (l *Logger) LogZTPConfigReceived(iface, nexusURL, configHash string) {
	event := &Event{
		Type:          EventZTPConfigReceived,
		ZTPInterface:  iface,
		ZTPNexusURL:   nexusURL,
		ZTPConfigHash: configHash,
		Metadata: map[string]string{
			"stage": "config",
		},
	}
	l.LogEvent(event)
}

// LogZTPConfigRejected logs rejection of configuration received via ZTP.
func (l *Logger) LogZTPConfigRejected(iface, nexusURL, reason string) {
	event := &Event{
		Type:         EventZTPConfigRejected,
		ZTPInterface: iface,
		ZTPNexusURL:  nexusURL,
		ErrorMessage: reason,
		Metadata: map[string]string{
			"stage":  "config",
			"reason": reason,
		},
	}
	l.LogEvent(event)
}

// SecurityAlert creates a high-severity security alert event.
func (l *Logger) SecurityAlert(eventType EventType, threatType string, threatScore int, details map[string]string) {
	event := &Event{
		Type:        eventType,
		ThreatType:  threatType,
		ThreatScore: threatScore,
		Metadata:    details,
	}
	l.LogEvent(event)
}
