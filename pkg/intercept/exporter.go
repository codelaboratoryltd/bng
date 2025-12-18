package intercept

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ETSIExporter exports intercept records using ETSI standard format.
type ETSIExporter struct {
	config ETSIExporterConfig
	logger *zap.Logger
	conn   net.Conn
	mu     sync.Mutex

	// Sequence numbers per LIID
	sequences map[string]uint64
}

// ETSIExporterConfig holds ETSI exporter configuration.
type ETSIExporterConfig struct {
	// Mediation device address
	Address string

	// TLS configuration
	UseTLS    bool
	TLSConfig *tls.Config
	CertFile  string
	KeyFile   string
	CAFile    string

	// Operator identification
	OperatorID  string
	CountryCode string

	// Connection settings
	ConnectTimeout time.Duration
	WriteTimeout   time.Duration
}

// DefaultETSIExporterConfig returns sensible defaults.
func DefaultETSIExporterConfig() ETSIExporterConfig {
	return ETSIExporterConfig{
		UseTLS:         true,
		ConnectTimeout: 30 * time.Second,
		WriteTimeout:   10 * time.Second,
		CountryCode:    "GB",
	}
}

// NewETSIExporter creates a new ETSI exporter.
func NewETSIExporter(config ETSIExporterConfig, logger *zap.Logger) (*ETSIExporter, error) {
	return &ETSIExporter{
		config:    config,
		logger:    logger,
		sequences: make(map[string]uint64),
	}, nil
}

// Name returns the exporter name.
func (e *ETSIExporter) Name() string {
	return "etsi"
}

// Connect establishes connection to the mediation device.
func (e *ETSIExporter) Connect() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var conn net.Conn
	var err error

	dialer := net.Dialer{Timeout: e.config.ConnectTimeout}

	if e.config.UseTLS {
		conn, err = tls.DialWithDialer(&dialer, "tcp", e.config.Address, e.config.TLSConfig)
	} else {
		conn, err = dialer.Dial("tcp", e.config.Address)
	}

	if err != nil {
		return fmt.Errorf("connect to mediation device: %w", err)
	}

	e.conn = conn

	e.logger.Info("Connected to mediation device",
		zap.String("address", e.config.Address),
		zap.Bool("tls", e.config.UseTLS),
	)

	return nil
}

// DeliverIRI delivers an IRI record via HI2.
func (e *ETSIExporter) DeliverIRI(ctx context.Context, record *InterceptRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn == nil {
		if err := e.connect(); err != nil {
			return err
		}
	}

	// Build ETSI HI2 PDU
	pdu := e.buildHI2PDU(record)

	// Set write deadline
	if e.config.WriteTimeout > 0 {
		e.conn.SetWriteDeadline(time.Now().Add(e.config.WriteTimeout))
	}

	if _, err := e.conn.Write(pdu); err != nil {
		e.conn = nil // Clear connection on error
		return fmt.Errorf("write HI2 PDU: %w", err)
	}

	return nil
}

// DeliverCC delivers a CC record via HI3.
func (e *ETSIExporter) DeliverCC(ctx context.Context, record *InterceptRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn == nil {
		if err := e.connect(); err != nil {
			return err
		}
	}

	// Build ETSI HI3 PDU
	pdu := e.buildHI3PDU(record)

	// Set write deadline
	if e.config.WriteTimeout > 0 {
		e.conn.SetWriteDeadline(time.Now().Add(e.config.WriteTimeout))
	}

	if _, err := e.conn.Write(pdu); err != nil {
		e.conn = nil // Clear connection on error
		return fmt.Errorf("write HI3 PDU: %w", err)
	}

	return nil
}

// Close closes the exporter connection.
func (e *ETSIExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn != nil {
		err := e.conn.Close()
		e.conn = nil
		return err
	}
	return nil
}

// connect establishes connection (must be called with mutex held).
func (e *ETSIExporter) connect() error {
	var conn net.Conn
	var err error

	dialer := net.Dialer{Timeout: e.config.ConnectTimeout}

	if e.config.UseTLS {
		conn, err = tls.DialWithDialer(&dialer, "tcp", e.config.Address, e.config.TLSConfig)
	} else {
		conn, err = dialer.Dial("tcp", e.config.Address)
	}

	if err != nil {
		return fmt.Errorf("connect to mediation device: %w", err)
	}

	e.conn = conn
	return nil
}

// buildHI2PDU builds an ETSI HI2 (IRI) PDU.
func (e *ETSIExporter) buildHI2PDU(record *InterceptRecord) []byte {
	// Simplified ETSI format - production would use proper ASN.1 encoding
	// Reference: ETSI TS 102 232-3

	// Increment sequence number
	seq := e.sequences[record.LIID]
	e.sequences[record.LIID] = seq + 1

	header := ETSIHeader{
		Version:      1,
		HandoverType: HI2,
		LIID:         record.LIID,
		CIN:          record.SessionID,
		SequenceNum:  seq,
		Timestamp:    record.Timestamp,
		CountryCode:  e.config.CountryCode,
	}

	// Build PDU
	buf := make([]byte, 0, 512)

	// PDU header
	buf = append(buf, 0x02) // Version
	buf = append(buf, 0x02) // HI2
	buf = append(buf, []byte(header.LIID)...)
	buf = append(buf, 0x00) // Null terminator
	buf = binary.BigEndian.AppendUint64(buf, header.SequenceNum)
	buf = binary.BigEndian.AppendUint64(buf, uint64(header.Timestamp.UnixMilli()))

	// IRI payload
	iri := struct {
		EventType    string     `json:"event_type"`
		Timestamp    time.Time  `json:"timestamp"`
		SessionID    string     `json:"session_id"`
		SubscriberID string     `json:"subscriber_id,omitempty"`
		SourceIP     string     `json:"source_ip,omitempty"`
		DestIP       string     `json:"dest_ip,omitempty"`
		SourcePort   uint16     `json:"source_port,omitempty"`
		DestPort     uint16     `json:"dest_port,omitempty"`
		Protocol     uint8      `json:"protocol,omitempty"`
		PartyInfo    *PartyInfo `json:"party_info,omitempty"`
	}{
		EventType:    string(record.EventType),
		Timestamp:    record.Timestamp,
		SessionID:    record.SessionID,
		SubscriberID: record.SubscriberID,
		SourcePort:   record.SourcePort,
		DestPort:     record.DestPort,
		Protocol:     record.Protocol,
		PartyInfo:    record.PartyInfo,
	}

	if record.SourceIP != nil {
		iri.SourceIP = record.SourceIP.String()
	}
	if record.DestIP != nil {
		iri.DestIP = record.DestIP.String()
	}

	payload, _ := json.Marshal(iri)

	// Add payload length and payload
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(payload)))
	buf = append(buf, payload...)

	return buf
}

// buildHI3PDU builds an ETSI HI3 (CC) PDU.
func (e *ETSIExporter) buildHI3PDU(record *InterceptRecord) []byte {
	// Simplified ETSI format - production would use proper ASN.1 encoding
	// Reference: ETSI TS 102 232-3

	// Increment sequence number
	seq := e.sequences[record.LIID]
	e.sequences[record.LIID] = seq + 1

	// Build PDU
	buf := make([]byte, 0, len(record.Payload)+128)

	// PDU header
	buf = append(buf, 0x02) // Version
	buf = append(buf, 0x03) // HI3
	buf = append(buf, []byte(record.LIID)...)
	buf = append(buf, 0x00) // Null terminator
	buf = binary.BigEndian.AppendUint64(buf, seq)
	buf = binary.BigEndian.AppendUint64(buf, uint64(record.Timestamp.UnixMilli()))

	// CC header
	buf = append(buf, byte(len(record.Direction)))
	buf = append(buf, []byte(record.Direction)...)

	// Source/dest info
	if record.SourceIP != nil {
		srcIP := record.SourceIP.To4()
		if srcIP == nil {
			srcIP = record.SourceIP.To16()
		}
		buf = append(buf, byte(len(srcIP)))
		buf = append(buf, srcIP...)
	} else {
		buf = append(buf, 0x00)
	}

	buf = binary.BigEndian.AppendUint16(buf, record.SourcePort)

	if record.DestIP != nil {
		dstIP := record.DestIP.To4()
		if dstIP == nil {
			dstIP = record.DestIP.To16()
		}
		buf = append(buf, byte(len(dstIP)))
		buf = append(buf, dstIP...)
	} else {
		buf = append(buf, 0x00)
	}

	buf = binary.BigEndian.AppendUint16(buf, record.DestPort)
	buf = append(buf, record.Protocol)

	// Payload
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(record.Payload)))
	buf = append(buf, record.Payload...)

	return buf
}

// JSONExporter exports intercept records as JSON over TCP/TLS.
type JSONExporter struct {
	config JSONExporterConfig
	logger *zap.Logger
	conn   net.Conn
	mu     sync.Mutex
}

// JSONExporterConfig holds JSON exporter configuration.
type JSONExporterConfig struct {
	Address        string
	UseTLS         bool
	TLSConfig      *tls.Config
	ConnectTimeout time.Duration
	WriteTimeout   time.Duration
}

// NewJSONExporter creates a new JSON exporter.
func NewJSONExporter(config JSONExporterConfig, logger *zap.Logger) (*JSONExporter, error) {
	return &JSONExporter{
		config: config,
		logger: logger,
	}, nil
}

// Name returns the exporter name.
func (e *JSONExporter) Name() string {
	return "json"
}

// DeliverIRI delivers an IRI record as JSON.
func (e *JSONExporter) DeliverIRI(ctx context.Context, record *InterceptRecord) error {
	return e.deliver(record)
}

// DeliverCC delivers a CC record as JSON.
func (e *JSONExporter) DeliverCC(ctx context.Context, record *InterceptRecord) error {
	return e.deliver(record)
}

// deliver sends a record as JSON.
func (e *JSONExporter) deliver(record *InterceptRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn == nil {
		if err := e.connect(); err != nil {
			return err
		}
	}

	// Serialize to JSON
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	// Add newline delimiter
	data = append(data, '\n')

	// Set write deadline
	if e.config.WriteTimeout > 0 {
		e.conn.SetWriteDeadline(time.Now().Add(e.config.WriteTimeout))
	}

	if _, err := e.conn.Write(data); err != nil {
		e.conn = nil
		return fmt.Errorf("write JSON: %w", err)
	}

	return nil
}

// connect establishes connection.
func (e *JSONExporter) connect() error {
	var conn net.Conn
	var err error

	dialer := net.Dialer{Timeout: e.config.ConnectTimeout}

	if e.config.UseTLS {
		conn, err = tls.DialWithDialer(&dialer, "tcp", e.config.Address, e.config.TLSConfig)
	} else {
		conn, err = dialer.Dial("tcp", e.config.Address)
	}

	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	e.conn = conn
	return nil
}

// Close closes the exporter connection.
func (e *JSONExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn != nil {
		err := e.conn.Close()
		e.conn = nil
		return err
	}
	return nil
}

// SyslogExporter exports IRI records to syslog (CC not supported).
type SyslogExporter struct {
	config SyslogExporterConfig
	logger *zap.Logger
	conn   net.Conn
	mu     sync.Mutex
}

// SyslogExporterConfig holds syslog exporter configuration.
type SyslogExporterConfig struct {
	Address  string // syslog server address
	Protocol string // "tcp", "udp"
	Facility int    // syslog facility
	Tag      string // syslog tag
}

// NewSyslogExporter creates a new syslog exporter.
func NewSyslogExporter(config SyslogExporterConfig, logger *zap.Logger) (*SyslogExporter, error) {
	if config.Protocol == "" {
		config.Protocol = "udp"
	}
	if config.Facility == 0 {
		config.Facility = 16 // LOG_LOCAL0
	}
	if config.Tag == "" {
		config.Tag = "lawful-intercept"
	}

	return &SyslogExporter{
		config: config,
		logger: logger,
	}, nil
}

// Name returns the exporter name.
func (e *SyslogExporter) Name() string {
	return "syslog"
}

// DeliverIRI delivers an IRI record to syslog.
func (e *SyslogExporter) DeliverIRI(ctx context.Context, record *InterceptRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn == nil {
		conn, err := net.Dial(e.config.Protocol, e.config.Address)
		if err != nil {
			return fmt.Errorf("connect to syslog: %w", err)
		}
		e.conn = conn
	}

	// Build syslog message
	// Format: <priority>timestamp hostname tag: message
	priority := e.config.Facility*8 + 6 // LOG_INFO
	timestamp := record.Timestamp.Format(time.RFC3339)

	msg := fmt.Sprintf("<%d>%s %s %s: LIID=%s event=%s session=%s subscriber=%s src=%s:%d dst=%s:%d proto=%d",
		priority,
		timestamp,
		"bng",
		e.config.Tag,
		record.LIID,
		record.EventType,
		record.SessionID,
		record.SubscriberID,
		record.SourceIP,
		record.SourcePort,
		record.DestIP,
		record.DestPort,
		record.Protocol,
	)

	if _, err := e.conn.Write([]byte(msg)); err != nil {
		e.conn = nil
		return fmt.Errorf("write syslog: %w", err)
	}

	return nil
}

// DeliverCC is not supported for syslog.
func (e *SyslogExporter) DeliverCC(ctx context.Context, record *InterceptRecord) error {
	// CC delivery via syslog is not practical
	return fmt.Errorf("CC delivery not supported via syslog")
}

// Close closes the syslog connection.
func (e *SyslogExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn != nil {
		err := e.conn.Close()
		e.conn = nil
		return err
	}
	return nil
}
