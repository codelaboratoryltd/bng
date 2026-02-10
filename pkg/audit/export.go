package audit

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/syslog"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SyslogExporter exports audit events to syslog.
type SyslogExporter struct {
	config SyslogConfig
	logger *zap.Logger
	writer *syslog.Writer
	mu     sync.Mutex
}

// SyslogConfig holds syslog exporter configuration.
type SyslogConfig struct {
	// Network is the network type ("tcp", "udp", or "" for local).
	Network string

	// Address is the syslog server address (e.g., "localhost:514").
	Address string

	// Tag is the syslog tag/program name.
	Tag string

	// Facility is the syslog facility.
	Facility syslog.Priority

	// Format is the message format ("rfc3164", "rfc5424", "json").
	Format string
}

// DefaultSyslogConfig returns sensible defaults.
func DefaultSyslogConfig() SyslogConfig {
	return SyslogConfig{
		Tag:      "bng-audit",
		Facility: syslog.LOG_LOCAL0,
		Format:   "rfc5424",
	}
}

// NewSyslogExporter creates a new syslog exporter.
func NewSyslogExporter(config SyslogConfig, logger *zap.Logger) (*SyslogExporter, error) {
	var writer *syslog.Writer
	var err error

	if config.Network != "" && config.Address != "" {
		writer, err = syslog.Dial(config.Network, config.Address, config.Facility, config.Tag)
	} else {
		writer, err = syslog.New(config.Facility, config.Tag)
	}

	if err != nil {
		return nil, fmt.Errorf("connect to syslog: %w", err)
	}

	return &SyslogExporter{
		config: config,
		logger: logger,
		writer: writer,
	}, nil
}

// Name returns the exporter name.
func (e *SyslogExporter) Name() string {
	return "syslog"
}

// Export sends an event to syslog.
func (e *SyslogExporter) Export(ctx context.Context, event *Event) error {
	msg := e.formatMessage(event)
	severity := event.Type.GetSeverity()

	e.mu.Lock()
	defer e.mu.Unlock()

	var err error
	switch severity {
	case SeverityEmergency:
		err = e.writer.Emerg(msg)
	case SeverityAlert:
		err = e.writer.Alert(msg)
	case SeverityCritical:
		err = e.writer.Crit(msg)
	case SeverityError:
		err = e.writer.Err(msg)
	case SeverityWarning:
		err = e.writer.Warning(msg)
	case SeverityNotice:
		err = e.writer.Notice(msg)
	case SeverityInfo:
		err = e.writer.Info(msg)
	default:
		err = e.writer.Debug(msg)
	}

	return err
}

// ExportBatch sends multiple events to syslog.
func (e *SyslogExporter) ExportBatch(ctx context.Context, events []*Event) error {
	for _, event := range events {
		if err := e.Export(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// Close releases syslog resources.
func (e *SyslogExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.writer != nil {
		return e.writer.Close()
	}
	return nil
}

// formatMessage formats an event for syslog.
func (e *SyslogExporter) formatMessage(event *Event) string {
	switch e.config.Format {
	case "json":
		data, _ := json.Marshal(event)
		return string(data)
	default:
		return FormatSyslog(event)
	}
}

// IPFIXExporter exports audit events in IPFIX format.
// IPFIX (RFC 7011) is the standard for network flow export.
type IPFIXExporter struct {
	config IPFIXConfig
	logger *zap.Logger
	conn   net.Conn
	mu     sync.Mutex

	// IPFIX state
	sequenceNumber uint32
	templateID     uint16
}

// IPFIXConfig holds IPFIX exporter configuration.
type IPFIXConfig struct {
	// CollectorAddress is the IPFIX collector address.
	CollectorAddress string

	// Protocol is "tcp" or "udp".
	Protocol string

	// ObservationDomainID identifies this exporter.
	ObservationDomainID uint32

	// TemplateRefreshInterval is how often to resend templates.
	TemplateRefreshInterval time.Duration

	// MaxRecordsPerMessage limits records per IPFIX message.
	MaxRecordsPerMessage int
}

// DefaultIPFIXConfig returns sensible defaults.
func DefaultIPFIXConfig() IPFIXConfig {
	return IPFIXConfig{
		Protocol:                "udp",
		ObservationDomainID:     1,
		TemplateRefreshInterval: 5 * time.Minute,
		MaxRecordsPerMessage:    100,
	}
}

// IPFIX Template IDs and Information Elements
const (
	ipfixTemplateNATMapping = 256
	ipfixTemplateSession    = 257
)

// NewIPFIXExporter creates a new IPFIX exporter.
func NewIPFIXExporter(config IPFIXConfig, logger *zap.Logger) (*IPFIXExporter, error) {
	conn, err := net.Dial(config.Protocol, config.CollectorAddress)
	if err != nil {
		return nil, fmt.Errorf("connect to IPFIX collector: %w", err)
	}

	exp := &IPFIXExporter{
		config:     config,
		logger:     logger,
		conn:       conn,
		templateID: ipfixTemplateNATMapping,
	}

	return exp, nil
}

// Name returns the exporter name.
func (e *IPFIXExporter) Name() string {
	return "ipfix"
}

// Export sends an event as IPFIX.
func (e *IPFIXExporter) Export(ctx context.Context, event *Event) error {
	// Only export NAT events as IPFIX
	if event.Type != EventNATMapping && event.Type != EventNATExpiry {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Build IPFIX message
	msg := e.buildNATRecord(event)

	_, err := e.conn.Write(msg)
	if err != nil {
		return fmt.Errorf("write IPFIX: %w", err)
	}

	e.sequenceNumber++
	return nil
}

// ExportBatch sends multiple events as IPFIX.
func (e *IPFIXExporter) ExportBatch(ctx context.Context, events []*Event) error {
	for _, event := range events {
		if err := e.Export(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// Close releases IPFIX resources.
func (e *IPFIXExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}

// buildNATRecord builds an IPFIX NAT logging record.
func (e *IPFIXExporter) buildNATRecord(event *Event) []byte {
	// Simplified IPFIX message structure
	// In production, use a proper IPFIX library

	buf := make([]byte, 0, 256)

	// IPFIX Message Header (RFC 7011)
	// Version (2 bytes): 10
	buf = append(buf, 0x00, 0x0A)
	// Length (2 bytes): placeholder
	buf = append(buf, 0x00, 0x00)
	// Export Time (4 bytes)
	exportTime := uint32(time.Now().Unix())
	buf = binary.BigEndian.AppendUint32(buf, exportTime)
	// Sequence Number (4 bytes)
	buf = binary.BigEndian.AppendUint32(buf, e.sequenceNumber)
	// Observation Domain ID (4 bytes)
	buf = binary.BigEndian.AppendUint32(buf, e.config.ObservationDomainID)

	// Data Set Header
	// Set ID = Template ID
	buf = binary.BigEndian.AppendUint16(buf, e.templateID)
	// Set Length: placeholder
	setLengthOffset := len(buf)
	buf = append(buf, 0x00, 0x00)

	// NAT Record Fields
	// Source IPv4 (private)
	if event.NATPrivateIP != nil {
		buf = append(buf, event.NATPrivateIP.To4()...)
	} else {
		buf = append(buf, 0, 0, 0, 0)
	}

	// Source Port (private)
	buf = binary.BigEndian.AppendUint16(buf, event.NATPrivatePort)

	// Post-NAT Source IPv4 (public)
	if event.NATPublicIP != nil {
		buf = append(buf, event.NATPublicIP.To4()...)
	} else {
		buf = append(buf, 0, 0, 0, 0)
	}

	// Post-NAT Source Port (public)
	buf = binary.BigEndian.AppendUint16(buf, event.NATPublicPort)

	// Protocol
	buf = append(buf, event.NATProtocol)

	// Timestamp (milliseconds)
	timestamp := uint64(event.Timestamp.UnixMilli())
	buf = binary.BigEndian.AppendUint64(buf, timestamp)

	// Update lengths
	msgLen := uint16(len(buf))
	binary.BigEndian.PutUint16(buf[2:4], msgLen)
	binary.BigEndian.PutUint16(buf[setLengthOffset:setLengthOffset+2], msgLen-16)

	return buf
}

// JSONExporter exports audit events as JSON to a remote endpoint.
type JSONExporter struct {
	config JSONExportConfig
	logger *zap.Logger
	conn   net.Conn
	mu     sync.Mutex
}

// JSONExportConfig holds JSON exporter configuration.
type JSONExportConfig struct {
	// Address is the remote address.
	Address string

	// Protocol is "tcp" or "udp".
	Protocol string

	// Delimiter separates JSON records ("\n" for JSON Lines).
	Delimiter string

	// IncludeNewline appends newline after each record.
	IncludeNewline bool
}

// NewJSONExporter creates a new JSON exporter.
func NewJSONExporter(config JSONExportConfig, logger *zap.Logger) (*JSONExporter, error) {
	conn, err := net.Dial(config.Protocol, config.Address)
	if err != nil {
		return nil, fmt.Errorf("connect to JSON endpoint: %w", err)
	}

	if config.Delimiter == "" {
		config.Delimiter = "\n"
	}

	return &JSONExporter{
		config: config,
		logger: logger,
		conn:   conn,
	}, nil
}

// Name returns the exporter name.
func (e *JSONExporter) Name() string {
	return "json"
}

// Export sends an event as JSON.
func (e *JSONExporter) Export(ctx context.Context, event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, err := e.conn.Write(data); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}

	if e.config.IncludeNewline {
		if _, err := e.conn.Write([]byte(e.config.Delimiter)); err != nil {
			return fmt.Errorf("write delimiter: %w", err)
		}
	}

	return nil
}

// ExportBatch sends multiple events as JSON.
func (e *JSONExporter) ExportBatch(ctx context.Context, events []*Event) error {
	for _, event := range events {
		if err := e.Export(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// Close releases JSON exporter resources.
func (e *JSONExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}

// FileExporter exports audit events to a file (for local persistence).
type FileExporter struct {
}

// FileExportConfig holds file exporter configuration.
type FileExportConfig struct {
	// Path is the output file path.
	Path string

	// Format is "json" or "csv".
	Format string

	// RotateSize is the size in bytes before rotation.
	RotateSize int64

	// RotateInterval is the time before rotation.
	RotateInterval time.Duration

	// MaxFiles is the maximum number of rotated files to keep.
	MaxFiles int

	// Compress enables gzip compression of rotated files.
	Compress bool
}

// Note: Kafka exporter would be implemented using a Kafka client library
// such as github.com/segmentio/kafka-go or github.com/confluentinc/confluent-kafka-go
// For brevity, here's the interface:

// KafkaExporter exports audit events to Kafka.
type KafkaExporter struct {
	config KafkaConfig
	logger *zap.Logger
	// writer *kafka.Writer // Would use actual Kafka client
}

// KafkaConfig holds Kafka exporter configuration.
type KafkaConfig struct {
	// Brokers is the list of Kafka brokers.
	Brokers []string

	// Topic is the Kafka topic for audit events.
	Topic string

	// TopicByCategory uses separate topics per event category.
	TopicByCategory bool

	// TopicPrefix is prepended to category names when TopicByCategory is true.
	TopicPrefix string

	// Key determines the message key ("subscriber_id", "session_id", "device_id").
	Key string

	// Compression is the compression type ("none", "gzip", "snappy", "lz4").
	Compression string

	// BatchSize is the number of messages per batch.
	BatchSize int

	// BatchTimeout is the maximum time to wait for a batch.
	BatchTimeout time.Duration

	// RequiredAcks is the required acknowledgement level.
	RequiredAcks int
}

// DefaultKafkaConfig returns sensible defaults.
func DefaultKafkaConfig() KafkaConfig {
	return KafkaConfig{
		Topic:        "bng-audit",
		Key:          "subscriber_id",
		Compression:  "snappy",
		BatchSize:    100,
		BatchTimeout: 1 * time.Second,
		RequiredAcks: 1,
	}
}

// NewKafkaExporter creates a new Kafka exporter.
// Note: This is a stub - real implementation would use kafka-go or similar.
func NewKafkaExporter(config KafkaConfig, logger *zap.Logger) (*KafkaExporter, error) {
	return &KafkaExporter{
		config: config,
		logger: logger,
	}, nil
}

// Name returns the exporter name.
func (e *KafkaExporter) Name() string {
	return "kafka"
}

// Export sends an event to Kafka.
func (e *KafkaExporter) Export(ctx context.Context, event *Event) error {
	// Stub implementation
	e.logger.Debug("Would export to Kafka",
		zap.String("topic", e.config.Topic),
		zap.String("event_id", event.ID),
	)
	return nil
}

// ExportBatch sends multiple events to Kafka.
func (e *KafkaExporter) ExportBatch(ctx context.Context, events []*Event) error {
	for _, event := range events {
		if err := e.Export(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// Close releases Kafka resources.
func (e *KafkaExporter) Close() error {
	return nil
}
