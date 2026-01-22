package nat

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// LogFormat represents the output format for NAT logs
type LogFormat string

const (
	LogFormatJSON   LogFormat = "json"
	LogFormatSyslog LogFormat = "syslog"
	LogFormatCSV    LogFormat = "csv"
	LogFormatNEL    LogFormat = "nel" // Network Event Logging (RFC 8610)
)

// NATLogEntry represents a NAT translation log entry for legal compliance
// ISPs are required to log NAT translations for law enforcement purposes
type NATLogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"` // "create", "delete", "timeout", "allocate", "deallocate"
	SubscriberID uint32    `json:"subscriber_id,omitempty"`
	PrivateIP    string    `json:"private_ip"`
	PrivatePort  uint16    `json:"private_port,omitempty"`
	PublicIP     string    `json:"public_ip"`
	PublicPort   uint16    `json:"public_port,omitempty"`
	Protocol     string    `json:"protocol,omitempty"` // "tcp", "udp", "icmp"
	DestIP       string    `json:"dest_ip,omitempty"`
	DestPort     uint16    `json:"dest_port,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	Duration     int64     `json:"duration_ms,omitempty"`
	BytesSent    uint64    `json:"bytes_sent,omitempty"`
	BytesRecv    uint64    `json:"bytes_recv,omitempty"`
	PacketsSent  uint64    `json:"packets_sent,omitempty"`
	PacketsRecv  uint64    `json:"packets_recv,omitempty"`
	IsHairpin    bool      `json:"is_hairpin,omitempty"`
}

// PortBlockLogEntry represents a port block allocation log entry (RFC 6908 bulk logging)
// This reduces log volume by ~1000x compared to per-session logging
type PortBlockLogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"` // "port_block_assign", "port_block_release"
	SubscriberID uint32    `json:"subscriber_id"`
	PrivateIP    string    `json:"private_ip"`
	PublicIP     string    `json:"public_ip"`
	PortStart    uint16    `json:"port_start"`
	PortEnd      uint16    `json:"port_end"`
	BlockSize    uint16    `json:"block_size"`
}

// Logger handles NAT translation logging for legal compliance
type Logger struct {
	writer     io.Writer
	logger     *zap.Logger
	mu         sync.Mutex
	enabled    bool
	format     LogFormat
	buffer     []NATLogEntry
	bufferMu   sync.Mutex
	bufferSize int
	flushCh    chan struct{}
	stopCh     chan struct{}

	// Bulk logging (RFC 6908)
	bulkLogging       bool
	portBlockBuffer   []PortBlockLogEntry
	portBlockBufferMu sync.Mutex

	// File rotation
	filePath    string
	maxFileSize int64
	maxAge      time.Duration
	compress    bool
	currentFile *os.File
	currentSize int64
	rotationMu  sync.Mutex

	// Query index for compliance lookups
	enableIndex bool
	indexPath   string
}

// LoggerConfig configures the NAT logger
type LoggerConfig struct {
	Enabled    bool
	FilePath   string    // Path to log file (empty for stdout)
	Format     LogFormat // "json", "syslog", "csv", "nel"
	BufferSize int       // Number of entries to buffer before flush

	// Bulk logging (RFC 6908)
	BulkLogging bool // Log port block assignments instead of individual sessions

	// File rotation
	MaxFileSize int64         // Max file size in bytes before rotation (0 = no rotation)
	MaxAge      time.Duration // Max age of log files (0 = no age limit)
	Compress    bool          // Compress rotated files

	// Query index for compliance
	EnableIndex bool   // Enable indexing for fast lookups
	IndexPath   string // Path to index database
}

// NewLogger creates a new NAT logger
func NewLogger(cfg LoggerConfig, logger *zap.Logger) (*Logger, error) {
	var writer io.Writer = os.Stdout
	var currentFile *os.File

	if cfg.FilePath != "" {
		f, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open NAT log file: %w", err)
		}
		writer = f
		currentFile = f
	}

	format := cfg.Format
	if format == "" {
		format = LogFormatJSON
	}

	bufferSize := cfg.BufferSize
	if bufferSize == 0 {
		bufferSize = 1000
	}

	return &Logger{
		writer:          writer,
		logger:          logger,
		enabled:         cfg.Enabled,
		format:          format,
		buffer:          make([]NATLogEntry, 0, bufferSize),
		bufferSize:      bufferSize,
		flushCh:         make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
		bulkLogging:     cfg.BulkLogging,
		portBlockBuffer: make([]PortBlockLogEntry, 0, bufferSize/10),
		filePath:        cfg.FilePath,
		maxFileSize:     cfg.MaxFileSize,
		maxAge:          cfg.MaxAge,
		compress:        cfg.Compress,
		currentFile:     currentFile,
		enableIndex:     cfg.EnableIndex,
		indexPath:       cfg.IndexPath,
	}, nil
}

// Start starts the background log flusher
func (l *Logger) Start() {
	go l.flushLoop()
	if l.maxAge > 0 {
		go l.rotationLoop()
	}
}

// Stop stops the logger and flushes remaining entries
func (l *Logger) Stop() {
	close(l.stopCh)
	l.Flush()
	l.FlushPortBlocks()
	if closer, ok := l.writer.(io.Closer); ok {
		closer.Close()
	}
}

// LogAllocation logs a NAT port block allocation event (RFC 6908 bulk logging)
func (l *Logger) LogAllocation(alloc *Allocation) {
	if !l.enabled {
		return
	}

	if l.bulkLogging {
		// Use bulk logging - log port block assignment only
		entry := PortBlockLogEntry{
			Timestamp:    time.Now().UTC(),
			EventType:    "port_block_assign",
			SubscriberID: alloc.SubscriberID,
			PrivateIP:    alloc.PrivateIP.String(),
			PublicIP:     alloc.PublicIP.String(),
			PortStart:    alloc.PortStart,
			PortEnd:      alloc.PortEnd,
			BlockSize:    alloc.PortEnd - alloc.PortStart + 1,
		}
		l.addPortBlockEntry(entry)
	} else {
		// Traditional logging
		entry := NATLogEntry{
			Timestamp:    time.Now().UTC(),
			EventType:    "allocate",
			SubscriberID: alloc.SubscriberID,
			PrivateIP:    alloc.PrivateIP.String(),
			PublicIP:     alloc.PublicIP.String(),
			PublicPort:   alloc.PortStart, // Port range start
		}
		l.addEntry(entry)
	}
}

// LogDeallocation logs a NAT port block deallocation event
func (l *Logger) LogDeallocation(privateIP, publicIP net.IP, portStart uint16, duration time.Duration) {
	if !l.enabled {
		return
	}

	if l.bulkLogging {
		entry := PortBlockLogEntry{
			Timestamp: time.Now().UTC(),
			EventType: "port_block_release",
			PrivateIP: privateIP.String(),
			PublicIP:  publicIP.String(),
			PortStart: portStart,
		}
		l.addPortBlockEntry(entry)
	} else {
		entry := NATLogEntry{
			Timestamp:  time.Now().UTC(),
			EventType:  "deallocate",
			PrivateIP:  privateIP.String(),
			PublicIP:   publicIP.String(),
			PublicPort: portStart,
			Duration:   duration.Milliseconds(),
		}
		l.addEntry(entry)
	}
}

// LogSession logs a NAT session creation
func (l *Logger) LogSession(privateIP net.IP, privatePort uint16, publicIP net.IP, publicPort uint16,
	destIP net.IP, destPort uint16, protocol string, subscriberID uint32, isHairpin bool) {
	if !l.enabled || l.bulkLogging {
		// Skip individual session logging when bulk logging is enabled
		return
	}

	entry := NATLogEntry{
		Timestamp:    time.Now().UTC(),
		EventType:    "session_create",
		SubscriberID: subscriberID,
		PrivateIP:    privateIP.String(),
		PrivatePort:  privatePort,
		PublicIP:     publicIP.String(),
		PublicPort:   publicPort,
		DestIP:       destIP.String(),
		DestPort:     destPort,
		Protocol:     protocol,
		IsHairpin:    isHairpin,
	}

	l.addEntry(entry)
}

// LogSessionEnd logs a NAT session termination
func (l *Logger) LogSessionEnd(privateIP net.IP, privatePort uint16, publicIP net.IP, publicPort uint16,
	destIP net.IP, destPort uint16, protocol string, duration time.Duration,
	bytesSent, bytesRecv, packetsSent, packetsRecv uint64, subscriberID uint32) {
	if !l.enabled || l.bulkLogging {
		return
	}

	entry := NATLogEntry{
		Timestamp:    time.Now().UTC(),
		EventType:    "session_end",
		SubscriberID: subscriberID,
		PrivateIP:    privateIP.String(),
		PrivatePort:  privatePort,
		PublicIP:     publicIP.String(),
		PublicPort:   publicPort,
		DestIP:       destIP.String(),
		DestPort:     destPort,
		Protocol:     protocol,
		Duration:     duration.Milliseconds(),
		BytesSent:    bytesSent,
		BytesRecv:    bytesRecv,
		PacketsSent:  packetsSent,
		PacketsRecv:  packetsRecv,
	}

	l.addEntry(entry)
}

// LogFromBPF logs an event from the eBPF ring buffer
func (l *Logger) LogFromBPF(bpfEntry *BPFLogEntry) {
	if !l.enabled {
		return
	}

	entry := NATLogEntry{
		Timestamp:    time.Now().UTC(),
		EventType:    l.bpfEventTypeToString(bpfEntry.EventType),
		SubscriberID: bpfEntry.SubscriberID,
		PrivateIP:    keyToIP(bpfEntry.PrivateIP).String(),
		PrivatePort:  bpfEntry.PrivatePort,
		PublicIP:     keyToIP(bpfEntry.PublicIP).String(),
		PublicPort:   bpfEntry.PublicPort,
		DestIP:       keyToIP(bpfEntry.DestIP).String(),
		DestPort:     bpfEntry.DestPort,
		Protocol:     l.protocolToString(bpfEntry.Protocol),
	}

	l.addEntry(entry)
}

func (l *Logger) bpfEventTypeToString(eventType uint32) string {
	switch eventType {
	case NATLogSessionCreate:
		return "session_create"
	case NATLogSessionDelete:
		return "session_delete"
	case NATLogPortBlockAssign:
		return "port_block_assign"
	case NATLogPortBlockRelease:
		return "port_block_release"
	case NATLogPortExhaustion:
		return "port_exhaustion"
	case NATLogHairpin:
		return "hairpin"
	case NATLogALGTrigger:
		return "alg_trigger"
	default:
		return "unknown"
	}
}

func (l *Logger) protocolToString(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return fmt.Sprintf("proto_%d", protocol)
	}
}

// addEntry adds an entry to the buffer
func (l *Logger) addEntry(entry NATLogEntry) {
	l.bufferMu.Lock()
	l.buffer = append(l.buffer, entry)
	shouldFlush := len(l.buffer) >= l.bufferSize
	l.bufferMu.Unlock()

	if shouldFlush {
		select {
		case l.flushCh <- struct{}{}:
		default:
		}
	}
}

// addPortBlockEntry adds a port block entry to the buffer
func (l *Logger) addPortBlockEntry(entry PortBlockLogEntry) {
	l.portBlockBufferMu.Lock()
	l.portBlockBuffer = append(l.portBlockBuffer, entry)
	shouldFlush := len(l.portBlockBuffer) >= cap(l.portBlockBuffer)
	l.portBlockBufferMu.Unlock()

	if shouldFlush {
		l.FlushPortBlocks()
	}
}

// Flush writes buffered entries to the output
func (l *Logger) Flush() {
	l.bufferMu.Lock()
	entries := l.buffer
	l.buffer = make([]NATLogEntry, 0, l.bufferSize)
	l.bufferMu.Unlock()

	if len(entries) == 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, entry := range entries {
		line := l.formatEntry(entry)
		l.writeWithRotation(line)
	}
}

// FlushPortBlocks writes buffered port block entries to the output
func (l *Logger) FlushPortBlocks() {
	l.portBlockBufferMu.Lock()
	entries := l.portBlockBuffer
	l.portBlockBuffer = make([]PortBlockLogEntry, 0, cap(entries))
	l.portBlockBufferMu.Unlock()

	if len(entries) == 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, entry := range entries {
		line := l.formatPortBlockEntry(entry)
		l.writeWithRotation(line)
	}
}

// formatEntry formats a NAT log entry based on the configured format
func (l *Logger) formatEntry(entry NATLogEntry) []byte {
	switch l.format {
	case LogFormatJSON:
		line, err := json.Marshal(entry)
		if err != nil {
			l.logger.Error("Failed to marshal NAT log entry", zap.Error(err))
			return nil
		}
		return append(line, '\n')

	case LogFormatSyslog:
		return []byte(l.formatSyslog(entry))

	case LogFormatCSV:
		return []byte(l.formatCSV(entry))

	case LogFormatNEL:
		return l.formatNEL(entry)

	default:
		line, _ := json.Marshal(entry)
		return append(line, '\n')
	}
}

// formatPortBlockEntry formats a port block log entry
func (l *Logger) formatPortBlockEntry(entry PortBlockLogEntry) []byte {
	switch l.format {
	case LogFormatJSON:
		line, err := json.Marshal(entry)
		if err != nil {
			l.logger.Error("Failed to marshal port block log entry", zap.Error(err))
			return nil
		}
		return append(line, '\n')

	case LogFormatSyslog:
		return []byte(fmt.Sprintf("%s NAT %s: subscriber=%d private=%s public=%s ports=%d-%d\n",
			entry.Timestamp.Format(time.RFC3339),
			entry.EventType,
			entry.SubscriberID,
			entry.PrivateIP,
			entry.PublicIP,
			entry.PortStart,
			entry.PortEnd,
		))

	default:
		line, _ := json.Marshal(entry)
		return append(line, '\n')
	}
}

// formatSyslog formats an entry in syslog format
func (l *Logger) formatSyslog(entry NATLogEntry) string {
	return fmt.Sprintf("%s NAT %s: subscriber=%d private=%s:%d public=%s:%d dest=%s:%d proto=%s duration=%dms\n",
		entry.Timestamp.Format(time.RFC3339),
		entry.EventType,
		entry.SubscriberID,
		entry.PrivateIP, entry.PrivatePort,
		entry.PublicIP, entry.PublicPort,
		entry.DestIP, entry.DestPort,
		entry.Protocol,
		entry.Duration,
	)
}

// formatCSV formats an entry in CSV format
func (l *Logger) formatCSV(entry NATLogEntry) string {
	return fmt.Sprintf("%s,%s,%d,%s,%d,%s,%d,%s,%d,%s,%d,%d,%d\n",
		entry.Timestamp.Format(time.RFC3339),
		entry.EventType,
		entry.SubscriberID,
		entry.PrivateIP,
		entry.PrivatePort,
		entry.PublicIP,
		entry.PublicPort,
		entry.DestIP,
		entry.DestPort,
		entry.Protocol,
		entry.Duration,
		entry.BytesSent,
		entry.BytesRecv,
	)
}

// formatNEL formats an entry in Network Event Logging format (RFC 8610)
func (l *Logger) formatNEL(entry NATLogEntry) []byte {
	// NEL is a JSON-based format with specific structure
	nel := map[string]interface{}{
		"type": "NAT",
		"age":  0,
		"body": map[string]interface{}{
			"event":        entry.EventType,
			"subscriber":   entry.SubscriberID,
			"private_ip":   entry.PrivateIP,
			"private_port": entry.PrivatePort,
			"public_ip":    entry.PublicIP,
			"public_port":  entry.PublicPort,
			"dest_ip":      entry.DestIP,
			"dest_port":    entry.DestPort,
			"protocol":     entry.Protocol,
		},
	}
	line, _ := json.Marshal(nel)
	return append(line, '\n')
}

// writeWithRotation writes data and handles file rotation
func (l *Logger) writeWithRotation(data []byte) {
	if data == nil {
		return
	}

	// Check if rotation is needed
	if l.maxFileSize > 0 && l.currentFile != nil {
		l.currentSize += int64(len(data))
		if l.currentSize >= l.maxFileSize {
			l.rotateFile()
		}
	}

	if _, err := l.writer.Write(data); err != nil {
		l.logger.Error("Failed to write NAT log entry", zap.Error(err))
	}
}

// rotateFile performs log file rotation
func (l *Logger) rotateFile() {
	l.rotationMu.Lock()
	defer l.rotationMu.Unlock()

	if l.currentFile == nil {
		return
	}

	// Close current file
	l.currentFile.Close()

	// Rename with timestamp
	rotatedPath := fmt.Sprintf("%s.%s", l.filePath, time.Now().Format("20060102-150405"))
	os.Rename(l.filePath, rotatedPath)

	// Compress if enabled
	if l.compress {
		go l.compressFile(rotatedPath)
	}

	// Open new file
	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		l.logger.Error("Failed to open new log file", zap.Error(err))
		return
	}

	l.currentFile = f
	l.writer = f
	l.currentSize = 0
}

// compressFile compresses a rotated log file
func (l *Logger) compressFile(path string) {
	src, err := os.Open(path)
	if err != nil {
		l.logger.Error("Failed to open file for compression", zap.Error(err))
		return
	}
	defer src.Close()

	dst, err := os.Create(path + ".gz")
	if err != nil {
		l.logger.Error("Failed to create compressed file", zap.Error(err))
		return
	}
	defer dst.Close()

	gz := gzip.NewWriter(dst)
	defer gz.Close()

	if _, err := io.Copy(gz, src); err != nil {
		l.logger.Error("Failed to compress file", zap.Error(err))
		return
	}

	// Remove original after successful compression
	os.Remove(path)
}

// flushLoop periodically flushes the buffer
func (l *Logger) flushLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCh:
			return
		case <-l.flushCh:
			l.Flush()
		case <-ticker.C:
			l.Flush()
			l.FlushPortBlocks()
		}
	}
}

// rotationLoop handles age-based log rotation
func (l *Logger) rotationLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.cleanOldLogs()
		}
	}
}

// cleanOldLogs removes logs older than maxAge
func (l *Logger) cleanOldLogs() {
	if l.maxAge == 0 || l.filePath == "" {
		return
	}

	dir := filepath.Dir(l.filePath)
	base := filepath.Base(l.filePath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-l.maxAge)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Check if it's a rotated log file
		if len(entry.Name()) <= len(base) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(dir, entry.Name()))
			l.logger.Info("Removed old log file", zap.String("file", entry.Name()))
		}
	}
}

// QueryByPublicEndpoint finds the subscriber for a given public IP:port at a specific time
// This is the primary compliance query: "Who had this public IP:port at this time?"
func (l *Logger) QueryByPublicEndpoint(publicIP string, publicPort uint16, timestamp time.Time) (*NATLogEntry, error) {
	if !l.enableIndex {
		return nil, fmt.Errorf("index not enabled")
	}

	// In a production implementation, this would query an indexed database
	// For now, this is a placeholder showing the interface
	return nil, fmt.Errorf("query not implemented - enable index database")
}

// ExportForCompliance exports logs for a time range in the specified format
func (l *Logger) ExportForCompliance(startTime, endTime time.Time, format LogFormat, writer io.Writer) error {
	// In production, this would read from the indexed database
	return fmt.Errorf("export not implemented - enable index database")
}

// GetStats returns logging statistics
func (l *Logger) GetStats() map[string]interface{} {
	l.bufferMu.Lock()
	bufferLen := len(l.buffer)
	l.bufferMu.Unlock()

	l.portBlockBufferMu.Lock()
	portBlockBufferLen := len(l.portBlockBuffer)
	l.portBlockBufferMu.Unlock()

	return map[string]interface{}{
		"enabled":                l.enabled,
		"format":                 string(l.format),
		"buffer_size":            l.bufferSize,
		"buffer_used":            bufferLen,
		"bulk_logging":           l.bulkLogging,
		"port_block_buffer_used": portBlockBufferLen,
		"current_file_size":      l.currentSize,
		"max_file_size":          l.maxFileSize,
		"compress":               l.compress,
		"index_enabled":          l.enableIndex,
	}
}
