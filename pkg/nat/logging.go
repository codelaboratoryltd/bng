package nat

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// NATLogEntry represents a NAT translation log entry for legal compliance
// ISPs are required to log NAT translations for law enforcement purposes
type NATLogEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"` // "create", "delete", "timeout"
	PrivateIP   string    `json:"private_ip"`
	PrivatePort uint16    `json:"private_port,omitempty"`
	PublicIP    string    `json:"public_ip"`
	PublicPort  uint16    `json:"public_port,omitempty"`
	Protocol    string    `json:"protocol,omitempty"` // "tcp", "udp", "icmp"
	DestIP      string    `json:"dest_ip,omitempty"`
	DestPort    uint16    `json:"dest_port,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	Duration    int64     `json:"duration_ms,omitempty"`
	BytesSent   uint64    `json:"bytes_sent,omitempty"`
	BytesRecv   uint64    `json:"bytes_recv,omitempty"`
}

// Logger handles NAT translation logging
type Logger struct {
	writer   io.Writer
	logger   *zap.Logger
	mu       sync.Mutex
	enabled  bool
	format   string // "json", "syslog"
	buffer   []NATLogEntry
	bufferMu sync.Mutex
	flushCh  chan struct{}
	stopCh   chan struct{}
}

// LoggerConfig configures the NAT logger
type LoggerConfig struct {
	Enabled    bool
	FilePath   string // Path to log file (empty for stdout)
	Format     string // "json" or "syslog"
	BufferSize int    // Number of entries to buffer before flush
}

// NewLogger creates a new NAT logger
func NewLogger(cfg LoggerConfig, logger *zap.Logger) (*Logger, error) {
	var writer io.Writer = os.Stdout

	if cfg.FilePath != "" {
		f, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open NAT log file: %w", err)
		}
		writer = f
	}

	format := cfg.Format
	if format == "" {
		format = "json"
	}

	bufferSize := cfg.BufferSize
	if bufferSize == 0 {
		bufferSize = 1000
	}

	return &Logger{
		writer:  writer,
		logger:  logger,
		enabled: cfg.Enabled,
		format:  format,
		buffer:  make([]NATLogEntry, 0, bufferSize),
		flushCh: make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
	}, nil
}

// Start starts the background log flusher
func (l *Logger) Start() {
	go l.flushLoop()
}

// Stop stops the logger and flushes remaining entries
func (l *Logger) Stop() {
	close(l.stopCh)
	l.Flush()
	if closer, ok := l.writer.(io.Closer); ok {
		closer.Close()
	}
}

// LogAllocation logs a NAT allocation event
func (l *Logger) LogAllocation(alloc *Allocation) {
	if !l.enabled {
		return
	}

	entry := NATLogEntry{
		Timestamp:  time.Now().UTC(),
		EventType:  "allocate",
		PrivateIP:  alloc.PrivateIP.String(),
		PublicIP:   alloc.PublicIP.String(),
		PublicPort: alloc.PortStart,
	}

	l.addEntry(entry)
}

// LogDeallocation logs a NAT deallocation event
func (l *Logger) LogDeallocation(privateIP, publicIP net.IP, portStart uint16, duration time.Duration) {
	if !l.enabled {
		return
	}

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

// LogSession logs a NAT session creation
func (l *Logger) LogSession(privateIP net.IP, privatePort uint16, publicIP net.IP, publicPort uint16,
	destIP net.IP, destPort uint16, protocol string) {
	if !l.enabled {
		return
	}

	entry := NATLogEntry{
		Timestamp:   time.Now().UTC(),
		EventType:   "session_create",
		PrivateIP:   privateIP.String(),
		PrivatePort: privatePort,
		PublicIP:    publicIP.String(),
		PublicPort:  publicPort,
		DestIP:      destIP.String(),
		DestPort:    destPort,
		Protocol:    protocol,
	}

	l.addEntry(entry)
}

// LogSessionEnd logs a NAT session termination
func (l *Logger) LogSessionEnd(privateIP net.IP, privatePort uint16, publicIP net.IP, publicPort uint16,
	destIP net.IP, destPort uint16, protocol string, duration time.Duration, bytesSent, bytesRecv uint64) {
	if !l.enabled {
		return
	}

	entry := NATLogEntry{
		Timestamp:   time.Now().UTC(),
		EventType:   "session_end",
		PrivateIP:   privateIP.String(),
		PrivatePort: privatePort,
		PublicIP:    publicIP.String(),
		PublicPort:  publicPort,
		DestIP:      destIP.String(),
		DestPort:    destPort,
		Protocol:    protocol,
		Duration:    duration.Milliseconds(),
		BytesSent:   bytesSent,
		BytesRecv:   bytesRecv,
	}

	l.addEntry(entry)
}

// addEntry adds an entry to the buffer
func (l *Logger) addEntry(entry NATLogEntry) {
	l.bufferMu.Lock()
	l.buffer = append(l.buffer, entry)
	shouldFlush := len(l.buffer) >= cap(l.buffer)
	l.bufferMu.Unlock()

	if shouldFlush {
		select {
		case l.flushCh <- struct{}{}:
		default:
		}
	}
}

// Flush writes buffered entries to the output
func (l *Logger) Flush() {
	l.bufferMu.Lock()
	entries := l.buffer
	l.buffer = make([]NATLogEntry, 0, cap(entries))
	l.bufferMu.Unlock()

	if len(entries) == 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, entry := range entries {
		var line []byte
		var err error

		switch l.format {
		case "json":
			line, err = json.Marshal(entry)
			if err != nil {
				l.logger.Error("Failed to marshal NAT log entry", zap.Error(err))
				continue
			}
			line = append(line, '\n')
		case "syslog":
			line = []byte(l.formatSyslog(entry))
		default:
			line, _ = json.Marshal(entry)
			line = append(line, '\n')
		}

		if _, err := l.writer.Write(line); err != nil {
			l.logger.Error("Failed to write NAT log entry", zap.Error(err))
		}
	}
}

// formatSyslog formats an entry in syslog format
func (l *Logger) formatSyslog(entry NATLogEntry) string {
	return fmt.Sprintf("%s NAT %s: private=%s:%d public=%s:%d dest=%s:%d proto=%s duration=%dms\n",
		entry.Timestamp.Format(time.RFC3339),
		entry.EventType,
		entry.PrivateIP, entry.PrivatePort,
		entry.PublicIP, entry.PublicPort,
		entry.DestIP, entry.DestPort,
		entry.Protocol,
		entry.Duration,
	)
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
		}
	}
}
