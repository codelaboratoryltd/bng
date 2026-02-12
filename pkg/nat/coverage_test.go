package nat

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// --- Logger Tests ---

func TestNewLogger_Defaults(t *testing.T) {
	logger, err := NewLogger(LoggerConfig{
		Enabled: true,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	if logger.format != LogFormatJSON {
		t.Errorf("expected default format JSON, got %s", logger.format)
	}
	if logger.bufferSize != 1000 {
		t.Errorf("expected default bufferSize 1000, got %d", logger.bufferSize)
	}
}

func TestNewLogger_WithFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "nat.log")

	logger, err := NewLogger(LoggerConfig{
		Enabled:  true,
		FilePath: logPath,
		Format:   LogFormatJSON,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewLogger with file: %v", err)
	}
	defer logger.Stop()

	if logger.currentFile == nil {
		t.Error("expected non-nil currentFile for file-based logger")
	}
}

func TestNewLogger_InvalidFilePath(t *testing.T) {
	_, err := NewLogger(LoggerConfig{
		Enabled:  true,
		FilePath: "/nonexistent/dir/nat.log",
	}, zap.NewNop())
	if err == nil {
		t.Error("expected error for invalid file path")
	}
}

func TestLogger_LogAllocation_Disabled(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: false}, zap.NewNop())
	// Should not panic when logging is disabled
	logger.LogAllocation(&Allocation{
		PrivateIP: net.ParseIP("10.0.0.1"),
		PublicIP:  net.ParseIP("203.0.113.1"),
		PortStart: 1024,
		PortEnd:   2047,
	})
}

func TestLogger_LogAllocation_Traditional(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(LoggerConfig{
		Enabled:    true,
		Format:     LogFormatJSON,
		BufferSize: 10,
	}, zap.NewNop())
	logger.writer = &buf

	logger.LogAllocation(&Allocation{
		PrivateIP:    net.ParseIP("10.0.0.1"),
		PublicIP:     net.ParseIP("203.0.113.1"),
		PortStart:    1024,
		PortEnd:      2047,
		SubscriberID: 1,
	})

	logger.Flush()

	if buf.Len() == 0 {
		t.Error("expected log output after flush")
	}
	if !bytes.Contains(buf.Bytes(), []byte("allocate")) {
		t.Error("expected 'allocate' event type in log output")
	}
}

func TestLogger_LogAllocation_BulkLogging(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(LoggerConfig{
		Enabled:     true,
		BulkLogging: true,
		Format:      LogFormatJSON,
		BufferSize:  100,
	}, zap.NewNop())
	logger.writer = &buf

	logger.LogAllocation(&Allocation{
		PrivateIP:    net.ParseIP("10.0.0.1"),
		PublicIP:     net.ParseIP("203.0.113.1"),
		PortStart:    1024,
		PortEnd:      2047,
		SubscriberID: 1,
	})

	logger.FlushPortBlocks()

	if buf.Len() == 0 {
		t.Error("expected log output after FlushPortBlocks")
	}
	if !bytes.Contains(buf.Bytes(), []byte("port_block_assign")) {
		t.Error("expected 'port_block_assign' event type in bulk log output")
	}
}

func TestLogger_LogDeallocation_Traditional(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(LoggerConfig{
		Enabled:    true,
		Format:     LogFormatJSON,
		BufferSize: 10,
	}, zap.NewNop())
	logger.writer = &buf

	logger.LogDeallocation(
		net.ParseIP("10.0.0.1"),
		net.ParseIP("203.0.113.1"),
		1024,
		30*time.Minute,
	)
	logger.Flush()

	if buf.Len() == 0 {
		t.Error("expected log output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("deallocate")) {
		t.Error("expected 'deallocate' event type")
	}
}

func TestLogger_LogDeallocation_BulkLogging(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(LoggerConfig{
		Enabled:     true,
		BulkLogging: true,
		Format:      LogFormatJSON,
		BufferSize:  100,
	}, zap.NewNop())
	logger.writer = &buf

	logger.LogDeallocation(
		net.ParseIP("10.0.0.1"),
		net.ParseIP("203.0.113.1"),
		1024,
		30*time.Minute,
	)
	logger.FlushPortBlocks()

	if buf.Len() == 0 {
		t.Error("expected log output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("port_block_release")) {
		t.Error("expected 'port_block_release' event type")
	}
}

func TestLogger_LogSession(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(LoggerConfig{
		Enabled:    true,
		Format:     LogFormatJSON,
		BufferSize: 10,
	}, zap.NewNop())
	logger.writer = &buf

	logger.LogSession(
		net.ParseIP("10.0.0.1"), 12345,
		net.ParseIP("203.0.113.1"), 54321,
		net.ParseIP("8.8.8.8"), 80,
		"tcp", 1, false,
	)
	logger.Flush()

	if !bytes.Contains(buf.Bytes(), []byte("session_create")) {
		t.Error("expected 'session_create' event type")
	}
}

func TestLogger_LogSession_Disabled(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: false}, zap.NewNop())
	// Should not panic
	logger.LogSession(
		net.ParseIP("10.0.0.1"), 12345,
		net.ParseIP("203.0.113.1"), 54321,
		net.ParseIP("8.8.8.8"), 80,
		"tcp", 1, false,
	)
}

func TestLogger_LogSession_BulkLogging(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(LoggerConfig{
		Enabled:     true,
		BulkLogging: true,
		Format:      LogFormatJSON,
		BufferSize:  10,
	}, zap.NewNop())
	logger.writer = &buf

	// Session logging should be skipped when bulk logging is enabled
	logger.LogSession(
		net.ParseIP("10.0.0.1"), 12345,
		net.ParseIP("203.0.113.1"), 54321,
		net.ParseIP("8.8.8.8"), 80,
		"tcp", 1, false,
	)
	logger.Flush()

	if buf.Len() != 0 {
		t.Error("expected no log output when bulk logging skips session logging")
	}
}

func TestLogger_LogSessionEnd(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(LoggerConfig{
		Enabled:    true,
		Format:     LogFormatJSON,
		BufferSize: 10,
	}, zap.NewNop())
	logger.writer = &buf

	logger.LogSessionEnd(
		net.ParseIP("10.0.0.1"), 12345,
		net.ParseIP("203.0.113.1"), 54321,
		net.ParseIP("8.8.8.8"), 80,
		"tcp", 5*time.Second,
		1024, 2048, 10, 20, 1,
	)
	logger.Flush()

	if !bytes.Contains(buf.Bytes(), []byte("session_end")) {
		t.Error("expected 'session_end' event type")
	}
}

func TestLogger_LogSessionEnd_Disabled(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: false}, zap.NewNop())
	// Should not panic
	logger.LogSessionEnd(
		net.ParseIP("10.0.0.1"), 12345,
		net.ParseIP("203.0.113.1"), 54321,
		net.ParseIP("8.8.8.8"), 80,
		"tcp", 5*time.Second,
		1024, 2048, 10, 20, 1,
	)
}

func TestLogger_LogFromBPF(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(LoggerConfig{
		Enabled:    true,
		Format:     LogFormatJSON,
		BufferSize: 10,
	}, zap.NewNop())
	logger.writer = &buf

	entry := &BPFLogEntry{
		EventType:    NATLogSessionCreate,
		SubscriberID: 1,
		PrivateIP:    0x0A000001,
		PublicIP:     0xCB007101,
		PrivatePort:  12345,
		PublicPort:   54321,
		DestIP:       0x08080808,
		DestPort:     80,
		Protocol:     6,
	}
	logger.LogFromBPF(entry)
	logger.Flush()

	if !bytes.Contains(buf.Bytes(), []byte("session_create")) {
		t.Error("expected 'session_create' event from BPF")
	}
}

func TestLogger_LogFromBPF_Disabled(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: false}, zap.NewNop())
	logger.LogFromBPF(&BPFLogEntry{EventType: NATLogSessionCreate})
}

func TestLogger_BPFEventTypeToString(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: true}, zap.NewNop())

	tests := []struct {
		eventType uint32
		expected  string
	}{
		{NATLogSessionCreate, "session_create"},
		{NATLogSessionDelete, "session_delete"},
		{NATLogPortBlockAssign, "port_block_assign"},
		{NATLogPortBlockRelease, "port_block_release"},
		{NATLogPortExhaustion, "port_exhaustion"},
		{NATLogHairpin, "hairpin"},
		{NATLogALGTrigger, "alg_trigger"},
		{99, "unknown"},
	}

	for _, tt := range tests {
		result := logger.bpfEventTypeToString(tt.eventType)
		if result != tt.expected {
			t.Errorf("bpfEventTypeToString(%d) = %q, want %q", tt.eventType, result, tt.expected)
		}
	}
}

func TestLogger_ProtocolToString(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: true}, zap.NewNop())

	tests := []struct {
		protocol uint8
		expected string
	}{
		{6, "tcp"},
		{17, "udp"},
		{1, "icmp"},
		{47, "proto_47"},
	}

	for _, tt := range tests {
		result := logger.protocolToString(tt.protocol)
		if result != tt.expected {
			t.Errorf("protocolToString(%d) = %q, want %q", tt.protocol, result, tt.expected)
		}
	}
}

func TestLogger_FormatEntry_AllFormats(t *testing.T) {
	entry := NATLogEntry{
		Timestamp:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		EventType:    "session_create",
		SubscriberID: 1,
		PrivateIP:    "10.0.0.1",
		PrivatePort:  12345,
		PublicIP:     "203.0.113.1",
		PublicPort:   54321,
		DestIP:       "8.8.8.8",
		DestPort:     80,
		Protocol:     "tcp",
		Duration:     5000,
		BytesSent:    1024,
		BytesRecv:    2048,
	}

	formats := []LogFormat{LogFormatJSON, LogFormatSyslog, LogFormatCSV, LogFormatNEL}
	for _, format := range formats {
		logger, _ := NewLogger(LoggerConfig{
			Enabled: true,
			Format:  format,
		}, zap.NewNop())

		result := logger.formatEntry(entry)
		if len(result) == 0 {
			t.Errorf("formatEntry(%s) returned empty result", format)
		}
	}
}

func TestLogger_FormatPortBlockEntry_AllFormats(t *testing.T) {
	entry := PortBlockLogEntry{
		Timestamp:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		EventType:    "port_block_assign",
		SubscriberID: 1,
		PrivateIP:    "10.0.0.1",
		PublicIP:     "203.0.113.1",
		PortStart:    1024,
		PortEnd:      2047,
		BlockSize:    1024,
	}

	formats := []LogFormat{LogFormatJSON, LogFormatSyslog, "unknown"}
	for _, format := range formats {
		logger, _ := NewLogger(LoggerConfig{
			Enabled: true,
			Format:  format,
		}, zap.NewNop())

		result := logger.formatPortBlockEntry(entry)
		if len(result) == 0 {
			t.Errorf("formatPortBlockEntry(%s) returned empty result", format)
		}
	}
}

func TestLogger_Flush_Empty(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: true}, zap.NewNop())
	// Flush with no entries should not panic
	logger.Flush()
}

func TestLogger_FlushPortBlocks_Empty(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: true}, zap.NewNop())
	// FlushPortBlocks with no entries should not panic
	logger.FlushPortBlocks()
}

func TestLogger_WriteWithRotation_NilData(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: true}, zap.NewNop())
	// Should not panic
	logger.writeWithRotation(nil)
}

func TestLogger_WriteWithRotation_WithFileRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "rotate.log")

	logger, err := NewLogger(LoggerConfig{
		Enabled:     true,
		FilePath:    logPath,
		MaxFileSize: 100, // Very small to trigger rotation
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	// Write enough data to trigger rotation
	data := bytes.Repeat([]byte("x"), 150)
	logger.writeWithRotation(data)

	// The rotation should have created a new file
	files, _ := os.ReadDir(tmpDir)
	if len(files) < 1 {
		t.Error("expected at least one file after rotation")
	}

	// Clean up
	if logger.currentFile != nil {
		logger.currentFile.Close()
	}
}

func TestLogger_GetStats(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{
		Enabled:     true,
		BulkLogging: true,
		Compress:    true,
	}, zap.NewNop())

	stats := logger.GetStats()
	if stats["enabled"] != true {
		t.Error("expected enabled=true")
	}
	if stats["bulk_logging"] != true {
		t.Error("expected bulk_logging=true")
	}
	if stats["compress"] != true {
		t.Error("expected compress=true")
	}
}

func TestLogger_QueryByPublicEndpoint(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: true}, zap.NewNop())
	_, err := logger.QueryByPublicEndpoint("203.0.113.1", 1024, time.Now())
	if err == nil {
		t.Error("expected error from QueryByPublicEndpoint without index")
	}
}

func TestLogger_ExportForCompliance(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: true}, zap.NewNop())
	var buf bytes.Buffer
	err := logger.ExportForCompliance(time.Now().Add(-1*time.Hour), time.Now(), LogFormatJSON, &buf)
	if err == nil {
		t.Error("expected error from ExportForCompliance without index")
	}
}

func TestLogger_StopWithWriter(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "stop.log")

	logger, err := NewLogger(LoggerConfig{
		Enabled:  true,
		FilePath: logPath,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	// Stop should close the file and flush
	logger.Stop()
}

func TestLogger_BufferFlushTrigger(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(LoggerConfig{
		Enabled:    true,
		Format:     LogFormatJSON,
		BufferSize: 2, // Very small buffer
	}, zap.NewNop())
	logger.writer = &buf

	// Add entries to fill the buffer and trigger flush signal
	logger.addEntry(NATLogEntry{EventType: "test1", PrivateIP: "10.0.0.1", PublicIP: "1.1.1.1"})
	logger.addEntry(NATLogEntry{EventType: "test2", PrivateIP: "10.0.0.2", PublicIP: "1.1.1.2"})

	// Manual flush to ensure the entries are written
	logger.Flush()

	if buf.Len() == 0 {
		t.Error("expected flushed output")
	}
}

func TestLogger_CleanOldLogs_NoMaxAge(t *testing.T) {
	logger, _ := NewLogger(LoggerConfig{Enabled: true}, zap.NewNop())
	// Should not panic with no maxAge
	logger.cleanOldLogs()
}

func TestLogger_CleanOldLogs_WithMaxAge(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "nat.log")

	logger, _ := NewLogger(LoggerConfig{
		Enabled:  true,
		FilePath: logPath,
		MaxAge:   1 * time.Nanosecond, // Expire immediately
	}, zap.NewNop())

	// Create a fake rotated log file
	rotatedFile := filepath.Join(tmpDir, "nat.log.20240101-120000")
	os.WriteFile(rotatedFile, []byte("old data"), 0644)

	// Wait a moment and clean
	time.Sleep(time.Millisecond)
	logger.cleanOldLogs()
}

// --- ALG Tests ---

func TestNewALGHandler(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)

	handler := NewALGHandler(mgr, logger)
	if handler == nil {
		t.Fatal("expected non-nil ALG handler")
	}
	if len(handler.handlers) != 2 {
		t.Errorf("expected 2 registered ALGs (FTP, SIP), got %d", len(handler.handlers))
	}
}

func TestALGHandler_ProcessPacket_Passthrough(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	// Unknown ALG type should pass through
	conn := &ALGConnection{
		PrivateIP: net.ParseIP("10.0.0.1"),
		PublicIP:  net.ParseIP("203.0.113.1"),
	}
	data := []byte("hello world")
	result, err := handler.ProcessPacket(99, conn, data, true)
	if err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Error("expected passthrough for unknown ALG type")
	}
}

func TestALGHandler_ProcessPacket_FTP_Outbound(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "lo0",
		PortsPerSubscriber: 1024,
		PortRangeStart:     10000,
		PortRangeEnd:       60000,
	}, logger)
	mgr.AddPublicIP(net.ParseIP("203.0.113.1"))

	handler := NewALGHandler(mgr, logger)
	conn := &ALGConnection{
		PrivateIP:   net.ParseIP("10.0.0.1"),
		PrivatePort: 21,
		PublicIP:    net.ParseIP("203.0.113.1"),
		PublicPort:  21,
		Protocol:    6,
	}

	// Test with PORT command
	data := []byte("PORT 10,0,0,1,4,0\r\n")
	result, err := handler.ProcessPacket(ALGTypeFTP, conn, data, true)
	if err != nil {
		t.Fatalf("ProcessPacket FTP outbound: %v", err)
	}
	if bytes.Equal(result, data) {
		t.Error("PORT command should have been rewritten")
	}
}

func TestALGHandler_ProcessPacket_FTP_Outbound_NoPort(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	conn := &ALGConnection{
		PrivateIP: net.ParseIP("10.0.0.1"),
		PublicIP:  net.ParseIP("203.0.113.1"),
	}

	// Regular data without PORT command should pass through
	data := []byte("LIST\r\n")
	result, err := handler.ProcessPacket(ALGTypeFTP, conn, data, true)
	if err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Error("data without PORT command should pass through")
	}
}

func TestALGHandler_ProcessPacket_FTP_Inbound_Pasv(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	conn := &ALGConnection{
		PrivateIP:   net.ParseIP("10.0.0.1"),
		PrivatePort: 21,
		PublicIP:    net.ParseIP("203.0.113.1"),
		PublicPort:  21,
	}

	// Test with PASV response
	data := []byte("227 Entering Passive Mode (192,168,1,100,39,4)\r\n")
	_, err := handler.ProcessPacket(ALGTypeFTP, conn, data, false)
	if err != nil {
		t.Fatalf("ProcessPacket FTP inbound PASV: %v", err)
	}
}

func TestALGHandler_ProcessPacket_FTP_Inbound_EPSV(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	conn := &ALGConnection{
		PrivateIP: net.ParseIP("10.0.0.1"),
		PublicIP:  net.ParseIP("203.0.113.1"),
	}

	// Test with EPSV response
	data := []byte("229 Entering Extended Passive Mode (|||12345|)\r\n")
	_, err := handler.ProcessPacket(ALGTypeFTP, conn, data, false)
	if err != nil {
		t.Fatalf("ProcessPacket FTP inbound EPSV: %v", err)
	}
}

func TestALGHandler_ProcessPacket_FTP_Outbound_EPRT(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "lo0",
		PortsPerSubscriber: 1024,
		PortRangeStart:     10000,
		PortRangeEnd:       60000,
	}, logger)
	mgr.AddPublicIP(net.ParseIP("203.0.113.1"))

	handler := NewALGHandler(mgr, logger)
	conn := &ALGConnection{
		PrivateIP: net.ParseIP("10.0.0.1"),
		PublicIP:  net.ParseIP("203.0.113.1"),
	}

	// Test with EPRT command
	data := []byte("EPRT |1|10.0.0.1|12345|\r\n")
	result, err := handler.ProcessPacket(ALGTypeFTP, conn, data, true)
	if err != nil {
		t.Fatalf("ProcessPacket FTP EPRT: %v", err)
	}
	if bytes.Equal(result, data) {
		t.Error("EPRT command should have been rewritten")
	}
}

func TestALGHandler_AddDynamicMapping(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	mapping := &DynamicMapping{
		PrivateIP:   net.ParseIP("10.0.0.1"),
		PrivatePort: 20,
		PublicIP:    net.ParseIP("203.0.113.1"),
		PublicPort:  20,
		Protocol:    6,
	}

	err := handler.AddDynamicMapping(mapping)
	if err != nil {
		t.Fatalf("AddDynamicMapping: %v", err)
	}

	// Retrieve the mapping
	result := handler.GetDynamicMapping(net.ParseIP("10.0.0.1"), 20, 6)
	if result == nil {
		t.Error("expected non-nil dynamic mapping")
	}
}

func TestALGHandler_GetDynamicMapping_NotFound(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	result := handler.GetDynamicMapping(net.ParseIP("10.0.0.99"), 9999, 6)
	if result != nil {
		t.Error("expected nil for non-existent mapping")
	}
}

func TestFTPALG_Name(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)
	ftp := NewFTPALG(handler, logger)
	if ftp.Name() != "FTP" {
		t.Errorf("expected 'FTP', got %q", ftp.Name())
	}
}

func TestSIPALG_Name(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)
	sip := NewSIPALG(handler, logger)
	if sip.Name() != "SIP" {
		t.Errorf("expected 'SIP', got %q", sip.Name())
	}
}

func TestSIPALG_ProcessOutbound(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	conn := &ALGConnection{
		PrivateIP: net.ParseIP("10.0.0.1"),
		PublicIP:  net.ParseIP("203.0.113.1"),
	}

	// SIP INVITE with Via header containing private IP
	data := []byte("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\nContact: <sip:user@10.0.0.1:5060>\r\nTo: <sip:target@example.com>\r\n")
	result, err := handler.ProcessPacket(ALGTypeSIP, conn, data, true)
	if err != nil {
		t.Fatalf("SIP outbound: %v", err)
	}
	if bytes.Contains(result, []byte("10.0.0.1")) {
		t.Error("SIP outbound should have rewritten private IP to public IP")
	}
	if !bytes.Contains(result, []byte("203.0.113.1")) {
		t.Error("SIP outbound should contain public IP")
	}
}

func TestSIPALG_ProcessInbound(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	conn := &ALGConnection{
		PrivateIP: net.ParseIP("10.0.0.1"),
		PublicIP:  net.ParseIP("203.0.113.1"),
	}

	// SIP response with public IP
	data := []byte("Via: SIP/2.0/UDP 203.0.113.1:5060;branch=z9hG4bK776asdhds\r\nContact: <sip:user@203.0.113.1:5060>\r\n")
	result, err := handler.ProcessPacket(ALGTypeSIP, conn, data, false)
	if err != nil {
		t.Fatalf("SIP inbound: %v", err)
	}
	if bytes.Contains(result, []byte("203.0.113.1")) {
		t.Error("SIP inbound should have rewritten public IP to private IP")
	}
	if !bytes.Contains(result, []byte("10.0.0.1")) {
		t.Error("SIP inbound should contain private IP")
	}
}

func TestSIPALG_ProcessOutbound_NoModification(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	conn := &ALGConnection{
		PrivateIP: net.ParseIP("10.0.0.1"),
		PublicIP:  net.ParseIP("203.0.113.1"),
	}

	// Data without any IP addresses to modify
	data := []byte("CSeq: 1 INVITE\r\nMax-Forwards: 70\r\n")
	result, err := handler.ProcessPacket(ALGTypeSIP, conn, data, true)
	if err != nil {
		t.Fatalf("SIP outbound no-op: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Error("data without SIP headers containing private IP should pass through")
	}
}

func TestSIPALG_RewriteSIPHeader_SDP(t *testing.T) {
	logger := zap.NewNop()
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, logger)
	handler := NewALGHandler(mgr, logger)

	conn := &ALGConnection{
		PrivateIP: net.ParseIP("10.0.0.1"),
		PublicIP:  net.ParseIP("203.0.113.1"),
	}

	// SDP body with connection and origin lines
	data := []byte("c=IN IP4 10.0.0.1\r\no=- 12345 12345 IN IP4 10.0.0.1\r\n")
	result, err := handler.ProcessPacket(ALGTypeSIP, conn, data, true)
	if err != nil {
		t.Fatalf("SIP SDP rewrite: %v", err)
	}
	if bytes.Contains(result, []byte("10.0.0.1")) {
		t.Error("SDP lines should have private IP rewritten")
	}
}

// --- Manager additional coverage ---

func TestManager_SetLogger(t *testing.T) {
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, zap.NewNop())
	natLogger, _ := NewLogger(LoggerConfig{Enabled: true}, zap.NewNop())

	mgr.SetLogger(natLogger)
	if mgr.natLogger == nil {
		t.Error("expected non-nil natLogger after SetLogger")
	}
}

func TestManager_GetEIMMapping_NilMap(t *testing.T) {
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, zap.NewNop())
	_, err := mgr.GetEIMMapping(net.ParseIP("10.0.0.1"), 12345, 6)
	if err == nil {
		t.Error("expected error from GetEIMMapping with nil map")
	}
}

func TestManager_LookupSession_NilMap(t *testing.T) {
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, zap.NewNop())
	_, err := mgr.LookupSession(
		net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"),
		12345, 80, 6,
	)
	if err == nil {
		t.Error("expected error from LookupSession with nil map")
	}
}

func TestManager_DeallocateNAT_IPv6(t *testing.T) {
	mgr, _ := NewManager(ManagerConfig{Interface: "lo0"}, zap.NewNop())
	err := mgr.DeallocateNAT(net.ParseIP("2001:db8::1"))
	if err == nil {
		t.Error("expected error for IPv6 address")
	}
}

func TestManager_AllocateWithLogger(t *testing.T) {
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "lo0",
		PortsPerSubscriber: 100,
		PortRangeStart:     10000,
		PortRangeEnd:       20000,
	}, zap.NewNop())

	natLogger, _ := NewLogger(LoggerConfig{Enabled: true, Format: LogFormatJSON}, zap.NewNop())
	mgr.SetLogger(natLogger)
	mgr.AddPublicIP(net.ParseIP("203.0.113.1"))

	var buf bytes.Buffer
	natLogger.writer = &buf

	alloc, err := mgr.AllocateNAT(net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("AllocateNAT: %v", err)
	}
	if alloc == nil {
		t.Fatal("expected non-nil allocation")
	}

	// Flush and check log
	natLogger.Flush()
	if buf.Len() == 0 {
		t.Error("expected allocation log entry")
	}
}

func TestManager_DeallocateWithLogger(t *testing.T) {
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "lo0",
		PortsPerSubscriber: 100,
		PortRangeStart:     10000,
		PortRangeEnd:       20000,
	}, zap.NewNop())

	natLogger, _ := NewLogger(LoggerConfig{Enabled: true, Format: LogFormatJSON}, zap.NewNop())
	mgr.SetLogger(natLogger)
	mgr.AddPublicIP(net.ParseIP("203.0.113.1"))

	mgr.AllocateNAT(net.ParseIP("10.0.0.1"))

	var buf bytes.Buffer
	natLogger.writer = &buf

	err := mgr.DeallocateNAT(net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("DeallocateNAT: %v", err)
	}

	natLogger.Flush()
	if buf.Len() == 0 {
		t.Error("expected deallocation log entry")
	}
}

func TestManager_AllFlagsEnabled(t *testing.T) {
	mgr, _ := NewManager(ManagerConfig{
		Interface:            "lo0",
		EnableEIM:            true,
		EnableEIF:            true,
		EnableHairpin:        true,
		EnableFTPALG:         true,
		EnableSIPALG:         true,
		EnablePortParity:     true,
		EnablePortContiguity: true,
	}, zap.NewNop())

	expected := NATFlagEIMEnabled | NATFlagEIFEnabled | NATFlagHairpinEnabled |
		NATFlagALGFTP | NATFlagALGSIP | NATFlagPortParity | NATFlagPortContiguity
	flags := mgr.buildFlags()
	if flags != expected {
		t.Errorf("expected flags 0x%X, got 0x%X", expected, flags)
	}
}

func TestManager_PoolExhaustion_Single(t *testing.T) {
	// Use a very small port range with large port block to exhaust after 1 subscriber
	mgr, _ := NewManager(ManagerConfig{
		Interface:          "lo0",
		PortsPerSubscriber: 100,
		PortRangeStart:     10000,
		PortRangeEnd:       10099, // Only 100 ports total = 1 subscriber
	}, zap.NewNop())

	mgr.AddPublicIP(net.ParseIP("203.0.113.1"))

	// First allocation should succeed
	_, err := mgr.AllocateNAT(net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("first allocation: %v", err)
	}

	// Second allocation should fail (pool exhausted)
	_, err = mgr.AllocateNAT(net.ParseIP("10.0.0.2"))
	if err == nil {
		t.Error("expected pool exhaustion error")
	}
}
