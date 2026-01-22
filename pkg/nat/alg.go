package nat

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// ALGHandler handles Application Layer Gateway protocol processing
// ALGs inspect and modify application-layer data that contains embedded IP addresses
type ALGHandler struct {
	manager  *Manager
	logger   *zap.Logger
	handlers map[uint8]ProtocolALG

	// Dynamic port mappings created by ALGs
	dynamicMappings   map[string]*DynamicMapping
	dynamicMappingsMu sync.RWMutex
}

// ProtocolALG interface for protocol-specific ALG implementations
type ProtocolALG interface {
	// Name returns the ALG name
	Name() string
	// ProcessOutbound processes outbound traffic (subscriber -> internet)
	ProcessOutbound(conn *ALGConnection, data []byte) ([]byte, error)
	// ProcessInbound processes inbound traffic (internet -> subscriber)
	ProcessInbound(conn *ALGConnection, data []byte) ([]byte, error)
}

// ALGConnection represents a connection being processed by an ALG
type ALGConnection struct {
	SubscriberID uint32
	PrivateIP    net.IP
	PrivatePort  uint16
	PublicIP     net.IP
	PublicPort   uint16
	DestIP       net.IP
	DestPort     uint16
	Protocol     uint8 // TCP=6, UDP=17
}

// DynamicMapping represents a dynamic NAT mapping created by an ALG
// For example, FTP data connections created in response to PORT/PASV commands
type DynamicMapping struct {
	PrivateIP   net.IP
	PrivatePort uint16
	PublicIP    net.IP
	PublicPort  uint16
	DestIP      net.IP
	DestPort    uint16
	Protocol    uint8
	ParentConn  *ALGConnection // The control connection that created this
	ALGType     uint8
	CreatedAt   int64
	ExpiresAt   int64
}

// NewALGHandler creates a new ALG handler
func NewALGHandler(manager *Manager, logger *zap.Logger) *ALGHandler {
	handler := &ALGHandler{
		manager:         manager,
		logger:          logger,
		handlers:        make(map[uint8]ProtocolALG),
		dynamicMappings: make(map[string]*DynamicMapping),
	}

	// Register built-in ALGs
	handler.RegisterALG(ALGTypeFTP, NewFTPALG(handler, logger))
	handler.RegisterALG(ALGTypeSIP, NewSIPALG(handler, logger))

	return handler
}

// RegisterALG registers an ALG handler for a specific ALG type
func (h *ALGHandler) RegisterALG(algType uint8, alg ProtocolALG) {
	h.handlers[algType] = alg
	h.logger.Info("Registered ALG", zap.String("name", alg.Name()), zap.Uint8("type", algType))
}

// ProcessPacket processes a packet through the appropriate ALG
func (h *ALGHandler) ProcessPacket(algType uint8, conn *ALGConnection, data []byte, outbound bool) ([]byte, error) {
	alg, ok := h.handlers[algType]
	if !ok {
		return data, nil // No ALG handler, pass through
	}

	if outbound {
		return alg.ProcessOutbound(conn, data)
	}
	return alg.ProcessInbound(conn, data)
}

// AddDynamicMapping adds a dynamic NAT mapping created by an ALG
func (h *ALGHandler) AddDynamicMapping(mapping *DynamicMapping) error {
	key := fmt.Sprintf("%s:%d:%d", mapping.PrivateIP.String(), mapping.PrivatePort, mapping.Protocol)

	h.dynamicMappingsMu.Lock()
	h.dynamicMappings[key] = mapping
	h.dynamicMappingsMu.Unlock()

	// Also add to the eBPF map for fast-path processing
	if h.manager != nil && h.manager.subscriberNAT != nil {
		// The dynamic mapping will be handled by the existing NAT session mechanism
		h.logger.Debug("Added dynamic ALG mapping",
			zap.String("private", fmt.Sprintf("%s:%d", mapping.PrivateIP, mapping.PrivatePort)),
			zap.String("public", fmt.Sprintf("%s:%d", mapping.PublicIP, mapping.PublicPort)),
		)
	}

	return nil
}

// GetDynamicMapping retrieves a dynamic mapping
func (h *ALGHandler) GetDynamicMapping(privateIP net.IP, privatePort uint16, protocol uint8) *DynamicMapping {
	key := fmt.Sprintf("%s:%d:%d", privateIP.String(), privatePort, protocol)

	h.dynamicMappingsMu.RLock()
	defer h.dynamicMappingsMu.RUnlock()

	return h.dynamicMappings[key]
}

// FTPALG handles FTP Application Layer Gateway
// TODO: This is a placeholder implementation. For production use, the following is needed:
// - Proper port allocation from subscriber's port block instead of simple offset
// - Full FTP command parsing with proper state machine
// - Support for multi-line FTP responses
// - Timeout handling for dynamic mappings
// - Thread-safe port allocation with atomic operations
type FTPALG struct {
	handler *ALGHandler
	logger  *zap.Logger

	// Regex patterns for FTP commands
	portPattern *regexp.Regexp
	pasvPattern *regexp.Regexp
	eprtPattern *regexp.Regexp
	epsvPattern *regexp.Regexp
}

// NewFTPALG creates a new FTP ALG
func NewFTPALG(handler *ALGHandler, logger *zap.Logger) *FTPALG {
	return &FTPALG{
		handler: handler,
		logger:  logger,
		// PORT h1,h2,h3,h4,p1,p2 - where IP = h1.h2.h3.h4 and port = p1*256 + p2
		portPattern: regexp.MustCompile(`(?i)PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)`),
		// 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
		pasvPattern: regexp.MustCompile(`227\s+.*\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`),
		// EPRT |1|ip|port| or EPRT |2|ip|port| (IPv4/IPv6)
		eprtPattern: regexp.MustCompile(`(?i)EPRT\s+\|1\|([^|]+)\|(\d+)\|`),
		// 229 Entering Extended Passive Mode (|||port|)
		epsvPattern: regexp.MustCompile(`229\s+.*\(\|\|\|(\d+)\|\)`),
	}
}

// Name returns the ALG name
func (f *FTPALG) Name() string {
	return "FTP"
}

// ProcessOutbound processes outbound FTP traffic
func (f *FTPALG) ProcessOutbound(conn *ALGConnection, data []byte) ([]byte, error) {
	// Look for PORT or EPRT commands
	lines := strings.Split(string(data), "\r\n")
	modified := false

	for i, line := range lines {
		// Process PORT command
		if matches := f.portPattern.FindStringSubmatch(line); matches != nil {
			newLine, err := f.rewritePortCommand(conn, matches)
			if err != nil {
				f.logger.Warn("Failed to rewrite PORT command", zap.Error(err))
				continue
			}
			lines[i] = newLine
			modified = true
			f.logger.Debug("Rewrote FTP PORT command",
				zap.String("original", line),
				zap.String("rewritten", newLine),
			)
		}

		// Process EPRT command
		if matches := f.eprtPattern.FindStringSubmatch(line); matches != nil {
			newLine, err := f.rewriteEPRTCommand(conn, matches)
			if err != nil {
				f.logger.Warn("Failed to rewrite EPRT command", zap.Error(err))
				continue
			}
			lines[i] = newLine
			modified = true
			f.logger.Debug("Rewrote FTP EPRT command",
				zap.String("original", line),
				zap.String("rewritten", newLine),
			)
		}
	}

	if modified {
		return []byte(strings.Join(lines, "\r\n")), nil
	}
	return data, nil
}

// ProcessInbound processes inbound FTP traffic
func (f *FTPALG) ProcessInbound(conn *ALGConnection, data []byte) ([]byte, error) {
	// Look for PASV or EPSV responses
	lines := strings.Split(string(data), "\r\n")
	modified := false

	for i, line := range lines {
		// Process PASV response (227)
		if matches := f.pasvPattern.FindStringSubmatch(line); matches != nil {
			newLine, err := f.rewritePasvResponse(conn, matches, line)
			if err != nil {
				f.logger.Warn("Failed to rewrite PASV response", zap.Error(err))
				continue
			}
			lines[i] = newLine
			modified = true
			f.logger.Debug("Rewrote FTP PASV response",
				zap.String("original", line),
				zap.String("rewritten", newLine),
			)
		}

		// Process EPSV response (229)
		if matches := f.epsvPattern.FindStringSubmatch(line); matches != nil {
			// EPSV doesn't need IP rewriting, just port mapping
			// Create dynamic mapping for the data connection
			port, _ := strconv.Atoi(matches[1])
			f.createDataConnectionMapping(conn, conn.PrivateIP, uint16(port))
		}
	}

	if modified {
		return []byte(strings.Join(lines, "\r\n")), nil
	}
	return data, nil
}

// rewritePortCommand rewrites a PORT command with the NAT'd address
func (f *FTPALG) rewritePortCommand(conn *ALGConnection, matches []string) (string, error) {
	// Parse original IP and port
	h1, _ := strconv.Atoi(matches[1])
	h2, _ := strconv.Atoi(matches[2])
	h3, _ := strconv.Atoi(matches[3])
	h4, _ := strconv.Atoi(matches[4])
	p1, _ := strconv.Atoi(matches[5])
	p2, _ := strconv.Atoi(matches[6])

	origIP := net.IPv4(byte(h1), byte(h2), byte(h3), byte(h4))
	origPort := uint16(p1*256 + p2)

	// Get NAT mapping for the data connection
	// For active FTP, the client listens, so we need to create an inbound mapping
	mapping, err := f.handler.manager.AllocateNAT(origIP)
	if err != nil {
		return "", err
	}

	// Use a port from the allocated block for the data connection
	natPort := mapping.PortStart + 1 // Simple allocation, should be more sophisticated

	// Create dynamic mapping for the data connection
	f.createDataConnectionMapping(conn, origIP, origPort)

	// Rewrite with public IP and port
	pubIP := conn.PublicIP.To4()
	return fmt.Sprintf("PORT %d,%d,%d,%d,%d,%d",
		pubIP[0], pubIP[1], pubIP[2], pubIP[3],
		natPort/256, natPort%256), nil
}

// rewriteEPRTCommand rewrites an EPRT command with the NAT'd address
func (f *FTPALG) rewriteEPRTCommand(conn *ALGConnection, matches []string) (string, error) {
	origIP := net.ParseIP(matches[1])
	origPort, _ := strconv.Atoi(matches[2])

	// Get NAT mapping for the data connection
	mapping, err := f.handler.manager.AllocateNAT(origIP)
	if err != nil {
		return "", err
	}

	natPort := mapping.PortStart + 1

	// Create dynamic mapping
	f.createDataConnectionMapping(conn, origIP, uint16(origPort))

	return fmt.Sprintf("EPRT |1|%s|%d|", conn.PublicIP.String(), natPort), nil
}

// rewritePasvResponse rewrites a PASV response with the correct public address
func (f *FTPALG) rewritePasvResponse(conn *ALGConnection, matches []string, originalLine string) (string, error) {
	// Parse server's data port
	h1, _ := strconv.Atoi(matches[1])
	h2, _ := strconv.Atoi(matches[2])
	h3, _ := strconv.Atoi(matches[3])
	h4, _ := strconv.Atoi(matches[4])
	p1, _ := strconv.Atoi(matches[5])
	p2, _ := strconv.Atoi(matches[6])

	serverIP := net.IPv4(byte(h1), byte(h2), byte(h3), byte(h4))
	serverPort := uint16(p1*256 + p2)

	// For passive FTP, the server listens, so we create an outbound mapping
	// to allow the client to connect to the server
	f.createDataConnectionMapping(conn, serverIP, serverPort)

	// The response IP/port stays the same (server's address)
	// We just need to ensure the outbound connection will be allowed
	return originalLine, nil
}

// createDataConnectionMapping creates a dynamic mapping for FTP data connections
func (f *FTPALG) createDataConnectionMapping(conn *ALGConnection, dataIP net.IP, dataPort uint16) {
	mapping := &DynamicMapping{
		PrivateIP:   conn.PrivateIP,
		PrivatePort: dataPort,
		PublicIP:    conn.PublicIP,
		PublicPort:  dataPort, // Ideally should be allocated from port block
		DestIP:      dataIP,
		DestPort:    dataPort,
		Protocol:    6, // TCP
		ParentConn:  conn,
		ALGType:     ALGTypeFTP,
	}

	f.handler.AddDynamicMapping(mapping)
}

// SIPALG handles SIP Application Layer Gateway
// Note: SIP ALG is controversial and often causes issues with modern VoIP
// Consider disabling by default as most SIP implementations use STUN/TURN/ICE
// TODO: This is a placeholder implementation. For production use, the following is needed:
// - Proper SIP message parsing (RFC 3261) instead of simple string replacement
// - Full SDP parsing (RFC 4566) for media port extraction
// - Proper port allocation from subscriber's port block for RTP/RTCP streams
// - Support for SIP over TCP and TLS (currently only basic UDP parsing)
// - Via header manipulation with proper branch parameter handling
// - Record-Route header support for dialog routing
// - SIP registration binding management
type SIPALG struct {
	handler *ALGHandler
	logger  *zap.Logger
}

// NewSIPALG creates a new SIP ALG
func NewSIPALG(handler *ALGHandler, logger *zap.Logger) *SIPALG {
	return &SIPALG{
		handler: handler,
		logger:  logger,
	}
}

// Name returns the ALG name
func (s *SIPALG) Name() string {
	return "SIP"
}

// ProcessOutbound processes outbound SIP traffic
func (s *SIPALG) ProcessOutbound(conn *ALGConnection, data []byte) ([]byte, error) {
	// Parse SIP message
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	var modified bool

	for scanner.Scan() {
		line := scanner.Text()
		newLine := s.rewriteSIPHeader(conn, line, true)
		if newLine != line {
			modified = true
		}
		lines = append(lines, newLine)
	}

	// Process SDP body if present
	// SDP contains c= (connection) and m= (media) lines with IP addresses

	if modified {
		return []byte(strings.Join(lines, "\r\n")), nil
	}
	return data, nil
}

// ProcessInbound processes inbound SIP traffic
func (s *SIPALG) ProcessInbound(conn *ALGConnection, data []byte) ([]byte, error) {
	// For inbound, we need to rewrite public IP back to private
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	var modified bool

	for scanner.Scan() {
		line := scanner.Text()
		newLine := s.rewriteSIPHeader(conn, line, false)
		if newLine != line {
			modified = true
		}
		lines = append(lines, newLine)
	}

	if modified {
		return []byte(strings.Join(lines, "\r\n")), nil
	}
	return data, nil
}

// rewriteSIPHeader rewrites SIP headers that contain IP addresses
func (s *SIPALG) rewriteSIPHeader(conn *ALGConnection, line string, outbound bool) string {
	// Headers that may contain IP addresses:
	// Via: SIP/2.0/UDP host:port
	// Contact: <sip:user@host:port>
	// From: <sip:user@host>
	// To: <sip:user@host>
	// Call-ID: unique-id@host
	// c=IN IP4 host (SDP)
	// m=audio port RTP/AVP ... (SDP)
	// o=- sess-id sess-version IN IP4 host (SDP)

	var oldIP, newIP string
	if outbound {
		oldIP = conn.PrivateIP.String()
		newIP = conn.PublicIP.String()
	} else {
		oldIP = conn.PublicIP.String()
		newIP = conn.PrivateIP.String()
	}

	// Simple replacement - in production, use proper SIP parsing
	// to avoid replacing IPs in wrong contexts
	if strings.Contains(line, oldIP) {
		// Check if this is a header we should modify
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "via:") ||
			strings.HasPrefix(lowerLine, "contact:") ||
			strings.HasPrefix(lowerLine, "c=") ||
			strings.HasPrefix(lowerLine, "o=") {
			return strings.Replace(line, oldIP, newIP, -1)
		}
	}

	return line
}

// createRTPMapping creates dynamic mappings for RTP/RTCP media streams
func (s *SIPALG) createRTPMapping(conn *ALGConnection, mediaPort uint16) {
	// RTP typically uses even ports, RTCP uses the next odd port
	rtpMapping := &DynamicMapping{
		PrivateIP:   conn.PrivateIP,
		PrivatePort: mediaPort,
		PublicIP:    conn.PublicIP,
		PublicPort:  mediaPort, // Ideally preserve port or allocate from block
		Protocol:    17,        // UDP
		ParentConn:  conn,
		ALGType:     ALGTypeSIP,
	}
	s.handler.AddDynamicMapping(rtpMapping)

	// RTCP on port+1
	rtcpMapping := &DynamicMapping{
		PrivateIP:   conn.PrivateIP,
		PrivatePort: mediaPort + 1,
		PublicIP:    conn.PublicIP,
		PublicPort:  mediaPort + 1,
		Protocol:    17, // UDP
		ParentConn:  conn,
		ALGType:     ALGTypeSIP,
	}
	s.handler.AddDynamicMapping(rtcpMapping)
}
