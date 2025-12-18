package pppoe

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Ethernet types
const (
	EtherTypePPPoEDiscovery = 0x8863
	EtherTypePPPoESession   = 0x8864
)

// PPPoE codes (Discovery stage)
const (
	CodePADI = 0x09 // Active Discovery Initiation
	CodePADO = 0x07 // Active Discovery Offer
	CodePADR = 0x19 // Active Discovery Request
	CodePADS = 0x65 // Active Discovery Session-confirmation
	CodePADT = 0xA7 // Active Discovery Terminate
)

// PPPoE session code
const (
	CodeSession = 0x00
)

// PPPoE tag types
const (
	TagEndOfList      = 0x0000
	TagServiceName    = 0x0101
	TagACName         = 0x0102
	TagHostUniq       = 0x0103
	TagACCookie       = 0x0104
	TagVendorSpecific = 0x0105
	TagRelaySessionID = 0x0110
	TagServiceNameErr = 0x0201
	TagACSystemErr    = 0x0202
	TagGenericErr     = 0x0203
)

// PPP protocol numbers
const (
	ProtocolLCP    = 0xC021 // Link Control Protocol
	ProtocolPAP    = 0xC023 // Password Authentication Protocol
	ProtocolCHAP   = 0xC223 // Challenge Handshake Auth Protocol
	ProtocolIPCP   = 0x8021 // IP Control Protocol
	ProtocolIPv6CP = 0x8057 // IPv6 Control Protocol
	ProtocolIP     = 0x0021 // Internet Protocol
	ProtocolIPv6   = 0x0057 // IPv6
)

// LCP codes
const (
	LCPCodeConfigRequest = 1
	LCPCodeConfigAck     = 2
	LCPCodeConfigNak     = 3
	LCPCodeConfigReject  = 4
	LCPCodeTermRequest   = 5
	LCPCodeTermAck       = 6
	LCPCodeCodeReject    = 7
	LCPCodeProtoReject   = 8
	LCPCodeEchoRequest   = 9
	LCPCodeEchoReply     = 10
	LCPCodeDiscardReq    = 11
)

// LCP option types
const (
	LCPOptMRU         = 1 // Maximum Receive Unit
	LCPOptAuthProto   = 3 // Authentication Protocol
	LCPOptMagicNumber = 5 // Magic Number
	LCPOptPFC         = 7 // Protocol Field Compression
	LCPOptACFC        = 8 // Address/Control Field Compression
)

// PAP codes
const (
	PAPCodeAuthRequest = 1
	PAPCodeAuthAck     = 2
	PAPCodeAuthNak     = 3
)

// CHAP codes
const (
	CHAPCodeChallenge = 1
	CHAPCodeResponse  = 2
	CHAPCodeSuccess   = 3
	CHAPCodeFailure   = 4
)

// IPCP option types
const (
	IPCPOptIPAddresses   = 1   // Deprecated
	IPCPOptIPCompression = 2   // IP Compression
	IPCPOptIPAddress     = 3   // IP Address
	IPCPOptPrimaryDNS    = 129 // Primary DNS
	IPCPOptSecondaryDNS  = 131 // Secondary DNS
)

// PPPoEHeader represents a PPPoE header
type PPPoEHeader struct {
	VerType   uint8  // Version (4 bits) + Type (4 bits) = 0x11
	Code      uint8  // PPPoE code
	SessionID uint16 // Session ID
	Length    uint16 // Payload length
}

// Tag represents a PPPoE tag
type Tag struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// PPPHeader represents a PPP header
type PPPHeader struct {
	Protocol uint16
}

// LCPPacket represents an LCP packet
type LCPPacket struct {
	Code       uint8
	Identifier uint8
	Length     uint16
	Data       []byte
}

// LCPOption represents an LCP configuration option
type LCPOption struct {
	Type   uint8
	Length uint8
	Data   []byte
}

// ParsePPPoEHeader parses a PPPoE header from bytes
func ParsePPPoEHeader(data []byte) (*PPPoEHeader, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("data too short for PPPoE header")
	}

	return &PPPoEHeader{
		VerType:   data[0],
		Code:      data[1],
		SessionID: binary.BigEndian.Uint16(data[2:4]),
		Length:    binary.BigEndian.Uint16(data[4:6]),
	}, nil
}

// Serialize serializes a PPPoE header to bytes
func (h *PPPoEHeader) Serialize() []byte {
	buf := make([]byte, 6)
	buf[0] = h.VerType
	buf[1] = h.Code
	binary.BigEndian.PutUint16(buf[2:4], h.SessionID)
	binary.BigEndian.PutUint16(buf[4:6], h.Length)
	return buf
}

// ParseTags parses PPPoE tags from payload
func ParseTags(data []byte) ([]Tag, error) {
	var tags []Tag
	offset := 0

	for offset+4 <= len(data) {
		tagType := binary.BigEndian.Uint16(data[offset : offset+2])
		tagLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])

		if tagType == TagEndOfList {
			break
		}

		if offset+4+int(tagLen) > len(data) {
			return nil, fmt.Errorf("tag length exceeds data")
		}

		tag := Tag{
			Type:   tagType,
			Length: tagLen,
			Value:  make([]byte, tagLen),
		}
		copy(tag.Value, data[offset+4:offset+4+int(tagLen)])
		tags = append(tags, tag)

		offset += 4 + int(tagLen)
	}

	return tags, nil
}

// SerializeTags serializes PPPoE tags to bytes
func SerializeTags(tags []Tag) []byte {
	var buf []byte
	for _, tag := range tags {
		tagBuf := make([]byte, 4+len(tag.Value))
		binary.BigEndian.PutUint16(tagBuf[0:2], tag.Type)
		binary.BigEndian.PutUint16(tagBuf[2:4], uint16(len(tag.Value)))
		copy(tagBuf[4:], tag.Value)
		buf = append(buf, tagBuf...)
	}
	return buf
}

// FindTag finds a tag by type
func FindTag(tags []Tag, tagType uint16) *Tag {
	for i := range tags {
		if tags[i].Type == tagType {
			return &tags[i]
		}
	}
	return nil
}

// ParseLCPPacket parses an LCP packet
func ParseLCPPacket(data []byte) (*LCPPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for LCP packet")
	}

	pkt := &LCPPacket{
		Code:       data[0],
		Identifier: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
	}

	if int(pkt.Length) > len(data) {
		return nil, fmt.Errorf("LCP length exceeds data")
	}

	if pkt.Length > 4 {
		pkt.Data = make([]byte, pkt.Length-4)
		copy(pkt.Data, data[4:pkt.Length])
	}

	return pkt, nil
}

// Serialize serializes an LCP packet
func (p *LCPPacket) Serialize() []byte {
	buf := make([]byte, 4+len(p.Data))
	buf[0] = p.Code
	buf[1] = p.Identifier
	binary.BigEndian.PutUint16(buf[2:4], uint16(4+len(p.Data)))
	copy(buf[4:], p.Data)
	return buf
}

// ParseLCPOptions parses LCP options from data
func ParseLCPOptions(data []byte) ([]LCPOption, error) {
	var opts []LCPOption
	offset := 0

	for offset+2 <= len(data) {
		optType := data[offset]
		optLen := data[offset+1]

		if optLen < 2 {
			return nil, fmt.Errorf("invalid option length")
		}

		if offset+int(optLen) > len(data) {
			return nil, fmt.Errorf("option length exceeds data")
		}

		opt := LCPOption{
			Type:   optType,
			Length: optLen,
		}
		if optLen > 2 {
			opt.Data = make([]byte, optLen-2)
			copy(opt.Data, data[offset+2:offset+int(optLen)])
		}
		opts = append(opts, opt)

		offset += int(optLen)
	}

	return opts, nil
}

// SerializeLCPOptions serializes LCP options
func SerializeLCPOptions(opts []LCPOption) []byte {
	var buf []byte
	for _, opt := range opts {
		optBuf := make([]byte, 2+len(opt.Data))
		optBuf[0] = opt.Type
		optBuf[1] = uint8(2 + len(opt.Data))
		copy(optBuf[2:], opt.Data)
		buf = append(buf, optBuf...)
	}
	return buf
}

// BuildEthernetFrame builds a complete Ethernet frame
func BuildEthernetFrame(dst, src net.HardwareAddr, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}
