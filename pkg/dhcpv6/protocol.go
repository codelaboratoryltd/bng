package dhcpv6

import (
	"encoding/binary"
	"fmt"
	"net"
)

// DHCPv6 message types
const (
	MsgTypeSolicit            = 1
	MsgTypeAdvertise          = 2
	MsgTypeRequest            = 3
	MsgTypeConfirm            = 4
	MsgTypeRenew              = 5
	MsgTypeRebind             = 6
	MsgTypeReply              = 7
	MsgTypeRelease            = 8
	MsgTypeDecline            = 9
	MsgTypeReconfigure        = 10
	MsgTypeInformationRequest = 11
	MsgTypeRelayForw          = 12
	MsgTypeRelayRepl          = 13
)

// DHCPv6 option types
const (
	OptClientID           = 1
	OptServerID           = 2
	OptIANA               = 3 // Identity Association for Non-temporary Addresses
	OptIATA               = 4 // Identity Association for Temporary Addresses
	OptIAAddr             = 5 // IA Address
	OptORO                = 6 // Option Request Option
	OptPreference         = 7
	OptElapsedTime        = 8
	OptRelayMsg           = 9
	OptAuth               = 11
	OptUnicast            = 12
	OptStatusCode         = 13
	OptRapidCommit        = 14
	OptUserClass          = 15
	OptVendorClass        = 16
	OptVendorOpts         = 17
	OptInterfaceID        = 18
	OptReconfMsg          = 19
	OptReconfAccept       = 20
	OptSIPServerDomains   = 21
	OptSIPServerAddresses = 22
	OptDNSServers         = 23
	OptDomainList         = 24
	OptIAPD               = 25 // Identity Association for Prefix Delegation
	OptIAPrefix           = 26
	OptNISServers         = 27
	OptNISPlusServers     = 28
	OptNISDomain          = 29
	OptNISPlusDomain      = 30
	OptSNTPServers        = 31
	OptInformationRefresh = 32
	OptBCMCSServer        = 33
	OptBCMCSAddress       = 34
	OptClientFQDN         = 39
	OptSOLMaxRT           = 82
	OptINFMaxRT           = 83
)

// DHCPv6 status codes
const (
	StatusSuccess       = 0
	StatusUnspecFail    = 1
	StatusNoAddrsAvail  = 2
	StatusNoBinding     = 3
	StatusNotOnLink     = 4
	StatusUseMulticast  = 5
	StatusNoPrefixAvail = 6
)

// DUID types
const (
	DUIDTypeLLT  = 1 // Link-layer address plus time
	DUIDTypeEN   = 2 // Vendor-assigned
	DUIDTypeLL   = 3 // Link-layer address
	DUIDTypeUUID = 4 // UUID
)

// Well-known multicast addresses
var (
	AllDHCPRelayAgentsAndServers = net.ParseIP("ff02::1:2")
	AllDHCPServers               = net.ParseIP("ff05::1:3")
)

// Ports
const (
	DHCPv6ClientPort = 546
	DHCPv6ServerPort = 547
)

// Message represents a DHCPv6 message
type Message struct {
	Type          uint8
	TransactionID [3]byte
	Options       []Option
}

// RelayMessage represents a DHCPv6 relay message
type RelayMessage struct {
	Type        uint8
	HopCount    uint8
	LinkAddress net.IP
	PeerAddress net.IP
	Options     []Option
}

// Option represents a DHCPv6 option
type Option struct {
	Code   uint16
	Length uint16
	Data   []byte
}

// DUID represents a DHCP Unique Identifier
type DUID struct {
	Type uint16
	Data []byte
}

// IANA represents an Identity Association for Non-temporary Addresses
type IANA struct {
	IAID    uint32
	T1      uint32 // Time until renewal
	T2      uint32 // Time until rebind
	Options []Option
}

// IAPD represents an Identity Association for Prefix Delegation
type IAPD struct {
	IAID    uint32
	T1      uint32
	T2      uint32
	Options []Option
}

// IAAddress represents an IPv6 address option within IA_NA or IA_TA
type IAAddress struct {
	Address           net.IP
	PreferredLifetime uint32
	ValidLifetime     uint32
	Options           []Option
}

// IAPrefix represents a delegated prefix
type IAPrefix struct {
	PreferredLifetime uint32
	ValidLifetime     uint32
	PrefixLength      uint8
	Prefix            net.IP
	Options           []Option
}

// StatusCode represents a status code option
type StatusCode struct {
	Code    uint16
	Message string
}

// ParseMessage parses a DHCPv6 message
func ParseMessage(data []byte) (*Message, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("message too short")
	}

	msg := &Message{
		Type: data[0],
	}
	copy(msg.TransactionID[:], data[1:4])

	// Parse options
	opts, err := ParseOptions(data[4:])
	if err != nil {
		return nil, err
	}
	msg.Options = opts

	return msg, nil
}

// Serialize serializes a DHCPv6 message
func (m *Message) Serialize() []byte {
	buf := make([]byte, 4)
	buf[0] = m.Type
	copy(buf[1:4], m.TransactionID[:])
	buf = append(buf, SerializeOptions(m.Options)...)
	return buf
}

// GetOption returns the first option of the specified type
func (m *Message) GetOption(code uint16) *Option {
	for i := range m.Options {
		if m.Options[i].Code == code {
			return &m.Options[i]
		}
	}
	return nil
}

// GetAllOptions returns all options of the specified type
func (m *Message) GetAllOptions(code uint16) []Option {
	var opts []Option
	for _, opt := range m.Options {
		if opt.Code == code {
			opts = append(opts, opt)
		}
	}
	return opts
}

// ParseOptions parses DHCPv6 options from bytes
func ParseOptions(data []byte) ([]Option, error) {
	var opts []Option
	offset := 0

	for offset+4 <= len(data) {
		code := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])

		if offset+4+int(length) > len(data) {
			return nil, fmt.Errorf("option length exceeds data")
		}

		opt := Option{
			Code:   code,
			Length: length,
			Data:   make([]byte, length),
		}
		copy(opt.Data, data[offset+4:offset+4+int(length)])
		opts = append(opts, opt)

		offset += 4 + int(length)
	}

	return opts, nil
}

// SerializeOptions serializes DHCPv6 options
func SerializeOptions(opts []Option) []byte {
	var buf []byte
	for _, opt := range opts {
		optBuf := make([]byte, 4+len(opt.Data))
		binary.BigEndian.PutUint16(optBuf[0:2], opt.Code)
		binary.BigEndian.PutUint16(optBuf[2:4], uint16(len(opt.Data)))
		copy(optBuf[4:], opt.Data)
		buf = append(buf, optBuf...)
	}
	return buf
}

// ParseDUID parses a DUID from bytes
func ParseDUID(data []byte) (*DUID, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("DUID too short")
	}

	return &DUID{
		Type: binary.BigEndian.Uint16(data[0:2]),
		Data: data[2:],
	}, nil
}

// Serialize serializes a DUID
func (d *DUID) Serialize() []byte {
	buf := make([]byte, 2+len(d.Data))
	binary.BigEndian.PutUint16(buf[0:2], d.Type)
	copy(buf[2:], d.Data)
	return buf
}

// ParseIANA parses an IA_NA option
func ParseIANA(data []byte) (*IANA, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("IA_NA too short")
	}

	iana := &IANA{
		IAID: binary.BigEndian.Uint32(data[0:4]),
		T1:   binary.BigEndian.Uint32(data[4:8]),
		T2:   binary.BigEndian.Uint32(data[8:12]),
	}

	if len(data) > 12 {
		opts, err := ParseOptions(data[12:])
		if err != nil {
			return nil, err
		}
		iana.Options = opts
	}

	return iana, nil
}

// Serialize serializes an IA_NA option
func (ia *IANA) Serialize() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], ia.IAID)
	binary.BigEndian.PutUint32(buf[4:8], ia.T1)
	binary.BigEndian.PutUint32(buf[8:12], ia.T2)
	buf = append(buf, SerializeOptions(ia.Options)...)
	return buf
}

// ParseIAPD parses an IA_PD option
func ParseIAPD(data []byte) (*IAPD, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("IA_PD too short")
	}

	iapd := &IAPD{
		IAID: binary.BigEndian.Uint32(data[0:4]),
		T1:   binary.BigEndian.Uint32(data[4:8]),
		T2:   binary.BigEndian.Uint32(data[8:12]),
	}

	if len(data) > 12 {
		opts, err := ParseOptions(data[12:])
		if err != nil {
			return nil, err
		}
		iapd.Options = opts
	}

	return iapd, nil
}

// Serialize serializes an IA_PD option
func (ia *IAPD) Serialize() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], ia.IAID)
	binary.BigEndian.PutUint32(buf[4:8], ia.T1)
	binary.BigEndian.PutUint32(buf[8:12], ia.T2)
	buf = append(buf, SerializeOptions(ia.Options)...)
	return buf
}

// ParseIAAddress parses an IA Address option
func ParseIAAddress(data []byte) (*IAAddress, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("IA Address too short")
	}

	addr := &IAAddress{
		Address:           net.IP(data[0:16]),
		PreferredLifetime: binary.BigEndian.Uint32(data[16:20]),
		ValidLifetime:     binary.BigEndian.Uint32(data[20:24]),
	}

	if len(data) > 24 {
		opts, err := ParseOptions(data[24:])
		if err != nil {
			return nil, err
		}
		addr.Options = opts
	}

	return addr, nil
}

// Serialize serializes an IA Address option
func (a *IAAddress) Serialize() []byte {
	buf := make([]byte, 24)
	copy(buf[0:16], a.Address.To16())
	binary.BigEndian.PutUint32(buf[16:20], a.PreferredLifetime)
	binary.BigEndian.PutUint32(buf[20:24], a.ValidLifetime)
	buf = append(buf, SerializeOptions(a.Options)...)
	return buf
}

// ParseIAPrefix parses an IA Prefix option
func ParseIAPrefix(data []byte) (*IAPrefix, error) {
	if len(data) < 25 {
		return nil, fmt.Errorf("IA Prefix too short")
	}

	prefix := &IAPrefix{
		PreferredLifetime: binary.BigEndian.Uint32(data[0:4]),
		ValidLifetime:     binary.BigEndian.Uint32(data[4:8]),
		PrefixLength:      data[8],
		Prefix:            net.IP(data[9:25]),
	}

	if len(data) > 25 {
		opts, err := ParseOptions(data[25:])
		if err != nil {
			return nil, err
		}
		prefix.Options = opts
	}

	return prefix, nil
}

// Serialize serializes an IA Prefix option
func (p *IAPrefix) Serialize() []byte {
	buf := make([]byte, 25)
	binary.BigEndian.PutUint32(buf[0:4], p.PreferredLifetime)
	binary.BigEndian.PutUint32(buf[4:8], p.ValidLifetime)
	buf[8] = p.PrefixLength
	copy(buf[9:25], p.Prefix.To16())
	buf = append(buf, SerializeOptions(p.Options)...)
	return buf
}

// MakeStatusCodeOption creates a status code option
func MakeStatusCodeOption(code uint16, message string) Option {
	data := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(data[0:2], code)
	copy(data[2:], message)
	return Option{Code: OptStatusCode, Data: data}
}

// MakeDNSServersOption creates a DNS servers option
func MakeDNSServersOption(servers []net.IP) Option {
	data := make([]byte, 16*len(servers))
	for i, srv := range servers {
		copy(data[i*16:(i+1)*16], srv.To16())
	}
	return Option{Code: OptDNSServers, Data: data}
}

// MakeServerIDOption creates a server ID option from a DUID
func MakeServerIDOption(duid *DUID) Option {
	return Option{Code: OptServerID, Data: duid.Serialize()}
}

// MakeClientIDOption creates a client ID option from raw data
func MakeClientIDOption(data []byte) Option {
	return Option{Code: OptClientID, Data: data}
}

// MakeIANAOption creates an IA_NA option
func MakeIANAOption(iana *IANA) Option {
	return Option{Code: OptIANA, Data: iana.Serialize()}
}

// MakeIAPDOption creates an IA_PD option
func MakeIAPDOption(iapd *IAPD) Option {
	return Option{Code: OptIAPD, Data: iapd.Serialize()}
}

// MakeIAAddressOption creates an IA Address option
func MakeIAAddressOption(addr *IAAddress) Option {
	return Option{Code: OptIAAddr, Data: addr.Serialize()}
}

// MakeIAPrefixOption creates an IA Prefix option
func MakeIAPrefixOption(prefix *IAPrefix) Option {
	return Option{Code: OptIAPrefix, Data: prefix.Serialize()}
}
