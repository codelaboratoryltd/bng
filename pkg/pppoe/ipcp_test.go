package pppoe_test

import (
	"encoding/binary"
	"net"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/pppoe"
)

var _ = Describe("IPCP State Machine", func() {
	var (
		ipcp          *pppoe.IPCPStateMachine
		config        pppoe.IPCPConfig
		sentPackets   [][]byte
		sentPacketsMu sync.Mutex
		logger        *zap.Logger
	)

	sendPacket := func(protocol uint16, data []byte) {
		sentPacketsMu.Lock()
		defer sentPacketsMu.Unlock()
		pktCopy := make([]byte, len(data))
		copy(pktCopy, data)
		sentPackets = append(sentPackets, pktCopy)
	}

	getLastPacket := func() []byte {
		sentPacketsMu.Lock()
		defer sentPacketsMu.Unlock()
		if len(sentPackets) == 0 {
			return nil
		}
		return sentPackets[len(sentPackets)-1]
	}

	clearPackets := func() {
		sentPacketsMu.Lock()
		defer sentPacketsMu.Unlock()
		sentPackets = nil
	}

	BeforeEach(func() {
		logger, _ = zap.NewDevelopment()
		config = pppoe.DefaultIPCPConfig()
		config.LocalIP = net.ParseIP("10.0.0.1")
		config.PeerIP = net.ParseIP("10.0.0.100")
		config.PrimaryDNS = net.ParseIP("8.8.8.8")
		config.SecondaryDNS = net.ParseIP("8.8.4.4")
		sentPackets = nil
		ipcp = pppoe.NewIPCPStateMachine(config, "test-session", sendPacket, logger)
	})

	Describe("State Machine Initialization", func() {
		It("should start in Initial state", func() {
			Expect(ipcp.GetState()).To(Equal(pppoe.IPCPStateInitial))
		})

		It("should have configured local IP", func() {
			opts := ipcp.GetNegotiatedOptions()
			Expect(opts.LocalIP.String()).To(Equal("10.0.0.1"))
		})
	})

	Describe("State Transitions", func() {
		Context("from Initial state", func() {
			It("should transition to Closed on Up", func() {
				ipcp.Up()
				Expect(ipcp.GetState()).To(Equal(pppoe.IPCPStateClosed))
			})

			It("should transition to Starting on Open", func() {
				ipcp.Open()
				Expect(ipcp.GetState()).To(Equal(pppoe.IPCPStateStarting))
			})
		})

		Context("from Closed state", func() {
			BeforeEach(func() {
				ipcp.Up()
			})

			It("should transition to Req-Sent on Open", func() {
				ipcp.Open()
				Expect(ipcp.GetState()).To(Equal(pppoe.IPCPStateReqSent))
			})
		})
	})

	Describe("Configure-Request Handling", func() {
		BeforeEach(func() {
			ipcp.Up()
			ipcp.Open()
			clearPackets()
		})

		It("should NAK peer requesting 0.0.0.0 with assigned IP", func() {
			configReq := buildIPCPConfigureRequest(1, net.IPv4zero)
			err := ipcp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigNak)))

			// Verify NAK contains our assigned IP
			lcpPkt, _ := pppoe.ParseLCPPacket(pkt)
			opts, _ := pppoe.ParseLCPOptions(lcpPkt.Data)
			Expect(opts).NotTo(BeEmpty())

			// Find IP-Address option
			var ipOpt *pppoe.LCPOption
			for i := range opts {
				if opts[i].Type == pppoe.IPCPOptIPAddress {
					ipOpt = &opts[i]
					break
				}
			}
			Expect(ipOpt).NotTo(BeNil())
			nakIP := net.IP(ipOpt.Data)
			Expect(nakIP.String()).To(Equal("10.0.0.100"))
		})

		It("should NAK peer requesting wrong IP", func() {
			configReq := buildIPCPConfigureRequest(1, net.ParseIP("192.168.1.1"))
			err := ipcp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigNak)))
		})

		It("should ACK peer requesting correct IP", func() {
			configReq := buildIPCPConfigureRequest(1, net.ParseIP("10.0.0.100"))
			err := ipcp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigAck)))
		})

		It("should provide DNS servers when requested with 0.0.0.0", func() {
			configReq := buildIPCPConfigureRequestWithDNS(1, net.IPv4zero, net.IPv4zero, net.IPv4zero)
			err := ipcp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigNak)))

			// Verify NAK contains DNS servers
			lcpPkt, _ := pppoe.ParseLCPPacket(pkt)
			opts, _ := pppoe.ParseLCPOptions(lcpPkt.Data)

			var primaryDNS, secondaryDNS net.IP
			for _, opt := range opts {
				if opt.Type == pppoe.IPCPOptPrimaryDNS {
					primaryDNS = net.IP(opt.Data)
				}
				if opt.Type == pppoe.IPCPOptSecondaryDNS {
					secondaryDNS = net.IP(opt.Data)
				}
			}

			Expect(primaryDNS.String()).To(Equal("8.8.8.8"))
			Expect(secondaryDNS.String()).To(Equal("8.8.4.4"))
		})

		It("should reject IP compression option", func() {
			configReq := buildIPCPConfigureRequestWithCompression(1, net.ParseIP("10.0.0.100"))
			err := ipcp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigReject)))
		})
	})

	Describe("Full Negotiation", func() {
		It("should reach Opened state with proper exchange", func() {
			ipcp.Up()
			ipcp.Open()
			Expect(ipcp.GetState()).To(Equal(pppoe.IPCPStateReqSent))
			clearPackets()

			// Peer sends Configure-Request with correct IP
			peerConfig := buildIPCPConfigureRequest(1, net.ParseIP("10.0.0.100"))
			err := ipcp.ReceivePacket(peerConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(ipcp.GetState()).To(Equal(pppoe.IPCPStateAckSent))

			// Peer sends Configure-Ack for our request
			ackPkt := buildIPCPConfigureAck(1)
			err = ipcp.ReceivePacket(ackPkt)
			Expect(err).NotTo(HaveOccurred())

			Expect(ipcp.GetState()).To(Equal(pppoe.IPCPStateOpened))
		})
	})

	Describe("SetPeerIP", func() {
		It("should update peer IP", func() {
			newIP := net.ParseIP("10.0.0.200")
			ipcp.SetPeerIP(newIP)

			opts := ipcp.GetNegotiatedOptions()
			Expect(opts.PeerIP.String()).To(Equal("10.0.0.200"))
		})
	})
})

var _ = Describe("IPV6CP State Machine", func() {
	var (
		ipv6cp        *pppoe.IPV6CPStateMachine
		config        pppoe.IPV6CPConfig
		sentPackets   [][]byte
		sentPacketsMu sync.Mutex
		logger        *zap.Logger
	)

	sendPacket := func(protocol uint16, data []byte) {
		sentPacketsMu.Lock()
		defer sentPacketsMu.Unlock()
		pktCopy := make([]byte, len(data))
		copy(pktCopy, data)
		sentPackets = append(sentPackets, pktCopy)
	}

	getLastPacket := func() []byte {
		sentPacketsMu.Lock()
		defer sentPacketsMu.Unlock()
		if len(sentPackets) == 0 {
			return nil
		}
		return sentPackets[len(sentPackets)-1]
	}

	clearPackets := func() {
		sentPacketsMu.Lock()
		defer sentPacketsMu.Unlock()
		sentPackets = nil
	}

	BeforeEach(func() {
		logger, _ = zap.NewDevelopment()
		var err error
		config, err = pppoe.DefaultIPV6CPConfig()
		Expect(err).NotTo(HaveOccurred())
		sentPackets = nil
		ipv6cp, err = pppoe.NewIPV6CPStateMachine(config, sendPacket, logger)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("State Machine Initialization", func() {
		It("should start in Initial state", func() {
			Expect(ipv6cp.GetState()).To(Equal(pppoe.IPV6CPStateInitial))
		})

		It("should have non-zero local interface ID", func() {
			opts := ipv6cp.GetNegotiatedOptions()
			Expect(opts.LocalInterfaceID).NotTo(BeZero())
		})
	})

	Describe("Configure-Request Handling", func() {
		BeforeEach(func() {
			ipv6cp.Up()
			ipv6cp.Open()
			clearPackets()
		})

		It("should NAK zero interface ID", func() {
			configReq := buildIPV6CPConfigureRequest(1, 0)
			err := ipv6cp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigNak)))
		})

		It("should ACK valid interface ID", func() {
			configReq := buildIPV6CPConfigureRequest(1, 0x1234567890ABCDEF)
			err := ipv6cp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigAck)))
		})

		It("should store peer interface ID on ACK", func() {
			configReq := buildIPV6CPConfigureRequest(1, 0x1234567890ABCDEF)
			ipv6cp.ReceivePacket(configReq)

			opts := ipv6cp.GetNegotiatedOptions()
			Expect(opts.PeerInterfaceID).To(Equal(uint64(0x1234567890ABCDEF)))
		})
	})

	Describe("Full Negotiation", func() {
		It("should reach Opened state", func() {
			ipv6cp.Up()
			ipv6cp.Open()
			clearPackets()

			// Peer sends Configure-Request
			peerConfig := buildIPV6CPConfigureRequest(1, 0x1234567890ABCDEF)
			ipv6cp.ReceivePacket(peerConfig)
			Expect(ipv6cp.GetState()).To(Equal(pppoe.IPV6CPStateAckSent))

			// Peer sends Configure-Ack
			ackPkt := buildIPV6CPConfigureAck(1)
			ipv6cp.ReceivePacket(ackPkt)

			Expect(ipv6cp.GetState()).To(Equal(pppoe.IPV6CPStateOpened))
			Expect(ipv6cp.IsOpened()).To(BeTrue())
		})
	})
})

// Helper functions for building IPCP/IPV6CP packets

func buildIPCPConfigureRequest(identifier uint8, ip net.IP) []byte {
	opts := []pppoe.LCPOption{
		{Type: pppoe.IPCPOptIPAddress, Data: ip.To4()},
	}

	optData := pppoe.SerializeLCPOptions(opts)

	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeConfigRequest,
		Identifier: identifier,
		Data:       optData,
	}

	return pkt.Serialize()
}

func buildIPCPConfigureRequestWithDNS(identifier uint8, ip, primaryDNS, secondaryDNS net.IP) []byte {
	opts := []pppoe.LCPOption{
		{Type: pppoe.IPCPOptIPAddress, Data: ip.To4()},
		{Type: pppoe.IPCPOptPrimaryDNS, Data: primaryDNS.To4()},
		{Type: pppoe.IPCPOptSecondaryDNS, Data: secondaryDNS.To4()},
	}

	optData := pppoe.SerializeLCPOptions(opts)

	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeConfigRequest,
		Identifier: identifier,
		Data:       optData,
	}

	return pkt.Serialize()
}

func buildIPCPConfigureRequestWithCompression(identifier uint8, ip net.IP) []byte {
	opts := []pppoe.LCPOption{
		{Type: pppoe.IPCPOptIPAddress, Data: ip.To4()},
		{Type: pppoe.IPCPOptIPCompression, Data: []byte{0x00, 0x2D}}, // VJ compression
	}

	optData := pppoe.SerializeLCPOptions(opts)

	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeConfigRequest,
		Identifier: identifier,
		Data:       optData,
	}

	return pkt.Serialize()
}

func buildIPCPConfigureAck(identifier uint8) []byte {
	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeConfigAck,
		Identifier: identifier,
		Data:       nil,
	}

	return pkt.Serialize()
}

func buildIPV6CPConfigureRequest(identifier uint8, interfaceID uint64) []byte {
	idData := make([]byte, 8)
	binary.BigEndian.PutUint64(idData, interfaceID)

	opts := []pppoe.LCPOption{
		{Type: pppoe.IPV6CPOptInterfaceID, Data: idData},
	}

	optData := pppoe.SerializeLCPOptions(opts)

	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeConfigRequest,
		Identifier: identifier,
		Data:       optData,
	}

	return pkt.Serialize()
}

func buildIPV6CPConfigureAck(identifier uint8) []byte {
	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeConfigAck,
		Identifier: identifier,
		Data:       nil,
	}

	return pkt.Serialize()
}
