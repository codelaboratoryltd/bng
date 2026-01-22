package pppoe_test

import (
	"encoding/binary"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/pppoe"
)

var _ = Describe("LCP State Machine", func() {
	var (
		lcp           *pppoe.LCPStateMachine
		config        pppoe.LCPConfig
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
		config = pppoe.DefaultLCPConfig()
		config.RestartTimer = 100 * time.Millisecond // Short timer for tests
		sentPackets = nil
		lcp = pppoe.NewLCPStateMachine(config, sendPacket, logger)
	})

	Describe("State Machine Initialization", func() {
		It("should start in Initial state", func() {
			Expect(lcp.GetState()).To(Equal(pppoe.LCPStateInitial))
		})

		It("should have non-zero magic number", func() {
			opts := lcp.GetNegotiatedOptions()
			Expect(opts.LocalMagic).NotTo(BeZero())
		})

		It("should have default MRU of 1492", func() {
			opts := lcp.GetNegotiatedOptions()
			Expect(opts.LocalMRU).To(Equal(uint16(1492)))
		})
	})

	Describe("State Transitions", func() {
		Context("from Initial state", func() {
			It("should transition to Closed on Up", func() {
				lcp.Up()
				Expect(lcp.GetState()).To(Equal(pppoe.LCPStateClosed))
			})

			It("should transition to Starting on Open", func() {
				lcp.Open()
				Expect(lcp.GetState()).To(Equal(pppoe.LCPStateStarting))
			})
		})

		Context("from Starting state", func() {
			BeforeEach(func() {
				lcp.Open() // Initial -> Starting
			})

			It("should transition to Req-Sent on Up and send Configure-Request", func() {
				lcp.Up()
				Expect(lcp.GetState()).To(Equal(pppoe.LCPStateReqSent))

				// Should have sent Configure-Request
				pkt := getLastPacket()
				Expect(pkt).NotTo(BeNil())
				Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigRequest)))
			})
		})

		Context("from Closed state", func() {
			BeforeEach(func() {
				lcp.Up() // Initial -> Closed
			})

			It("should transition to Req-Sent on Open and send Configure-Request", func() {
				lcp.Open()
				Expect(lcp.GetState()).To(Equal(pppoe.LCPStateReqSent))

				pkt := getLastPacket()
				Expect(pkt).NotTo(BeNil())
				Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigRequest)))
			})
		})

		Context("full negotiation flow", func() {
			It("should reach Opened state with proper exchange", func() {
				// Start negotiation
				lcp.Up()
				lcp.Open()
				Expect(lcp.GetState()).To(Equal(pppoe.LCPStateReqSent))
				clearPackets()

				// Simulate peer's Configure-Request
				peerConfig := buildConfigureRequest(1, 1492, 0x12345678)
				err := lcp.ReceivePacket(peerConfig)
				Expect(err).NotTo(HaveOccurred())

				// Should now be in Ack-Sent (sent our request, sent ack to peer)
				Expect(lcp.GetState()).To(Equal(pppoe.LCPStateAckSent))

				// Simulate peer's Configure-Ack
				ackPkt := buildConfigureAck(1) // Identifier 1 matches our request
				err = lcp.ReceivePacket(ackPkt)
				Expect(err).NotTo(HaveOccurred())

				// Should now be Opened
				Expect(lcp.GetState()).To(Equal(pppoe.LCPStateOpened))
			})
		})
	})

	Describe("Configure-Request Handling", func() {
		BeforeEach(func() {
			lcp.Up()
			lcp.Open()
			clearPackets()
		})

		It("should ACK valid options", func() {
			configReq := buildConfigureRequest(1, 1492, 0x12345678)
			err := lcp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigAck)))
		})

		It("should NAK MRU greater than 1492", func() {
			configReq := buildConfigureRequestWithMRU(1, 1500, 0x12345678)
			err := lcp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigNak)))

			// Parse NAK to verify suggested MRU
			lcpPkt, _ := pppoe.ParseLCPPacket(pkt)
			opts, _ := pppoe.ParseLCPOptions(lcpPkt.Data)
			Expect(opts).To(HaveLen(1))
			Expect(opts[0].Type).To(Equal(uint8(pppoe.LCPOptMRU)))
			nakMRU := binary.BigEndian.Uint16(opts[0].Data)
			Expect(nakMRU).To(Equal(uint16(1492)))
		})

		It("should NAK zero magic number", func() {
			configReq := buildConfigureRequest(1, 1492, 0)
			err := lcp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigNak)))
		})

		It("should reject unknown options", func() {
			configReq := buildConfigureRequestWithUnknown(1)
			err := lcp.ReceivePacket(configReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeConfigReject)))
		})
	})

	Describe("Echo Request/Reply", func() {
		BeforeEach(func() {
			// Get to Opened state
			lcp.Up()
			lcp.Open()

			// Simulate peer's Configure-Request and our Ack
			peerConfig := buildConfigureRequest(1, 1492, 0x12345678)
			lcp.ReceivePacket(peerConfig)

			// Simulate peer's Configure-Ack
			ackPkt := buildConfigureAck(1)
			lcp.ReceivePacket(ackPkt)

			Expect(lcp.GetState()).To(Equal(pppoe.LCPStateOpened))
			clearPackets()
		})

		It("should respond to Echo-Request with Echo-Reply", func() {
			echoReq := buildEchoRequest(5, 0x12345678)
			err := lcp.ReceivePacket(echoReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt).NotTo(BeNil())
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeEchoReply)))
			Expect(pkt[1]).To(Equal(uint8(5))) // Same identifier
		})

		It("should send Echo-Request", func() {
			id := lcp.SendEchoRequest()
			Expect(id).NotTo(BeZero())

			pkt := getLastPacket()
			Expect(pkt).NotTo(BeNil())
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeEchoRequest)))
			Expect(pkt[1]).To(Equal(id))
		})
	})

	Describe("Termination", func() {
		BeforeEach(func() {
			// Get to Opened state
			lcp.Up()
			lcp.Open()
			peerConfig := buildConfigureRequest(1, 1492, 0x12345678)
			lcp.ReceivePacket(peerConfig)
			ackPkt := buildConfigureAck(1)
			lcp.ReceivePacket(ackPkt)
			Expect(lcp.GetState()).To(Equal(pppoe.LCPStateOpened))
			clearPackets()
		})

		It("should send Terminate-Request on Close", func() {
			lcp.Close()
			Expect(lcp.GetState()).To(Equal(pppoe.LCPStateClosing))

			pkt := getLastPacket()
			Expect(pkt).NotTo(BeNil())
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeTermRequest)))
		})

		It("should respond to Terminate-Request with Terminate-Ack", func() {
			termReq := buildTerminateRequest(10, "Bye")
			err := lcp.ReceivePacket(termReq)
			Expect(err).NotTo(HaveOccurred())

			pkt := getLastPacket()
			Expect(pkt).NotTo(BeNil())
			Expect(pkt[0]).To(Equal(uint8(pppoe.LCPCodeTermAck)))
			Expect(pkt[1]).To(Equal(uint8(10))) // Same identifier
		})

		It("should transition to Closed on receiving Terminate-Ack", func() {
			lcp.Close()
			Expect(lcp.GetState()).To(Equal(pppoe.LCPStateClosing))

			lastPkt := getLastPacket()
			identifier := lastPkt[1]

			termAck := buildTerminateAck(identifier)
			err := lcp.ReceivePacket(termAck)
			Expect(err).NotTo(HaveOccurred())

			Expect(lcp.GetState()).To(Equal(pppoe.LCPStateClosed))
		})
	})

	Describe("State Change Callback", func() {
		It("should call callback on state changes", func() {
			var transitions []struct {
				from, to pppoe.LCPState
			}

			lcp.SetOnStateChange(func(from, to pppoe.LCPState) {
				transitions = append(transitions, struct {
					from, to pppoe.LCPState
				}{from, to})
			})

			lcp.Up()
			lcp.Open()

			Expect(transitions).To(HaveLen(2))
			Expect(transitions[0].from).To(Equal(pppoe.LCPStateInitial))
			Expect(transitions[0].to).To(Equal(pppoe.LCPStateClosed))
			Expect(transitions[1].from).To(Equal(pppoe.LCPStateClosed))
			Expect(transitions[1].to).To(Equal(pppoe.LCPStateReqSent))
		})
	})
})

// Helper functions to build LCP packets

func buildConfigureRequest(identifier uint8, mru uint16, magic uint32) []byte {
	return buildConfigureRequestWithMRU(identifier, mru, magic)
}

func buildConfigureRequestWithMRU(identifier uint8, mru uint16, magic uint32) []byte {
	var opts []pppoe.LCPOption

	// MRU option
	mruData := make([]byte, 2)
	binary.BigEndian.PutUint16(mruData, mru)
	opts = append(opts, pppoe.LCPOption{Type: pppoe.LCPOptMRU, Data: mruData})

	// Magic number option
	magicData := make([]byte, 4)
	binary.BigEndian.PutUint32(magicData, magic)
	opts = append(opts, pppoe.LCPOption{Type: pppoe.LCPOptMagicNumber, Data: magicData})

	optData := pppoe.SerializeLCPOptions(opts)

	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeConfigRequest,
		Identifier: identifier,
		Data:       optData,
	}

	return pkt.Serialize()
}

func buildConfigureRequestWithUnknown(identifier uint8) []byte {
	opts := []pppoe.LCPOption{
		{Type: 99, Data: []byte{0x01, 0x02}}, // Unknown option
	}

	optData := pppoe.SerializeLCPOptions(opts)

	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeConfigRequest,
		Identifier: identifier,
		Data:       optData,
	}

	return pkt.Serialize()
}

func buildConfigureAck(identifier uint8) []byte {
	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeConfigAck,
		Identifier: identifier,
		Data:       nil, // Empty is fine for ACK
	}

	return pkt.Serialize()
}

func buildEchoRequest(identifier uint8, magic uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, magic)

	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeEchoRequest,
		Identifier: identifier,
		Data:       data,
	}

	return pkt.Serialize()
}

func buildTerminateRequest(identifier uint8, reason string) []byte {
	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeTermRequest,
		Identifier: identifier,
		Data:       []byte(reason),
	}

	return pkt.Serialize()
}

func buildTerminateAck(identifier uint8) []byte {
	pkt := &pppoe.LCPPacket{
		Code:       pppoe.LCPCodeTermAck,
		Identifier: identifier,
		Data:       nil,
	}

	return pkt.Serialize()
}
