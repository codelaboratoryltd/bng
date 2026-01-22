package pppoe_test

import (
	"encoding/binary"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/pppoe"
)

var _ = Describe("PPPoE Authentication", func() {
	var (
		auth        *pppoe.Authenticator
		config      pppoe.AuthConfig
		sentPackets []struct {
			protocol uint16
			data     []byte
		}
		sentPacketsMu sync.Mutex
		logger        *zap.Logger
	)

	sendPacket := func(protocol uint16, data []byte) {
		sentPacketsMu.Lock()
		defer sentPacketsMu.Unlock()
		pktCopy := make([]byte, len(data))
		copy(pktCopy, data)
		sentPackets = append(sentPackets, struct {
			protocol uint16
			data     []byte
		}{protocol, pktCopy})
	}

	getLastPacket := func() (uint16, []byte) {
		sentPacketsMu.Lock()
		defer sentPacketsMu.Unlock()
		if len(sentPackets) == 0 {
			return 0, nil
		}
		last := sentPackets[len(sentPackets)-1]
		return last.protocol, last.data
	}

	BeforeEach(func() {
		logger, _ = zap.NewDevelopment()
		config = pppoe.DefaultAuthConfig()
		sentPackets = nil
		auth = pppoe.NewAuthenticator(config, nil, sendPacket, logger)
	})

	Describe("PAP Authentication", func() {
		BeforeEach(func() {
			config.Protocol = pppoe.ProtocolPAP
			auth = pppoe.NewAuthenticator(config, nil, sendPacket, logger)
		})

		It("should start in None state", func() {
			Expect(auth.GetState()).To(Equal(pppoe.AuthStateNone))
		})

		It("should transition to Pending on Start", func() {
			auth.Start()
			Expect(auth.GetState()).To(Equal(pppoe.AuthStatePending))
		})

		It("should authenticate valid PAP credentials without RADIUS", func() {
			auth.Start()

			var authResult *pppoe.AuthResult
			auth.SetOnAuthComplete(func(result *pppoe.AuthResult) {
				authResult = result
			})

			// Send PAP Authenticate-Request
			papRequest := buildPAPAuthRequest(1, "testuser", "testpass")
			err := auth.ReceivePacket(pppoe.ProtocolPAP, papRequest)
			Expect(err).NotTo(HaveOccurred())

			// Should succeed (no RADIUS = accept all)
			Expect(auth.GetState()).To(Equal(pppoe.AuthStateSuccess))
			Expect(auth.GetUsername()).To(Equal("testuser"))
			Expect(authResult).NotTo(BeNil())
			Expect(authResult.Success).To(BeTrue())
			Expect(authResult.Method).To(Equal("PAP"))

			// Should have sent PAP-Ack
			proto, pkt := getLastPacket()
			Expect(proto).To(Equal(uint16(pppoe.ProtocolPAP)))
			Expect(pkt[0]).To(Equal(uint8(pppoe.PAPCodeAuthAck)))
		})

		It("should parse PAP credentials correctly", func() {
			auth.Start()

			papRequest := buildPAPAuthRequest(1, "myuser", "mypassword123")
			err := auth.ReceivePacket(pppoe.ProtocolPAP, papRequest)
			Expect(err).NotTo(HaveOccurred())

			Expect(auth.GetUsername()).To(Equal("myuser"))
		})

		It("should handle empty username", func() {
			auth.Start()

			papRequest := buildPAPAuthRequest(1, "", "password")
			err := auth.ReceivePacket(pppoe.ProtocolPAP, papRequest)
			Expect(err).NotTo(HaveOccurred())

			Expect(auth.GetUsername()).To(Equal(""))
		})

		It("should handle empty password", func() {
			auth.Start()

			papRequest := buildPAPAuthRequest(1, "user", "")
			err := auth.ReceivePacket(pppoe.ProtocolPAP, papRequest)
			Expect(err).NotTo(HaveOccurred())

			Expect(auth.GetState()).To(Equal(pppoe.AuthStateSuccess))
		})

		It("should use correct identifier in response", func() {
			auth.Start()

			papRequest := buildPAPAuthRequest(42, "user", "pass")
			auth.ReceivePacket(pppoe.ProtocolPAP, papRequest)

			_, pkt := getLastPacket()
			Expect(pkt[1]).To(Equal(uint8(42)))
		})
	})

	Describe("CHAP Authentication", func() {
		BeforeEach(func() {
			config.Protocol = pppoe.ProtocolCHAP
			config.CHAPAlgorithm = pppoe.CHAPAlgorithmMD5
			auth = pppoe.NewAuthenticator(config, nil, sendPacket, logger)
		})

		It("should send CHAP Challenge on Start", func() {
			auth.Start()

			proto, pkt := getLastPacket()
			Expect(proto).To(Equal(uint16(pppoe.ProtocolCHAP)))
			Expect(pkt[0]).To(Equal(uint8(pppoe.CHAPCodeChallenge)))
		})

		It("should include challenge value in CHAP Challenge", func() {
			auth.Start()

			_, pkt := getLastPacket()

			// Parse CHAP Challenge
			// Format: Code (1) + ID (1) + Length (2) + Value-Size (1) + Value + Name
			valueSize := int(pkt[4])
			Expect(valueSize).To(BeNumerically(">=", 16)) // At least 16 bytes
		})

		It("should accept valid CHAP response without RADIUS", func() {
			auth.Start()

			var authResult *pppoe.AuthResult
			auth.SetOnAuthComplete(func(result *pppoe.AuthResult) {
				authResult = result
			})

			// Get the challenge ID
			_, challengePkt := getLastPacket()
			challengeID := challengePkt[1]

			// Send CHAP Response (without RADIUS, any response is accepted)
			chapResponse := buildCHAPResponse(challengeID, "testuser", make([]byte, 16))
			err := auth.ReceivePacket(pppoe.ProtocolCHAP, chapResponse)
			Expect(err).NotTo(HaveOccurred())

			// Should succeed (no RADIUS = accept all)
			Expect(auth.GetState()).To(Equal(pppoe.AuthStateSuccess))
			Expect(authResult).NotTo(BeNil())
			Expect(authResult.Success).To(BeTrue())
			Expect(authResult.Method).To(Equal("CHAP"))
		})

		It("should send CHAP Success on valid authentication", func() {
			auth.Start()

			_, challengePkt := getLastPacket()
			challengeID := challengePkt[1]

			chapResponse := buildCHAPResponse(challengeID, "user", make([]byte, 16))
			auth.ReceivePacket(pppoe.ProtocolCHAP, chapResponse)

			proto, pkt := getLastPacket()
			Expect(proto).To(Equal(uint16(pppoe.ProtocolCHAP)))
			Expect(pkt[0]).To(Equal(uint8(pppoe.CHAPCodeSuccess)))
		})

		It("should ignore CHAP response with wrong identifier", func() {
			auth.Start()

			_, challengePkt := getLastPacket()
			challengeID := challengePkt[1]

			// Send response with wrong ID
			chapResponse := buildCHAPResponse(challengeID+1, "user", make([]byte, 16))
			err := auth.ReceivePacket(pppoe.ProtocolCHAP, chapResponse)
			Expect(err).NotTo(HaveOccurred())

			// Should still be pending
			Expect(auth.GetState()).To(Equal(pppoe.AuthStatePending))
		})
	})

	Describe("Auth State", func() {
		It("should return correct string for each state", func() {
			Expect(pppoe.AuthStateNone.String()).To(Equal("None"))
			Expect(pppoe.AuthStatePending.String()).To(Equal("Pending"))
			Expect(pppoe.AuthStateSuccess.String()).To(Equal("Success"))
			Expect(pppoe.AuthStateFailure.String()).To(Equal("Failure"))
		})
	})
})

// Helper functions to build PAP/CHAP packets

func buildPAPAuthRequest(identifier uint8, peerID, password string) []byte {
	peerIDBytes := []byte(peerID)
	passwordBytes := []byte(password)

	// PAP Auth-Request format:
	// Code (1) + ID (1) + Length (2) + Peer-ID-Length (1) + Peer-ID + Passwd-Length (1) + Passwd
	dataLen := 1 + len(peerIDBytes) + 1 + len(passwordBytes)
	totalLen := 4 + dataLen

	pkt := make([]byte, totalLen)
	pkt[0] = pppoe.PAPCodeAuthRequest
	pkt[1] = identifier
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[4] = byte(len(peerIDBytes))
	copy(pkt[5:5+len(peerIDBytes)], peerIDBytes)
	pkt[5+len(peerIDBytes)] = byte(len(passwordBytes))
	copy(pkt[6+len(peerIDBytes):], passwordBytes)

	return pkt
}

func buildCHAPResponse(identifier uint8, name string, value []byte) []byte {
	nameBytes := []byte(name)

	// CHAP Response format:
	// Code (1) + ID (1) + Length (2) + Value-Size (1) + Value + Name
	dataLen := 1 + len(value) + len(nameBytes)
	totalLen := 4 + dataLen

	pkt := make([]byte, totalLen)
	pkt[0] = pppoe.CHAPCodeResponse
	pkt[1] = identifier
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[4] = byte(len(value))
	copy(pkt[5:5+len(value)], value)
	copy(pkt[5+len(value):], nameBytes)

	return pkt
}
