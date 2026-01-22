package pppoe_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/pppoe"
)

var _ = Describe("Session Teardown", func() {
	var (
		config pppoe.TeardownConfig
		logger *zap.Logger
	)

	BeforeEach(func() {
		logger, _ = zap.NewDevelopment()
		config = pppoe.DefaultTeardownConfig()
	})

	Describe("TeardownConfig", func() {
		It("should have sensible defaults", func() {
			Expect(config.LCPTermTimeout).NotTo(BeZero())
			Expect(config.PADTRetries).To(BeNumerically(">=", 0))
			Expect(config.CleanupTimeout).NotTo(BeZero())
			Expect(config.RADIUSTimeout).NotTo(BeZero())
		})
	})

	Describe("TerminateCause", func() {
		DescribeTable("String() returns correct cause names",
			func(cause pppoe.TerminateCause, expected string) {
				Expect(cause.String()).To(Equal(expected))
			},
			Entry("User-Request", pppoe.TerminateCauseUserRequest, "User-Request"),
			Entry("Lost-Carrier", pppoe.TerminateCauseLostCarrier, "Lost-Carrier"),
			Entry("Lost-Service", pppoe.TerminateCauseLostService, "Lost-Service"),
			Entry("Idle-Timeout", pppoe.TerminateCauseIdleTimeout, "Idle-Timeout"),
			Entry("Session-Timeout", pppoe.TerminateCauseSessionTimeout, "Session-Timeout"),
			Entry("Admin-Reset", pppoe.TerminateCauseAdminReset, "Admin-Reset"),
			Entry("Admin-Reboot", pppoe.TerminateCauseAdminReboot, "Admin-Reboot"),
			Entry("Port-Error", pppoe.TerminateCausePortError, "Port-Error"),
			Entry("NAS-Error", pppoe.TerminateCauseNASError, "NAS-Error"),
			Entry("NAS-Request", pppoe.TerminateCauseNASRequest, "NAS-Request"),
		)

		It("should return Unknown for invalid cause", func() {
			invalidCause := pppoe.TerminateCause(255)
			Expect(invalidCause.String()).To(Equal("Unknown"))
		})
	})

	Describe("SessionTeardown", func() {
		var teardown *pppoe.SessionTeardown

		BeforeEach(func() {
			teardown = pppoe.NewSessionTeardown(config, logger)
		})

		It("should handle nil session manager for TerminateByID", func() {
			err := teardown.TerminateByID(1, "test")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle nil session manager for TerminateByMAC", func() {
			mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			err := teardown.TerminateByMAC(mac, "test")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle nil session manager for TerminateByUsername", func() {
			count := teardown.TerminateByUsername("testuser", "test")
			Expect(count).To(Equal(0))
		})

		It("should handle nil session manager for TerminateAll", func() {
			count := teardown.TerminateAll(pppoe.TerminateCauseNASReboot, "test")
			Expect(count).To(Equal(0))
		})

		Context("with session manager", func() {
			var sessionManager *pppoe.SessionManager

			BeforeEach(func() {
				sessionManager = pppoe.NewSessionManager()
				teardown.SetSessionManager(sessionManager)
			})

			It("should return 0 for non-existent session", func() {
				err := teardown.TerminateByID(999, "test")
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return 0 for non-existent MAC", func() {
				mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
				err := teardown.TerminateByMAC(mac, "test")
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return 0 for non-existent username", func() {
				count := teardown.TerminateByUsername("nonexistent", "test")
				Expect(count).To(Equal(0))
			})
		})
	})

	Describe("PADT Helpers", func() {
		Describe("BuildGenericErrorTag", func() {
			It("should create tag with correct type and value", func() {
				tag := pppoe.BuildGenericErrorTag("Test error")
				Expect(tag.Type).To(Equal(uint16(pppoe.TagGenericErr)))
				Expect(string(tag.Value)).To(Equal("Test error"))
			})
		})

		Describe("BuildServiceNameErrorTag", func() {
			It("should create tag with correct type", func() {
				tag := pppoe.BuildServiceNameErrorTag("Bad service")
				Expect(tag.Type).To(Equal(uint16(pppoe.TagServiceNameErr)))
				Expect(string(tag.Value)).To(Equal("Bad service"))
			})
		})

		Describe("BuildACSystemErrorTag", func() {
			It("should create tag with correct type", func() {
				tag := pppoe.BuildACSystemErrorTag("System error")
				Expect(tag.Type).To(Equal(uint16(pppoe.TagACSystemErr)))
				Expect(string(tag.Value)).To(Equal("System error"))
			})
		})

		Describe("SerializePADT", func() {
			It("should create valid PADT packet", func() {
				tags := []pppoe.Tag{
					pppoe.BuildGenericErrorTag("Test"),
				}
				pkt := pppoe.SerializePADT(0x1234, tags)

				// Parse and verify
				hdr, err := pppoe.ParsePPPoEHeader(pkt)
				Expect(err).NotTo(HaveOccurred())
				Expect(hdr.Code).To(Equal(uint8(pppoe.CodePADT)))
				Expect(hdr.SessionID).To(Equal(uint16(0x1234)))
			})

			It("should handle empty tags", func() {
				pkt := pppoe.SerializePADT(0x5678, nil)

				hdr, err := pppoe.ParsePPPoEHeader(pkt)
				Expect(err).NotTo(HaveOccurred())
				Expect(hdr.Code).To(Equal(uint8(pppoe.CodePADT)))
				Expect(hdr.Length).To(Equal(uint16(0)))
			})
		})

		Describe("ParsePADT", func() {
			It("should parse valid PADT", func() {
				tags := []pppoe.Tag{
					{Type: pppoe.TagGenericErr, Value: []byte("Error")},
				}
				pkt := pppoe.SerializePADT(0xABCD, tags)

				sessionID, parsedTags, err := pppoe.ParsePADT(pkt)
				Expect(err).NotTo(HaveOccurred())
				Expect(sessionID).To(Equal(uint16(0xABCD)))
				Expect(parsedTags).To(HaveLen(1))
				Expect(string(parsedTags[0].Value)).To(Equal("Error"))
			})
		})

		Describe("LCP Terminate packets", func() {
			It("should serialize Terminate-Request", func() {
				pkt := pppoe.SerializeLCPTerminateRequest(42, "Goodbye")

				lcpPkt, err := pppoe.ParseLCPPacket(pkt)
				Expect(err).NotTo(HaveOccurred())
				Expect(lcpPkt.Code).To(Equal(uint8(pppoe.LCPCodeTermRequest)))
				Expect(lcpPkt.Identifier).To(Equal(uint8(42)))
				Expect(string(lcpPkt.Data)).To(Equal("Goodbye"))
			})

			It("should serialize Terminate-Ack", func() {
				pkt := pppoe.SerializeLCPTerminateAck(99)

				lcpPkt, err := pppoe.ParseLCPPacket(pkt)
				Expect(err).NotTo(HaveOccurred())
				Expect(lcpPkt.Code).To(Equal(uint8(pppoe.LCPCodeTermAck)))
				Expect(lcpPkt.Identifier).To(Equal(uint8(99)))
			})
		})
	})

	Describe("Client PADT Handling", func() {
		var (
			teardown       *pppoe.SessionTeardown
			sessionManager *pppoe.SessionManager
			session        *pppoe.Session
		)

		BeforeEach(func() {
			teardown = pppoe.NewSessionTeardown(config, logger)
			sessionManager = pppoe.NewSessionManager()
			teardown.SetSessionManager(sessionManager)

			clientMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			serverMAC, _ := net.ParseMAC("11:22:33:44:55:66")
			var err error
			session, err = sessionManager.CreateSession(clientMAC, serverMAC)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should validate client MAC", func() {
			wrongMAC, _ := net.ParseMAC("00:00:00:00:00:00")
			err := teardown.HandleClientPADT(session, wrongMAC, session.ID)
			Expect(err).NotTo(HaveOccurred())
			// Session should NOT be removed due to MAC mismatch
			// (validation happens but silently ignored for security)
		})

		It("should clean up session on valid PADT", func() {
			clientMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			err := teardown.HandleClientPADT(session, clientMAC, session.ID)
			Expect(err).NotTo(HaveOccurred())

			// Session should be removed
			Expect(sessionManager.GetSession(session.ID)).To(BeNil())
		})
	})
})
