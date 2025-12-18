package pppoe_test

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/pppoe"
)

var _ = Describe("PPPoE Session", func() {

	Describe("SessionState", func() {
		DescribeTable("String() returns correct state names",
			func(state pppoe.SessionState, expected string) {
				Expect(state.String()).To(Equal(expected))
			},
			Entry("Discovery", pppoe.StateDiscovery, "Discovery"),
			Entry("LCP Negotiation", pppoe.StateLCPNegotiation, "LCP Negotiation"),
			Entry("Authentication", pppoe.StateAuthentication, "Authentication"),
			Entry("IPCP Negotiation", pppoe.StateIPCPNegotiation, "IPCP Negotiation"),
			Entry("Established", pppoe.StateEstablished, "Established"),
			Entry("Terminating", pppoe.StateTerminating, "Terminating"),
			Entry("Closed", pppoe.StateClosed, "Closed"),
		)

		It("should return Unknown for invalid states", func() {
			invalidState := pppoe.SessionState(99)
			Expect(invalidState.String()).To(Equal("Unknown"))
		})
	})

	Describe("Session", func() {
		var (
			session   *pppoe.Session
			clientMAC net.HardwareAddr
			serverMAC net.HardwareAddr
		)

		BeforeEach(func() {
			clientMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
			serverMAC, _ = net.ParseMAC("11:22:33:44:55:66")
			session = pppoe.NewSession(1, clientMAC, serverMAC)
		})

		Context("when creating a new session", func() {
			It("should initialize with correct values", func() {
				Expect(session.ID).To(Equal(uint16(1)))
				Expect(session.ClientMAC.String()).To(Equal(clientMAC.String()))
				Expect(session.ServerMAC.String()).To(Equal(serverMAC.String()))
				Expect(session.State).To(Equal(pppoe.StateDiscovery))
				Expect(session.MRU).To(Equal(uint16(1492)))
				Expect(session.MagicNumber).NotTo(BeZero())
				Expect(session.SessionID).NotTo(BeEmpty())
				Expect(session.CreatedAt).NotTo(BeZero())
			})

			It("should generate unique magic numbers", func() {
				session2 := pppoe.NewSession(2, clientMAC, serverMAC)
				// Magic numbers should be different (random)
				// Note: There's a tiny chance they could be equal
				Expect(session.MagicNumber).NotTo(Equal(session2.MagicNumber))
			})
		})

		Context("when updating activity", func() {
			It("should update LastActivity timestamp", func() {
				originalTime := session.LastActivity
				time.Sleep(10 * time.Millisecond)

				session.UpdateActivity()

				Expect(session.LastActivity).To(BeTemporally(">", originalTime))
			})
		})

		Context("when tracking bytes", func() {
			It("should increment input counters", func() {
				session.AddBytesIn(100)
				session.AddBytesIn(50)

				Expect(session.BytesIn).To(Equal(uint64(150)))
				Expect(session.PacketsIn).To(Equal(uint64(2)))
			})

			It("should increment output counters", func() {
				session.AddBytesOut(200)
				session.AddBytesOut(300)

				Expect(session.BytesOut).To(Equal(uint64(500)))
				Expect(session.PacketsOut).To(Equal(uint64(2)))
			})
		})

		Context("when managing state", func() {
			It("should update state correctly", func() {
				session.SetState(pppoe.StateLCPNegotiation)
				Expect(session.GetState()).To(Equal(pppoe.StateLCPNegotiation))
			})

			It("should set EstablishedAt when entering Established state", func() {
				Expect(session.EstablishedAt).To(BeZero())

				session.SetState(pppoe.StateEstablished)

				Expect(session.EstablishedAt).NotTo(BeZero())
			})

			It("should not set EstablishedAt for other states", func() {
				session.SetState(pppoe.StateAuthentication)
				Expect(session.EstablishedAt).To(BeZero())
			})
		})

		Context("when checking established status", func() {
			It("should return false when not established", func() {
				Expect(session.IsEstablished()).To(BeFalse())
			})

			It("should return true when established", func() {
				session.SetState(pppoe.StateEstablished)
				Expect(session.IsEstablished()).To(BeTrue())
			})
		})

		Context("when calculating duration", func() {
			It("should return zero if not established", func() {
				Expect(session.Duration()).To(BeZero())
			})

			It("should return duration since establishment", func() {
				session.SetState(pppoe.StateEstablished)
				time.Sleep(50 * time.Millisecond)

				duration := session.Duration()
				Expect(duration).To(BeNumerically(">=", 50*time.Millisecond))
			})
		})

		Context("when getting LCP identifier", func() {
			It("should increment with each call", func() {
				id1 := session.NextLCPIdentifier()
				id2 := session.NextLCPIdentifier()
				id3 := session.NextLCPIdentifier()

				Expect(id1).To(Equal(uint8(1)))
				Expect(id2).To(Equal(uint8(2)))
				Expect(id3).To(Equal(uint8(3)))
			})
		})
	})

	Describe("SessionManager", func() {
		var (
			manager   *pppoe.SessionManager
			clientMAC net.HardwareAddr
			serverMAC net.HardwareAddr
		)

		BeforeEach(func() {
			manager = pppoe.NewSessionManager()
			clientMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
			serverMAC, _ = net.ParseMAC("11:22:33:44:55:66")
		})

		Context("when creating sessions", func() {
			It("should create a session with unique ID", func() {
				session := manager.CreateSession(clientMAC, serverMAC)

				Expect(session).NotTo(BeNil())
				Expect(session.ID).To(Equal(uint16(1)))
				Expect(session.ClientMAC.String()).To(Equal(clientMAC.String()))
			})

			It("should create sessions with incrementing IDs", func() {
				mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
				mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
				mac3, _ := net.ParseMAC("aa:bb:cc:dd:ee:03")

				s1 := manager.CreateSession(mac1, serverMAC)
				s2 := manager.CreateSession(mac2, serverMAC)
				s3 := manager.CreateSession(mac3, serverMAC)

				Expect(s1.ID).To(Equal(uint16(1)))
				Expect(s2.ID).To(Equal(uint16(2)))
				Expect(s3.ID).To(Equal(uint16(3)))
			})

			It("should skip session ID 0", func() {
				// Create many sessions to potentially wrap around
				for i := 0; i < 10; i++ {
					mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:" + string(rune('a'+i)))
					session := manager.CreateSession(mac, serverMAC)
					Expect(session.ID).NotTo(BeZero())
				}
			})
		})

		Context("when getting sessions", func() {
			It("should return session by ID", func() {
				created := manager.CreateSession(clientMAC, serverMAC)
				found := manager.GetSession(created.ID)

				Expect(found).NotTo(BeNil())
				Expect(found.ID).To(Equal(created.ID))
			})

			It("should return nil for non-existent ID", func() {
				found := manager.GetSession(999)
				Expect(found).To(BeNil())
			})

			It("should return session by MAC", func() {
				created := manager.CreateSession(clientMAC, serverMAC)
				found := manager.GetSessionByMAC(clientMAC)

				Expect(found).NotTo(BeNil())
				Expect(found.ID).To(Equal(created.ID))
			})

			It("should return nil for non-existent MAC", func() {
				unknownMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
				found := manager.GetSessionByMAC(unknownMAC)
				Expect(found).To(BeNil())
			})
		})

		Context("when removing sessions", func() {
			It("should remove session by ID", func() {
				session := manager.CreateSession(clientMAC, serverMAC)
				Expect(manager.Count()).To(Equal(1))

				manager.RemoveSession(session.ID)

				Expect(manager.Count()).To(Equal(0))
				Expect(manager.GetSession(session.ID)).To(BeNil())
				Expect(manager.GetSessionByMAC(clientMAC)).To(BeNil())
			})

			It("should handle removing non-existent session gracefully", func() {
				Expect(func() {
					manager.RemoveSession(999)
				}).NotTo(Panic())
			})
		})

		Context("when getting all sessions", func() {
			It("should return empty slice when no sessions", func() {
				sessions := manager.GetAllSessions()
				Expect(sessions).To(BeEmpty())
			})

			It("should return all sessions", func() {
				mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
				mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")

				manager.CreateSession(mac1, serverMAC)
				manager.CreateSession(mac2, serverMAC)

				sessions := manager.GetAllSessions()
				Expect(sessions).To(HaveLen(2))
			})
		})

		Context("when counting sessions", func() {
			It("should return 0 for empty manager", func() {
				Expect(manager.Count()).To(Equal(0))
			})

			It("should return correct count", func() {
				mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
				mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")

				manager.CreateSession(mac1, serverMAC)
				manager.CreateSession(mac2, serverMAC)

				Expect(manager.Count()).To(Equal(2))
			})
		})

		Context("when cleaning up expired sessions", func() {
			It("should remove inactive sessions", func() {
				session := manager.CreateSession(clientMAC, serverMAC)
				session.LastActivity = time.Now().Add(-10 * time.Minute)

				removed := manager.CleanupExpired(5 * time.Minute)

				Expect(removed).To(Equal(1))
				Expect(manager.Count()).To(Equal(0))
			})

			It("should not remove active sessions", func() {
				session := manager.CreateSession(clientMAC, serverMAC)
				session.UpdateActivity()

				removed := manager.CleanupExpired(5 * time.Minute)

				Expect(removed).To(Equal(0))
				Expect(manager.Count()).To(Equal(1))
			})

			It("should only remove expired sessions", func() {
				mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
				mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")

				active := manager.CreateSession(mac1, serverMAC)
				active.UpdateActivity()

				expired := manager.CreateSession(mac2, serverMAC)
				expired.LastActivity = time.Now().Add(-10 * time.Minute)

				removed := manager.CleanupExpired(5 * time.Minute)

				Expect(removed).To(Equal(1))
				Expect(manager.Count()).To(Equal(1))
				Expect(manager.GetSession(active.ID)).NotTo(BeNil())
				Expect(manager.GetSession(expired.ID)).To(BeNil())
			})
		})
	})
})
