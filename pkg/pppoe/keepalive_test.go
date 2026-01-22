package pppoe_test

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/pppoe"
)

var _ = Describe("Keep-Alive", func() {
	var (
		config pppoe.KeepAliveConfig
		logger *zap.Logger
	)

	BeforeEach(func() {
		logger, _ = zap.NewDevelopment()
		config = pppoe.DefaultKeepAliveConfig()
		config.Interval = 100 * time.Millisecond // Short for tests
		config.Timeout = 50 * time.Millisecond
		config.IdleThreshold = 50 * time.Millisecond
		config.MaxFailures = 3
	})

	Describe("KeepAliveConfig", func() {
		It("should have sensible defaults", func() {
			defaultConfig := pppoe.DefaultKeepAliveConfig()
			Expect(defaultConfig.Enabled).To(BeTrue())
			Expect(defaultConfig.Interval).To(Equal(30 * time.Second))
			Expect(defaultConfig.Timeout).To(Equal(5 * time.Second))
			Expect(defaultConfig.MaxFailures).To(Equal(3))
			Expect(defaultConfig.IdleThreshold).To(Equal(60 * time.Second))
		})
	})

	Describe("KeepAliveManager", func() {
		var manager *pppoe.KeepAliveManager

		BeforeEach(func() {
			manager = pppoe.NewKeepAliveManager(config, logger)
		})

		AfterEach(func() {
			manager.Stop()
		})

		It("should start and stop cleanly", func() {
			manager.Start()
			time.Sleep(10 * time.Millisecond)
			manager.Stop()
		})

		It("should not panic on double start", func() {
			manager.Start()
			Expect(func() { manager.Start() }).NotTo(Panic())
			manager.Stop()
		})

		It("should not panic on double stop", func() {
			manager.Start()
			manager.Stop()
			Expect(func() { manager.Stop() }).NotTo(Panic())
		})

		It("should register sessions", func() {
			clientMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			serverMAC, _ := net.ParseMAC("11:22:33:44:55:66")
			session, err := pppoe.NewSession(1, clientMAC, serverMAC)
			Expect(err).NotTo(HaveOccurred())

			manager.RegisterSession(session)

			failures, latency, lastSeen := manager.GetSessionHealth(session.ID)
			Expect(failures).To(Equal(0))
			Expect(latency).To(Equal(time.Duration(0)))
			Expect(lastSeen).NotTo(BeZero())
		})

		It("should unregister sessions", func() {
			clientMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			serverMAC, _ := net.ParseMAC("11:22:33:44:55:66")
			session, err := pppoe.NewSession(1, clientMAC, serverMAC)
			Expect(err).NotTo(HaveOccurred())

			manager.RegisterSession(session)
			manager.UnregisterSession(session.ID)

			_, _, lastSeen := manager.GetSessionHealth(session.ID)
			Expect(lastSeen).To(BeZero())
		})

		It("should update activity", func() {
			clientMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			serverMAC, _ := net.ParseMAC("11:22:33:44:55:66")
			session, err := pppoe.NewSession(1, clientMAC, serverMAC)
			Expect(err).NotTo(HaveOccurred())

			manager.RegisterSession(session)
			time.Sleep(10 * time.Millisecond)

			before, _, _ := manager.GetSessionHealth(session.ID)
			_ = before

			manager.UpdateActivity(session.ID)

			_, _, lastSeen := manager.GetSessionHealth(session.ID)
			Expect(lastSeen).To(BeTemporally("~", time.Now(), 100*time.Millisecond))
		})

		It("should return stats", func() {
			manager.Start()
			stats := manager.GetStats()

			Expect(stats).To(HaveKey("echo_requests_sent"))
			Expect(stats).To(HaveKey("echo_replies_recv"))
			Expect(stats).To(HaveKey("echo_timeouts"))
			Expect(stats).To(HaveKey("sessions_killed"))
		})
	})

	Describe("SessionKeepAlive", func() {
		var (
			session   *pppoe.Session
			keepalive *pppoe.SessionKeepAlive
			lcp       *pppoe.LCPStateMachine
		)

		BeforeEach(func() {
			clientMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			serverMAC, _ := net.ParseMAC("11:22:33:44:55:66")
			var err error
			session, err = pppoe.NewSession(1, clientMAC, serverMAC)
			Expect(err).NotTo(HaveOccurred())

			lcpConfig := pppoe.DefaultLCPConfig()
			lcp, err = pppoe.NewLCPStateMachine(lcpConfig, func(uint16, []byte) {}, logger)
			Expect(err).NotTo(HaveOccurred())

			keepalive = pppoe.NewSessionKeepAlive(session, lcp, config, logger)
		})

		AfterEach(func() {
			keepalive.Stop()
		})

		It("should start and stop cleanly", func() {
			keepalive.Start()
			time.Sleep(10 * time.Millisecond)
			keepalive.Stop()
		})

		It("should return zero latency initially", func() {
			Expect(keepalive.GetLatency()).To(Equal(time.Duration(0)))
		})

		It("should return zero failures initially", func() {
			Expect(keepalive.GetFailures()).To(Equal(0))
		})

		It("should not be dead initially", func() {
			Expect(keepalive.IsDead()).To(BeFalse())
		})
	})

	Describe("ParseEchoPacket", func() {
		It("should parse valid echo packet", func() {
			data := []byte{0x12, 0x34, 0x56, 0x78, 0x01, 0x02, 0x03}
			magic, payload, err := pppoe.ParseEchoPacket(data)

			Expect(err).NotTo(HaveOccurred())
			Expect(magic).To(Equal(uint32(0x12345678)))
			Expect(payload).To(Equal([]byte{0x01, 0x02, 0x03}))
		})

		It("should handle packet with only magic number", func() {
			data := []byte{0xAB, 0xCD, 0xEF, 0x01}
			magic, payload, err := pppoe.ParseEchoPacket(data)

			Expect(err).NotTo(HaveOccurred())
			Expect(magic).To(Equal(uint32(0xABCDEF01)))
			Expect(payload).To(BeNil())
		})

		It("should handle short packet", func() {
			data := []byte{0x12, 0x34}
			magic, payload, err := pppoe.ParseEchoPacket(data)

			Expect(err).NotTo(HaveOccurred())
			Expect(magic).To(Equal(uint32(0)))
			Expect(payload).To(BeNil())
		})
	})
})
