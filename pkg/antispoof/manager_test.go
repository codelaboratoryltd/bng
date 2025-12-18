package antispoof_test

import (
	"net"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/antispoof"
	"go.uber.org/zap"
)

func TestAntispoof(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Anti-Spoofing Suite")
}

var _ = Describe("Anti-Spoofing Manager", func() {
	var (
		logger *zap.Logger
	)

	BeforeEach(func() {
		logger = zap.NewNop()
	})

	Describe("Mode Constants", func() {
		DescribeTable("should have correct values",
			func(mode antispoof.Mode, expected uint8) {
				Expect(uint8(mode)).To(Equal(expected))
			},
			Entry("Disabled", antispoof.ModeDisabled, uint8(0)),
			Entry("Strict", antispoof.ModeStrict, uint8(1)),
			Entry("Loose", antispoof.ModeLoose, uint8(2)),
			Entry("LogOnly", antispoof.ModeLogOnly, uint8(3)),
		)
	})

	Describe("NewManager", func() {
		Context("when creating with valid config", func() {
			It("should create successfully with minimal config", func() {
				cfg := antispoof.ManagerConfig{
					Interface: "eth0",
				}

				mgr, err := antispoof.NewManager(cfg, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should create with custom mode", func() {
				cfg := antispoof.ManagerConfig{
					Interface:   "eth0",
					DefaultMode: antispoof.ModeLoose,
				}

				mgr, err := antispoof.NewManager(cfg, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should create with custom BPF path", func() {
				cfg := antispoof.ManagerConfig{
					Interface: "eth0",
					BPFPath:   "/custom/path/antispoof.bpf.o",
				}

				mgr, err := antispoof.NewManager(cfg, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})
		})

		Context("when creating with invalid config", func() {
			It("should return error when interface is empty", func() {
				cfg := antispoof.ManagerConfig{}

				mgr, err := antispoof.NewManager(cfg, logger)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("interface required"))
				Expect(mgr).To(BeNil())
			})
		})
	})

	Describe("Binding Management", func() {
		var mgr *antispoof.Manager

		BeforeEach(func() {
			cfg := antispoof.ManagerConfig{
				Interface:   "eth0",
				DefaultMode: antispoof.ModeStrict,
			}
			var err error
			mgr, err = antispoof.NewManager(cfg, logger)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when adding bindings", func() {
			It("should add IPv4 binding successfully", func() {
				mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
				ipv4 := net.ParseIP("10.0.1.100")

				err := mgr.AddBinding(mac, ipv4)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr.GetBindingCount()).To(Equal(1))
			})

			It("should add multiple bindings", func() {
				mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
				mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")

				mgr.AddBinding(mac1, net.ParseIP("10.0.1.1"))
				mgr.AddBinding(mac2, net.ParseIP("10.0.1.2"))

				Expect(mgr.GetBindingCount()).To(Equal(2))
			})

			It("should update existing binding for same MAC", func() {
				mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

				mgr.AddBinding(mac, net.ParseIP("10.0.1.1"))
				mgr.AddBinding(mac, net.ParseIP("10.0.1.2"))

				Expect(mgr.GetBindingCount()).To(Equal(1))
			})

			It("should reject invalid MAC address", func() {
				invalidMAC := net.HardwareAddr{0x00, 0x01} // Too short

				err := mgr.AddBinding(invalidMAC, net.ParseIP("10.0.1.1"))

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid MAC"))
			})

			It("should handle nil IPv4", func() {
				mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

				err := mgr.AddBinding(mac, nil)

				// Should not error - just won't have IPv4 binding
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when adding IPv6 bindings", func() {
			It("should add IPv6 binding successfully", func() {
				mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
				ipv6 := net.ParseIP("2001:db8::1")

				err := mgr.AddBindingV6(mac, ipv6)

				Expect(err).NotTo(HaveOccurred())
			})

			It("should reject invalid MAC for IPv6", func() {
				invalidMAC := net.HardwareAddr{0x00}

				err := mgr.AddBindingV6(invalidMAC, net.ParseIP("2001:db8::1"))

				Expect(err).To(HaveOccurred())
			})
		})

		Context("when removing bindings", func() {
			It("should remove existing binding", func() {
				mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
				mgr.AddBinding(mac, net.ParseIP("10.0.1.100"))
				Expect(mgr.GetBindingCount()).To(Equal(1))

				err := mgr.RemoveBinding(mac)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr.GetBindingCount()).To(Equal(0))
			})

			It("should handle removing non-existent binding gracefully", func() {
				mac, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

				err := mgr.RemoveBinding(mac)

				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when getting binding count", func() {
			It("should return 0 initially", func() {
				Expect(mgr.GetBindingCount()).To(Equal(0))
			})

			It("should reflect current bindings", func() {
				macs := []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03", "aa:bb:cc:dd:ee:04", "aa:bb:cc:dd:ee:05"}
				ips := []string{"10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4", "10.0.1.5"}
				for i := 0; i < 5; i++ {
					mac, _ := net.ParseMAC(macs[i])
					mgr.AddBinding(mac, net.ParseIP(ips[i]))
				}

				Expect(mgr.GetBindingCount()).To(Equal(5))
			})
		})
	})

	Describe("Mode Management", func() {
		var mgr *antispoof.Manager

		BeforeEach(func() {
			cfg := antispoof.ManagerConfig{
				Interface:   "eth0",
				DefaultMode: antispoof.ModeStrict,
			}
			var err error
			mgr, err = antispoof.NewManager(cfg, logger)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when setting mode", func() {
			DescribeTable("should accept all valid modes",
				func(mode antispoof.Mode) {
					err := mgr.SetMode(mode)
					Expect(err).NotTo(HaveOccurred())
				},
				Entry("Disabled", antispoof.ModeDisabled),
				Entry("Strict", antispoof.ModeStrict),
				Entry("Loose", antispoof.ModeLoose),
				Entry("LogOnly", antispoof.ModeLogOnly),
			)
		})
	})

	Describe("Binding Struct", func() {
		It("should contain all expected fields", func() {
			mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			binding := &antispoof.Binding{
				MAC:      mac,
				IPv4:     net.ParseIP("10.0.1.100"),
				IPv6:     net.ParseIP("2001:db8::1"),
				Mode:     antispoof.ModeStrict,
				Verified: true,
			}

			Expect(binding.MAC.String()).To(Equal("aa:bb:cc:dd:ee:ff"))
			Expect(binding.IPv4.String()).To(Equal("10.0.1.100"))
			Expect(binding.IPv6.String()).To(Equal("2001:db8::1"))
			Expect(binding.Mode).To(Equal(antispoof.ModeStrict))
			Expect(binding.Verified).To(BeTrue())
		})
	})

	Describe("SubscriberBinding Struct", func() {
		It("should have correct field layout for eBPF", func() {
			binding := antispoof.SubscriberBinding{
				IPv4Addr:  0x0A000164, // 10.0.1.100
				IPv4Valid: 1,
				IPv6Valid: 0,
				Mode:      1,
			}

			Expect(binding.IPv4Addr).To(Equal(uint32(0x0A000164)))
			Expect(binding.IPv4Valid).To(Equal(uint8(1)))
			Expect(binding.IPv6Valid).To(Equal(uint8(0)))
			Expect(binding.Mode).To(Equal(uint8(1)))
		})
	})

	Describe("Stats Struct", func() {
		It("should contain all statistics fields", func() {
			stats := antispoof.Stats{
				PacketsAllowed: 1000,
				PacketsDropped: 50,
				PacketsLogged:  100,
				IPv4Violations: 30,
				IPv6Violations: 20,
				UnknownMAC:     10,
			}

			Expect(stats.PacketsAllowed).To(Equal(uint64(1000)))
			Expect(stats.PacketsDropped).To(Equal(uint64(50)))
			Expect(stats.PacketsLogged).To(Equal(uint64(100)))
			Expect(stats.IPv4Violations).To(Equal(uint64(30)))
			Expect(stats.IPv6Violations).To(Equal(uint64(20)))
			Expect(stats.UnknownMAC).To(Equal(uint64(10)))
		})
	})

	Describe("SpoofEvent Struct", func() {
		It("should contain event details", func() {
			event := antispoof.SpoofEvent{
				Timestamp: 1234567890,
				Protocol:  4,
				SpoofedIP: 0xC0A80165, // 192.168.1.101
				AllowedIP: 0xC0A80164, // 192.168.1.100
			}
			event.SrcMAC = [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

			Expect(event.Timestamp).To(Equal(uint64(1234567890)))
			Expect(event.Protocol).To(Equal(uint8(4)))
			Expect(event.SrcMAC).To(Equal([6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}))
		})
	})

	Describe("ManagerConfig", func() {
		DescribeTable("should validate configurations",
			func(cfg antispoof.ManagerConfig, expectValid bool) {
				mgr, err := antispoof.NewManager(cfg, logger)
				if expectValid {
					Expect(err).NotTo(HaveOccurred())
					Expect(mgr).NotTo(BeNil())
				} else {
					Expect(err).To(HaveOccurred())
				}
			},
			Entry("valid: minimal", antispoof.ManagerConfig{Interface: "eth0"}, true),
			Entry("valid: with mode", antispoof.ManagerConfig{Interface: "eth0", DefaultMode: antispoof.ModeLoose}, true),
			Entry("valid: with logging", antispoof.ManagerConfig{Interface: "eth0", LogEnabled: true}, true),
			Entry("invalid: no interface", antispoof.ManagerConfig{}, false),
		)
	})
})
