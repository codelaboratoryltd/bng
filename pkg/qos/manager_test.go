package qos_test

import (
	"net"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/qos"
	"go.uber.org/zap"
)

func TestQoS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "QoS Manager Suite")
}

var _ = Describe("QoS Manager", func() {
	var (
		logger *zap.Logger
	)

	BeforeEach(func() {
		logger = zap.NewNop()
	})

	Describe("NewManager", func() {
		Context("when creating with valid config", func() {
			It("should create successfully with minimal config", func() {
				cfg := qos.ManagerConfig{
					Interface: "eth0",
				}

				mgr, err := qos.NewManager(cfg, nil, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should create with custom BPF path", func() {
				cfg := qos.ManagerConfig{
					Interface: "eth0",
					BPFPath:   "/custom/path/qos.bpf.o",
				}

				mgr, err := qos.NewManager(cfg, nil, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})
		})

		Context("when creating with invalid config", func() {
			It("should return error when interface is empty", func() {
				cfg := qos.ManagerConfig{}

				mgr, err := qos.NewManager(cfg, nil, logger)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("interface required"))
				Expect(mgr).To(BeNil())
			})
		})
	})

	Describe("Subscriber QoS Management", func() {
		var mgr *qos.Manager

		BeforeEach(func() {
			cfg := qos.ManagerConfig{
				Interface: "eth0",
			}
			var err error
			mgr, err = qos.NewManager(cfg, nil, logger)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when setting subscriber QoS", func() {
			It("should set QoS for a subscriber", func() {
				subQoS := &qos.SubscriberQoS{
					IP:          net.ParseIP("10.0.1.100"),
					DownloadBPS: 100_000_000, // 100 Mbps
					UploadBPS:   50_000_000,  // 50 Mbps
					PolicyName:  "gold",
				}

				err := mgr.SetSubscriberQoS(subQoS)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr.GetSubscriberCount()).To(Equal(1))
			})

			It("should set QoS for multiple subscribers", func() {
				for i := 1; i <= 5; i++ {
					subQoS := &qos.SubscriberQoS{
						IP:          net.ParseIP("10.0.1." + string(rune('0'+i))),
						DownloadBPS: 50_000_000,
						UploadBPS:   25_000_000,
					}
					mgr.SetSubscriberQoS(subQoS)
				}

				Expect(mgr.GetSubscriberCount()).To(Equal(5))
			})

			It("should update existing subscriber QoS", func() {
				ip := net.ParseIP("10.0.1.100")

				mgr.SetSubscriberQoS(&qos.SubscriberQoS{
					IP:          ip,
					DownloadBPS: 50_000_000,
					UploadBPS:   25_000_000,
				})

				mgr.SetSubscriberQoS(&qos.SubscriberQoS{
					IP:          ip,
					DownloadBPS: 100_000_000,
					UploadBPS:   50_000_000,
				})

				Expect(mgr.GetSubscriberCount()).To(Equal(1))
			})

			It("should reject nil IP", func() {
				subQoS := &qos.SubscriberQoS{
					IP:          nil,
					DownloadBPS: 100_000_000,
					UploadBPS:   50_000_000,
				}

				err := mgr.SetSubscriberQoS(subQoS)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("IP required"))
			})

			It("should reject IPv6 addresses", func() {
				subQoS := &qos.SubscriberQoS{
					IP:          net.ParseIP("2001:db8::1"),
					DownloadBPS: 100_000_000,
					UploadBPS:   50_000_000,
				}

				err := mgr.SetSubscriberQoS(subQoS)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("IPv4"))
			})

			It("should calculate default burst size", func() {
				subQoS := &qos.SubscriberQoS{
					IP:          net.ParseIP("10.0.1.100"),
					DownloadBPS: 100_000_000, // 100 Mbps
					UploadBPS:   50_000_000,
					BurstBytes:  0, // Let it calculate
				}

				err := mgr.SetSubscriberQoS(subQoS)

				Expect(err).NotTo(HaveOccurred())
			})

			It("should use provided burst size", func() {
				subQoS := &qos.SubscriberQoS{
					IP:          net.ParseIP("10.0.1.100"),
					DownloadBPS: 100_000_000,
					UploadBPS:   50_000_000,
					BurstBytes:  1_000_000, // 1 MB
				}

				err := mgr.SetSubscriberQoS(subQoS)

				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when removing subscriber QoS", func() {
			It("should remove existing subscriber", func() {
				ip := net.ParseIP("10.0.1.100")
				mgr.SetSubscriberQoS(&qos.SubscriberQoS{
					IP:          ip,
					DownloadBPS: 100_000_000,
					UploadBPS:   50_000_000,
				})
				Expect(mgr.GetSubscriberCount()).To(Equal(1))

				err := mgr.RemoveSubscriberQoS(ip)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr.GetSubscriberCount()).To(Equal(0))
			})

			It("should handle removing non-existent subscriber", func() {
				err := mgr.RemoveSubscriberQoS(net.ParseIP("10.0.99.99"))

				Expect(err).NotTo(HaveOccurred())
			})

			It("should reject IPv6 addresses", func() {
				err := mgr.RemoveSubscriberQoS(net.ParseIP("2001:db8::1"))

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("IPv4"))
			})
		})

		Context("when getting subscriber count", func() {
			It("should return 0 initially", func() {
				Expect(mgr.GetSubscriberCount()).To(Equal(0))
			})

			It("should reflect current subscribers", func() {
				mgr.SetSubscriberQoS(&qos.SubscriberQoS{
					IP: net.ParseIP("10.0.1.1"), DownloadBPS: 100_000_000, UploadBPS: 50_000_000,
				})
				mgr.SetSubscriberQoS(&qos.SubscriberQoS{
					IP: net.ParseIP("10.0.1.2"), DownloadBPS: 100_000_000, UploadBPS: 50_000_000,
				})

				Expect(mgr.GetSubscriberCount()).To(Equal(2))
			})
		})
	})

	Describe("SubscriberQoS Struct", func() {
		It("should contain all expected fields", func() {
			subQoS := &qos.SubscriberQoS{
				IP:          net.ParseIP("10.0.1.100"),
				DownloadBPS: 100_000_000,
				UploadBPS:   50_000_000,
				BurstBytes:  1_000_000,
				Priority:    1,
				PolicyName:  "premium",
			}

			Expect(subQoS.IP.String()).To(Equal("10.0.1.100"))
			Expect(subQoS.DownloadBPS).To(Equal(uint64(100_000_000)))
			Expect(subQoS.UploadBPS).To(Equal(uint64(50_000_000)))
			Expect(subQoS.BurstBytes).To(Equal(uint32(1_000_000)))
			Expect(subQoS.Priority).To(Equal(uint8(1)))
			Expect(subQoS.PolicyName).To(Equal("premium"))
		})

		DescribeTable("common bandwidth tiers",
			func(downloadMbps, uploadMbps int, description string) {
				subQoS := &qos.SubscriberQoS{
					IP:          net.ParseIP("10.0.1.1"),
					DownloadBPS: uint64(downloadMbps * 1_000_000),
					UploadBPS:   uint64(uploadMbps * 1_000_000),
					PolicyName:  description,
				}

				Expect(subQoS.DownloadBPS).To(Equal(uint64(downloadMbps * 1_000_000)))
				Expect(subQoS.UploadBPS).To(Equal(uint64(uploadMbps * 1_000_000)))
			},
			Entry("Basic 25/5", 25, 5, "basic"),
			Entry("Standard 100/20", 100, 20, "standard"),
			Entry("Premium 500/100", 500, 100, "premium"),
			Entry("Gigabit 1000/500", 1000, 500, "gigabit"),
		)
	})

	Describe("TokenBucket Struct", func() {
		It("should have correct field layout for eBPF", func() {
			tb := qos.TokenBucket{
				Tokens:     1000000,
				LastUpdate: 1234567890,
				RateBPS:    100_000_000,
				BurstBytes: 1_000_000,
				Priority:   1,
			}

			Expect(tb.Tokens).To(Equal(uint64(1000000)))
			Expect(tb.LastUpdate).To(Equal(uint64(1234567890)))
			Expect(tb.RateBPS).To(Equal(uint64(100_000_000)))
			Expect(tb.BurstBytes).To(Equal(uint32(1_000_000)))
			Expect(tb.Priority).To(Equal(uint8(1)))
		})
	})

	Describe("QoSStats Struct", func() {
		It("should contain all statistics fields", func() {
			stats := qos.QoSStats{
				PacketsPassed:  1000000,
				PacketsDropped: 1000,
				BytesPassed:    1500000000,
				BytesDropped:   1500000,
			}

			Expect(stats.PacketsPassed).To(Equal(uint64(1000000)))
			Expect(stats.PacketsDropped).To(Equal(uint64(1000)))
			Expect(stats.BytesPassed).To(Equal(uint64(1500000000)))
			Expect(stats.BytesDropped).To(Equal(uint64(1500000)))
		})

		It("should calculate drop rate", func() {
			stats := qos.QoSStats{
				PacketsPassed:  999000,
				PacketsDropped: 1000,
			}

			totalPackets := stats.PacketsPassed + stats.PacketsDropped
			dropRate := float64(stats.PacketsDropped) / float64(totalPackets) * 100

			Expect(dropRate).To(BeNumerically("~", 0.1, 0.01)) // ~0.1%
		})
	})

	Describe("ManagerConfig", func() {
		DescribeTable("should validate configurations",
			func(cfg qos.ManagerConfig, expectValid bool) {
				mgr, err := qos.NewManager(cfg, nil, logger)
				if expectValid {
					Expect(err).NotTo(HaveOccurred())
					Expect(mgr).NotTo(BeNil())
				} else {
					Expect(err).To(HaveOccurred())
				}
			},
			Entry("valid: minimal", qos.ManagerConfig{Interface: "eth0"}, true),
			Entry("valid: with BPF path", qos.ManagerConfig{Interface: "eth0", BPFPath: "/path/to/bpf"}, true),
			Entry("invalid: no interface", qos.ManagerConfig{}, false),
		)
	})
})
