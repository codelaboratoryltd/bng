package nat_test

import (
	"net"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/nat"
	"go.uber.org/zap"
)

func TestNATManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NAT Manager Suite")
}

var _ = Describe("NAT Manager", func() {
	var (
		logger *zap.Logger
	)

	BeforeEach(func() {
		logger = zap.NewNop()
	})

	Describe("NewManager", func() {
		Context("when creating a manager with valid config", func() {
			It("should create successfully", func() {
				cfg := nat.ManagerConfig{
					Interface:          "eth0",
					PortsPerSubscriber: 1000,
				}

				mgr, err := nat.NewManager(cfg, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should use default values when not specified", func() {
				cfg := nat.ManagerConfig{
					Interface: "eth0",
				}

				mgr, err := nat.NewManager(cfg, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should accept feature flags", func() {
				cfg := nat.ManagerConfig{
					Interface:        "eth0",
					EnableEIM:        true,
					EnableHairpin:    true,
					EnableFTPALG:     true,
					EnablePortParity: true,
				}

				mgr, err := nat.NewManager(cfg, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})
		})

		Context("when creating a manager with invalid config", func() {
			It("should return error when interface is empty", func() {
				cfg := nat.ManagerConfig{}

				mgr, err := nat.NewManager(cfg, logger)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("interface required"))
				Expect(mgr).To(BeNil())
			})
		})
	})

	Describe("Public IP Pool Management", func() {
		var mgr *nat.Manager

		BeforeEach(func() {
			cfg := nat.ManagerConfig{
				Interface:          "eth0",
				PortsPerSubscriber: 1000,
			}
			var err error
			mgr, err = nat.NewManager(cfg, logger)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when adding public IPs", func() {
			It("should add a single IP successfully", func() {
				ip := net.ParseIP("203.0.113.1")

				err := mgr.AddPublicIP(ip)

				Expect(err).NotTo(HaveOccurred())
			})

			It("should add multiple IPs", func() {
				ips := []net.IP{
					net.ParseIP("203.0.113.1"),
					net.ParseIP("203.0.113.2"),
					net.ParseIP("203.0.113.3"),
				}

				for _, ip := range ips {
					err := mgr.AddPublicIP(ip)
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("should reject IPv6 addresses", func() {
				ip := net.ParseIP("2001:db8::1")
				err := mgr.AddPublicIP(ip)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("IPv4"))
			})
		})

		Context("when adding IP range", func() {
			It("should add a range of IPs", func() {
				startIP := net.ParseIP("203.0.113.1")
				endIP := net.ParseIP("203.0.113.5")

				err := mgr.AddPublicIPRange(startIP, endIP)

				Expect(err).NotTo(HaveOccurred())
				stats := mgr.GetPoolStats()
				Expect(stats).To(HaveLen(5))
			})

			It("should reject invalid range", func() {
				startIP := net.ParseIP("203.0.113.10")
				endIP := net.ParseIP("203.0.113.5")

				err := mgr.AddPublicIPRange(startIP, endIP)

				Expect(err).To(HaveOccurred())
			})
		})

		Context("when getting pool stats", func() {
			It("should return empty slice when no IPs added", func() {
				stats := mgr.GetPoolStats()
				Expect(stats).To(BeEmpty())
			})

			It("should return pool entries after adding IPs", func() {
				mgr.AddPublicIP(net.ParseIP("203.0.113.1"))
				mgr.AddPublicIP(net.ParseIP("203.0.113.2"))

				stats := mgr.GetPoolStats()

				Expect(stats).To(HaveLen(2))
			})
		})
	})

	Describe("NAT Allocation (Port Block Allocation - RFC 6431)", func() {
		var mgr *nat.Manager

		BeforeEach(func() {
			cfg := nat.ManagerConfig{
				Interface:          "eth0",
				PortsPerSubscriber: 100,
				PortRangeStart:     10000,
				PortRangeEnd:       20000,
			}
			var err error
			mgr, err = nat.NewManager(cfg, logger)
			Expect(err).NotTo(HaveOccurred())

			// Add public IP
			mgr.AddPublicIP(net.ParseIP("203.0.113.1"))
		})

		Context("when allocating NAT for a subscriber", func() {
			It("should allocate successfully", func() {
				subscriberIP := net.ParseIP("10.0.1.100")

				allocation, err := mgr.AllocateNAT(subscriberIP)

				Expect(err).NotTo(HaveOccurred())
				Expect(allocation).NotTo(BeNil())
				Expect(allocation.PublicIP).NotTo(BeNil())
				Expect(allocation.PublicIP.String()).To(Equal("203.0.113.1"))
				Expect(allocation.PortStart).To(BeNumerically(">=", 10000))
				Expect(allocation.PortEnd).To(BeNumerically(">", allocation.PortStart))
			})

			It("should assign a subscriber ID", func() {
				subscriberIP := net.ParseIP("10.0.1.100")

				allocation, err := mgr.AllocateNAT(subscriberIP)

				Expect(err).NotTo(HaveOccurred())
				Expect(allocation.SubscriberID).To(BeNumerically(">", 0))
			})

			It("should return same allocation for same subscriber", func() {
				subscriberIP := net.ParseIP("10.0.1.100")

				alloc1, err1 := mgr.AllocateNAT(subscriberIP)
				alloc2, err2 := mgr.AllocateNAT(subscriberIP)

				Expect(err1).NotTo(HaveOccurred())
				Expect(err2).NotTo(HaveOccurred())
				Expect(alloc1.PublicIP.String()).To(Equal(alloc2.PublicIP.String()))
				Expect(alloc1.PortStart).To(Equal(alloc2.PortStart))
				Expect(alloc1.PortEnd).To(Equal(alloc2.PortEnd))
				Expect(alloc1.SubscriberID).To(Equal(alloc2.SubscriberID))
			})

			It("should allocate different port ranges for different subscribers", func() {
				sub1 := net.ParseIP("10.0.1.1")
				sub2 := net.ParseIP("10.0.1.2")

				alloc1, _ := mgr.AllocateNAT(sub1)
				alloc2, _ := mgr.AllocateNAT(sub2)

				// Port ranges should not overlap
				Expect(alloc1.PortEnd).To(BeNumerically("<", alloc2.PortStart))
				// Different subscriber IDs
				Expect(alloc1.SubscriberID).NotTo(Equal(alloc2.SubscriberID))
			})

			It("should reject IPv6 addresses", func() {
				ipv6 := net.ParseIP("2001:db8::1")
				alloc, err := mgr.AllocateNAT(ipv6)
				Expect(err).To(HaveOccurred())
				Expect(alloc).To(BeNil())
			})

			It("should allocate correct number of ports", func() {
				subscriberIP := net.ParseIP("10.0.1.100")

				allocation, _ := mgr.AllocateNAT(subscriberIP)

				portCount := allocation.PortEnd - allocation.PortStart + 1
				Expect(portCount).To(Equal(uint16(100)))
			})
		})

		Context("when deallocating NAT", func() {
			It("should deallocate successfully", func() {
				subscriberIP := net.ParseIP("10.0.1.100")

				_, err := mgr.AllocateNAT(subscriberIP)
				Expect(err).NotTo(HaveOccurred())

				err = mgr.DeallocateNAT(subscriberIP)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should remove allocation from tracking", func() {
				subscriberIP := net.ParseIP("10.0.1.100")

				mgr.AllocateNAT(subscriberIP)
				Expect(mgr.GetAllocationCount()).To(Equal(1))

				mgr.DeallocateNAT(subscriberIP)
				Expect(mgr.GetAllocationCount()).To(Equal(0))
			})

			It("should allow reallocation after deallocation", func() {
				subscriberIP := net.ParseIP("10.0.1.100")

				alloc1, _ := mgr.AllocateNAT(subscriberIP)
				mgr.DeallocateNAT(subscriberIP)
				alloc2, err := mgr.AllocateNAT(subscriberIP)

				Expect(err).NotTo(HaveOccurred())
				Expect(alloc2).NotTo(BeNil())
				Expect(alloc2.PublicIP).NotTo(BeNil())
				// Port range may be different after reallocation
				_ = alloc1
			})

			It("should handle deallocating non-existent allocation gracefully", func() {
				subscriberIP := net.ParseIP("10.0.99.99")

				err := mgr.DeallocateNAT(subscriberIP)
				Expect(err).NotTo(HaveOccurred()) // Should not error
			})
		})

		Context("when no public IPs are available", func() {
			It("should return error", func() {
				emptyMgr, _ := nat.NewManager(nat.ManagerConfig{
					Interface:          "eth0",
					PortsPerSubscriber: 100,
				}, logger)
				subscriberIP := net.ParseIP("10.0.1.100")

				allocation, err := emptyMgr.AllocateNAT(subscriberIP)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("pool exhausted"))
				Expect(allocation).To(BeNil())
			})
		})
	})

	Describe("Allocation Tracking", func() {
		var mgr *nat.Manager

		BeforeEach(func() {
			cfg := nat.ManagerConfig{
				Interface:          "eth0",
				PortsPerSubscriber: 100,
			}
			var err error
			mgr, err = nat.NewManager(cfg, logger)
			Expect(err).NotTo(HaveOccurred())
			mgr.AddPublicIP(net.ParseIP("203.0.113.1"))
		})

		Context("when getting allocation count", func() {
			It("should return 0 initially", func() {
				Expect(mgr.GetAllocationCount()).To(Equal(0))
			})

			It("should increase after allocation", func() {
				mgr.AllocateNAT(net.ParseIP("10.0.1.1"))
				mgr.AllocateNAT(net.ParseIP("10.0.1.2"))

				Expect(mgr.GetAllocationCount()).To(Equal(2))
			})

			It("should decrease after deallocation", func() {
				sub1 := net.ParseIP("10.0.1.1")
				sub2 := net.ParseIP("10.0.1.2")

				mgr.AllocateNAT(sub1)
				mgr.AllocateNAT(sub2)
				mgr.DeallocateNAT(sub1)

				Expect(mgr.GetAllocationCount()).To(Equal(1))
			})
		})

		Context("when getting allocation by IP", func() {
			It("should return allocation for existing subscriber", func() {
				subscriberIP := net.ParseIP("10.0.1.100")
				mgr.AllocateNAT(subscriberIP)

				alloc := mgr.GetAllocation(subscriberIP)

				Expect(alloc).NotTo(BeNil())
				Expect(alloc.PrivateIP.String()).To(Equal("10.0.1.100"))
			})

			It("should return nil for non-existent subscriber", func() {
				alloc := mgr.GetAllocation(net.ParseIP("10.0.99.99"))
				Expect(alloc).To(BeNil())
			})

			It("should return nil for IPv6 address", func() {
				alloc := mgr.GetAllocation(net.ParseIP("2001:db8::1"))
				Expect(alloc).To(BeNil())
			})
		})
	})

	Describe("Allocation Struct", func() {
		It("should contain all required fields", func() {
			alloc := &nat.Allocation{
				PrivateIP:    net.ParseIP("10.0.1.100"),
				PublicIP:     net.ParseIP("203.0.113.1"),
				PortStart:    10000,
				PortEnd:      10999,
				PoolIndex:    0,
				SubscriberID: 1,
			}

			Expect(alloc.PrivateIP.String()).To(Equal("10.0.1.100"))
			Expect(alloc.PublicIP.String()).To(Equal("203.0.113.1"))
			Expect(alloc.PortStart).To(Equal(uint16(10000)))
			Expect(alloc.PortEnd).To(Equal(uint16(10999)))
			Expect(alloc.PoolIndex).To(Equal(0))
			Expect(alloc.SubscriberID).To(Equal(uint32(1)))
		})

		It("should track allocation time", func() {
			alloc := &nat.Allocation{}
			Expect(alloc.AllocatedAt.IsZero()).To(BeTrue())
		})
	})

	Describe("PoolEntry", func() {
		It("should contain pool statistics", func() {
			entry := nat.PoolEntry{
				PublicIP:       net.ParseIP("203.0.113.1"),
				TotalPorts:     64512,
				PortsPerSub:    1024,
				Subscribers:    10,
				MaxSubscribers: 63,
			}

			Expect(entry.PublicIP.String()).To(Equal("203.0.113.1"))
			Expect(entry.TotalPorts).To(Equal(64512))
			Expect(entry.PortsPerSub).To(Equal(1024))
			Expect(entry.Subscribers).To(Equal(10))
			Expect(entry.MaxSubscribers).To(Equal(63))
		})
	})

	Describe("ManagerConfig", func() {
		DescribeTable("should accept valid configurations",
			func(cfg nat.ManagerConfig, expectValid bool) {
				mgr, err := nat.NewManager(cfg, logger)
				if expectValid {
					Expect(err).NotTo(HaveOccurred())
					Expect(mgr).NotTo(BeNil())
				} else {
					Expect(err).To(HaveOccurred())
				}
			},
			Entry("valid: minimal config", nat.ManagerConfig{Interface: "eth0"}, true),
			Entry("valid: custom ports", nat.ManagerConfig{Interface: "eth0", PortsPerSubscriber: 500}, true),
			Entry("valid: custom port range", nat.ManagerConfig{Interface: "eth0", PortRangeStart: 5000, PortRangeEnd: 60000}, true),
			Entry("valid: with EIM enabled", nat.ManagerConfig{Interface: "eth0", EnableEIM: true}, true),
			Entry("valid: with hairpin enabled", nat.ManagerConfig{Interface: "eth0", EnableHairpin: true}, true),
			Entry("valid: with ALGs enabled", nat.ManagerConfig{Interface: "eth0", EnableFTPALG: true, EnableSIPALG: true}, true),
			Entry("invalid: no interface", nat.ManagerConfig{}, false),
		)
	})

	Describe("NAT Configuration Flags", func() {
		It("should have correct flag values", func() {
			Expect(nat.NATFlagEIMEnabled).To(Equal(uint32(0x01)))
			Expect(nat.NATFlagEIFEnabled).To(Equal(uint32(0x02)))
			Expect(nat.NATFlagHairpinEnabled).To(Equal(uint32(0x04)))
			Expect(nat.NATFlagALGFTP).To(Equal(uint32(0x08)))
			Expect(nat.NATFlagALGSIP).To(Equal(uint32(0x10)))
			Expect(nat.NATFlagPortParity).To(Equal(uint32(0x20)))
			Expect(nat.NATFlagPortContiguity).To(Equal(uint32(0x40)))
		})
	})

	Describe("NAT Log Event Types", func() {
		It("should have correct event type values", func() {
			Expect(nat.NATLogSessionCreate).To(Equal(uint32(1)))
			Expect(nat.NATLogSessionDelete).To(Equal(uint32(2)))
			Expect(nat.NATLogPortBlockAssign).To(Equal(uint32(3)))
			Expect(nat.NATLogPortBlockRelease).To(Equal(uint32(4)))
			Expect(nat.NATLogPortExhaustion).To(Equal(uint32(5)))
			Expect(nat.NATLogHairpin).To(Equal(uint32(6)))
			Expect(nat.NATLogALGTrigger).To(Equal(uint32(7)))
		})
	})

	Describe("ALG Types", func() {
		It("should have correct ALG type values", func() {
			Expect(nat.ALGTypeFTP).To(Equal(uint8(1)))
			Expect(nat.ALGTypeSIP).To(Equal(uint8(2)))
			Expect(nat.ALGTypeRTSP).To(Equal(uint8(3)))
		})
	})
})
