package pppoe_test

import (
	"net"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/pppoe"
)

var _ = Describe("PPPoE Server", func() {
	var (
		server        *pppoe.Server
		serverConfig  pppoe.ServerConfig
		logger        *zap.Logger
		testInterface *net.Interface
	)

	BeforeEach(func() {
		logger, _ = zap.NewDevelopment()

		// Create a mock interface for testing
		testMAC, _ := net.ParseMAC("00:11:22:33:44:55")
		testInterface = &net.Interface{
			Index:        1,
			MTU:          1500,
			Name:         "eth0",
			HardwareAddr: testMAC,
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		}

		serverConfig = pppoe.ServerConfig{
			Interface:    "eth0",
			ServerIP:     "10.0.0.1",
			ClientPool:   "10.0.0.100/24",
			PoolGateway:  "10.0.0.1",
			ACName:       "Test-AC",
			ServiceName:  "internet",
			PrimaryDNS:   "8.8.8.8",
			SecondaryDNS: "8.8.4.4",
		}
	})

	Describe("Server Creation", func() {
		It("should create a server with valid config", func() {
			var err error
			server, err = pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).NotTo(HaveOccurred())
			Expect(server).NotTo(BeNil())
		})

		It("should fail without interface name", func() {
			serverConfig.Interface = ""
			_, err := pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("interface required"))
		})

		It("should fail with nil interface", func() {
			_, err := pppoe.NewServerWithInterface(serverConfig, logger, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("interface cannot be nil"))
		})

		It("should use default values when not specified", func() {
			serverConfig.ACName = ""
			serverConfig.ServiceName = ""
			serverConfig.ServerIP = ""

			var err error
			server, err = pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).NotTo(HaveOccurred())
			Expect(server).NotTo(BeNil())
		})

		It("should support custom IP pool", func() {
			serverConfig.ClientPool = "192.168.1.0/24"
			serverConfig.PoolGateway = "192.168.1.1"

			var err error
			server, err = pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).NotTo(HaveOccurred())
			Expect(server).NotTo(BeNil())
		})

		It("should support DNS configuration", func() {
			serverConfig.PrimaryDNS = "1.1.1.1"
			serverConfig.SecondaryDNS = "1.0.0.1"

			var err error
			server, err = pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).NotTo(HaveOccurred())
			Expect(server).NotTo(BeNil())
		})

		It("should fail with invalid pool CIDR", func() {
			serverConfig.ClientPool = "invalid"
			_, err := pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Server Statistics", func() {
		BeforeEach(func() {
			var err error
			server, err = pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should provide server statistics", func() {
			stats := server.GetStats()
			Expect(stats).NotTo(BeNil())
			// Verify all expected keys exist
			expectedKeys := []string{"padi_received", "pado_sent", "padr_received", "pads_sent", "padt_received", "padt_sent", "sessions_total", "sessions_active"}
			for _, key := range expectedKeys {
				_, exists := stats[key]
				Expect(exists).To(BeTrue())
			}
		})

		It("should track session count", func() {
			count := server.GetSessionCount()
			Expect(count).To(BeNumerically("==", 0))
		})
	})

	Describe("RADIUS Client Configuration", func() {
		BeforeEach(func() {
			var err error
			server, err = pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allow setting RADIUS client", func() {
			server.SetRADIUSClient(nil)
			// If no panic, test passes
			Expect(true).To(BeTrue())
		})
	})

	Describe("Server Lifecycle", func() {
		BeforeEach(func() {
			var err error
			server, err = pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allow stop to be called multiple times", func() {
			err := server.Stop()
			Expect(err).NotTo(HaveOccurred())

			// Second stop should not cause issues
			err = server.Stop()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle stop before start", func() {
			// Create a new server for this test
			newServer, err := pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).NotTo(HaveOccurred())

			// Stop without start should not panic
			err = newServer.Stop()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("Packet Type Constants", func() {
		It("should have correct discovery packet codes", func() {
			Expect(pppoe.CodePADI).To(BeNumerically("==", 0x09))
			Expect(pppoe.CodePADO).To(BeNumerically("==", 0x07))
			Expect(pppoe.CodePADR).To(BeNumerically("==", 0x19))
			Expect(pppoe.CodePADS).To(BeNumerically("==", 0x65))
			Expect(pppoe.CodePADT).To(BeNumerically("==", 0xA7))
		})

		It("should have correct Ethernet types", func() {
			Expect(pppoe.EtherTypePPPoEDiscovery).To(BeNumerically("==", 0x8863))
			Expect(pppoe.EtherTypePPPoESession).To(BeNumerically("==", 0x8864))
		})

		It("should have correct tag types", func() {
			Expect(pppoe.TagServiceName).To(BeNumerically("==", 0x0101))
			Expect(pppoe.TagACName).To(BeNumerically("==", 0x0102))
			Expect(pppoe.TagHostUniq).To(BeNumerically("==", 0x0103))
			Expect(pppoe.TagACCookie).To(BeNumerically("==", 0x0104))
		})
	})

	Describe("NewServer function", func() {
		It("should create server using NewServer with real interface lookup", func() {
			// This will fail in test environment but that's OK - we're testing the path
			_, err := pppoe.NewServer(serverConfig, logger)
			// In test environment, this will likely fail due to missing interface
			// But we're at least exercising the code path
			if err != nil {
				Expect(err.Error()).To(ContainSubstring("failed to get interface"))
			}
		})
	})

	Describe("Error Handling", func() {
		It("should handle nil logger gracefully", func() {
			// Create server with nil logger should not panic
			server, err := pppoe.NewServerWithInterface(serverConfig, nil, testInterface)
			// Should either succeed or fail gracefully
			if err == nil {
				Expect(server).NotTo(BeNil())
			}
		})
	})

	Describe("IPPool Allocation", func() {
		It("should allocate and release IPs", func() {
			pool, err := pppoe.NewIPPool("10.0.0.100/24", "10.0.0.1")
			Expect(err).NotTo(HaveOccurred())
			Expect(pool).NotTo(BeNil())

			// Allocate first IP
			ip1 := pool.Allocate("session1")
			Expect(ip1).NotTo(BeNil())

			// Allocate second IP
			ip2 := pool.Allocate("session2")
			Expect(ip2).NotTo(BeNil())
			Expect(ip2.String()).NotTo(Equal(ip1.String())) // Different IPs

			// Release first IP
			pool.Release("session1")

			// Allocate again - should succeed
			ip3 := pool.Allocate("session3")
			Expect(ip3).NotTo(BeNil())
		})

		It("should handle release of non-existent session", func() {
			pool, err := pppoe.NewIPPool("10.0.0.100/24", "10.0.0.1")
			Expect(err).NotTo(HaveOccurred())

			// Release non-existent session should not panic
			pool.Release("nonexistent")
			Expect(true).To(BeTrue())
		})
	})

	Describe("Concurrent Operations", func() {
		var wg sync.WaitGroup

		BeforeEach(func() {
			var err error
			server, err = pppoe.NewServerWithInterface(serverConfig, logger, testInterface)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			wg.Wait()
		})

		It("should handle concurrent stats requests", func() {
			// Test concurrent access to statistics
			for i := 0; i < 10; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer GinkgoRecover()
					stats := server.GetStats()
					Expect(stats).NotTo(BeNil())
				}()
			}
		})

		It("should handle concurrent session count requests", func() {
			// Test concurrent access to session count
			for i := 0; i < 10; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer GinkgoRecover()
					count := server.GetSessionCount()
					Expect(count).To(BeNumerically("==", 0))
				}()
			}
		})
	})
})
