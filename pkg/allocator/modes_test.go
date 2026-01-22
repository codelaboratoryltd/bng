package allocator_test

import (
	"context"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/allocator"
)

var _ = Describe("LocalAllocator", func() {
	var (
		alloc *allocator.LocalAllocator
		ctx   context.Context
	)

	BeforeEach(func() {
		var err error
		alloc, err = allocator.NewLocalAllocator(allocator.LocalAllocatorConfig{
			Pools: []allocator.PoolConfig{
				{
					ID:           "pool-1",
					CIDR:         "10.0.1.0/24",
					PrefixLength: 32,
				},
				{
					ID:           "pool-2",
					CIDR:         "10.0.2.0/24",
					PrefixLength: 32,
				},
			},
			Logger: zap.NewNop(),
		})
		Expect(err).NotTo(HaveOccurred())
		ctx = context.Background()
	})

	AfterEach(func() {
		alloc.Close()
	})

	Describe("Allocate", func() {
		It("should allocate from specified pool", func() {
			prefix, err := alloc.Allocate(ctx, "sub-1", "pool-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix).NotTo(BeNil())
			Expect(prefix.IP.String()).To(HavePrefix("10.0.1."))
		})

		It("should return error for unknown pool", func() {
			_, err := alloc.Allocate(ctx, "sub-1", "unknown-pool")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("should return same allocation for same subscriber", func() {
			prefix1, err := alloc.Allocate(ctx, "sub-1", "pool-1")
			Expect(err).NotTo(HaveOccurred())

			prefix2, err := alloc.Allocate(ctx, "sub-1", "pool-1")
			Expect(err).NotTo(HaveOccurred())

			Expect(prefix1.String()).To(Equal(prefix2.String()))
		})

		It("should allocate different IPs for different subscribers", func() {
			prefix1, err := alloc.Allocate(ctx, "sub-1", "pool-1")
			Expect(err).NotTo(HaveOccurred())

			prefix2, err := alloc.Allocate(ctx, "sub-2", "pool-1")
			Expect(err).NotTo(HaveOccurred())

			Expect(prefix1.String()).NotTo(Equal(prefix2.String()))
		})
	})

	Describe("AllocateWithMAC", func() {
		It("should allocate with MAC tracking", func() {
			prefix, err := alloc.AllocateWithMAC(ctx, "sub-1", "pool-1", "aa:bb:cc:dd:ee:ff")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix).NotTo(BeNil())
		})
	})

	Describe("Release", func() {
		It("should release allocation", func() {
			prefix1, _ := alloc.Allocate(ctx, "sub-1", "pool-1")

			err := alloc.Release(ctx, "sub-1", "pool-1")
			Expect(err).NotTo(HaveOccurred())

			// Should be able to allocate again
			prefix2, err := alloc.Allocate(ctx, "sub-2", "pool-1")
			Expect(err).NotTo(HaveOccurred())
			// Should get the same IP since it was released
			Expect(prefix2.String()).To(Equal(prefix1.String()))
		})

		It("should return error for unknown pool", func() {
			err := alloc.Release(ctx, "sub-1", "unknown-pool")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Lookup", func() {
		It("should lookup by subscriber", func() {
			alloc.Allocate(ctx, "sub-1", "pool-1")
			alloc.Allocate(ctx, "sub-1", "pool-2")

			allocations, err := alloc.Lookup(ctx, "sub-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(allocations).To(HaveLen(2))
		})

		It("should return empty for unknown subscriber", func() {
			allocations, err := alloc.Lookup(ctx, "unknown")
			Expect(err).NotTo(HaveOccurred())
			Expect(allocations).To(BeEmpty())
		})
	})

	Describe("LookupByPool", func() {
		It("should lookup by pool", func() {
			alloc.Allocate(ctx, "sub-1", "pool-1")
			alloc.Allocate(ctx, "sub-2", "pool-1")
			alloc.Allocate(ctx, "sub-3", "pool-2")

			allocations, err := alloc.LookupByPool(ctx, "pool-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(allocations).To(HaveLen(2))
		})
	})

	Describe("LookupByIP", func() {
		It("should lookup by IP", func() {
			prefix, _ := alloc.Allocate(ctx, "sub-1", "pool-1")

			allocation, err := alloc.LookupByIP(ctx, prefix.IP)
			Expect(err).NotTo(HaveOccurred())
			Expect(allocation.SubscriberID).To(Equal("sub-1"))
			Expect(allocation.PoolID).To(Equal("pool-1"))
		})

		It("should return error for unknown IP", func() {
			_, err := alloc.LookupByIP(ctx, net.ParseIP("192.168.1.1"))
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Stats", func() {
		It("should return pool statistics", func() {
			alloc.Allocate(ctx, "sub-1", "pool-1")
			alloc.Allocate(ctx, "sub-2", "pool-1")

			allocated, total, util, err := alloc.Stats(ctx, "pool-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(allocated).To(Equal(uint64(2)))
			Expect(total).To(Equal(uint64(256)))
			Expect(util).To(BeNumerically("~", 0.78, 0.1))
		})

		It("should return error for unknown pool", func() {
			_, _, _, err := alloc.Stats(ctx, "unknown")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("ListPools", func() {
		It("should list all pools", func() {
			pools := alloc.ListPools()
			Expect(pools).To(HaveLen(2))
			Expect(pools).To(ContainElements("pool-1", "pool-2"))
		})
	})

	Describe("GetPool", func() {
		It("should return pool allocator", func() {
			pool, exists := alloc.GetPool("pool-1")
			Expect(exists).To(BeTrue())
			Expect(pool).NotTo(BeNil())
		})

		It("should return false for unknown pool", func() {
			_, exists := alloc.GetPool("unknown")
			Expect(exists).To(BeFalse())
		})
	})
})

var _ = Describe("WiFiGatewayAllocator", func() {
	var (
		alloc *allocator.WiFiGatewayAllocator
		ctx   context.Context
	)

	BeforeEach(func() {
		var err error
		alloc, err = allocator.NewWiFiGatewayAllocator(allocator.WiFiGatewayConfig{
			GuestPool: allocator.PoolConfig{
				ID:           "guest",
				CIDR:         "10.99.0.0/16",
				PrefixLength: 32,
			},
			LeaseDuration: 5 * time.Minute,
			Logger:        zap.NewNop(),
		})
		Expect(err).NotTo(HaveOccurred())
		ctx = context.Background()
	})

	AfterEach(func() {
		alloc.Close()
	})

	Describe("AllocateGuest", func() {
		It("should allocate for guest MAC", func() {
			prefix, err := alloc.AllocateGuest(ctx, "aa:bb:cc:dd:ee:ff")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix).NotTo(BeNil())
			Expect(prefix.IP.String()).To(HavePrefix("10.99."))
		})

		It("should return same IP for same MAC", func() {
			prefix1, _ := alloc.AllocateGuest(ctx, "aa:bb:cc:dd:ee:ff")
			prefix2, _ := alloc.AllocateGuest(ctx, "aa:bb:cc:dd:ee:ff")
			Expect(prefix1.String()).To(Equal(prefix2.String()))
		})
	})
})

var _ = Describe("HybridAllocator", func() {
	var (
		alloc *allocator.HybridAllocator
		ctx   context.Context
	)

	BeforeEach(func() {
		var err error
		alloc, err = allocator.NewHybridAllocator(allocator.HybridAllocatorConfig{
			Pools: []allocator.PoolConfig{
				{
					ID:           "main",
					CIDR:         "10.0.0.0/24",
					PrefixLength: 32,
				},
			},
			NexusURL:     "http://nexus.internal:9000",
			SyncInterval: 100 * time.Millisecond, // Fast for testing
			Logger:       zap.NewNop(),
		})
		Expect(err).NotTo(HaveOccurred())
		ctx = context.Background()
	})

	AfterEach(func() {
		alloc.Close()
	})

	Describe("Allocate", func() {
		It("should allocate locally when Nexus unavailable", func() {
			prefix, err := alloc.Allocate(ctx, "sub-1", "main")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix).NotTo(BeNil())
		})

		It("should mark partition active when Nexus unavailable", func() {
			alloc.Allocate(ctx, "sub-1", "main")
			Expect(alloc.IsPartitionActive()).To(BeTrue())
		})
	})

	Describe("Lookup", func() {
		It("should lookup local allocations", func() {
			alloc.Allocate(ctx, "sub-1", "main")

			allocations, err := alloc.Lookup(ctx, "sub-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(allocations).To(HaveLen(1))
		})
	})

	Describe("Release", func() {
		It("should release allocation", func() {
			alloc.Allocate(ctx, "sub-1", "main")

			err := alloc.Release(ctx, "sub-1", "main")
			Expect(err).NotTo(HaveOccurred())

			allocations, _ := alloc.Lookup(ctx, "sub-1")
			Expect(allocations).To(BeEmpty())
		})
	})
})

var _ = Describe("Allocator Interface", func() {
	// Verify all allocators implement the interface
	It("LocalAllocator should implement Allocator", func() {
		var _ allocator.Allocator = &allocator.LocalAllocator{}
	})

	It("WiFiGatewayAllocator should implement Allocator", func() {
		var _ allocator.Allocator = &allocator.WiFiGatewayAllocator{}
	})

	It("HybridAllocator should implement Allocator", func() {
		var _ allocator.Allocator = &allocator.HybridAllocator{}
	})
})
