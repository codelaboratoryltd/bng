package allocator_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/allocator"
)

var _ = Describe("AllocationStore", func() {
	var (
		store *allocator.MemoryAllocationStore
		ctx   context.Context
	)

	BeforeEach(func() {
		store = allocator.NewMemoryAllocationStore()
		ctx = context.Background()
	})

	Describe("SaveAllocation", func() {
		It("should save and retrieve allocation", func() {
			_, ipNet, _ := net.ParseCIDR("10.0.1.100/32")
			record := allocator.AllocationRecord{
				SubscriberID: "sub-1",
				PoolID:       "pool-1",
				Prefix:       ipNet,
				MAC:          "aa:bb:cc:dd:ee:ff",
				AllocatedAt:  time.Now(),
			}

			err := store.SaveAllocation(ctx, record)
			Expect(err).NotTo(HaveOccurred())

			// Verify retrieval by subscriber
			allocs, err := store.GetBySubscriber(ctx, "sub-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(allocs).To(HaveLen(1))
			Expect(allocs[0].Prefix.IP.String()).To(Equal("10.0.1.100"))

			// Verify retrieval by pool
			allocs, err = store.GetByPool(ctx, "pool-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(allocs).To(HaveLen(1))

			// Verify retrieval by IP
			alloc, err := store.GetByIP(ctx, ipNet.IP)
			Expect(err).NotTo(HaveOccurred())
			Expect(alloc.SubscriberID).To(Equal("sub-1"))
		})

		It("should detect IP conflicts", func() {
			_, ipNet, _ := net.ParseCIDR("10.0.1.100/32")

			record1 := allocator.AllocationRecord{
				SubscriberID: "sub-1",
				PoolID:       "pool-1",
				Prefix:       ipNet,
				AllocatedAt:  time.Now(),
			}
			err := store.SaveAllocation(ctx, record1)
			Expect(err).NotTo(HaveOccurred())

			// Try to allocate same IP to different subscriber
			record2 := allocator.AllocationRecord{
				SubscriberID: "sub-2",
				PoolID:       "pool-1",
				Prefix:       ipNet,
				AllocatedAt:  time.Now(),
			}
			err = store.SaveAllocation(ctx, record2)
			Expect(err).To(MatchError(ContainSubstring("conflict")))
		})

		It("should allow update for same subscriber", func() {
			_, ipNet, _ := net.ParseCIDR("10.0.1.100/32")

			record := allocator.AllocationRecord{
				SubscriberID: "sub-1",
				PoolID:       "pool-1",
				Prefix:       ipNet,
				AllocatedAt:  time.Now(),
			}
			err := store.SaveAllocation(ctx, record)
			Expect(err).NotTo(HaveOccurred())

			// Update same subscriber's record
			record.MAC = "new:ma:ca:dd:re:ss"
			err = store.SaveAllocation(ctx, record)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("RemoveAllocation", func() {
		It("should remove allocation from all indexes", func() {
			_, ipNet, _ := net.ParseCIDR("10.0.1.100/32")
			record := allocator.AllocationRecord{
				SubscriberID: "sub-1",
				PoolID:       "pool-1",
				Prefix:       ipNet,
				AllocatedAt:  time.Now(),
			}
			store.SaveAllocation(ctx, record)

			err := store.RemoveAllocation(ctx, "pool-1", "sub-1")
			Expect(err).NotTo(HaveOccurred())

			// Verify removed from all indexes
			allocs, _ := store.GetBySubscriber(ctx, "sub-1")
			Expect(allocs).To(BeEmpty())

			allocs, _ = store.GetByPool(ctx, "pool-1")
			Expect(allocs).To(BeEmpty())

			_, err = store.GetByIP(ctx, ipNet.IP)
			Expect(err).To(MatchError(allocator.ErrNotFound))
		})
	})

	Describe("GetPoolUtilization", func() {
		It("should return correct utilization", func() {
			store.SetPoolTotal("pool-1", 256)

			for i := 0; i < 10; i++ {
				_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("10.0.1.%d/32", i))
				record := allocator.AllocationRecord{
					SubscriberID: fmt.Sprintf("sub-%d", i),
					PoolID:       "pool-1",
					Prefix:       ipNet,
					AllocatedAt:  time.Now(),
				}
				store.SaveAllocation(ctx, record)
			}

			allocated, total, err := store.GetPoolUtilization(ctx, "pool-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(allocated).To(Equal(10))
			Expect(total).To(Equal(256))
		})
	})

	Describe("ListPools", func() {
		It("should list all pools with allocations", func() {
			// Add allocations to multiple pools with unique IPs
			pools := []string{"pool-1", "pool-2", "pool-3"}
			for i, poolID := range pools {
				_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("10.0.%d.1/32", i+1))
				record := allocator.AllocationRecord{
					SubscriberID: "sub-" + poolID,
					PoolID:       poolID,
					Prefix:       ipNet,
					AllocatedAt:  time.Now(),
				}
				store.SaveAllocation(ctx, record)
			}

			pools, err := store.ListPools(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(pools).To(HaveLen(3))
			Expect(pools).To(ContainElements("pool-1", "pool-2", "pool-3"))
		})
	})

	Describe("Persistence", func() {
		It("should marshal and unmarshal state", func() {
			// Add some allocations
			for i := 0; i < 5; i++ {
				_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("10.0.1.%d/32", i))
				record := allocator.AllocationRecord{
					SubscriberID: fmt.Sprintf("sub-%d", i),
					PoolID:       "pool-1",
					Prefix:       ipNet,
					MAC:          fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i),
					AllocatedAt:  time.Now(),
				}
				store.SaveAllocation(ctx, record)
			}
			store.SetPoolTotal("pool-1", 256)

			// Marshal
			data, err := json.Marshal(store)
			Expect(err).NotTo(HaveOccurred())

			// Unmarshal into new store
			restored := allocator.NewMemoryAllocationStore()
			err = json.Unmarshal(data, restored)
			Expect(err).NotTo(HaveOccurred())

			// Verify state
			allocs, _ := restored.GetByPool(ctx, "pool-1")
			Expect(allocs).To(HaveLen(5))

			allocated, total, _ := restored.GetPoolUtilization(ctx, "pool-1")
			Expect(allocated).To(Equal(5))
			Expect(total).To(Equal(256))
		})
	})
})

var _ = Describe("PoolAllocator", func() {
	var (
		store     *allocator.MemoryAllocationStore
		poolAlloc *allocator.PoolAllocator
		ctx       context.Context
	)

	BeforeEach(func() {
		store = allocator.NewMemoryAllocationStore()
		ctx = context.Background()

		var err error
		poolAlloc, err = allocator.NewPoolAllocator("test-pool", "10.0.1.0/24", 32, store)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allocate and persist", func() {
		prefix, err := poolAlloc.Allocate(ctx, "sub-1", "aa:bb:cc:dd:ee:ff")
		Expect(err).NotTo(HaveOccurred())
		Expect(prefix).NotTo(BeNil())

		// Verify in store
		allocs, err := store.GetBySubscriber(ctx, "sub-1")
		Expect(err).NotTo(HaveOccurred())
		Expect(allocs).To(HaveLen(1))
		Expect(allocs[0].MAC).To(Equal("aa:bb:cc:dd:ee:ff"))
	})

	It("should release and remove from store", func() {
		poolAlloc.Allocate(ctx, "sub-1", "aa:bb:cc:dd:ee:ff")

		err := poolAlloc.Release(ctx, "sub-1")
		Expect(err).NotTo(HaveOccurred())

		// Verify removed from store
		allocs, _ := store.GetBySubscriber(ctx, "sub-1")
		Expect(allocs).To(BeEmpty())

		// Verify removed from allocator
		Expect(poolAlloc.Lookup("sub-1")).To(BeNil())
	})

	It("should track pool utilization", func() {
		for i := 0; i < 10; i++ {
			poolAlloc.Allocate(ctx, fmt.Sprintf("sub-%d", i), "")
		}

		allocated, total, util := poolAlloc.Stats()
		Expect(allocated).To(Equal(uint64(10)))
		Expect(total).To(Equal(uint64(256)))
		Expect(util).To(BeNumerically("~", 3.9, 0.1))
	})
})
