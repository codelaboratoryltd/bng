package allocator_test

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/allocator"
)

func TestAllocator(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Allocator Suite")
}

var _ = Describe("IPAllocator", func() {
	Describe("IPv4 Allocation", func() {
		var alloc *allocator.IPAllocator

		BeforeEach(func() {
			var err error
			alloc, err = allocator.NewIPAllocator("10.0.1.0/24", 32)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allocate sequential addresses", func() {
			prefix1, err := alloc.Allocate("sub-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix1.IP.String()).To(Equal("10.0.1.0"))
			Expect(prefix1.String()).To(Equal("10.0.1.0/32"))

			prefix2, err := alloc.Allocate("sub-2")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix2.IP.String()).To(Equal("10.0.1.1"))

			prefix3, err := alloc.Allocate("sub-3")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix3.IP.String()).To(Equal("10.0.1.2"))
		})

		It("should return existing allocation for same subscriber", func() {
			prefix1, err := alloc.Allocate("sub-1")
			Expect(err).NotTo(HaveOccurred())

			prefix2, err := alloc.Allocate("sub-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix2.String()).To(Equal(prefix1.String()))
		})

		It("should release and reuse addresses", func() {
			prefix1, _ := alloc.Allocate("sub-1")
			alloc.Allocate("sub-2")

			err := alloc.Release("sub-1")
			Expect(err).NotTo(HaveOccurred())

			// New allocation should get the released address
			prefix3, err := alloc.Allocate("sub-3")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix3.String()).To(Equal(prefix1.String()))
		})

		It("should exhaust pool", func() {
			// Allocate all 256 addresses
			for i := 0; i < 256; i++ {
				_, err := alloc.Allocate(fmt.Sprintf("sub-%d", i))
				Expect(err).NotTo(HaveOccurred())
			}

			// Next allocation should fail
			_, err := alloc.Allocate("overflow")
			Expect(err).To(MatchError(allocator.ErrPoolExhausted))
		})

		It("should track statistics", func() {
			alloc.Allocate("sub-1")
			alloc.Allocate("sub-2")

			allocated, total, util := alloc.Stats()
			Expect(allocated).To(Equal(uint64(2)))
			Expect(total).To(Equal(uint64(256)))
			Expect(util).To(BeNumerically("~", 0.78, 0.1))
		})

		It("should lookup by subscriber", func() {
			alloc.Allocate("sub-1")

			prefix := alloc.Lookup("sub-1")
			Expect(prefix).NotTo(BeNil())
			Expect(prefix.IP.String()).To(Equal("10.0.1.0"))

			prefix = alloc.Lookup("nonexistent")
			Expect(prefix).To(BeNil())
		})

		It("should lookup by prefix", func() {
			alloc.Allocate("sub-1")

			_, ipNet, _ := net.ParseCIDR("10.0.1.0/32")
			subID := alloc.LookupByPrefix(ipNet)
			Expect(subID).To(Equal("sub-1"))

			_, ipNet, _ = net.ParseCIDR("10.0.1.100/32")
			subID = alloc.LookupByPrefix(ipNet)
			Expect(subID).To(Equal(""))
		})

		It("should allocate specific address", func() {
			_, ipNet, _ := net.ParseCIDR("10.0.1.100/32")
			err := alloc.AllocateSpecific("sub-1", ipNet)
			Expect(err).NotTo(HaveOccurred())

			prefix := alloc.Lookup("sub-1")
			Expect(prefix.IP.String()).To(Equal("10.0.1.100"))
		})

		It("should reject duplicate specific allocation", func() {
			_, ipNet, _ := net.ParseCIDR("10.0.1.100/32")
			alloc.AllocateSpecific("sub-1", ipNet)

			err := alloc.AllocateSpecific("sub-2", ipNet)
			Expect(err).To(MatchError(ContainSubstring("already allocated")))
		})

		It("should check if prefix is allocated", func() {
			alloc.Allocate("sub-1")

			_, ipNet, _ := net.ParseCIDR("10.0.1.0/32")
			Expect(alloc.IsAllocated(ipNet)).To(BeTrue())

			_, ipNet, _ = net.ParseCIDR("10.0.1.1/32")
			Expect(alloc.IsAllocated(ipNet)).To(BeFalse())
		})

		It("should list all allocations", func() {
			alloc.Allocate("sub-1")
			alloc.Allocate("sub-2")

			allocations := alloc.ListAllocations()
			Expect(allocations).To(HaveLen(2))
		})
	})

	Describe("IPv6 Address Allocation", func() {
		var alloc *allocator.IPAllocator

		BeforeEach(func() {
			var err error
			// /48 pool allocating /64 subscriber prefixes
			alloc, err = allocator.NewIPAllocator("2001:db8::/48", 64)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allocate /64 prefixes", func() {
			prefix, err := alloc.Allocate("sub-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix.String()).To(Equal("2001:db8::/64"))

			prefix, err = alloc.Allocate("sub-2")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix.String()).To(Equal("2001:db8:0:1::/64"))
		})

		It("should have correct stats for /48 to /64", func() {
			_, total, _ := alloc.Stats()
			// /48 to /64 = 2^16 = 65536 prefixes
			Expect(total).To(Equal(uint64(65536)))
		})
	})

	Describe("IPv6 Prefix Delegation", func() {
		var alloc *allocator.IPAllocator

		BeforeEach(func() {
			var err error
			// /48 pool delegating /56 prefixes
			alloc, err = allocator.NewIPAllocator("2001:db8::/48", 56)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allocate /56 prefixes", func() {
			prefix, err := alloc.Allocate("sub-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix.String()).To(Equal("2001:db8::/56"))

			prefix, err = alloc.Allocate("sub-2")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix.String()).To(Equal("2001:db8:0:100::/56"))
		})

		It("should have correct stats for /48 to /56", func() {
			_, total, _ := alloc.Stats()
			// /48 to /56 = 2^8 = 256 prefixes
			Expect(total).To(Equal(uint64(256)))
		})
	})

	Describe("Configuration Validation", func() {
		It("should reject invalid CIDR", func() {
			_, err := allocator.NewIPAllocator("invalid", 32)
			Expect(err).To(HaveOccurred())
		})

		It("should reject prefix length smaller than pool", func() {
			_, err := allocator.NewIPAllocator("10.0.0.0/24", 16)
			Expect(err).To(HaveOccurred())
		})

		It("should reject prefix length larger than address size", func() {
			_, err := allocator.NewIPAllocator("10.0.0.0/24", 64)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Persistence", func() {
		It("should marshal and unmarshal state", func() {
			alloc, _ := allocator.NewIPAllocator("10.0.1.0/24", 32)
			alloc.Allocate("sub-1")
			alloc.Allocate("sub-2")
			alloc.Allocate("sub-3")
			alloc.Release("sub-2")

			// Marshal
			data, err := json.Marshal(alloc)
			Expect(err).NotTo(HaveOccurred())

			// Unmarshal into new allocator
			var restored allocator.IPAllocator
			err = json.Unmarshal(data, &restored)
			Expect(err).NotTo(HaveOccurred())

			// Verify state
			Expect(restored.Lookup("sub-1")).NotTo(BeNil())
			Expect(restored.Lookup("sub-2")).To(BeNil())
			Expect(restored.Lookup("sub-3")).NotTo(BeNil())

			allocated, total, _ := restored.Stats()
			Expect(allocated).To(Equal(uint64(2)))
			Expect(total).To(Equal(uint64(256)))
		})
	})

	Describe("Concurrency", func() {
		It("should handle concurrent allocations", func() {
			alloc, _ := allocator.NewIPAllocator("10.0.0.0/20", 32) // 4096 addresses

			var wg sync.WaitGroup
			allocations := make(chan *net.IPNet, 1000)
			errors := make(chan error, 1000)

			// Spawn 100 goroutines each allocating 10 addresses
			for i := 0; i < 100; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					for j := 0; j < 10; j++ {
						// Use unique subscriber ID based on goroutine id and iteration
						subID := fmt.Sprintf("sub-%d-%d", id, j)
						prefix, err := alloc.Allocate(subID)
						if err != nil {
							errors <- err
						} else {
							allocations <- prefix
						}
					}
				}(i)
			}

			wg.Wait()
			close(allocations)
			close(errors)

			// Verify no errors
			for err := range errors {
				Fail("Unexpected error: " + err.Error())
			}

			// Verify all allocations are unique
			seen := make(map[string]bool)
			for prefix := range allocations {
				key := prefix.String()
				Expect(seen[key]).To(BeFalse(), "Duplicate allocation: "+key)
				seen[key] = true
			}
		})
	})

	Describe("Edge Cases", func() {
		It("should handle /32 pool (single address)", func() {
			alloc, err := allocator.NewIPAllocator("10.0.0.1/32", 32)
			Expect(err).NotTo(HaveOccurred())

			prefix, err := alloc.Allocate("sub-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(prefix.IP.String()).To(Equal("10.0.0.1"))

			_, err = alloc.Allocate("sub-2")
			Expect(err).To(MatchError(allocator.ErrPoolExhausted))
		})

		It("should handle release of non-existent subscriber", func() {
			alloc, _ := allocator.NewIPAllocator("10.0.1.0/24", 32)

			err := alloc.Release("nonexistent")
			Expect(err).To(MatchError(ContainSubstring("no allocation")))
		})

		It("should handle out-of-range prefix lookup", func() {
			alloc, _ := allocator.NewIPAllocator("10.0.1.0/24", 32)

			_, ipNet, _ := net.ParseCIDR("192.168.1.1/32")
			Expect(alloc.Contains(ipNet)).To(BeFalse())
		})

		It("should reject wrong prefix length in specific allocation", func() {
			alloc, _ := allocator.NewIPAllocator("10.0.1.0/24", 32)

			_, ipNet, _ := net.ParseCIDR("10.0.1.0/24") // Wrong prefix length
			err := alloc.AllocateSpecific("sub-1", ipNet)
			Expect(err).To(HaveOccurred())
		})
	})
})
