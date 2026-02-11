package nexus_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"github.com/codelaboratoryltd/bng/pkg/nexus"
)

var _ = Describe("CLSetStore", func() {
	var (
		store *nexus.CLSetStore
		ctx   context.Context
	)

	BeforeEach(func() {
		var err error
		store, err = nexus.NewCLSetStore(nexus.CLSetConfig{
			PeerID:       "test-peer-1",
			Namespace:    "test",
			SyncInterval: 100 * time.Millisecond,
			PeerTTL:      500 * time.Millisecond,
			Logger:       zap.NewNop(),
		})
		Expect(err).NotTo(HaveOccurred())
		ctx = context.Background()
	})

	AfterEach(func() {
		store.Close()
	})

	Describe("NewCLSetStore", func() {
		It("should require peer ID", func() {
			_, err := nexus.NewCLSetStore(nexus.CLSetConfig{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("peer ID"))
		})

		It("should create store with valid config", func() {
			s, err := nexus.NewCLSetStore(nexus.CLSetConfig{
				PeerID: "peer-1",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(s).NotTo(BeNil())
			s.Close()
		})

		It("should apply default values", func() {
			cfg := nexus.DefaultCLSetConfig()
			Expect(cfg.Namespace).To(Equal("nexus"))
			Expect(cfg.SyncInterval).To(Equal(5 * time.Second))
			Expect(cfg.PeerTTL).To(Equal(30 * time.Second))
		})
	})

	Describe("Get/Put", func() {
		It("should store and retrieve values", func() {
			err := store.Put(ctx, "key1", []byte("value1"))
			Expect(err).NotTo(HaveOccurred())

			value, err := store.Get(ctx, "key1")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(value)).To(Equal("value1"))
		})

		It("should return ErrNotFound for missing keys", func() {
			_, err := store.Get(ctx, "nonexistent")
			Expect(err).To(MatchError(nexus.ErrNotFound))
		})

		It("should overwrite existing values", func() {
			store.Put(ctx, "key1", []byte("value1"))
			store.Put(ctx, "key1", []byte("value2"))

			value, _ := store.Get(ctx, "key1")
			Expect(string(value)).To(Equal("value2"))
		})
	})

	Describe("Delete", func() {
		It("should delete values", func() {
			store.Put(ctx, "key1", []byte("value1"))

			err := store.Delete(ctx, "key1")
			Expect(err).NotTo(HaveOccurred())

			_, err = store.Get(ctx, "key1")
			Expect(err).To(MatchError(nexus.ErrNotFound))
		})

		It("should not error when deleting nonexistent key", func() {
			err := store.Delete(ctx, "nonexistent")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("Query", func() {
		BeforeEach(func() {
			store.Put(ctx, "users/1", []byte("user1"))
			store.Put(ctx, "users/2", []byte("user2"))
			store.Put(ctx, "posts/1", []byte("post1"))
		})

		It("should query by prefix", func() {
			results, err := store.Query(ctx, "users/")
			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(2))
		})

		It("should return empty for non-matching prefix", func() {
			results, err := store.Query(ctx, "comments/")
			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(BeEmpty())
		})

		It("should return all with empty prefix", func() {
			results, err := store.Query(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(3))
		})
	})

	Describe("Watch", func() {
		It("should notify watchers on put", func() {
			received := make(chan bool, 1)
			store.Watch("test/", func(key string, value []byte, deleted bool) {
				Expect(key).To(Equal("test/key1"))
				Expect(string(value)).To(Equal("value1"))
				Expect(deleted).To(BeFalse())
				received <- true
			})

			store.Put(ctx, "test/key1", []byte("value1"))

			Eventually(received).Should(Receive())
		})

		It("should notify watchers on delete", func() {
			store.Put(ctx, "test/key1", []byte("value1"))

			received := make(chan bool, 1)
			store.Watch("test/", func(key string, value []byte, deleted bool) {
				if deleted {
					Expect(key).To(Equal("test/key1"))
					received <- true
				}
			})

			store.Delete(ctx, "test/key1")

			Eventually(received).Should(Receive())
		})

		It("should not notify for non-matching prefixes", func() {
			received := make(chan bool, 1)
			store.Watch("other/", func(key string, value []byte, deleted bool) {
				received <- true
			})

			store.Put(ctx, "test/key1", []byte("value1"))

			Consistently(received, 50*time.Millisecond).ShouldNot(Receive())
		})
	})

	Describe("Peer Management", func() {
		It("should register self as peer", func() {
			peers := store.GetPeers()
			Expect(peers).To(HaveLen(1))
			Expect(peers[0].ID).To(Equal("test-peer-1"))
		})

		It("should register additional peers", func() {
			store.RegisterPeer("peer-2", "localhost:8001")
			store.RegisterPeer("peer-3", "localhost:8002")

			peers := store.GetPeers()
			Expect(peers).To(HaveLen(3))
		})

		It("should return active peer count", func() {
			store.RegisterPeer("peer-2", "localhost:8001")

			Expect(store.ActivePeerCount()).To(Equal(2))
		})

		It("should update peer heartbeat", func() {
			store.RegisterPeer("peer-2", "localhost:8001")
			time.Sleep(10 * time.Millisecond)

			store.UpdatePeerHeartbeat("peer-2")

			peers := store.GetPeers()
			for _, p := range peers {
				if p.ID == "peer-2" {
					Expect(p.Active).To(BeTrue())
				}
			}
		})
	})

	Describe("Hooks", func() {
		It("should call insert hook", func() {
			called := make(chan string, 1)
			store.SetInsertHook(func(key string, value []byte) {
				called <- key
			})

			store.Put(ctx, "key1", []byte("value1"))

			Eventually(called).Should(Receive(ContainSubstring("key1")))
		})

		It("should call update hook on existing key", func() {
			store.Put(ctx, "key1", []byte("value1"))

			called := make(chan string, 1)
			store.SetUpdateHook(func(key string, value []byte) {
				called <- key
			})

			store.Put(ctx, "key1", []byte("value2"))

			Eventually(called).Should(Receive(ContainSubstring("key1")))
		})

		It("should call delete hook", func() {
			store.Put(ctx, "key1", []byte("value1"))

			called := make(chan string, 1)
			store.SetDeleteHook(func(key string) {
				called <- key
			})

			store.Delete(ctx, "key1")

			Eventually(called).Should(Receive(ContainSubstring("key1")))
		})
	})

	Describe("ApplyRemoteChange", func() {
		It("should apply remote insert", func() {
			store.ApplyRemoteChange("test/remote-key", []byte("remote-value"), false)

			value, err := store.Get(ctx, "remote-key")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(value)).To(Equal("remote-value"))
		})

		It("should apply remote delete", func() {
			store.Put(ctx, "key1", []byte("value1"))

			store.ApplyRemoteChange("test/key1", nil, true)

			_, err := store.Get(ctx, "key1")
			Expect(err).To(MatchError(nexus.ErrNotFound))
		})

		It("should notify watchers for remote changes", func() {
			received := make(chan bool, 1)
			store.Watch("remote/", func(key string, value []byte, deleted bool) {
				received <- true
			})

			store.ApplyRemoteChange("test/remote/key1", []byte("value"), false)

			Eventually(received).Should(Receive())
		})
	})

	Describe("Close", func() {
		It("should close without error", func() {
			err := store.Close()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should reject operations after close", func() {
			store.Close()

			_, err := store.Get(ctx, "key1")
			Expect(err).To(HaveOccurred())

			err = store.Put(ctx, "key1", []byte("value1"))
			Expect(err).To(HaveOccurred())
		})
	})
})

var _ = Describe("NewStore Factory", func() {
	It("should create memory store by default", func() {
		store, err := nexus.NewStore(nexus.StoreConfig{})
		Expect(err).NotTo(HaveOccurred())
		Expect(store).NotTo(BeNil())
		store.Close()
	})

	It("should create memory store explicitly", func() {
		store, err := nexus.NewStore(nexus.StoreConfig{
			Backend: nexus.BackendMemory,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(store).NotTo(BeNil())
		store.Close()
	})

	It("should create CLSet store", func() {
		store, err := nexus.NewStore(nexus.StoreConfig{
			Backend: nexus.BackendCLSet,
			CLSet: nexus.CLSetConfig{
				PeerID: "test-peer",
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(store).NotTo(BeNil())
		store.Close()
	})

	It("should reject unknown backend", func() {
		_, err := nexus.NewStore(nexus.StoreConfig{
			Backend: "unknown",
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unknown"))
	})
})

var _ = Describe("CLSetStore implements Store", func() {
	It("should implement Store interface", func() {
		var _ nexus.Store = &nexus.CLSetStore{}
	})
})
