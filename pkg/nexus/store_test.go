package nexus_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/nexus"
)

func TestMemoryStore_BasicOperations(t *testing.T) {
	store := nexus.NewMemoryStore()
	ctx := context.Background()

	// Test Put and Get
	t.Run("put and get", func(t *testing.T) {
		err := store.Put(ctx, "/test/key1", []byte("value1"))
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		val, err := store.Get(ctx, "/test/key1")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if string(val) != "value1" {
			t.Errorf("Expected 'value1', got '%s'", string(val))
		}
	})

	// Test Get non-existent key
	t.Run("get non-existent", func(t *testing.T) {
		_, err := store.Get(ctx, "/test/nonexistent")
		if !errors.Is(err, nexus.ErrNotFound) {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}
	})

	// Test Delete
	t.Run("delete", func(t *testing.T) {
		err := store.Put(ctx, "/test/todelete", []byte("temp"))
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		err = store.Delete(ctx, "/test/todelete")
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = store.Get(ctx, "/test/todelete")
		if !errors.Is(err, nexus.ErrNotFound) {
			t.Errorf("Expected ErrNotFound after delete, got %v", err)
		}
	})
}

func TestMemoryStore_Query(t *testing.T) {
	store := nexus.NewMemoryStore()
	ctx := context.Background()

	// Set up test data
	testData := map[string]string{
		"/subscriber/sub1": "data1",
		"/subscriber/sub2": "data2",
		"/subscriber/sub3": "data3",
		"/nte/nte1":        "nte_data1",
		"/nte/nte2":        "nte_data2",
		"/isp/isp1":        "isp_data1",
	}

	for k, v := range testData {
		if err := store.Put(ctx, k, []byte(v)); err != nil {
			t.Fatalf("Setup failed: %v", err)
		}
	}

	t.Run("query with prefix", func(t *testing.T) {
		results, err := store.Query(ctx, "/subscriber/")
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if len(results) != 3 {
			t.Errorf("Expected 3 results, got %d", len(results))
		}
	})

	t.Run("query different prefix", func(t *testing.T) {
		results, err := store.Query(ctx, "/nte/")
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("Expected 2 results, got %d", len(results))
		}
	})

	t.Run("query empty prefix matches all", func(t *testing.T) {
		results, err := store.Query(ctx, "/")
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if len(results) != 6 {
			t.Errorf("Expected 6 results, got %d", len(results))
		}
	})
}

func TestMemoryStore_Watch(t *testing.T) {
	store := nexus.NewMemoryStore()
	ctx := context.Background()

	// Set up watch
	changes := make(chan struct {
		key     string
		deleted bool
	}, 10)

	store.Watch("/subscriber/", func(key string, value []byte, deleted bool) {
		changes <- struct {
			key     string
			deleted bool
		}{key, deleted}
	})

	// Trigger changes
	t.Run("watch triggers on put", func(t *testing.T) {
		err := store.Put(ctx, "/subscriber/watched", []byte("test"))
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		select {
		case change := <-changes:
			if change.key != "/subscriber/watched" {
				t.Errorf("Expected key '/subscriber/watched', got '%s'", change.key)
			}
			if change.deleted {
				t.Error("Expected deleted=false")
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Timed out waiting for watch callback")
		}
	})

	t.Run("watch triggers on delete", func(t *testing.T) {
		err := store.Delete(ctx, "/subscriber/watched")
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		select {
		case change := <-changes:
			if change.key != "/subscriber/watched" {
				t.Errorf("Expected key '/subscriber/watched', got '%s'", change.key)
			}
			if !change.deleted {
				t.Error("Expected deleted=true")
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Timed out waiting for watch callback")
		}
	})

	t.Run("watch does not trigger for other prefixes", func(t *testing.T) {
		err := store.Put(ctx, "/nte/other", []byte("test"))
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		select {
		case <-changes:
			t.Error("Should not have received change for /nte/ prefix")
		case <-time.After(50 * time.Millisecond):
			// Expected - no callback for other prefix
		}
	})
}

func TestTypedStore(t *testing.T) {
	store := nexus.NewMemoryStore()
	ctx := context.Background()

	subscribers := nexus.NewTypedStore[nexus.Subscriber](store, "/subscriber")

	t.Run("put and get typed", func(t *testing.T) {
		sub := &nexus.Subscriber{
			ID:    "sub-001",
			NTEID: "nte-001",
			ISPID: "isp-001",
			State: "active",
		}

		err := subscribers.Put(ctx, sub.ID, sub)
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		got, err := subscribers.Get(ctx, sub.ID)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if got.ID != sub.ID {
			t.Errorf("Expected ID '%s', got '%s'", sub.ID, got.ID)
		}
		if got.NTEID != sub.NTEID {
			t.Errorf("Expected NTEID '%s', got '%s'", sub.NTEID, got.NTEID)
		}
	})

	t.Run("list typed", func(t *testing.T) {
		// Add more subscribers
		for i := 2; i <= 3; i++ {
			sub := &nexus.Subscriber{
				ID:    "sub-00" + string(rune('0'+i)),
				State: "active",
			}
			if err := subscribers.Put(ctx, sub.ID, sub); err != nil {
				t.Fatalf("Put failed: %v", err)
			}
		}

		list, err := subscribers.List(ctx)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		if len(list) != 3 {
			t.Errorf("Expected 3 subscribers, got %d", len(list))
		}
	})

	t.Run("delete typed", func(t *testing.T) {
		err := subscribers.Delete(ctx, "sub-002")
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = subscribers.Get(ctx, "sub-002")
		if !errors.Is(err, nexus.ErrNotFound) {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}
	})
}

func TestTypedStore_Watch(t *testing.T) {
	store := nexus.NewMemoryStore()
	ctx := context.Background()

	subscribers := nexus.NewTypedStore[nexus.Subscriber](store, "/subscriber")

	changes := make(chan struct {
		id      string
		sub     *nexus.Subscriber
		deleted bool
	}, 10)

	subscribers.Watch(func(id string, sub *nexus.Subscriber, deleted bool) {
		changes <- struct {
			id      string
			sub     *nexus.Subscriber
			deleted bool
		}{id, sub, deleted}
	})

	t.Run("watch typed put", func(t *testing.T) {
		sub := &nexus.Subscriber{
			ID:    "watch-001",
			State: "pending",
		}

		err := subscribers.Put(ctx, sub.ID, sub)
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		select {
		case change := <-changes:
			if change.id != "watch-001" {
				t.Errorf("Expected id 'watch-001', got '%s'", change.id)
			}
			if change.sub == nil {
				t.Error("Expected non-nil subscriber")
			}
			if change.deleted {
				t.Error("Expected deleted=false")
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Timed out waiting for watch callback")
		}
	})
}
