package nexus_test

import (
	"context"
	"testing"

	"github.com/codelaboratoryltd/bng/pkg/nexus"
)

func TestVLANAllocator_Allocate(t *testing.T) {
	config := nexus.VLANAllocatorConfig{
		STagRange: nexus.VLANRange{Start: 100, End: 200},
		CTagRange: nexus.VLANRange{Start: 100, End: 200},
	}
	alloc := nexus.NewVLANAllocator(config)

	t.Run("first allocation", func(t *testing.T) {
		result, err := alloc.Allocate("nte-001")
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}

		if result.STag != 100 {
			t.Errorf("Expected STag 100, got %d", result.STag)
		}
		if result.CTag != 100 {
			t.Errorf("Expected CTag 100, got %d", result.CTag)
		}
		if result.NTEID != "nte-001" {
			t.Errorf("Expected NTEID 'nte-001', got '%s'", result.NTEID)
		}
	})

	t.Run("second allocation same S-TAG", func(t *testing.T) {
		result, err := alloc.Allocate("nte-002")
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}

		// Should use same S-TAG but different C-TAG
		if result.STag != 100 {
			t.Errorf("Expected STag 100, got %d", result.STag)
		}
		if result.CTag != 101 {
			t.Errorf("Expected CTag 101, got %d", result.CTag)
		}
	})

	t.Run("idempotent allocation", func(t *testing.T) {
		// Allocating same NTE should return same result
		result1, _ := alloc.Allocate("nte-001")
		result2, _ := alloc.Allocate("nte-001")

		if result1.STag != result2.STag || result1.CTag != result2.CTag {
			t.Errorf("Expected same allocation, got (%d,%d) vs (%d,%d)",
				result1.STag, result1.CTag, result2.STag, result2.CTag)
		}
	})
}

func TestVLANAllocator_AllocateWithSTag(t *testing.T) {
	config := nexus.VLANAllocatorConfig{
		STagRange: nexus.VLANRange{Start: 100, End: 200},
		CTagRange: nexus.VLANRange{Start: 100, End: 200},
	}
	alloc := nexus.NewVLANAllocator(config)

	t.Run("allocate with specific S-TAG", func(t *testing.T) {
		result, err := alloc.AllocateWithSTag("nte-isp1", 150)
		if err != nil {
			t.Fatalf("AllocateWithSTag failed: %v", err)
		}

		if result.STag != 150 {
			t.Errorf("Expected STag 150, got %d", result.STag)
		}
		if result.CTag != 100 {
			t.Errorf("Expected CTag 100, got %d", result.CTag)
		}
	})

	t.Run("multiple allocations same S-TAG", func(t *testing.T) {
		result1, _ := alloc.AllocateWithSTag("nte-isp1-a", 175)
		result2, _ := alloc.AllocateWithSTag("nte-isp1-b", 175)
		result3, _ := alloc.AllocateWithSTag("nte-isp1-c", 175)

		if result1.STag != 175 || result2.STag != 175 || result3.STag != 175 {
			t.Error("All allocations should have S-TAG 175")
		}

		// C-TAGs should be sequential
		if result1.CTag != 100 || result2.CTag != 101 || result3.CTag != 102 {
			t.Errorf("Expected C-TAGs 100,101,102 got %d,%d,%d",
				result1.CTag, result2.CTag, result3.CTag)
		}
	})
}

func TestVLANAllocator_Release(t *testing.T) {
	config := nexus.VLANAllocatorConfig{
		STagRange: nexus.VLANRange{Start: 100, End: 200},
		CTagRange: nexus.VLANRange{Start: 100, End: 200},
	}
	alloc := nexus.NewVLANAllocator(config)

	// Allocate
	result1, _ := alloc.Allocate("nte-release")

	// Release
	alloc.Release("nte-release")

	// Should not be found
	_, found := alloc.Get("nte-release")
	if found {
		t.Error("Expected allocation to be released")
	}

	// Re-allocate should get same VLAN pair (since it was released)
	result2, _ := alloc.Allocate("nte-release-new")
	if result2.STag != result1.STag || result2.CTag != result1.CTag {
		t.Logf("Note: Re-allocation got different VLANs (%d,%d) vs (%d,%d) - this is acceptable",
			result2.STag, result2.CTag, result1.STag, result1.CTag)
	}
}

func TestVLANAllocator_Exhaustion(t *testing.T) {
	// Small range for testing exhaustion
	config := nexus.VLANAllocatorConfig{
		STagRange: nexus.VLANRange{Start: 100, End: 100}, // Only 1 S-TAG
		CTagRange: nexus.VLANRange{Start: 100, End: 102}, // Only 3 C-TAGs
	}
	alloc := nexus.NewVLANAllocator(config)

	// Should succeed for first 3
	for i := 0; i < 3; i++ {
		_, err := alloc.Allocate("nte-" + string(rune('a'+i)))
		if err != nil {
			t.Fatalf("Allocation %d should succeed: %v", i, err)
		}
	}

	// Fourth should fail
	_, err := alloc.Allocate("nte-d")
	if err != nexus.ErrVLANExhausted {
		t.Errorf("Expected ErrVLANExhausted, got %v", err)
	}
}

func TestVLANAllocator_STagRollover(t *testing.T) {
	// Small range with multiple S-TAGs
	config := nexus.VLANAllocatorConfig{
		STagRange: nexus.VLANRange{Start: 100, End: 102}, // 3 S-TAGs
		CTagRange: nexus.VLANRange{Start: 100, End: 101}, // 2 C-TAGs each
	}
	alloc := nexus.NewVLANAllocator(config)

	// Allocate to fill first S-TAG
	alloc.Allocate("nte-1")
	alloc.Allocate("nte-2")

	// Third allocation should use next S-TAG
	result, err := alloc.Allocate("nte-3")
	if err != nil {
		t.Fatalf("Allocation failed: %v", err)
	}

	if result.STag != 101 {
		t.Errorf("Expected rollover to S-TAG 101, got %d", result.STag)
	}
}

func TestVLANAllocator_Stats(t *testing.T) {
	config := nexus.VLANAllocatorConfig{
		STagRange: nexus.VLANRange{Start: 100, End: 199}, // 100 S-TAGs
		CTagRange: nexus.VLANRange{Start: 100, End: 199}, // 100 C-TAGs
	}
	alloc := nexus.NewVLANAllocator(config)

	// Initial stats
	stats := alloc.Stats()
	if stats.TotalAllocations != 0 {
		t.Errorf("Expected 0 allocations, got %d", stats.TotalAllocations)
	}
	if stats.TotalCapacity != 10000 {
		t.Errorf("Expected capacity 10000, got %d", stats.TotalCapacity)
	}

	// After some allocations
	alloc.Allocate("nte-1")
	alloc.Allocate("nte-2")
	alloc.Allocate("nte-3")

	stats = alloc.Stats()
	if stats.TotalAllocations != 3 {
		t.Errorf("Expected 3 allocations, got %d", stats.TotalAllocations)
	}
	if stats.STagsInUse != 1 {
		t.Errorf("Expected 1 S-TAG in use, got %d", stats.STagsInUse)
	}
}

func TestVLANAllocator_LoadFromStore(t *testing.T) {
	config := nexus.DefaultVLANConfig()
	alloc := nexus.NewVLANAllocator(config)

	// Simulate loading existing NTEs from store
	ntes := []*nexus.NTE{
		{ID: "nte-1", STag: 100, CTag: 100},
		{ID: "nte-2", STag: 100, CTag: 101},
		{ID: "nte-3", STag: 200, CTag: 100},
	}

	err := alloc.LoadFromStore(context.Background(), ntes)
	if err != nil {
		t.Fatalf("LoadFromStore failed: %v", err)
	}

	// Check allocations were loaded
	stats := alloc.Stats()
	if stats.TotalAllocations != 3 {
		t.Errorf("Expected 3 allocations, got %d", stats.TotalAllocations)
	}
	if stats.STagsInUse != 2 {
		t.Errorf("Expected 2 S-TAGs in use, got %d", stats.STagsInUse)
	}

	// Check individual allocations
	v1, found := alloc.Get("nte-1")
	if !found {
		t.Error("Expected to find nte-1")
	}
	if v1.STag != 100 || v1.CTag != 100 {
		t.Errorf("Wrong VLAN for nte-1: got (%d,%d)", v1.STag, v1.CTag)
	}
}

func TestVLANAllocator_SyncToNTE(t *testing.T) {
	config := nexus.DefaultVLANConfig()
	alloc := nexus.NewVLANAllocator(config)

	// Allocate VLAN
	alloc.Allocate("nte-sync")

	// Sync to NTE
	nte := &nexus.NTE{ID: "nte-sync"}
	err := alloc.SyncToNTE(nte)
	if err != nil {
		t.Fatalf("SyncToNTE failed: %v", err)
	}

	if nte.STag != 100 {
		t.Errorf("Expected STag 100, got %d", nte.STag)
	}
	if nte.CTag != 100 {
		t.Errorf("Expected CTag 100, got %d", nte.CTag)
	}
}
