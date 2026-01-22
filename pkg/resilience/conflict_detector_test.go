package resilience

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// mockAllocationStore implements AllocationStore for testing.
type mockAllocationStore struct {
	localAllocations  []IPAllocation
	remoteAllocations []IPAllocation
}

func (m *mockAllocationStore) GetLocalAllocations() []IPAllocation {
	return m.localAllocations
}

func (m *mockAllocationStore) GetRemoteAllocations(ctx context.Context) ([]IPAllocation, error) {
	return m.remoteAllocations, nil
}

func (m *mockAllocationStore) UpdateAllocation(ctx context.Context, alloc IPAllocation) error {
	return nil
}

func (m *mockAllocationStore) ReleaseAllocation(ctx context.Context, ip net.IP) error {
	return nil
}

func TestConflictDetectorRecordAllocation(t *testing.T) {
	logger := zap.NewNop()
	detector := NewConflictDetector("site-1", logger)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.1.100")

	alloc := IPAllocation{
		IP:           ip,
		MAC:          mac,
		SubscriberID: "sub-123",
		PoolID:       "pool-1",
		AllocatedAt:  time.Now(),
	}

	detector.RecordAllocation(alloc)

	// Verify we can retrieve it
	retrieved, ok := detector.GetAllocation(ip)
	if !ok {
		t.Fatal("Failed to retrieve recorded allocation")
	}

	if retrieved.SubscriberID != "sub-123" {
		t.Errorf("Expected subscriber ID 'sub-123', got '%s'", retrieved.SubscriberID)
	}

	if retrieved.SiteID != "site-1" {
		t.Errorf("Expected site ID 'site-1', got '%s'", retrieved.SiteID)
	}
}

func TestConflictDetectorPartitionAllocation(t *testing.T) {
	logger := zap.NewNop()
	detector := NewConflictDetector("site-1", logger)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.1.100")

	alloc := IPAllocation{
		IP:          ip,
		MAC:         mac,
		AllocatedAt: time.Now(),
		IsPartition: true,
	}

	detector.RecordAllocation(alloc)

	partitionAllocs := detector.GetPartitionAllocations()
	if len(partitionAllocs) != 1 {
		t.Errorf("Expected 1 partition allocation, got %d", len(partitionAllocs))
	}

	// Clear partition allocations
	detector.ClearPartitionAllocations()

	partitionAllocs = detector.GetPartitionAllocations()
	if len(partitionAllocs) != 0 {
		t.Errorf("Expected 0 partition allocations after clear, got %d", len(partitionAllocs))
	}

	// Original allocation should still exist but no longer marked as partition
	retrieved, ok := detector.GetAllocation(ip)
	if !ok {
		t.Fatal("Allocation should still exist after clearing partition flag")
	}

	if retrieved.IsPartition {
		t.Error("IsPartition flag should have been cleared")
	}
}

func TestConflictDetectorDetectConflicts(t *testing.T) {
	logger := zap.NewNop()
	detector := NewConflictDetector("site-1", logger)

	// Record local allocation
	mac1, _ := net.ParseMAC("00:11:22:33:44:01")
	ip := net.ParseIP("10.0.1.100")

	detector.RecordAllocation(IPAllocation{
		IP:           ip,
		MAC:          mac1,
		SubscriberID: "sub-1",
		AllocatedAt:  time.Now(),
		SiteID:       "site-1",
	})

	// Set up mock store with conflicting remote allocation
	mac2, _ := net.ParseMAC("00:11:22:33:44:02")
	store := &mockAllocationStore{
		remoteAllocations: []IPAllocation{
			{
				IP:           ip,
				MAC:          mac2,
				SubscriberID: "sub-2",
				AllocatedAt:  time.Now(),
				SiteID:       "site-2", // Different site
			},
		},
	}

	detector.SetStore(store)

	// Detect conflicts
	ctx := context.Background()
	conflicts := detector.DetectConflicts(ctx)

	if len(conflicts) != 1 {
		t.Fatalf("Expected 1 conflict, got %d", len(conflicts))
	}

	conflict := conflicts[0]
	if conflict.IP.String() != ip.String() {
		t.Errorf("Expected conflict IP %s, got %s", ip, conflict.IP)
	}

	if conflict.LocalAlloc.MAC.String() != mac1.String() {
		t.Errorf("Expected local MAC %s, got %s", mac1, conflict.LocalAlloc.MAC)
	}

	if conflict.RemoteAlloc.MAC.String() != mac2.String() {
		t.Errorf("Expected remote MAC %s, got %s", mac2, conflict.RemoteAlloc.MAC)
	}

	if conflict.Resolution != ResolutionPending {
		t.Errorf("Expected pending resolution, got %v", conflict.Resolution)
	}
}

func TestConflictDetectorNoConflictSameMAC(t *testing.T) {
	logger := zap.NewNop()
	detector := NewConflictDetector("site-1", logger)

	// Record local allocation
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.1.100")

	detector.RecordAllocation(IPAllocation{
		IP:           ip,
		MAC:          mac,
		SubscriberID: "sub-1",
		AllocatedAt:  time.Now(),
		SiteID:       "site-1",
	})

	// Set up mock store with same MAC (same subscriber)
	store := &mockAllocationStore{
		remoteAllocations: []IPAllocation{
			{
				IP:           ip,
				MAC:          mac, // Same MAC
				SubscriberID: "sub-1",
				AllocatedAt:  time.Now(),
				SiteID:       "site-2",
			},
		},
	}

	detector.SetStore(store)

	// Detect conflicts - should be none since same subscriber
	ctx := context.Background()
	conflicts := detector.DetectConflicts(ctx)

	if len(conflicts) != 0 {
		t.Errorf("Expected no conflicts for same MAC, got %d", len(conflicts))
	}
}

func TestConflictDetectorValidateAllocation(t *testing.T) {
	logger := zap.NewNop()
	detector := NewConflictDetector("site-1", logger)

	mac1, _ := net.ParseMAC("00:11:22:33:44:01")
	mac2, _ := net.ParseMAC("00:11:22:33:44:02")
	ip := net.ParseIP("10.0.1.100")

	// Record existing allocation
	detector.RecordAllocation(IPAllocation{
		IP:          ip,
		MAC:         mac1,
		AllocatedAt: time.Now(),
	})

	// Validate same MAC - should succeed
	err := detector.ValidateAllocation(ip, mac1)
	if err != nil {
		t.Errorf("Expected no error for same MAC, got %v", err)
	}

	// Validate different MAC - should fail
	err = detector.ValidateAllocation(ip, mac2)
	if err == nil {
		t.Error("Expected error for different MAC")
	}

	conflictErr, ok := err.(*ConflictError)
	if !ok {
		t.Fatalf("Expected ConflictError, got %T", err)
	}

	if conflictErr.IP.String() != ip.String() {
		t.Errorf("Expected IP %s in error, got %s", ip, conflictErr.IP)
	}
}

func TestConflictDetectorMarkResolved(t *testing.T) {
	logger := zap.NewNop()
	detector := NewConflictDetector("site-1", logger)

	mac1, _ := net.ParseMAC("00:11:22:33:44:01")
	mac2, _ := net.ParseMAC("00:11:22:33:44:02")
	ip := net.ParseIP("10.0.1.100")

	detector.RecordAllocation(IPAllocation{
		IP:     ip,
		MAC:    mac1,
		SiteID: "site-1",
	})

	store := &mockAllocationStore{
		remoteAllocations: []IPAllocation{
			{IP: ip, MAC: mac2, SiteID: "site-2"},
		},
	}
	detector.SetStore(store)

	ctx := context.Background()
	conflicts := detector.DetectConflicts(ctx)

	if len(conflicts) != 1 {
		t.Fatalf("Expected 1 conflict, got %d", len(conflicts))
	}

	// Mark as resolved
	detector.MarkResolved(ip, ResolutionLocalWins)

	// Check unresolved - should be 0
	unresolved := detector.GetUnresolvedConflicts()
	if len(unresolved) != 0 {
		t.Errorf("Expected 0 unresolved conflicts, got %d", len(unresolved))
	}
}

func TestConflictDetectorExportImport(t *testing.T) {
	logger := zap.NewNop()
	detector := NewConflictDetector("site-1", logger)

	// Record some allocations with different IPs
	ips := []string{"10.0.1.100", "10.0.1.101", "10.0.1.102"}
	for i := 0; i < 3; i++ {
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)}
		ip := net.ParseIP(ips[i])
		detector.RecordAllocation(IPAllocation{
			IP:          ip,
			MAC:         mac,
			AllocatedAt: time.Now(),
		})
	}

	// Export
	exported := detector.ExportAllocations()
	if len(exported) != 3 {
		t.Fatalf("Expected 3 exported allocations, got %d", len(exported))
	}

	// Create new detector and import
	detector2 := NewConflictDetector("site-1", logger)
	detector2.ImportAllocations(exported)

	localCount, _, _ := detector2.Stats()
	if localCount != 3 {
		t.Errorf("Expected 3 local allocations after import, got %d", localCount)
	}
}
