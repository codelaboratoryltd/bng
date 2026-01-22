package resilience

import (
	"context"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AllocationStore provides access to IP allocation records.
type AllocationStore interface {
	// GetLocalAllocations returns all local IP allocations.
	GetLocalAllocations() []IPAllocation
	// GetRemoteAllocations fetches remote allocations from Nexus.
	GetRemoteAllocations(ctx context.Context) ([]IPAllocation, error)
	// UpdateAllocation updates a local allocation.
	UpdateAllocation(ctx context.Context, alloc IPAllocation) error
	// ReleaseAllocation releases an IP allocation.
	ReleaseAllocation(ctx context.Context, ip net.IP) error
}

// ConflictDetector detects and helps resolve IP allocation conflicts.
type ConflictDetector struct {
	siteID string
	logger *zap.Logger
	store  AllocationStore

	mu                   sync.RWMutex
	localAllocations     map[string]IPAllocation // IP string -> allocation
	partitionAllocations map[string]IPAllocation // Allocations made during partition
	conflicts            []AllocationConflict
}

// NewConflictDetector creates a new conflict detector.
func NewConflictDetector(siteID string, logger *zap.Logger) *ConflictDetector {
	return &ConflictDetector{
		siteID:               siteID,
		logger:               logger,
		localAllocations:     make(map[string]IPAllocation),
		partitionAllocations: make(map[string]IPAllocation),
	}
}

// SetStore sets the allocation store.
func (d *ConflictDetector) SetStore(store AllocationStore) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.store = store
}

// RecordAllocation records a new IP allocation.
func (d *ConflictDetector) RecordAllocation(alloc IPAllocation) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipKey := alloc.IP.String()
	alloc.SiteID = d.siteID

	d.localAllocations[ipKey] = alloc

	// If this is a partition allocation, track separately
	if alloc.IsPartition {
		d.partitionAllocations[ipKey] = alloc
	}

	d.logger.Debug("Recorded allocation",
		zap.String("ip", ipKey),
		zap.String("mac", alloc.MAC.String()),
		zap.String("subscriber_id", alloc.SubscriberID),
		zap.Bool("is_partition", alloc.IsPartition),
	)
}

// RemoveAllocation removes an allocation record.
func (d *ConflictDetector) RemoveAllocation(ip net.IP) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipKey := ip.String()
	delete(d.localAllocations, ipKey)
	delete(d.partitionAllocations, ipKey)
}

// GetAllocation returns the allocation for an IP.
func (d *ConflictDetector) GetAllocation(ip net.IP) (IPAllocation, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	alloc, ok := d.localAllocations[ip.String()]
	return alloc, ok
}

// GetPartitionAllocations returns allocations made during partition.
func (d *ConflictDetector) GetPartitionAllocations() []IPAllocation {
	d.mu.RLock()
	defer d.mu.RUnlock()

	allocations := make([]IPAllocation, 0, len(d.partitionAllocations))
	for _, alloc := range d.partitionAllocations {
		allocations = append(allocations, alloc)
	}
	return allocations
}

// ClearPartitionAllocations clears the partition allocation tracking.
func (d *ConflictDetector) ClearPartitionAllocations() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Clear partition flag but keep in local allocations
	for ipKey, alloc := range d.partitionAllocations {
		alloc.IsPartition = false
		d.localAllocations[ipKey] = alloc
	}
	d.partitionAllocations = make(map[string]IPAllocation)
}

// DetectConflicts detects IP allocation conflicts after partition recovery.
func (d *ConflictDetector) DetectConflicts(ctx context.Context) []AllocationConflict {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		d.logger.Warn("No allocation store configured, skipping conflict detection")
		return nil
	}

	// Get remote allocations from Nexus
	remoteAllocations, err := store.GetRemoteAllocations(ctx)
	if err != nil {
		d.logger.Error("Failed to get remote allocations",
			zap.Error(err),
		)
		return nil
	}

	// Build map of remote allocations
	remoteByIP := make(map[string]IPAllocation)
	for _, alloc := range remoteAllocations {
		remoteByIP[alloc.IP.String()] = alloc
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	var conflicts []AllocationConflict

	// Check each local allocation against remote
	for ipKey, localAlloc := range d.localAllocations {
		remoteAlloc, hasRemote := remoteByIP[ipKey]

		if !hasRemote {
			// No conflict - IP only allocated locally
			continue
		}

		// Check if it's the same subscriber (no conflict)
		if localAlloc.MAC.String() == remoteAlloc.MAC.String() &&
			localAlloc.SubscriberID == remoteAlloc.SubscriberID {
			// Same subscriber - no conflict, just need to sync timestamps
			continue
		}

		// Check if it's a different site's allocation
		if localAlloc.SiteID != remoteAlloc.SiteID {
			// Different sites allocated the same IP - conflict!
			conflict := AllocationConflict{
				IP:          localAlloc.IP,
				LocalAlloc:  localAlloc,
				RemoteAlloc: remoteAlloc,
				DetectedAt:  time.Now(),
				Resolution:  ResolutionPending,
			}
			conflicts = append(conflicts, conflict)

			d.logger.Warn("IP allocation conflict detected",
				zap.String("ip", ipKey),
				zap.String("local_mac", localAlloc.MAC.String()),
				zap.String("local_subscriber", localAlloc.SubscriberID),
				zap.String("remote_mac", remoteAlloc.MAC.String()),
				zap.String("remote_subscriber", remoteAlloc.SubscriberID),
				zap.String("local_site", localAlloc.SiteID),
				zap.String("remote_site", remoteAlloc.SiteID),
			)
		}
	}

	// Also check for MACs with different IPs across sites
	localByMAC := make(map[string]IPAllocation)
	for _, alloc := range d.localAllocations {
		localByMAC[alloc.MAC.String()] = alloc
	}

	remoteByMAC := make(map[string]IPAllocation)
	for _, alloc := range remoteAllocations {
		remoteByMAC[alloc.MAC.String()] = alloc
	}

	for macKey, localAlloc := range localByMAC {
		remoteAlloc, hasRemote := remoteByMAC[macKey]
		if !hasRemote {
			continue
		}

		// Same MAC but different IP - potential roaming or conflict
		if localAlloc.IP.String() != remoteAlloc.IP.String() {
			// This could be roaming (subscriber moved) or a conflict
			// Log it but don't necessarily treat as conflict
			d.logger.Info("MAC has different IP across sites (potential roaming)",
				zap.String("mac", macKey),
				zap.String("local_ip", localAlloc.IP.String()),
				zap.String("remote_ip", remoteAlloc.IP.String()),
				zap.String("local_site", localAlloc.SiteID),
				zap.String("remote_site", remoteAlloc.SiteID),
			)
		}
	}

	d.conflicts = conflicts

	d.logger.Info("Conflict detection complete",
		zap.Int("conflicts_found", len(conflicts)),
		zap.Int("local_allocations", len(d.localAllocations)),
		zap.Int("remote_allocations", len(remoteAllocations)),
	)

	return conflicts
}

// GetConflicts returns the last detected conflicts.
func (d *ConflictDetector) GetConflicts() []AllocationConflict {
	d.mu.RLock()
	defer d.mu.RUnlock()

	conflicts := make([]AllocationConflict, len(d.conflicts))
	copy(conflicts, d.conflicts)
	return conflicts
}

// ValidateAllocation checks if a new allocation would conflict.
func (d *ConflictDetector) ValidateAllocation(ip net.IP, mac net.HardwareAddr) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ipKey := ip.String()
	if existing, ok := d.localAllocations[ipKey]; ok {
		if existing.MAC.String() != mac.String() {
			return &ConflictError{
				IP:           ip,
				ExistingMAC:  existing.MAC,
				RequestedMAC: mac,
			}
		}
	}
	return nil
}

// ConflictError represents an IP allocation conflict.
type ConflictError struct {
	IP           net.IP
	ExistingMAC  net.HardwareAddr
	RequestedMAC net.HardwareAddr
}

func (e *ConflictError) Error() string {
	return "IP " + e.IP.String() + " already allocated to " + e.ExistingMAC.String()
}

// MarkResolved marks a conflict as resolved.
func (d *ConflictDetector) MarkResolved(ip net.IP, resolution ConflictResolution) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipKey := ip.String()
	for i := range d.conflicts {
		if d.conflicts[i].IP.String() == ipKey {
			d.conflicts[i].Resolution = resolution
			d.conflicts[i].ResolvedAt = time.Now()
			break
		}
	}
}

// GetUnresolvedConflicts returns conflicts that are still pending.
func (d *ConflictDetector) GetUnresolvedConflicts() []AllocationConflict {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var unresolved []AllocationConflict
	for _, conflict := range d.conflicts {
		if conflict.Resolution == ResolutionPending {
			unresolved = append(unresolved, conflict)
		}
	}
	return unresolved
}

// Stats returns conflict detection statistics.
func (d *ConflictDetector) Stats() (localCount, partitionCount, conflictCount int) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return len(d.localAllocations), len(d.partitionAllocations), len(d.conflicts)
}

// ExportAllocations exports all local allocations for sync.
func (d *ConflictDetector) ExportAllocations() []IPAllocation {
	d.mu.RLock()
	defer d.mu.RUnlock()

	allocations := make([]IPAllocation, 0, len(d.localAllocations))
	for _, alloc := range d.localAllocations {
		allocations = append(allocations, alloc)
	}
	return allocations
}

// ImportAllocations imports allocations (e.g., from persistence).
func (d *ConflictDetector) ImportAllocations(allocations []IPAllocation) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, alloc := range allocations {
		ipKey := alloc.IP.String()
		d.localAllocations[ipKey] = alloc
		if alloc.IsPartition {
			d.partitionAllocations[ipKey] = alloc
		}
	}

	d.logger.Info("Imported allocations",
		zap.Int("count", len(allocations)),
	)
}
