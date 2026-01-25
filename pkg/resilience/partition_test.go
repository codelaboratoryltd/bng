package resilience

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// partitionTestHealthChecker is a health checker for partition tests with control methods.
type partitionTestHealthChecker struct {
	mu        sync.RWMutex
	nexusErr  error
	radiusErr error
}

func (h *partitionTestHealthChecker) CheckNexus(ctx context.Context) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.nexusErr
}

func (h *partitionTestHealthChecker) CheckRADIUS(ctx context.Context) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.radiusErr
}

func (h *partitionTestHealthChecker) setNexusHealthy(healthy bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if healthy {
		h.nexusErr = nil
	} else {
		h.nexusErr = context.DeadlineExceeded
	}
}

func (h *partitionTestHealthChecker) setRADIUSHealthy(healthy bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if healthy {
		h.radiusErr = nil
	} else {
		h.radiusErr = context.DeadlineExceeded
	}
}

// partitionTestAllocationStore implements AllocationStore for partition tests.
type partitionTestAllocationStore struct {
	mu                sync.RWMutex
	localAllocations  []IPAllocation
	remoteAllocations []IPAllocation
}

func (s *partitionTestAllocationStore) GetLocalAllocations() []IPAllocation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]IPAllocation, len(s.localAllocations))
	copy(result, s.localAllocations)
	return result
}

func (s *partitionTestAllocationStore) GetRemoteAllocations(ctx context.Context) ([]IPAllocation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]IPAllocation, len(s.remoteAllocations))
	copy(result, s.remoteAllocations)
	return result, nil
}

func (s *partitionTestAllocationStore) UpdateAllocation(ctx context.Context, alloc IPAllocation) error {
	return nil
}

func (s *partitionTestAllocationStore) ReleaseAllocation(ctx context.Context, ip net.IP) error {
	return nil
}

// partitionTestRADIUSAuthenticator implements RADIUSAuthenticator for partition tests.
type partitionTestRADIUSAuthenticator struct {
	successfulAuth bool
	authError      error
}

func (m *partitionTestRADIUSAuthenticator) Authenticate(ctx context.Context, mac net.HardwareAddr, username string) (*AuthResult, error) {
	if m.authError != nil {
		return nil, m.authError
	}
	return &AuthResult{
		Success:         m.successfulAuth,
		SubscriberID:    username,
		ISPID:           "isp-001",
		DownloadRateBps: 100_000_000,
		UploadRateBps:   50_000_000,
	}, nil
}

func (m *partitionTestRADIUSAuthenticator) SendAccounting(ctx context.Context, record *AccountingRecord) error {
	return nil
}

func (m *partitionTestRADIUSAuthenticator) IsReachable(ctx context.Context) bool {
	return true
}

// TestPartitionScenario_NetworkPartition tests partition detection and handling.
func TestPartitionScenario_NetworkPartition(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultPartitionConfig()
	config.HealthCheckInterval = 50 * time.Millisecond
	config.HealthCheckTimeout = 30 * time.Millisecond
	config.HealthCheckRetries = 2

	healthChecker := &partitionTestHealthChecker{
		nexusErr:  nil,
		radiusErr: nil,
	}

	manager := NewManager(config, "site-001", healthChecker, logger)

	// Track partition events
	var partitionEvents []PartitionEvent
	var eventMu sync.Mutex
	manager.OnPartitionChange(func(event PartitionEvent) {
		eventMu.Lock()
		partitionEvents = append(partitionEvents, event)
		eventMu.Unlock()
	})

	if err := manager.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer manager.Stop()

	// Verify initial online state
	time.Sleep(100 * time.Millisecond)
	if manager.State() != StateOnline {
		t.Errorf("Initial state = %v, want online", manager.State())
	}

	// Simulate network partition (Nexus becomes unreachable)
	healthChecker.setNexusHealthy(false)

	// Wait for partition detection
	time.Sleep(300 * time.Millisecond)

	// Verify partitioned state
	if manager.State() != StatePartitioned && manager.State() != StateRecovering {
		t.Errorf("State after partition = %v, want partitioned or recovering", manager.State())
	}
	if !manager.IsPartitioned() {
		t.Error("IsPartitioned() = false, want true")
	}

	// Verify partition duration is tracked
	duration := manager.PartitionDuration()
	if duration == 0 {
		t.Error("PartitionDuration() = 0, expected > 0")
	}

	// Verify partition event was received
	eventMu.Lock()
	foundPartitionEvent := false
	for _, event := range partitionEvents {
		if event.NewState == StatePartitioned {
			foundPartitionEvent = true
			break
		}
	}
	eventMu.Unlock()

	if !foundPartitionEvent {
		t.Error("Expected to receive partition event")
	}

	// Verify stats
	stats := manager.Stats()
	if stats.TotalPartitions == 0 {
		t.Error("TotalPartitions = 0, expected > 0")
	}
}

// TestPartitionScenario_PartitionRecovery tests recovery after partition heals.
func TestPartitionScenario_PartitionRecovery(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultPartitionConfig()
	config.HealthCheckInterval = 50 * time.Millisecond
	config.HealthCheckTimeout = 30 * time.Millisecond
	config.HealthCheckRetries = 2
	config.ReconciliationTimeout = 1 * time.Second

	healthChecker := &partitionTestHealthChecker{
		nexusErr:  nil,
		radiusErr: nil,
	}

	manager := NewManager(config, "site-001", healthChecker, logger)

	var recoveryEventReceived int32
	manager.OnPartitionChange(func(event PartitionEvent) {
		if event.NewState == StateRecovering || event.NewState == StateOnline {
			atomic.StoreInt32(&recoveryEventReceived, 1)
		}
	})

	if err := manager.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer manager.Stop()

	// Wait for initial online state
	time.Sleep(100 * time.Millisecond)

	// Cause partition
	healthChecker.setNexusHealthy(false)
	time.Sleep(300 * time.Millisecond)

	// Verify partitioned
	if !manager.IsPartitioned() {
		t.Fatal("Expected to be partitioned")
	}

	// Heal partition
	healthChecker.setNexusHealthy(true)
	time.Sleep(500 * time.Millisecond)

	// Verify recovery
	state := manager.State()
	if state != StateOnline && state != StateRecovering {
		t.Errorf("State after recovery = %v, want online or recovering", state)
	}

	// Verify recovery event
	if atomic.LoadInt32(&recoveryEventReceived) == 0 {
		t.Error("Expected to receive recovery event")
	}
}

// TestPartitionScenario_SplitBrainConflicts tests conflict detection after split-brain.
func TestPartitionScenario_SplitBrainConflicts(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	detector := NewConflictDetector("site-001", logger)

	// Simulate allocations made by local site during partition
	localAlloc := IPAllocation{
		IP:           net.ParseIP("10.0.0.100"),
		MAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SubscriberID: "sub-local",
		PoolID:       "pool-1",
		AllocatedAt:  time.Now().Add(-5 * time.Minute),
		SiteID:       "site-001",
		IsPartition:  true,
	}
	detector.RecordAllocation(localAlloc)

	// Simulate conflicting allocation from another site
	remoteAlloc := IPAllocation{
		IP:           net.ParseIP("10.0.0.100"),                            // Same IP!
		MAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66}, // Different MAC
		SubscriberID: "sub-remote",
		PoolID:       "pool-1",
		AllocatedAt:  time.Now().Add(-3 * time.Minute), // More recent
		SiteID:       "site-002",                       // Different site
		IsPartition:  true,
	}

	// Set up mock store that returns the remote allocation
	store := &partitionTestAllocationStore{
		remoteAllocations: []IPAllocation{remoteAlloc},
	}
	detector.SetStore(store)

	// Detect conflicts
	ctx := context.Background()
	conflicts := detector.DetectConflicts(ctx)

	// Should find the conflict
	if len(conflicts) == 0 {
		t.Error("Expected to detect conflict")
	}

	// Verify conflict details
	found := false
	for _, conflict := range conflicts {
		if conflict.IP.String() == "10.0.0.100" {
			found = true
			if conflict.LocalAlloc.SubscriberID != "sub-local" {
				t.Errorf("LocalAlloc.SubscriberID = %v, want sub-local", conflict.LocalAlloc.SubscriberID)
			}
			if conflict.RemoteAlloc.SubscriberID != "sub-remote" {
				t.Errorf("RemoteAlloc.SubscriberID = %v, want sub-remote", conflict.RemoteAlloc.SubscriberID)
			}
			if conflict.Resolution != ResolutionPending {
				t.Errorf("Resolution = %v, want pending", conflict.Resolution)
			}
		}
	}

	if !found {
		t.Error("Did not find expected conflict for IP 10.0.0.100")
	}
}

// TestPartitionScenario_ConflictResolution tests conflict resolution strategies.
func TestPartitionScenario_ConflictResolution(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultPartitionConfig()
	config.HealthCheckInterval = time.Hour // Don't check

	healthChecker := &partitionTestHealthChecker{
		nexusErr:  nil,
		radiusErr: nil,
	}

	manager := NewManager(config, "site-001", healthChecker, logger)

	// Track resolved conflicts
	var resolvedConflicts []AllocationConflict
	var conflictMu sync.Mutex
	manager.OnConflict(func(conflict AllocationConflict) {
		conflictMu.Lock()
		resolvedConflicts = append(resolvedConflicts, conflict)
		conflictMu.Unlock()
	})

	// Test case 1: Remote was pre-partition (Nexus source of truth), local was during partition
	// Remote should win
	conflict1 := &AllocationConflict{
		IP: net.ParseIP("10.0.0.1"),
		LocalAlloc: IPAllocation{
			IP:          net.ParseIP("10.0.0.1"),
			MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			AllocatedAt: time.Now(),
			IsPartition: true, // Allocated during partition
		},
		RemoteAlloc: IPAllocation{
			IP:          net.ParseIP("10.0.0.1"),
			MAC:         net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
			AllocatedAt: time.Now().Add(-1 * time.Hour),
			IsPartition: false, // Pre-partition (authoritative)
		},
		DetectedAt: time.Now(),
		Resolution: ResolutionPending,
	}

	ctx := context.Background()
	err := manager.resolveConflict(ctx, conflict1)
	if err != nil {
		t.Errorf("resolveConflict error: %v", err)
	}

	if conflict1.Resolution != ResolutionRemoteWins {
		t.Errorf("Conflict 1 resolution = %v, want remote_wins", conflict1.Resolution)
	}

	// Test case 2: Local was pre-partition, remote was during partition
	// Local should win
	conflict2 := &AllocationConflict{
		IP: net.ParseIP("10.0.0.2"),
		LocalAlloc: IPAllocation{
			IP:          net.ParseIP("10.0.0.2"),
			MAC:         net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11},
			AllocatedAt: time.Now().Add(-1 * time.Hour),
			IsPartition: false, // Pre-partition (authoritative)
		},
		RemoteAlloc: IPAllocation{
			IP:          net.ParseIP("10.0.0.2"),
			MAC:         net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x22},
			AllocatedAt: time.Now(),
			IsPartition: true, // During partition
		},
		DetectedAt: time.Now(),
		Resolution: ResolutionPending,
	}

	err = manager.resolveConflict(ctx, conflict2)
	if err != nil {
		t.Errorf("resolveConflict error: %v", err)
	}

	if conflict2.Resolution != ResolutionLocalWins {
		t.Errorf("Conflict 2 resolution = %v, want local_wins", conflict2.Resolution)
	}

	// Test case 3: Both during partition - most recent wins
	conflict3 := &AllocationConflict{
		IP: net.ParseIP("10.0.0.3"),
		LocalAlloc: IPAllocation{
			IP:          net.ParseIP("10.0.0.3"),
			MAC:         net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			AllocatedAt: time.Now().Add(-10 * time.Minute), // Older
			IsPartition: true,
		},
		RemoteAlloc: IPAllocation{
			IP:          net.ParseIP("10.0.0.3"),
			MAC:         net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x77},
			AllocatedAt: time.Now().Add(-5 * time.Minute), // More recent
			IsPartition: true,
		},
		DetectedAt: time.Now(),
		Resolution: ResolutionPending,
	}

	err = manager.resolveConflict(ctx, conflict3)
	if err != nil {
		t.Errorf("resolveConflict error: %v", err)
	}

	if conflict3.Resolution != ResolutionRemoteWins {
		t.Errorf("Conflict 3 resolution = %v, want remote_wins (more recent)", conflict3.Resolution)
	}

	// Verify stats
	stats := manager.Stats()
	if stats.ConflictsResolved != 3 {
		t.Errorf("ConflictsResolved = %v, want 3", stats.ConflictsResolved)
	}

	// Verify handlers were notified
	conflictMu.Lock()
	if len(resolvedConflicts) != 3 {
		t.Errorf("Received %d conflict notifications, want 3", len(resolvedConflicts))
	}
	conflictMu.Unlock()
}

// TestPartitionScenario_GracefulDegradation tests graceful degradation during partition.
func TestPartitionScenario_GracefulDegradation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultPartitionConfig()
	config.HealthCheckInterval = 50 * time.Millisecond
	config.HealthCheckRetries = 2
	config.RADIUSPartitionMode = RADIUSModeCached
	config.ShortLeaseEnabled = true
	config.ShortLeaseThreshold = 0.90

	healthChecker := &partitionTestHealthChecker{
		nexusErr:  nil,
		radiusErr: nil,
	}

	manager := NewManager(config, "site-001", healthChecker, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer manager.Stop()

	// Cause partition
	healthChecker.setNexusHealthy(false)
	healthChecker.setRADIUSHealthy(false)
	time.Sleep(300 * time.Millisecond)

	// Verify we're partitioned
	if !manager.IsPartitioned() {
		t.Fatal("Expected to be partitioned")
	}

	// Verify RADIUS mode is cached
	if manager.GetRADIUSPartitionMode() != RADIUSModeCached {
		t.Errorf("RADIUSPartitionMode = %v, want cached", manager.GetRADIUSPartitionMode())
	}

	// Test short lease determination for high utilization pool
	// First, simulate high pool utilization
	poolMonitor := manager.PoolMonitor()
	poolMonitor.UpdatePoolStatus(&PoolStatus{
		PoolID:      "pool-1",
		Utilization: 0.95,
		Total:       1000,
		Allocated:   950,
		Available:   50,
	})

	if !manager.ShouldUseShortLease("pool-1") {
		t.Error("ShouldUseShortLease = false, want true for high utilization during partition")
	}

	// Test short lease duration
	shortDuration := manager.GetShortLeaseDuration()
	if shortDuration != config.ShortLeaseDuration {
		t.Errorf("GetShortLeaseDuration() = %v, want %v", shortDuration, config.ShortLeaseDuration)
	}
}

// TestPartitionScenario_RequestQueuing tests request queuing during partition.
func TestPartitionScenario_RequestQueuing(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultPartitionConfig()
	config.HealthCheckInterval = 50 * time.Millisecond
	config.HealthCheckRetries = 2
	config.RequestQueueSize = 100
	config.RequestQueueTimeout = 1 * time.Second

	healthChecker := &partitionTestHealthChecker{
		nexusErr:  context.DeadlineExceeded, // Start partitioned
		radiusErr: context.DeadlineExceeded,
	}

	manager := NewManager(config, "site-001", healthChecker, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer manager.Stop()

	// Wait for partition state
	time.Sleep(300 * time.Millisecond)

	if !manager.IsPartitioned() {
		t.Fatal("Expected to be partitioned")
	}

	// Queue some requests
	for i := 0; i < 5; i++ {
		req := &QueuedRequest{
			Type:         RequestTypeDHCPDiscover,
			MAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)},
			SubscriberID: "sub-" + string(rune('0'+i)),
			QueuedAt:     time.Now(),
		}
		err := manager.QueueRequest(req)
		if err != nil {
			t.Errorf("QueueRequest error: %v", err)
		}
	}

	// Verify stats
	stats := manager.Stats()
	if stats.RequestsQueued != 5 {
		t.Errorf("RequestsQueued = %v, want 5", stats.RequestsQueued)
	}
}

// TestPartitionScenario_PoolExhaustion tests behavior when pools approach exhaustion.
func TestPartitionScenario_PoolExhaustion(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultPartitionConfig()
	config.PoolWarningThreshold = 0.80
	config.PoolCriticalThreshold = 0.90
	config.PoolExhaustedThreshold = 0.95

	healthChecker := &partitionTestHealthChecker{
		nexusErr:  nil,
		radiusErr: nil,
	}

	manager := NewManager(config, "site-001", healthChecker, logger)

	// Track pool alerts
	var alertEvents []struct {
		pool  PoolStatus
		level PoolUtilizationLevel
	}
	var alertMu sync.Mutex

	manager.OnPoolAlert(func(pool PoolStatus, level PoolUtilizationLevel) {
		alertMu.Lock()
		alertEvents = append(alertEvents, struct {
			pool  PoolStatus
			level PoolUtilizationLevel
		}{pool, level})
		alertMu.Unlock()
	})

	if err := manager.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer manager.Stop()

	poolMonitor := manager.PoolMonitor()

	// Simulate pool approaching exhaustion
	poolMonitor.UpdatePoolStatus(&PoolStatus{
		PoolID:      "pool-1",
		PoolName:    "IPv4 Pool 1",
		Total:       1000,
		Allocated:   800,
		Available:   200,
		Utilization: 0.80,
	})

	// Should trigger warning
	time.Sleep(100 * time.Millisecond)

	poolMonitor.UpdatePoolStatus(&PoolStatus{
		PoolID:      "pool-1",
		PoolName:    "IPv4 Pool 1",
		Total:       1000,
		Allocated:   920,
		Available:   80,
		Utilization: 0.92,
	})

	// Should trigger critical
	time.Sleep(100 * time.Millisecond)

	poolMonitor.UpdatePoolStatus(&PoolStatus{
		PoolID:      "pool-1",
		PoolName:    "IPv4 Pool 1",
		Total:       1000,
		Allocated:   960,
		Available:   40,
		Utilization: 0.96,
	})

	// Should trigger exhausted
	time.Sleep(100 * time.Millisecond)

	// Verify alerts
	alertMu.Lock()
	defer alertMu.Unlock()

	if len(alertEvents) < 2 {
		t.Errorf("Expected at least 2 alert events, got %d", len(alertEvents))
	}

	// Verify stats
	stats := manager.Stats()
	if stats.PoolWarnings == 0 && stats.PoolCriticals == 0 && stats.PoolExhaustions == 0 {
		t.Error("Expected some pool alerts to be recorded")
	}
}

// TestPartitionScenario_RADIUSCachedAuth tests cached authentication during partition.
func TestPartitionScenario_RADIUSCachedAuth(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultPartitionConfig()
	config.RADIUSPartitionMode = RADIUSModeCached
	config.CachedProfileTTL = 24 * time.Hour

	radiusHandler := NewRADIUSHandler(config, logger)

	// Cache a profile
	profile := &CachedProfile{
		SubscriberID:    "sub-001",
		ISPID:           "isp-001",
		QoSPolicyID:     "qos-premium",
		DownloadRateBps: 100_000_000,
		UploadRateBps:   50_000_000,
		IPv4PoolID:      "pool-1",
		SessionTimeout:  24 * time.Hour,
	}
	radiusHandler.CacheProfile(profile)

	// Verify profile is cached
	cached, ok := radiusHandler.GetCachedProfile("sub-001")
	if !ok {
		t.Fatal("Expected to find cached profile")
	}
	if cached.ISPID != "isp-001" {
		t.Errorf("ISPID = %v, want isp-001", cached.ISPID)
	}

	// Authenticate using cached profile (degraded mode)
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	session, err := radiusHandler.AuthenticateDegraded(mac, "sub-001")
	if err != nil {
		t.Fatalf("AuthenticateDegraded error: %v", err)
	}

	if session.SubscriberID != "sub-001" {
		t.Errorf("SubscriberID = %v, want sub-001", session.SubscriberID)
	}
	if !session.NeedsReauth {
		t.Error("NeedsReauth = false, want true")
	}
	if session.CachedProfile == nil {
		t.Error("CachedProfile is nil")
	}

	// Verify stats
	degraded, _, _, _, _, _ := radiusHandler.Stats()
	if degraded != 1 {
		t.Errorf("Degraded auths = %v, want 1", degraded)
	}
}

// TestPartitionScenario_AccountingBuffering tests accounting record buffering.
func TestPartitionScenario_AccountingBuffering(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultPartitionConfig()
	config.AccountingBufferSize = 100

	radiusHandler := NewRADIUSHandler(config, logger)

	// Buffer some accounting records
	for i := 0; i < 10; i++ {
		record := &BufferedAcctRecord{
			SessionID:    "sess-" + string(rune('0'+i)),
			MAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)},
			FramedIP:     net.ParseIP("10.0.0." + string(rune('0'+i))),
			StatusType:   3, // Interim-Update
			InputOctets:  uint64(i * 1000),
			OutputOctets: uint64(i * 2000),
			SessionTime:  uint32(i * 60),
		}
		err := radiusHandler.BufferAccounting(record)
		if err != nil {
			t.Errorf("BufferAccounting error: %v", err)
		}
	}

	// Verify buffered count
	count := radiusHandler.GetBufferedAccountingCount()
	if count != 10 {
		t.Errorf("Buffered count = %v, want 10", count)
	}

	// Verify stats
	_, _, _, buffered, _, _ := radiusHandler.Stats()
	if buffered != 10 {
		t.Errorf("Stats.buffered = %v, want 10", buffered)
	}
}

// TestPartitionScenario_CRDTMergeAfterPartition simulates CRDT merge after partition heals.
func TestPartitionScenario_CRDTMergeAfterPartition(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Simulate two sites that were partitioned
	site1Detector := NewConflictDetector("site-001", logger)
	site2Detector := NewConflictDetector("site-002", logger)

	// During partition, site 1 allocates some IPs
	site1Allocations := []IPAllocation{
		{
			IP:           net.ParseIP("10.0.0.10"),
			MAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x10},
			SubscriberID: "sub-site1-1",
			PoolID:       "pool-1",
			AllocatedAt:  time.Now().Add(-10 * time.Minute),
			SiteID:       "site-001",
			IsPartition:  true,
		},
		{
			IP:           net.ParseIP("10.0.0.11"),
			MAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x11},
			SubscriberID: "sub-site1-2",
			PoolID:       "pool-1",
			AllocatedAt:  time.Now().Add(-8 * time.Minute),
			SiteID:       "site-001",
			IsPartition:  true,
		},
	}

	for _, alloc := range site1Allocations {
		site1Detector.RecordAllocation(alloc)
	}

	// During partition, site 2 allocates some IPs (with one conflict)
	site2Allocations := []IPAllocation{
		{
			IP:           net.ParseIP("10.0.0.10"), // CONFLICT with site1!
			MAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x20},
			SubscriberID: "sub-site2-1",
			PoolID:       "pool-1",
			AllocatedAt:  time.Now().Add(-5 * time.Minute), // More recent
			SiteID:       "site-002",
			IsPartition:  true,
		},
		{
			IP:           net.ParseIP("10.0.0.20"), // No conflict
			MAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x21},
			SubscriberID: "sub-site2-2",
			PoolID:       "pool-1",
			AllocatedAt:  time.Now().Add(-3 * time.Minute),
			SiteID:       "site-002",
			IsPartition:  true,
		},
	}

	for _, alloc := range site2Allocations {
		site2Detector.RecordAllocation(alloc)
	}

	// Partition heals - site 1 gets site 2's allocations from Nexus
	store := &partitionTestAllocationStore{
		remoteAllocations: site2Allocations,
	}
	site1Detector.SetStore(store)

	// Detect conflicts
	ctx := context.Background()
	conflicts := site1Detector.DetectConflicts(ctx)

	// Should find exactly one conflict (10.0.0.10)
	if len(conflicts) != 1 {
		t.Errorf("Expected 1 conflict, got %d", len(conflicts))
	}

	if len(conflicts) > 0 && conflicts[0].IP.String() != "10.0.0.10" {
		t.Errorf("Conflict IP = %v, want 10.0.0.10", conflicts[0].IP)
	}

	// Verify partition allocations can be exported for CRDT merge
	partitionAllocs := site1Detector.GetPartitionAllocations()
	if len(partitionAllocs) != 2 {
		t.Errorf("Partition allocations = %d, want 2", len(partitionAllocs))
	}
}

// TestPartitionScenario_ReauthenticationAfterRecovery tests re-auth queue processing.
func TestPartitionScenario_ReauthenticationAfterRecovery(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultPartitionConfig()
	config.ReauthRateLimit = 10 // 10 per second for testing

	radiusHandler := NewRADIUSHandler(config, logger)

	// Cache some profiles
	for i := 0; i < 3; i++ {
		profile := &CachedProfile{
			SubscriberID:    "sub-00" + string(rune('1'+i)),
			ISPID:           "isp-001",
			DownloadRateBps: 100_000_000,
		}
		radiusHandler.CacheProfile(profile)
	}

	// Create degraded sessions
	var sessions []*DegradedSession
	for i := 0; i < 3; i++ {
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)}
		subscriberID := "sub-00" + string(rune('1'+i))
		session, err := radiusHandler.AuthenticateDegraded(mac, subscriberID)
		if err != nil {
			t.Fatalf("AuthenticateDegraded error: %v", err)
		}
		sessions = append(sessions, session)
	}

	// Verify all need re-auth
	degradedSessions := radiusHandler.GetDegradedSessions()
	if len(degradedSessions) != 3 {
		t.Errorf("Degraded sessions = %d, want 3", len(degradedSessions))
	}

	// Set up mock authenticator
	auth := &partitionTestRADIUSAuthenticator{
		successfulAuth: true,
	}
	radiusHandler.SetAuthenticator(auth)

	// Queue for re-auth
	for _, session := range sessions {
		radiusHandler.QueueReauth(session)
	}

	// Process re-auths
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	completed, failed := radiusHandler.ProcessReauths(ctx, config.ReauthRateLimit)

	if completed != 3 {
		t.Errorf("Completed = %d, want 3", completed)
	}
	if failed != 0 {
		t.Errorf("Failed = %d, want 0", failed)
	}

	// Verify stats
	_, reauthCompleted, reauthFailed, _, _, _ := radiusHandler.Stats()
	if reauthCompleted != 3 {
		t.Errorf("Stats.reauthCompleted = %d, want 3", reauthCompleted)
	}
	if reauthFailed != 0 {
		t.Errorf("Stats.reauthFailed = %d, want 0", reauthFailed)
	}
}
