package state

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	config := DefaultConfig()
	// Use short intervals for testing
	config.LeaseCleanupInterval = 50 * time.Millisecond
	config.SessionCleanupInterval = 50 * time.Millisecond
	config.NATCleanupInterval = 50 * time.Millisecond
	return NewStore(config, logger)
}

func TestStore_StartStop(t *testing.T) {
	store := newTestStore(t)

	if err := store.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Allow cleanup goroutines to run
	time.Sleep(10 * time.Millisecond)

	if err := store.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestStore_SubscriberCRUD(t *testing.T) {
	store := newTestStore(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Create subscriber
	sub := &Subscriber{
		MAC:    mac,
		NTEID:  "nte-001",
		ISPID:  "isp-1",
		Class:  ClassResidential,
		Status: StatusActive,
	}

	if err := store.CreateSubscriber(sub); err != nil {
		t.Fatalf("CreateSubscriber() error = %v", err)
	}

	if sub.ID == "" {
		t.Error("Expected ID to be set")
	}
	if sub.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}

	// Get by ID
	retrieved, err := store.GetSubscriber(sub.ID)
	if err != nil {
		t.Fatalf("GetSubscriber() error = %v", err)
	}
	if retrieved.NTEID != "nte-001" {
		t.Errorf("NTEID = %v, want nte-001", retrieved.NTEID)
	}

	// Get by MAC
	retrieved, err = store.GetSubscriberByMAC(mac)
	if err != nil {
		t.Fatalf("GetSubscriberByMAC() error = %v", err)
	}
	if retrieved.ID != sub.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, sub.ID)
	}

	// Get by NTE
	retrieved, err = store.GetSubscriberByNTE("nte-001")
	if err != nil {
		t.Fatalf("GetSubscriberByNTE() error = %v", err)
	}
	if retrieved.ID != sub.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, sub.ID)
	}

	// Update
	sub.Status = StatusSuspended
	if err := store.UpdateSubscriber(sub); err != nil {
		t.Fatalf("UpdateSubscriber() error = %v", err)
	}

	retrieved, _ = store.GetSubscriber(sub.ID)
	if retrieved.Status != StatusSuspended {
		t.Errorf("Status = %v, want suspended", retrieved.Status)
	}

	// List
	subs := store.ListSubscribers()
	if len(subs) != 1 {
		t.Errorf("ListSubscribers() = %d, want 1", len(subs))
	}

	// Delete
	if err := store.DeleteSubscriber(sub.ID); err != nil {
		t.Fatalf("DeleteSubscriber() error = %v", err)
	}

	// Verify deleted
	_, err = store.GetSubscriber(sub.ID)
	if err == nil {
		t.Error("Expected error after delete")
	}

	// Verify indexes cleaned up
	_, err = store.GetSubscriberByMAC(mac)
	if err == nil {
		t.Error("Expected MAC index to be removed")
	}
	_, err = store.GetSubscriberByNTE("nte-001")
	if err == nil {
		t.Error("Expected NTE index to be removed")
	}
}

func TestStore_PoolCRUD(t *testing.T) {
	store := newTestStore(t)

	// Create pool
	pool := &Pool{
		Name:       "test-pool",
		Type:       PoolTypePrivate,
		Version:    4,
		Network:    net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(24, 32)},
		StartIP:    net.ParseIP("10.0.0.10"),
		EndIP:      net.ParseIP("10.0.0.100"),
		Gateway:    net.ParseIP("10.0.0.1"),
		SubnetMask: net.CIDRMask(24, 32),
		DNSServers: []net.IP{net.ParseIP("8.8.8.8")},
		LeaseTime:  1 * time.Hour,
		Enabled:    true,
		Priority:   10,
	}

	if err := store.CreatePool(pool); err != nil {
		t.Fatalf("CreatePool() error = %v", err)
	}

	if pool.ID == "" {
		t.Error("Expected ID to be set")
	}
	if pool.TotalAddresses != 91 {
		t.Errorf("TotalAddresses = %d, want 91", pool.TotalAddresses)
	}

	// Get by ID
	retrieved, err := store.GetPool(pool.ID)
	if err != nil {
		t.Fatalf("GetPool() error = %v", err)
	}
	if retrieved.Name != "test-pool" {
		t.Errorf("Name = %v, want test-pool", retrieved.Name)
	}

	// Get by name
	retrieved, err = store.GetPoolByName("test-pool")
	if err != nil {
		t.Fatalf("GetPoolByName() error = %v", err)
	}
	if retrieved.ID != pool.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, pool.ID)
	}

	// List
	pools := store.ListPools()
	if len(pools) != 1 {
		t.Errorf("ListPools() = %d, want 1", len(pools))
	}

	// Update
	pool.Priority = 20
	if err := store.UpdatePool(pool); err != nil {
		t.Fatalf("UpdatePool() error = %v", err)
	}

	// Delete
	if err := store.DeletePool(pool.ID); err != nil {
		t.Fatalf("DeletePool() error = %v", err)
	}

	_, err = store.GetPool(pool.ID)
	if err == nil {
		t.Error("Expected error after delete")
	}
}

func TestStore_FindPoolForSubscriber(t *testing.T) {
	store := newTestStore(t)

	// Create pools with different ISP/class restrictions
	pool1 := &Pool{
		Name:            "isp1-pool",
		Type:            PoolTypePrivate,
		Version:         4,
		StartIP:         net.ParseIP("10.0.1.10"),
		EndIP:           net.ParseIP("10.0.1.100"),
		Enabled:         true,
		Priority:        5,
		ISPIDs:          []string{"isp-1"},
		SubscriberClass: []SubscriberClass{ClassResidential},
		TotalAddresses:  91,
	}
	store.CreatePool(pool1)

	pool2 := &Pool{
		Name:           "generic-pool",
		Type:           PoolTypePrivate,
		Version:        4,
		StartIP:        net.ParseIP("10.0.2.10"),
		EndIP:          net.ParseIP("10.0.2.100"),
		Enabled:        true,
		Priority:       1, // Lower priority
		TotalAddresses: 91,
	}
	store.CreatePool(pool2)

	pool3 := &Pool{
		Name:           "high-priority-pool",
		Type:           PoolTypePrivate,
		Version:        4,
		StartIP:        net.ParseIP("10.0.3.10"),
		EndIP:          net.ParseIP("10.0.3.100"),
		Enabled:        true,
		Priority:       10, // Highest priority
		ISPIDs:         []string{"isp-1"},
		TotalAddresses: 91,
	}
	store.CreatePool(pool3)

	// Test: subscriber matches ISP1 - should get highest priority ISP1 pool
	sub := &Subscriber{
		ISPID: "isp-1",
		Class: ClassResidential,
	}

	pool, err := store.FindPoolForSubscriber(sub, 4)
	if err != nil {
		t.Fatalf("FindPoolForSubscriber() error = %v", err)
	}
	if pool.ID != pool3.ID {
		t.Errorf("Expected high-priority-pool, got %s", pool.Name)
	}

	// Test: subscriber doesn't match any ISP - should get generic pool
	sub2 := &Subscriber{
		ISPID: "isp-unknown",
		Class: ClassBusiness,
	}

	pool, err = store.FindPoolForSubscriber(sub2, 4)
	if err != nil {
		t.Fatalf("FindPoolForSubscriber() error = %v", err)
	}
	if pool.ID != pool2.ID {
		t.Errorf("Expected generic-pool, got %s", pool.Name)
	}

	// Test: IPv6 pool not found
	_, err = store.FindPoolForSubscriber(sub, 6)
	if err == nil {
		t.Error("Expected no pool found for IPv6")
	}
}

func TestStore_LeaseCRUD(t *testing.T) {
	store := newTestStore(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.50")

	// Create pool first
	pool := &Pool{
		Name:           "test-pool",
		Type:           PoolTypePrivate,
		Version:        4,
		StartIP:        net.ParseIP("10.0.0.10"),
		EndIP:          net.ParseIP("10.0.0.100"),
		Enabled:        true,
		TotalAddresses: 91,
	}
	store.CreatePool(pool)

	// Create lease
	lease := &Lease{
		SubscriberID: "sub-1",
		MAC:          mac,
		IPv4:         ip,
		PoolID:       pool.ID,
		LeaseTime:    1 * time.Hour,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		State:        LeaseStateBound,
	}

	if err := store.CreateLease(lease); err != nil {
		t.Fatalf("CreateLease() error = %v", err)
	}

	if lease.ID == "" {
		t.Error("Expected ID to be set")
	}

	// Check pool allocation count
	pool, _ = store.GetPool(pool.ID)
	if pool.AllocatedAddresses != 1 {
		t.Errorf("AllocatedAddresses = %d, want 1", pool.AllocatedAddresses)
	}

	// Get by ID
	retrieved, err := store.GetLease(lease.ID)
	if err != nil {
		t.Fatalf("GetLease() error = %v", err)
	}
	if retrieved.SubscriberID != "sub-1" {
		t.Errorf("SubscriberID = %v, want sub-1", retrieved.SubscriberID)
	}

	// Get by IP
	retrieved, err = store.GetLeaseByIP(ip)
	if err != nil {
		t.Fatalf("GetLeaseByIP() error = %v", err)
	}
	if retrieved.ID != lease.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, lease.ID)
	}

	// Get by MAC
	retrieved, err = store.GetLeaseByMAC(mac)
	if err != nil {
		t.Fatalf("GetLeaseByMAC() error = %v", err)
	}
	if retrieved.ID != lease.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, lease.ID)
	}

	// Renew
	if err := store.RenewLease(lease.ID, 2*time.Hour); err != nil {
		t.Fatalf("RenewLease() error = %v", err)
	}

	retrieved, _ = store.GetLease(lease.ID)
	if retrieved.RenewCount != 1 {
		t.Errorf("RenewCount = %d, want 1", retrieved.RenewCount)
	}

	// List
	leases := store.ListLeases()
	if len(leases) != 1 {
		t.Errorf("ListLeases() = %d, want 1", len(leases))
	}

	// Delete
	if err := store.DeleteLease(lease.ID); err != nil {
		t.Fatalf("DeleteLease() error = %v", err)
	}

	// Check pool allocation count decreased
	pool, _ = store.GetPool(pool.ID)
	if pool.AllocatedAddresses != 0 {
		t.Errorf("AllocatedAddresses = %d, want 0", pool.AllocatedAddresses)
	}

	// Verify indexes cleaned up
	_, err = store.GetLeaseByIP(ip)
	if err == nil {
		t.Error("Expected IP index to be removed")
	}
	_, err = store.GetLeaseByMAC(mac)
	if err == nil {
		t.Error("Expected MAC index to be removed")
	}
}

func TestStore_SessionCRUD(t *testing.T) {
	store := newTestStore(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.50")

	// Create session
	session := &Session{
		SubscriberID: "sub-1",
		MAC:          mac,
		IPv4:         ip,
		Type:         SessionTypeIPoE,
		ISPID:        "isp-1",
		State:        SessionStateActive,
	}

	if err := store.CreateSession(session); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if session.ID == "" {
		t.Error("Expected ID to be set")
	}
	if session.StartTime.IsZero() {
		t.Error("Expected StartTime to be set")
	}

	// Get by ID
	retrieved, err := store.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if retrieved.SubscriberID != "sub-1" {
		t.Errorf("SubscriberID = %v, want sub-1", retrieved.SubscriberID)
	}

	// Get by MAC
	retrieved, err = store.GetSessionByMAC(mac)
	if err != nil {
		t.Fatalf("GetSessionByMAC() error = %v", err)
	}
	if retrieved.ID != session.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, session.ID)
	}

	// Get by IP
	retrieved, err = store.GetSessionByIP(ip)
	if err != nil {
		t.Fatalf("GetSessionByIP() error = %v", err)
	}
	if retrieved.ID != session.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, session.ID)
	}

	// Update activity
	if err := store.UpdateSessionActivity(session.ID, 1000, 2000); err != nil {
		t.Fatalf("UpdateSessionActivity() error = %v", err)
	}

	retrieved, _ = store.GetSession(session.ID)
	if retrieved.BytesIn != 1000 {
		t.Errorf("BytesIn = %d, want 1000", retrieved.BytesIn)
	}
	if retrieved.BytesOut != 2000 {
		t.Errorf("BytesOut = %d, want 2000", retrieved.BytesOut)
	}

	// List
	sessions := store.ListSessions()
	if len(sessions) != 1 {
		t.Errorf("ListSessions() = %d, want 1", len(sessions))
	}

	// Delete
	if err := store.DeleteSession(session.ID); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}

	// Verify indexes cleaned up
	_, err = store.GetSessionByMAC(mac)
	if err == nil {
		t.Error("Expected MAC index to be removed")
	}
	_, err = store.GetSessionByIP(ip)
	if err == nil {
		t.Error("Expected IP index to be removed")
	}
}

func TestStore_NATBindingCRUD(t *testing.T) {
	store := newTestStore(t)
	privateIP := net.ParseIP("192.168.1.100")
	publicIP := net.ParseIP("203.0.113.1")

	// Create binding
	binding := &NATBinding{
		SessionID:    "session-1",
		SubscriberID: "sub-1",
		PrivateIP:    privateIP,
		PrivatePort:  12345,
		PublicIP:     publicIP,
		PublicPort:   54321,
		Protocol:     6, // TCP
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	if err := store.CreateNATBinding(binding); err != nil {
		t.Fatalf("CreateNATBinding() error = %v", err)
	}

	if binding.ID == "" {
		t.Error("Expected ID to be set")
	}

	// Get by ID
	retrieved, err := store.GetNATBinding(binding.ID)
	if err != nil {
		t.Fatalf("GetNATBinding() error = %v", err)
	}
	if retrieved.SessionID != "session-1" {
		t.Errorf("SessionID = %v, want session-1", retrieved.SessionID)
	}

	// Get by private address
	retrieved, err = store.GetNATBindingByPrivate(privateIP, 12345, 6)
	if err != nil {
		t.Fatalf("GetNATBindingByPrivate() error = %v", err)
	}
	if retrieved.ID != binding.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, binding.ID)
	}

	// Get by public address
	retrieved, err = store.GetNATBindingByPublic(publicIP, 54321, 6)
	if err != nil {
		t.Fatalf("GetNATBindingByPublic() error = %v", err)
	}
	if retrieved.ID != binding.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, binding.ID)
	}

	// Delete
	if err := store.DeleteNATBinding(binding.ID); err != nil {
		t.Fatalf("DeleteNATBinding() error = %v", err)
	}

	// Verify indexes cleaned up
	_, err = store.GetNATBindingByPrivate(privateIP, 12345, 6)
	if err == nil {
		t.Error("Expected private index to be removed")
	}
	_, err = store.GetNATBindingByPublic(publicIP, 54321, 6)
	if err == nil {
		t.Error("Expected public index to be removed")
	}
}

func TestStore_Stats(t *testing.T) {
	store := newTestStore(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Verify initial stats
	stats := store.Stats()
	if stats.Subscribers != 0 {
		t.Errorf("Subscribers = %d, want 0", stats.Subscribers)
	}

	// Create subscriber
	sub := &Subscriber{MAC: mac, ISPID: "isp-1"}
	store.CreateSubscriber(sub)

	// Verify stats updated
	stats = store.Stats()
	if stats.Subscribers != 1 {
		t.Errorf("Subscribers = %d, want 1", stats.Subscribers)
	}
	if stats.Writes != 1 {
		t.Errorf("Writes = %d, want 1", stats.Writes)
	}

	// Read and verify read count
	store.GetSubscriber(sub.ID)
	stats = store.Stats()
	if stats.Reads != 1 {
		t.Errorf("Reads = %d, want 1", stats.Reads)
	}

	// Delete and verify delete count
	store.DeleteSubscriber(sub.ID)
	stats = store.Stats()
	if stats.Deletes != 1 {
		t.Errorf("Deletes = %d, want 1", stats.Deletes)
	}
}

func TestStore_LeaseCleanup(t *testing.T) {
	store := newTestStore(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("10.0.0.50")

	// Create pool
	pool := &Pool{
		Name:           "test-pool",
		Type:           PoolTypePrivate,
		Version:        4,
		StartIP:        net.ParseIP("10.0.0.10"),
		EndIP:          net.ParseIP("10.0.0.100"),
		Enabled:        true,
		TotalAddresses: 91,
	}
	store.CreatePool(pool)

	// Create lease that expires immediately
	lease := &Lease{
		SubscriberID: "sub-1",
		MAC:          mac,
		IPv4:         ip,
		PoolID:       pool.ID,
		ExpiresAt:    time.Now().Add(-1 * time.Second), // Already expired
		State:        LeaseStateBound,
	}
	store.CreateLease(lease)

	// Start store to activate cleanup
	store.Start()
	defer store.Stop()

	// Wait for cleanup to run
	time.Sleep(150 * time.Millisecond)

	// Verify lease was cleaned up
	leases := store.ListLeases()
	if len(leases) != 0 {
		t.Errorf("Expected 0 leases after cleanup, got %d", len(leases))
	}

	// Verify pool allocation decreased
	pool, _ = store.GetPool(pool.ID)
	if pool.AllocatedAddresses != 0 {
		t.Errorf("AllocatedAddresses = %d, want 0", pool.AllocatedAddresses)
	}
}

func TestStore_SessionIdleCleanup(t *testing.T) {
	store := newTestStore(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Create session with very short idle timeout
	session := &Session{
		SubscriberID: "sub-1",
		MAC:          mac,
		Type:         SessionTypeIPoE,
		State:        SessionStateActive,
		IdleTimeout:  1 * time.Millisecond, // Very short
	}
	store.CreateSession(session)

	// Wait for session to become idle
	time.Sleep(10 * time.Millisecond)

	// Start store to activate cleanup
	store.Start()
	defer store.Stop()

	// Wait for cleanup to run
	time.Sleep(150 * time.Millisecond)

	// Verify session was cleaned up
	sessions := store.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions after cleanup, got %d", len(sessions))
	}
}

func TestStore_NATBindingCleanup(t *testing.T) {
	store := newTestStore(t)
	privateIP := net.ParseIP("192.168.1.100")
	publicIP := net.ParseIP("203.0.113.1")

	// Create binding that expires immediately
	binding := &NATBinding{
		SessionID:    "session-1",
		SubscriberID: "sub-1",
		PrivateIP:    privateIP,
		PrivatePort:  12345,
		PublicIP:     publicIP,
		PublicPort:   54321,
		Protocol:     6,
		ExpiresAt:    time.Now().Add(-1 * time.Second), // Already expired
	}
	store.CreateNATBinding(binding)

	// Start store to activate cleanup
	store.Start()
	defer store.Stop()

	// Wait for cleanup to run
	time.Sleep(150 * time.Millisecond)

	// Verify binding was cleaned up
	_, err := store.GetNATBinding(binding.ID)
	if err == nil {
		t.Error("Expected NAT binding to be cleaned up")
	}
}

func TestStore_MaxLimits(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := DefaultConfig()
	config.MaxSubscribers = 2
	config.MaxSessions = 2
	config.MaxLeases = 2
	config.MaxNATBindings = 2
	store := NewStore(config, logger)

	// Create max subscribers
	for i := 0; i < 2; i++ {
		mac, _ := net.ParseMAC("00:11:22:33:44:5" + string(rune('0'+i)))
		store.CreateSubscriber(&Subscriber{MAC: mac, ISPID: "isp-1"})
	}

	// Next one should fail
	mac, _ := net.ParseMAC("00:11:22:33:44:59")
	err := store.CreateSubscriber(&Subscriber{MAC: mac, ISPID: "isp-1"})
	if err == nil {
		t.Error("Expected max subscribers error")
	}

	// Similar test for sessions
	for i := 0; i < 2; i++ {
		mac, _ := net.ParseMAC("00:11:22:33:55:5" + string(rune('0'+i)))
		store.CreateSession(&Session{MAC: mac, Type: SessionTypeIPoE})
	}

	mac, _ = net.ParseMAC("00:11:22:33:55:59")
	err = store.CreateSession(&Session{MAC: mac, Type: SessionTypeIPoE})
	if err == nil {
		t.Error("Expected max sessions error")
	}
}

func TestStore_SubscriberIndexUpdate(t *testing.T) {
	store := newTestStore(t)
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	// Create subscriber
	sub := &Subscriber{
		MAC:   mac1,
		NTEID: "nte-001",
		ISPID: "isp-1",
	}
	store.CreateSubscriber(sub)

	// Update MAC and NTE
	sub.MAC = mac2
	sub.NTEID = "nte-002"
	store.UpdateSubscriber(sub)

	// Old indexes should be removed
	_, err := store.GetSubscriberByMAC(mac1)
	if err == nil {
		t.Error("Expected old MAC index to be removed")
	}
	_, err = store.GetSubscriberByNTE("nte-001")
	if err == nil {
		t.Error("Expected old NTE index to be removed")
	}

	// New indexes should work
	retrieved, err := store.GetSubscriberByMAC(mac2)
	if err != nil {
		t.Fatalf("GetSubscriberByMAC() error = %v", err)
	}
	if retrieved.ID != sub.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, sub.ID)
	}

	retrieved, err = store.GetSubscriberByNTE("nte-002")
	if err != nil {
		t.Fatalf("GetSubscriberByNTE() error = %v", err)
	}
	if retrieved.ID != sub.ID {
		t.Errorf("ID = %v, want %v", retrieved.ID, sub.ID)
	}
}

func TestCountAddresses(t *testing.T) {
	tests := []struct {
		name  string
		start net.IP
		end   net.IP
		want  int
	}{
		{
			name:  "simple range",
			start: net.ParseIP("10.0.0.10"),
			end:   net.ParseIP("10.0.0.100"),
			want:  91,
		},
		{
			name:  "single address",
			start: net.ParseIP("10.0.0.1"),
			end:   net.ParseIP("10.0.0.1"),
			want:  1,
		},
		{
			name:  "reversed range",
			start: net.ParseIP("10.0.0.100"),
			end:   net.ParseIP("10.0.0.10"),
			want:  0,
		},
		{
			name:  "full /24",
			start: net.ParseIP("10.0.0.0"),
			end:   net.ParseIP("10.0.0.255"),
			want:  256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countAddresses(tt.start, tt.end)
			if got != tt.want {
				t.Errorf("countAddresses() = %d, want %d", got, tt.want)
			}
		})
	}
}
