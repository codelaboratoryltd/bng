package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func TestNew(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	if m == nil {
		t.Fatal("Expected non-nil Metrics")
	}

	// Verify all metric fields are initialized
	if m.dhcpRequestsTotal == nil {
		t.Error("dhcpRequestsTotal not initialized")
	}
	if m.sessionActive == nil {
		t.Error("sessionActive not initialized")
	}
	if m.natBindingsActive == nil {
		t.Error("natBindingsActive not initialized")
	}
	if m.radiusRequests == nil {
		t.Error("radiusRequests not initialized")
	}
	if m.qosPoliciesActive == nil {
		t.Error("qosPoliciesActive not initialized")
	}
	if m.pppoeSessionsActive == nil {
		t.Error("pppoeSessionsActive not initialized")
	}
	if m.routesActive == nil {
		t.Error("routesActive not initialized")
	}
	if m.subscriberTotal == nil {
		t.Error("subscriberTotal not initialized")
	}
}

func TestRegister(t *testing.T) {
	// Use a new registry for isolation
	reg := prometheus.NewRegistry()
	oldDefault := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = reg
	defer func() { prometheus.DefaultRegisterer = oldDefault }()

	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	err := m.Register()
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Register again should not fail (already registered is ignored)
	err = m.Register()
	if err != nil {
		t.Fatalf("Register() second call error = %v", err)
	}
}

func TestHandler(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	handler := m.Handler()
	if handler == nil {
		t.Error("Expected non-nil handler")
	}
}

func TestRecordSessionCreated(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.RecordSessionCreated("ipoe", "isp-1")
	m.RecordSessionCreated("pppoe", "isp-2")
}

func TestRecordSessionTerminated(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.RecordSessionTerminated("ipoe", "isp-1", 3600.0, 1000000, 2000000)
}

func TestSetActiveSessions(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.SetActiveSessions("ipoe", "active", 100)
	m.SetActiveSessions("pppoe", "walled_garden", 5)
}

func TestRecordNATTranslation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.RecordNATTranslation("inbound", "tcp")
	m.RecordNATTranslation("outbound", "udp")
}

func TestSetNATBindings(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.SetNATBindings(5000)
}

func TestSetNATPortsUsed(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.SetNATPortsUsed("203.0.113.1", 1000)
}

func TestRecordRADIUSRequest(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.RecordRADIUSRequest("auth", "accept", "10.0.0.1", 0.05)
	m.RecordRADIUSRequest("acct", "success", "10.0.0.2", 0.02)
}

func TestRecordRADIUSTimeout(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.RecordRADIUSTimeout("10.0.0.1")
}

func TestSetQoSPoliciesActive(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.SetQoSPoliciesActive(50)
}

func TestRecordQoSDropped(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.RecordQoSDropped("policy-1", "egress", 100, 50000)
}

func TestSetPPPoESessions(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.SetPPPoESessions(200)
}

func TestRecordPPPoENegotiation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.RecordPPPoENegotiation("lcp", "success")
	m.RecordPPPoENegotiation("auth", "failure")
}

func TestSetRoutesActive(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.SetRoutesActive("main", 100)
	m.SetRoutesActive("isp-1", 50)
}

func TestSetBGPPeersUp(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.SetBGPPeersUp(3)
}

func TestSetBGPPrefixes(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic
	m.SetBGPPrefixes("192.0.2.1", "ipv4", 500)
	m.SetBGPPrefixes("2001:db8::1", "ipv6", 100)
}

func TestSetSubscriberCount(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	byClass := map[string]int{
		"residential": 800,
		"business":    150,
		"wholesale":   50,
	}
	byISP := map[string]int{
		"isp-1": 500,
		"isp-2": 300,
		"isp-3": 200,
	}

	// Should not panic
	m.SetSubscriberCount(1000, byClass, byISP)
}

func TestCollect(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	// Should not panic even with nil references
	m.Collect()
}

// Issue #90: Test circuit-ID collision metrics
func TestCircuitIDCollisionMetrics(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	if m.circuitIDCollisionsTotal == nil {
		t.Error("circuitIDCollisionsTotal not initialized")
	}
	if m.circuitIDCollisionRate == nil {
		t.Error("circuitIDCollisionRate not initialized")
	}

	// Should not panic
	m.RecordCircuitIDCollision()
	m.RecordCircuitIDCollision()
	m.SetCircuitIDCollisionRate(0.001)
}

// Issue #90: Test circuit-ID collision metrics registration
func TestCircuitIDCollisionMetricsRegister(t *testing.T) {
	reg := prometheus.NewRegistry()
	oldDefault := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = reg
	defer func() { prometheus.DefaultRegisterer = oldDefault }()

	logger, _ := zap.NewDevelopment()
	m := New(nil, nil, nil, logger)

	err := m.Register()
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Verify the metrics are queryable
	m.RecordCircuitIDCollision()
	m.SetCircuitIDCollisionRate(0.05)

	// Gather and check metric names are registered
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	found := map[string]bool{
		"bng_circuit_id_hash_collisions_total": false,
		"bng_circuit_id_collision_rate":        false,
	}
	for _, f := range families {
		if _, ok := found[f.GetName()]; ok {
			found[f.GetName()] = true
		}
	}
	for name, ok := range found {
		if !ok {
			t.Errorf("Metric %q not found in registry", name)
		}
	}
}
