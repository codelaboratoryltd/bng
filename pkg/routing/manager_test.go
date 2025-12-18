package routing_test

import (
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/routing"
	"go.uber.org/zap"
)

func TestLinkState_String(t *testing.T) {
	tests := []struct {
		state    routing.LinkState
		expected string
	}{
		{routing.LinkStateUnknown, "UNKNOWN"},
		{routing.LinkStateUp, "UP"},
		{routing.LinkStateDown, "DOWN"},
		{routing.LinkStateDegraded, "DEGRADED"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("LinkState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

func TestManager_StartStop(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	manager := routing.NewManager(config, logger)

	// Start
	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Allow goroutines to start
	time.Sleep(10 * time.Millisecond)

	// Stop
	if err := manager.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestManager_AddUpstream(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	manager := routing.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	upstream := &routing.Upstream{
		Name:        "isp1",
		Interface:   "eth0",
		Gateway:     net.ParseIP("192.168.1.1"),
		Weight:      100,
		Priority:    1,
		HealthCheck: "8.8.8.8",
	}

	err := manager.AddUpstream(upstream)
	if err != nil {
		t.Fatalf("AddUpstream failed: %v", err)
	}

	// Try to add duplicate
	err = manager.AddUpstream(upstream)
	if err == nil {
		t.Error("Expected error when adding duplicate upstream")
	}

	// Get upstream
	got, exists := manager.GetUpstream("isp1")
	if !exists {
		t.Error("Upstream not found")
	}
	if got.Name != upstream.Name {
		t.Errorf("Upstream name = %s, want %s", got.Name, upstream.Name)
	}

	// List upstreams
	upstreams := manager.ListUpstreams()
	if len(upstreams) != 1 {
		t.Errorf("Expected 1 upstream, got %d", len(upstreams))
	}
}

func TestManager_RemoveUpstream(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	manager := routing.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	upstream := &routing.Upstream{
		Name:      "isp1",
		Interface: "eth0",
		Gateway:   net.ParseIP("192.168.1.1"),
	}

	manager.AddUpstream(upstream)

	// Remove upstream
	err := manager.RemoveUpstream("isp1")
	if err != nil {
		t.Fatalf("RemoveUpstream failed: %v", err)
	}

	// Verify removed
	_, exists := manager.GetUpstream("isp1")
	if exists {
		t.Error("Upstream should not exist after removal")
	}

	// Remove non-existent
	err = manager.RemoveUpstream("nonexistent")
	if err == nil {
		t.Error("Expected error when removing non-existent upstream")
	}
}

func TestManager_AddRoute(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	manager := routing.NewManager(config, logger)

	// Set up stub platform
	platform, _ := routing.NewNetlinkPlatform()
	manager.SetPlatform(platform)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	_, dest, _ := net.ParseCIDR("10.0.0.0/8")
	route := &routing.Route{
		Destination: dest,
		Gateway:     net.ParseIP("192.168.1.1"),
		Interface:   "eth0",
		Metric:      100,
	}

	err := manager.AddRoute(route)
	if err != nil {
		t.Fatalf("AddRoute failed: %v", err)
	}

	// Get routes from default table
	routes := manager.GetRoutes(config.DefaultTable)
	if len(routes) == 0 {
		t.Error("Expected at least one route")
	}

	found := false
	for _, r := range routes {
		if r.Destination.String() == dest.String() {
			found = true
			break
		}
	}
	if !found {
		t.Error("Added route not found in table")
	}
}

func TestManager_DeleteRoute(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	manager := routing.NewManager(config, logger)

	// Set up stub platform
	platform, _ := routing.NewNetlinkPlatform()
	manager.SetPlatform(platform)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	_, dest, _ := net.ParseCIDR("10.0.0.0/8")
	route := &routing.Route{
		Destination: dest,
		Gateway:     net.ParseIP("192.168.1.1"),
		Interface:   "eth0",
	}

	manager.AddRoute(route)

	// Delete route
	err := manager.DeleteRoute(route)
	if err != nil {
		t.Fatalf("DeleteRoute failed: %v", err)
	}

	// Verify deleted
	routes := manager.GetRoutes(config.DefaultTable)
	for _, r := range routes {
		if r.Destination.String() == dest.String() {
			t.Error("Route should have been deleted")
		}
	}
}

func TestManager_SetDefaultGateway(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	manager := routing.NewManager(config, logger)

	// Set up stub platform
	platform, _ := routing.NewNetlinkPlatform()
	manager.SetPlatform(platform)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	gateway := net.ParseIP("192.168.1.1")
	err := manager.SetDefaultGateway(gateway, "eth0")
	if err != nil {
		t.Fatalf("SetDefaultGateway failed: %v", err)
	}

	// Verify default route exists
	routes := manager.GetRoutes(config.DefaultTable)
	found := false
	for _, r := range routes {
		if r.Destination.String() == "0.0.0.0/0" && r.Gateway.Equal(gateway) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Default route not found")
	}
}

func TestManager_SetDefaultGatewayECMP(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	config.EnableECMP = true
	manager := routing.NewManager(config, logger)

	// Set up stub platform
	platform, _ := routing.NewNetlinkPlatform()
	manager.SetPlatform(platform)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	nexthops := []routing.NextHop{
		{Gateway: net.ParseIP("192.168.1.1"), Interface: "eth0", Weight: 50},
		{Gateway: net.ParseIP("192.168.2.1"), Interface: "eth1", Weight: 50},
	}

	err := manager.SetDefaultGatewayECMP(nexthops)
	if err != nil {
		t.Fatalf("SetDefaultGatewayECMP failed: %v", err)
	}
}

func TestManager_SetDefaultGatewayECMP_Disabled(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	config.EnableECMP = false
	manager := routing.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	nexthops := []routing.NextHop{
		{Gateway: net.ParseIP("192.168.1.1"), Interface: "eth0"},
	}

	err := manager.SetDefaultGatewayECMP(nexthops)
	if err == nil {
		t.Error("Expected error when ECMP is disabled")
	}
}

func TestManager_AddPolicyRule(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	config.EnablePolicyRouting = true
	manager := routing.NewManager(config, logger)

	// Set up stub platform
	platform, _ := routing.NewNetlinkPlatform()
	manager.SetPlatform(platform)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	_, source, _ := net.ParseCIDR("10.0.0.0/24")
	rule := &routing.PolicyRule{
		Priority:    100,
		Table:       100,
		Source:      source,
		Description: "test rule",
	}

	err := manager.AddPolicyRule(rule)
	if err != nil {
		t.Fatalf("AddPolicyRule failed: %v", err)
	}

	// Get rules
	rules := manager.GetPolicyRules()
	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}
}

func TestManager_AddPolicyRule_Disabled(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	config.EnablePolicyRouting = false
	manager := routing.NewManager(config, logger)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	rule := &routing.PolicyRule{
		Priority: 100,
		Table:    100,
	}

	err := manager.AddPolicyRule(rule)
	if err == nil {
		t.Error("Expected error when policy routing is disabled")
	}
}

func TestManager_DeletePolicyRule(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	config.EnablePolicyRouting = true
	manager := routing.NewManager(config, logger)

	// Set up stub platform
	platform, _ := routing.NewNetlinkPlatform()
	manager.SetPlatform(platform)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	rule := &routing.PolicyRule{
		Priority:    100,
		Table:       100,
		Description: "test rule",
	}

	manager.AddPolicyRule(rule)

	// Delete rule
	err := manager.DeletePolicyRule(rule)
	if err != nil {
		t.Fatalf("DeletePolicyRule failed: %v", err)
	}

	// Verify deleted
	rules := manager.GetPolicyRules()
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules, got %d", len(rules))
	}
}

func TestManager_CreateISPTable(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	manager := routing.NewManager(config, logger)

	// Set up stub platform
	platform, _ := routing.NewNetlinkPlatform()
	manager.SetPlatform(platform)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	err := manager.CreateISPTable("ISP-A", 100, net.ParseIP("192.168.1.1"), "eth0")
	if err != nil {
		t.Fatalf("CreateISPTable failed: %v", err)
	}

	// Check routes in ISP table
	routes := manager.GetRoutes(100)
	if len(routes) == 0 {
		t.Error("Expected default route in ISP table")
	}

	// Verify default route
	found := false
	for _, r := range routes {
		if r.Destination.String() == "0.0.0.0/0" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Default route not found in ISP table")
	}
}

func TestManager_RouteSubscriberToISP(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	config.EnablePolicyRouting = true
	manager := routing.NewManager(config, logger)

	// Set up stub platform
	platform, _ := routing.NewNetlinkPlatform()
	manager.SetPlatform(platform)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	// Create ISP table first
	manager.CreateISPTable("ISP-A", 100, net.ParseIP("192.168.1.1"), "eth0")

	// Route subscriber to ISP
	subscriberIP := net.ParseIP("10.0.0.50")
	err := manager.RouteSubscriberToISP(subscriberIP, 100)
	if err != nil {
		t.Fatalf("RouteSubscriberToISP failed: %v", err)
	}

	// Verify rule created
	rules := manager.GetPolicyRules()
	if len(rules) == 0 {
		t.Error("Expected policy rule for subscriber")
	}

	found := false
	for _, r := range rules {
		if r.Table == 100 && r.Source != nil {
			if r.Source.IP.Equal(subscriberIP) {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("Subscriber policy rule not found")
	}
}

func TestManager_Stats(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	config.EnablePolicyRouting = true
	manager := routing.NewManager(config, logger)

	// Set up stub platform
	platform, _ := routing.NewNetlinkPlatform()
	manager.SetPlatform(platform)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	// Add some data
	manager.AddUpstream(&routing.Upstream{
		Name:      "isp1",
		Interface: "eth0",
		Gateway:   net.ParseIP("192.168.1.1"),
	})

	_, dest, _ := net.ParseCIDR("10.0.0.0/8")
	manager.AddRoute(&routing.Route{
		Destination: dest,
		Gateway:     net.ParseIP("192.168.1.1"),
	})

	manager.AddPolicyRule(&routing.PolicyRule{
		Priority: 100,
		Table:    100,
	})

	stats := manager.Stats()
	if stats.UpstreamsTotal != 1 {
		t.Errorf("Expected 1 upstream, got %d", stats.UpstreamsTotal)
	}
	if stats.RoutesTotal < 1 {
		t.Errorf("Expected at least 1 route, got %d", stats.RoutesTotal)
	}
	if stats.RulesTotal != 1 {
		t.Errorf("Expected 1 rule, got %d", stats.RulesTotal)
	}
}

func TestManager_UpstreamCallbacks(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultConfig()
	manager := routing.NewManager(config, logger)

	upCalled := false
	downCalled := false

	manager.OnUpstreamUp(func(name string) {
		upCalled = true
	})

	manager.OnUpstreamDown(func(name string) {
		downCalled = true
	})

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	// The callbacks are triggered by health checker state changes,
	// which we can't easily test without mocking.
	// This just verifies the callbacks can be registered without error.
	_ = upCalled
	_ = downCalled
}

func TestDefaultConfig(t *testing.T) {
	config := routing.DefaultConfig()

	if config.DefaultTable != 254 {
		t.Errorf("DefaultTable = %d, want 254", config.DefaultTable)
	}

	if config.HealthCheckInterval == 0 {
		t.Error("HealthCheckInterval should not be 0")
	}

	if config.HealthCheckTimeout == 0 {
		t.Error("HealthCheckTimeout should not be 0")
	}

	if !config.EnableECMP {
		t.Error("EnableECMP should be true by default")
	}

	if !config.EnablePolicyRouting {
		t.Error("EnablePolicyRouting should be true by default")
	}
}
