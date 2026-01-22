package routing_test

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/codelaboratoryltd/bng/pkg/routing"
	"go.uber.org/zap"
)

// mockFRRExecutor is a mock FRR executor for testing.
type mockFRRExecutor struct {
	mu       sync.Mutex
	commands []string
	outputs  map[string]string
	errors   map[string]error
}

func newMockFRRExecutor() *mockFRRExecutor {
	return &mockFRRExecutor{
		commands: make([]string, 0),
		outputs:  make(map[string]string),
		errors:   make(map[string]error),
	}
}

func (m *mockFRRExecutor) ExecuteCommand(ctx context.Context, command string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commands = append(m.commands, command)

	if output, ok := m.outputs[command]; ok {
		return output, nil
	}
	if err, ok := m.errors[command]; ok {
		return "", err
	}
	return "", nil
}

func (m *mockFRRExecutor) getCommands() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.commands...)
}

func TestSubscriberRouteManager_InjectRoute(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultSubscriberRouteConfig()
	config.LocalAS = 64500

	manager := routing.NewSubscriberRouteManager(config, nil, logger)
	executor := newMockFRRExecutor()
	manager.SetFRRExecutor(executor)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	ctx := context.Background()
	ip := net.ParseIP("10.0.1.100")

	err := manager.InjectRoute(ctx, "session-1", "subscriber-1", ip, "residential")
	if err != nil {
		t.Fatalf("InjectRoute failed: %v", err)
	}

	// Verify route is tracked
	route, found := manager.GetRouteByIP(ip)
	if !found {
		t.Fatal("Route not found after injection")
	}

	if route.SessionID != "session-1" {
		t.Errorf("SessionID = %s, want session-1", route.SessionID)
	}

	if route.SubscriberID != "subscriber-1" {
		t.Errorf("SubscriberID = %s, want subscriber-1", route.SubscriberID)
	}

	// Verify FRR command was executed
	commands := executor.getCommands()
	if len(commands) == 0 {
		t.Error("No FRR commands executed")
	}
}

func TestSubscriberRouteManager_WithdrawRoute(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultSubscriberRouteConfig()
	config.LocalAS = 64500

	manager := routing.NewSubscriberRouteManager(config, nil, logger)
	executor := newMockFRRExecutor()
	manager.SetFRRExecutor(executor)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	ctx := context.Background()
	ip := net.ParseIP("10.0.1.100")

	// First inject a route
	err := manager.InjectRoute(ctx, "session-1", "subscriber-1", ip, "residential")
	if err != nil {
		t.Fatalf("InjectRoute failed: %v", err)
	}

	// Then withdraw it
	err = manager.WithdrawRoute(ctx, "session-1", ip)
	if err != nil {
		t.Fatalf("WithdrawRoute failed: %v", err)
	}

	// Verify route is no longer tracked
	_, found := manager.GetRouteByIP(ip)
	if found {
		t.Error("Route still found after withdrawal")
	}

	// Verify stats
	stats := manager.Stats()
	if stats.RoutesWithdrawn != 1 {
		t.Errorf("RoutesWithdrawn = %d, want 1", stats.RoutesWithdrawn)
	}
}

func TestSubscriberRouteManager_IdempotentInjection(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultSubscriberRouteConfig()
	config.LocalAS = 64500

	manager := routing.NewSubscriberRouteManager(config, nil, logger)
	executor := newMockFRRExecutor()
	manager.SetFRRExecutor(executor)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	ctx := context.Background()
	ip := net.ParseIP("10.0.1.100")

	// Inject twice
	err := manager.InjectRoute(ctx, "session-1", "subscriber-1", ip, "residential")
	if err != nil {
		t.Fatalf("First InjectRoute failed: %v", err)
	}

	err = manager.InjectRoute(ctx, "session-1", "subscriber-1", ip, "residential")
	if err != nil {
		t.Fatalf("Second InjectRoute failed: %v", err)
	}

	// Should only have one route tracked
	routes := manager.GetActiveRoutes()
	if len(routes) != 1 {
		t.Errorf("Expected 1 route, got %d", len(routes))
	}
}

func TestSubscriberRouteManager_IdempotentWithdrawal(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultSubscriberRouteConfig()
	config.LocalAS = 64500

	manager := routing.NewSubscriberRouteManager(config, nil, logger)
	executor := newMockFRRExecutor()
	manager.SetFRRExecutor(executor)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	ctx := context.Background()
	ip := net.ParseIP("10.0.1.100")

	// Inject a route
	err := manager.InjectRoute(ctx, "session-1", "subscriber-1", ip, "residential")
	if err != nil {
		t.Fatalf("InjectRoute failed: %v", err)
	}

	// Withdraw twice - second should not error
	err = manager.WithdrawRoute(ctx, "session-1", ip)
	if err != nil {
		t.Fatalf("First WithdrawRoute failed: %v", err)
	}

	err = manager.WithdrawRoute(ctx, "session-1", ip)
	if err != nil {
		t.Fatalf("Second WithdrawRoute should not error: %v", err)
	}
}

func TestSubscriberRouteManager_SessionIDMismatch(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultSubscriberRouteConfig()
	config.LocalAS = 64500

	manager := routing.NewSubscriberRouteManager(config, nil, logger)
	executor := newMockFRRExecutor()
	manager.SetFRRExecutor(executor)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	ctx := context.Background()
	ip := net.ParseIP("10.0.1.100")

	// Inject with session-1
	err := manager.InjectRoute(ctx, "session-1", "subscriber-1", ip, "residential")
	if err != nil {
		t.Fatalf("InjectRoute failed: %v", err)
	}

	// Try to withdraw with session-2 - should fail
	err = manager.WithdrawRoute(ctx, "session-2", ip)
	if err == nil {
		t.Error("WithdrawRoute should fail with session ID mismatch")
	}

	// Route should still exist
	_, found := manager.GetRouteByIP(ip)
	if !found {
		t.Error("Route should still exist after failed withdrawal")
	}
}

func TestSubscriberRouteManager_BulkInject(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultSubscriberRouteConfig()
	config.LocalAS = 64500
	config.BulkBatchSize = 10
	config.BulkBatchDelay = 0 // No delay for testing

	manager := routing.NewSubscriberRouteManager(config, nil, logger)
	executor := newMockFRRExecutor()
	manager.SetFRRExecutor(executor)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	ctx := context.Background()

	// Create 25 routes
	routes := make([]*routing.SubscriberRoute, 25)
	for i := 0; i < 25; i++ {
		routes[i] = &routing.SubscriberRoute{
			IP:           net.IPv4(10, 0, 1, byte(i+1)),
			SessionID:    "session-bulk",
			SubscriberID: "subscriber-bulk",
		}
	}

	err := manager.BulkInjectRoutes(ctx, routes)
	if err != nil {
		t.Fatalf("BulkInjectRoutes failed: %v", err)
	}

	// Verify all routes were injected
	activeRoutes := manager.GetActiveRoutes()
	if len(activeRoutes) != 25 {
		t.Errorf("Expected 25 routes, got %d", len(activeRoutes))
	}

	stats := manager.Stats()
	if stats.BulkInjections != 1 {
		t.Errorf("BulkInjections = %d, want 1", stats.BulkInjections)
	}
}

func TestSubscriberRouteManager_Stats(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultSubscriberRouteConfig()
	config.LocalAS = 64500

	manager := routing.NewSubscriberRouteManager(config, nil, logger)
	executor := newMockFRRExecutor()
	manager.SetFRRExecutor(executor)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	ctx := context.Background()

	// Inject a few routes
	for i := 0; i < 5; i++ {
		ip := net.IPv4(10, 0, 1, byte(i+1))
		err := manager.InjectRoute(ctx, "session", "subscriber", ip, "")
		if err != nil {
			t.Fatalf("InjectRoute failed: %v", err)
		}
	}

	stats := manager.Stats()

	if stats.RoutesActive != 5 {
		t.Errorf("RoutesActive = %d, want 5", stats.RoutesActive)
	}

	if stats.RoutesInjected != 5 {
		t.Errorf("RoutesInjected = %d, want 5", stats.RoutesInjected)
	}

	if stats.InjectionSuccesses != 5 {
		t.Errorf("InjectionSuccesses = %d, want 5", stats.InjectionSuccesses)
	}
}

func TestSubscriberRouteConfig_Communities(t *testing.T) {
	logger := zap.NewNop()
	config := routing.DefaultSubscriberRouteConfig()
	config.LocalAS = 64500
	config.DefaultCommunity = "64500:100"
	config.CommunityByClass = map[string]string{
		"residential": "64500:101",
		"business":    "64500:102",
	}

	manager := routing.NewSubscriberRouteManager(config, nil, logger)
	executor := newMockFRRExecutor()
	manager.SetFRRExecutor(executor)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer manager.Stop()

	ctx := context.Background()

	// Inject with residential class
	ip1 := net.ParseIP("10.0.1.1")
	err := manager.InjectRoute(ctx, "s1", "sub1", ip1, "residential")
	if err != nil {
		t.Fatalf("InjectRoute failed: %v", err)
	}

	route1, _ := manager.GetRouteByIP(ip1)
	if route1.Community != "64500:101" {
		t.Errorf("Community = %s, want 64500:101", route1.Community)
	}

	// Inject with unknown class (should use default)
	ip2 := net.ParseIP("10.0.1.2")
	err = manager.InjectRoute(ctx, "s2", "sub2", ip2, "unknown")
	if err != nil {
		t.Fatalf("InjectRoute failed: %v", err)
	}

	route2, _ := manager.GetRouteByIP(ip2)
	if route2.Community != "64500:100" {
		t.Errorf("Community = %s, want 64500:100", route2.Community)
	}
}

func TestDefaultSubscriberRouteConfig(t *testing.T) {
	config := routing.DefaultSubscriberRouteConfig()

	if config.RetryInterval == 0 {
		t.Error("RetryInterval should not be 0")
	}

	if config.MaxRetries == 0 {
		t.Error("MaxRetries should not be 0")
	}

	if config.BulkBatchSize == 0 {
		t.Error("BulkBatchSize should not be 0")
	}
}
