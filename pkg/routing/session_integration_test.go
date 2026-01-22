package routing_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/routing"
	"go.uber.org/zap"
)

func TestSessionRouteIntegration_OnSessionActivate(t *testing.T) {
	logger := zap.NewNop()

	// Create route manager
	routeConfig := routing.DefaultSubscriberRouteConfig()
	routeConfig.LocalAS = 64500
	routeManager := routing.NewSubscriberRouteManager(routeConfig, nil, logger)
	executor := newMockFRRExecutor()
	routeManager.SetFRRExecutor(executor)
	routeManager.Start()
	defer routeManager.Stop()

	// Create integration
	config := routing.DefaultSessionRouteConfig()
	integration := routing.NewSessionRouteIntegration(routeManager, nil, nil, config, logger)
	integration.Start()
	defer integration.Stop()

	// Simulate session activation
	ip := net.ParseIP("10.0.1.100")
	err := integration.OnSessionActivate("session-1", "subscriber-1", ip, nil, "residential")
	if err != nil {
		t.Fatalf("OnSessionActivate failed: %v", err)
	}

	// Verify route was injected
	route, found := routeManager.GetRouteByIP(ip)
	if !found {
		t.Fatal("Route not found after session activation")
	}

	if route.SessionID != "session-1" {
		t.Errorf("SessionID = %s, want session-1", route.SessionID)
	}

	// Verify tracked sessions
	stats := integration.Stats()
	if stats.TrackedSessions != 1 {
		t.Errorf("TrackedSessions = %d, want 1", stats.TrackedSessions)
	}

	if stats.InjectedRoutes != 1 {
		t.Errorf("InjectedRoutes = %d, want 1", stats.InjectedRoutes)
	}
}

func TestSessionRouteIntegration_OnSessionTerminate(t *testing.T) {
	logger := zap.NewNop()

	// Create route manager
	routeConfig := routing.DefaultSubscriberRouteConfig()
	routeConfig.LocalAS = 64500
	routeManager := routing.NewSubscriberRouteManager(routeConfig, nil, logger)
	executor := newMockFRRExecutor()
	routeManager.SetFRRExecutor(executor)
	routeManager.Start()
	defer routeManager.Stop()

	// Create integration
	config := routing.DefaultSessionRouteConfig()
	integration := routing.NewSessionRouteIntegration(routeManager, nil, nil, config, logger)
	integration.Start()
	defer integration.Stop()

	// Activate then terminate
	ip := net.ParseIP("10.0.1.100")
	err := integration.OnSessionActivate("session-1", "subscriber-1", ip, nil, "residential")
	if err != nil {
		t.Fatalf("OnSessionActivate failed: %v", err)
	}

	err = integration.OnSessionTerminate("session-1", "user_logout")
	if err != nil {
		t.Fatalf("OnSessionTerminate failed: %v", err)
	}

	// Verify route was withdrawn
	_, found := routeManager.GetRouteByIP(ip)
	if found {
		t.Error("Route should not be found after session termination")
	}

	// Verify tracking cleared
	stats := integration.Stats()
	if stats.TrackedSessions != 0 {
		t.Errorf("TrackedSessions = %d, want 0", stats.TrackedSessions)
	}
}

func TestSessionRouteIntegration_DisabledInjection(t *testing.T) {
	logger := zap.NewNop()

	// Create route manager
	routeConfig := routing.DefaultSubscriberRouteConfig()
	routeConfig.LocalAS = 64500
	routeManager := routing.NewSubscriberRouteManager(routeConfig, nil, logger)
	executor := newMockFRRExecutor()
	routeManager.SetFRRExecutor(executor)
	routeManager.Start()
	defer routeManager.Stop()

	// Create integration with injection disabled
	config := routing.DefaultSessionRouteConfig()
	config.EnableRouteInjection = false
	integration := routing.NewSessionRouteIntegration(routeManager, nil, nil, config, logger)
	integration.Start()
	defer integration.Stop()

	// Attempt activation
	ip := net.ParseIP("10.0.1.100")
	err := integration.OnSessionActivate("session-1", "subscriber-1", ip, nil, "residential")
	if err != nil {
		t.Fatalf("OnSessionActivate should not fail: %v", err)
	}

	// Verify no route was injected
	_, found := routeManager.GetRouteByIP(ip)
	if found {
		t.Error("Route should not be injected when injection is disabled")
	}
}

func TestSessionRouteIntegration_DisabledWithdrawal(t *testing.T) {
	logger := zap.NewNop()

	// Create route manager
	routeConfig := routing.DefaultSubscriberRouteConfig()
	routeConfig.LocalAS = 64500
	routeManager := routing.NewSubscriberRouteManager(routeConfig, nil, logger)
	executor := newMockFRRExecutor()
	routeManager.SetFRRExecutor(executor)
	routeManager.Start()
	defer routeManager.Stop()

	// Create integration with withdrawal disabled
	config := routing.DefaultSessionRouteConfig()
	config.EnableRouteWithdrawal = false
	integration := routing.NewSessionRouteIntegration(routeManager, nil, nil, config, logger)
	integration.Start()
	defer integration.Stop()

	// Activate then terminate
	ip := net.ParseIP("10.0.1.100")
	err := integration.OnSessionActivate("session-1", "subscriber-1", ip, nil, "residential")
	if err != nil {
		t.Fatalf("OnSessionActivate failed: %v", err)
	}

	err = integration.OnSessionTerminate("session-1", "user_logout")
	if err != nil {
		t.Fatalf("OnSessionTerminate should not fail: %v", err)
	}

	// Route should still exist when withdrawal is disabled
	_, found := routeManager.GetRouteByIP(ip)
	if !found {
		t.Error("Route should still exist when withdrawal is disabled")
	}
}

func TestSessionRouteIntegration_OnSessionStateChange(t *testing.T) {
	logger := zap.NewNop()

	// Create route manager
	routeConfig := routing.DefaultSubscriberRouteConfig()
	routeConfig.LocalAS = 64500
	routeManager := routing.NewSubscriberRouteManager(routeConfig, nil, logger)
	executor := newMockFRRExecutor()
	routeManager.SetFRRExecutor(executor)
	routeManager.Start()
	defer routeManager.Stop()

	// Create integration
	config := routing.DefaultSessionRouteConfig()
	integration := routing.NewSessionRouteIntegration(routeManager, nil, nil, config, logger)
	integration.Start()
	defer integration.Stop()

	ip := net.ParseIP("10.0.1.100")

	// Test state change to active
	err := integration.OnSessionStateChange("session-1", "subscriber-1", "establishing", "active", ip, nil, "residential", "")
	if err != nil {
		t.Fatalf("OnSessionStateChange to active failed: %v", err)
	}

	_, found := routeManager.GetRouteByIP(ip)
	if !found {
		t.Error("Route should be injected on transition to active")
	}

	// Test state change to terminated
	err = integration.OnSessionStateChange("session-1", "subscriber-1", "active", "terminated", ip, nil, "", "user_logout")
	if err != nil {
		t.Fatalf("OnSessionStateChange to terminated failed: %v", err)
	}

	_, found = routeManager.GetRouteByIP(ip)
	if found {
		t.Error("Route should be withdrawn on transition to terminated")
	}
}

func TestSessionRouteIntegration_RecoverRoutes(t *testing.T) {
	logger := zap.NewNop()

	// Create route manager
	routeConfig := routing.DefaultSubscriberRouteConfig()
	routeConfig.LocalAS = 64500
	routeManager := routing.NewSubscriberRouteManager(routeConfig, nil, logger)
	executor := newMockFRRExecutor()
	routeManager.SetFRRExecutor(executor)
	routeManager.Start()
	defer routeManager.Stop()

	// Create integration
	config := routing.DefaultSessionRouteConfig()
	integration := routing.NewSessionRouteIntegration(routeManager, nil, nil, config, logger)
	integration.Start()
	defer integration.Stop()

	// Activate multiple sessions
	for i := 0; i < 5; i++ {
		ip := net.IPv4(10, 0, 1, byte(i+1))
		err := integration.OnSessionActivate("session-"+string(rune('A'+i)), "subscriber", ip, nil, "")
		if err != nil {
			t.Fatalf("OnSessionActivate failed: %v", err)
		}
	}

	// Count initial commands (route injections)
	initialCommands := len(executor.getCommands())
	if initialCommands < 5 {
		t.Errorf("Expected at least 5 initial commands, got %d", initialCommands)
	}

	// Recover routes (should re-inject all tracked routes)
	ctx := context.Background()
	err := integration.RecoverRoutes(ctx)
	if err != nil {
		t.Fatalf("RecoverRoutes failed: %v", err)
	}

	// Verify additional commands were issued for recovery
	totalCommands := len(executor.getCommands())
	recoveryCommands := totalCommands - initialCommands
	if recoveryCommands < 5 {
		t.Errorf("Expected at least 5 recovery commands, got %d (total: %d, initial: %d)", recoveryCommands, totalCommands, initialCommands)
	}
}

func TestSessionRouteIntegration_GetTrackedSessions(t *testing.T) {
	logger := zap.NewNop()

	// Create route manager
	routeConfig := routing.DefaultSubscriberRouteConfig()
	routeConfig.LocalAS = 64500
	routeManager := routing.NewSubscriberRouteManager(routeConfig, nil, logger)
	executor := newMockFRRExecutor()
	routeManager.SetFRRExecutor(executor)
	routeManager.Start()
	defer routeManager.Stop()

	// Create integration
	config := routing.DefaultSessionRouteConfig()
	integration := routing.NewSessionRouteIntegration(routeManager, nil, nil, config, logger)
	integration.Start()
	defer integration.Stop()

	// Activate sessions
	ip1 := net.ParseIP("10.0.1.1")
	ip2 := net.ParseIP("10.0.1.2")
	integration.OnSessionActivate("session-1", "subscriber-1", ip1, nil, "residential")
	integration.OnSessionActivate("session-2", "subscriber-2", ip2, nil, "business")

	// Get tracked sessions
	sessions := integration.GetTrackedSessions()
	if len(sessions) != 2 {
		t.Errorf("Expected 2 tracked sessions, got %d", len(sessions))
	}
}

func TestDefaultSessionRouteConfig(t *testing.T) {
	config := routing.DefaultSessionRouteConfig()

	if !config.EnableRouteInjection {
		t.Error("EnableRouteInjection should be true by default")
	}

	if !config.EnableRouteWithdrawal {
		t.Error("EnableRouteWithdrawal should be true by default")
	}

	if config.InjectionTimeout == 0 {
		t.Error("InjectionTimeout should not be 0")
	}

	if config.WithdrawalTimeout == 0 {
		t.Error("WithdrawalTimeout should not be 0")
	}
}

func TestSessionEventAdapter(t *testing.T) {
	logger := zap.NewNop()

	// Create route manager
	routeConfig := routing.DefaultSubscriberRouteConfig()
	routeConfig.LocalAS = 64500
	routeManager := routing.NewSubscriberRouteManager(routeConfig, nil, logger)
	executor := newMockFRRExecutor()
	routeManager.SetFRRExecutor(executor)
	routeManager.Start()
	defer routeManager.Stop()

	// Create integration
	config := routing.DefaultSessionRouteConfig()
	integration := routing.NewSessionRouteIntegration(routeManager, nil, nil, config, logger)
	integration.Start()
	defer integration.Stop()

	// Create adapter
	adapter := routing.NewSessionEventAdapter(integration, logger)

	// Test activation handling
	ip := net.ParseIP("10.0.1.100")
	adapter.HandleActivation("session-1", "subscriber-1", ip, nil, "residential")

	_, found := routeManager.GetRouteByIP(ip)
	if !found {
		t.Error("Route should be injected via adapter")
	}

	// Test termination handling
	adapter.HandleTermination("session-1", "logout")

	_, found = routeManager.GetRouteByIP(ip)
	if found {
		t.Error("Route should be withdrawn via adapter")
	}
}

func TestSessionRouteIntegration_Timeouts(t *testing.T) {
	logger := zap.NewNop()

	// Create route manager
	routeConfig := routing.DefaultSubscriberRouteConfig()
	routeConfig.LocalAS = 64500
	routeManager := routing.NewSubscriberRouteManager(routeConfig, nil, logger)
	executor := newMockFRRExecutor()
	routeManager.SetFRRExecutor(executor)
	routeManager.Start()
	defer routeManager.Stop()

	// Create integration with short timeouts
	config := routing.DefaultSessionRouteConfig()
	config.InjectionTimeout = 100 * time.Millisecond
	config.WithdrawalTimeout = 100 * time.Millisecond
	integration := routing.NewSessionRouteIntegration(routeManager, nil, nil, config, logger)
	integration.Start()
	defer integration.Stop()

	// Should succeed quickly
	ip := net.ParseIP("10.0.1.100")
	err := integration.OnSessionActivate("session-1", "subscriber-1", ip, nil, "")
	if err != nil {
		t.Fatalf("OnSessionActivate failed: %v", err)
	}
}
