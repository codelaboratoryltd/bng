package routing_test

import (
	"testing"

	"github.com/codelaboratoryltd/bng/pkg/routing"
)

func TestNewRoutingMetrics(t *testing.T) {
	metrics := routing.NewRoutingMetrics()
	if metrics == nil {
		t.Fatal("NewRoutingMetrics returned nil")
	}
}

func TestRoutingMetrics_Register(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	// First registration should succeed
	err := metrics.Register()
	if err != nil {
		t.Fatalf("First Register failed: %v", err)
	}

	// Second registration should also succeed (idempotent)
	err = metrics.Register()
	if err != nil {
		t.Fatalf("Second Register failed: %v", err)
	}
}

func TestRoutingMetrics_SetSubscriberRoutesActive(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	// Should not panic
	metrics.SetSubscriberRoutesActive(100)
	metrics.SetSubscriberRoutesActive(0)
	metrics.SetSubscriberRoutesActive(50000)
}

func TestRoutingMetrics_RecordRouteInjection(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	// Record successful injections
	metrics.RecordRouteInjection(0.001, true)
	metrics.RecordRouteInjection(0.002, true)

	// Record failed injection
	metrics.RecordRouteInjection(0.005, false)
}

func TestRoutingMetrics_RecordRouteWithdrawal(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	// Record successful withdrawals
	metrics.RecordRouteWithdrawal(0.001, true)
	metrics.RecordRouteWithdrawal(0.002, true)

	// Record failed withdrawal
	metrics.RecordRouteWithdrawal(0.005, false)
}

func TestRoutingMetrics_SetBGPNeighborStats(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.SetBGPNeighborStats(5, 3)
	metrics.SetBGPNeighborStats(10, 10)
	metrics.SetBGPNeighborStats(0, 0)
}

func TestRoutingMetrics_SetBGPPrefixesAnnounced(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.SetBGPPrefixesAnnounced(1000)
	metrics.SetBGPPrefixesAnnounced(5000)
	metrics.SetBGPPrefixesAnnounced(0)
}

func TestRoutingMetrics_SetBGPPrefixesReceived(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.SetBGPPrefixesReceived("10.0.0.1", "ipv4", 500)
	metrics.SetBGPPrefixesReceived("10.0.0.2", "ipv4", 1000)
	metrics.SetBGPPrefixesReceived("2001:db8::1", "ipv6", 100)
}

func TestRoutingMetrics_RecordBGPStateChange(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.RecordBGPStateChange("10.0.0.1", "Idle", "Connect")
	metrics.RecordBGPStateChange("10.0.0.1", "Connect", "Established")
	metrics.RecordBGPStateChange("10.0.0.1", "Established", "Idle")
}

func TestRoutingMetrics_SetBFDPeerStats(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.SetBFDPeerStats(5, 4, 1)
	metrics.SetBFDPeerStats(10, 10, 0)
	metrics.SetBFDPeerStats(0, 0, 0)
}

func TestRoutingMetrics_RecordBFDStateChange(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.RecordBFDStateChange("10.0.0.1", "Down", "Init")
	metrics.RecordBFDStateChange("10.0.0.1", "Init", "Up")
	metrics.RecordBFDStateChange("10.0.0.1", "Up", "Down")
}

func TestRoutingMetrics_RecordBFDPackets(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.RecordBFDPackets("10.0.0.1", 100, 100)
	metrics.RecordBFDPackets("10.0.0.2", 50, 55)
}

func TestRoutingMetrics_RecordFRRCommand(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.RecordFRRCommand("announce", "success", 0.01)
	metrics.RecordFRRCommand("withdraw", "success", 0.005)
	metrics.RecordFRRCommand("announce", "error", 0.1)
}

func TestRoutingMetrics_RecordFRRError(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.RecordFRRError()
	metrics.RecordFRRError()
	metrics.RecordFRRError()
}

func TestRoutingMetrics_RecordFRRReconnection(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.RecordFRRReconnection()
	metrics.RecordFRRReconnection()
}

func TestRoutingMetrics_UpdateFromRouteManager(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	// Should not panic with nil
	metrics.UpdateFromRouteManager(nil)
}

func TestRoutingMetrics_UpdateFromBGPController(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	// Should not panic with nil
	metrics.UpdateFromBGPController(nil)
}

func TestRoutingMetrics_UpdateFromBFDManager(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	// Should not panic with nil
	metrics.UpdateFromBFDManager(nil)
}

func TestRoutingMetrics_Collect(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	// Should not panic with nil components
	metrics.Collect(nil, nil, nil)
}

func TestGlobalMetrics(t *testing.T) {
	// Get global metrics instance
	metrics1 := routing.GlobalMetrics()
	if metrics1 == nil {
		t.Fatal("GlobalMetrics returned nil")
	}

	// Should return the same instance
	metrics2 := routing.GlobalMetrics()
	if metrics1 != metrics2 {
		t.Error("GlobalMetrics should return singleton")
	}
}

func TestRoutingMetrics_RecordRouteInjectionError(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.RecordRouteInjectionError("frr_unavailable")
	metrics.RecordRouteInjectionError("timeout")
	metrics.RecordRouteInjectionError("invalid_ip")
}

func TestRoutingMetrics_RecordRouteWithdrawalError(t *testing.T) {
	metrics := routing.NewRoutingMetrics()

	metrics.RecordRouteWithdrawalError("frr_unavailable")
	metrics.RecordRouteWithdrawalError("route_not_found")
	metrics.RecordRouteWithdrawalError("session_mismatch")
}
