package routing

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// RoutingMetrics holds Prometheus metrics for routing operations.
type RoutingMetrics struct {
	// Subscriber route metrics
	subscriberRoutesActive    prometheus.Gauge
	subscriberRoutesInjected  prometheus.Counter
	subscriberRoutesWithdrawn prometheus.Counter
	routeInjectionLatency     prometheus.Histogram
	routeWithdrawalLatency    prometheus.Histogram
	routeInjectionErrors      *prometheus.CounterVec
	routeWithdrawalErrors     *prometheus.CounterVec

	// BGP metrics
	bgpNeighborsTotal       prometheus.Gauge
	bgpNeighborsEstablished prometheus.Gauge
	bgpPrefixesAnnounced    prometheus.Gauge
	bgpPrefixesReceived     *prometheus.GaugeVec
	bgpSessionStateChanges  *prometheus.CounterVec

	// BFD metrics
	bfdPeersTotal   prometheus.Gauge
	bfdPeersUp      prometheus.Gauge
	bfdPeersDown    prometheus.Gauge
	bfdStateChanges *prometheus.CounterVec
	bfdPacketsTx    *prometheus.CounterVec
	bfdPacketsRx    *prometheus.CounterVec

	// FRR communication metrics
	frrCommandsTotal  *prometheus.CounterVec
	frrCommandLatency prometheus.Histogram
	frrCommandErrors  prometheus.Counter
	frrReconnections  prometheus.Counter

	registered bool
	mu         sync.Mutex
}

// NewRoutingMetrics creates a new RoutingMetrics instance.
func NewRoutingMetrics() *RoutingMetrics {
	return &RoutingMetrics{
		subscriberRoutesActive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_routing_subscriber_routes_active",
				Help: "Number of active subscriber /32 routes",
			},
		),

		subscriberRoutesInjected: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_routing_subscriber_routes_injected_total",
				Help: "Total subscriber routes injected into BGP",
			},
		),

		subscriberRoutesWithdrawn: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_routing_subscriber_routes_withdrawn_total",
				Help: "Total subscriber routes withdrawn from BGP",
			},
		),

		routeInjectionLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "bng_routing_route_injection_latency_seconds",
				Help:    "Latency of route injection operations",
				Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
			},
		),

		routeWithdrawalLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "bng_routing_route_withdrawal_latency_seconds",
				Help:    "Latency of route withdrawal operations",
				Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
			},
		),

		routeInjectionErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_routing_route_injection_errors_total",
				Help: "Total route injection errors by type",
			},
			[]string{"error_type"},
		),

		routeWithdrawalErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_routing_route_withdrawal_errors_total",
				Help: "Total route withdrawal errors by type",
			},
			[]string{"error_type"},
		),

		bgpNeighborsTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_routing_bgp_neighbors_total",
				Help: "Total number of configured BGP neighbors",
			},
		),

		bgpNeighborsEstablished: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_routing_bgp_neighbors_established",
				Help: "Number of BGP neighbors in Established state",
			},
		),

		bgpPrefixesAnnounced: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_routing_bgp_prefixes_announced",
				Help: "Number of prefixes announced via BGP",
			},
		),

		bgpPrefixesReceived: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_routing_bgp_prefixes_received",
				Help: "Number of prefixes received from BGP peer",
			},
			[]string{"peer_ip", "address_family"},
		),

		bgpSessionStateChanges: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_routing_bgp_session_state_changes_total",
				Help: "Total BGP session state changes",
			},
			[]string{"peer_ip", "from_state", "to_state"},
		),

		bfdPeersTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_routing_bfd_peers_total",
				Help: "Total number of configured BFD peers",
			},
		),

		bfdPeersUp: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_routing_bfd_peers_up",
				Help: "Number of BFD peers in Up state",
			},
		),

		bfdPeersDown: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_routing_bfd_peers_down",
				Help: "Number of BFD peers in Down state",
			},
		),

		bfdStateChanges: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_routing_bfd_state_changes_total",
				Help: "Total BFD session state changes",
			},
			[]string{"peer_ip", "from_state", "to_state"},
		),

		bfdPacketsTx: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_routing_bfd_packets_tx_total",
				Help: "Total BFD packets transmitted",
			},
			[]string{"peer_ip"},
		),

		bfdPacketsRx: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_routing_bfd_packets_rx_total",
				Help: "Total BFD packets received",
			},
			[]string{"peer_ip"},
		),

		frrCommandsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_routing_frr_commands_total",
				Help: "Total FRR (vtysh) commands executed",
			},
			[]string{"command_type", "result"},
		),

		frrCommandLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "bng_routing_frr_command_latency_seconds",
				Help:    "Latency of FRR command execution",
				Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5},
			},
		),

		frrCommandErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_routing_frr_command_errors_total",
				Help: "Total FRR command errors",
			},
		),

		frrReconnections: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_routing_frr_reconnections_total",
				Help: "Total FRR reconnection attempts",
			},
		),
	}
}

// Register registers all metrics with Prometheus.
func (m *RoutingMetrics) Register() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.registered {
		return nil
	}

	collectors := []prometheus.Collector{
		m.subscriberRoutesActive,
		m.subscriberRoutesInjected,
		m.subscriberRoutesWithdrawn,
		m.routeInjectionLatency,
		m.routeWithdrawalLatency,
		m.routeInjectionErrors,
		m.routeWithdrawalErrors,
		m.bgpNeighborsTotal,
		m.bgpNeighborsEstablished,
		m.bgpPrefixesAnnounced,
		m.bgpPrefixesReceived,
		m.bgpSessionStateChanges,
		m.bfdPeersTotal,
		m.bfdPeersUp,
		m.bfdPeersDown,
		m.bfdStateChanges,
		m.bfdPacketsTx,
		m.bfdPacketsRx,
		m.frrCommandsTotal,
		m.frrCommandLatency,
		m.frrCommandErrors,
		m.frrReconnections,
	}

	for _, c := range collectors {
		if err := prometheus.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				return err
			}
		}
	}

	m.registered = true
	return nil
}

// --- Metric update methods ---

// SetSubscriberRoutesActive sets the number of active subscriber routes.
func (m *RoutingMetrics) SetSubscriberRoutesActive(count int) {
	m.subscriberRoutesActive.Set(float64(count))
}

// RecordRouteInjection records a route injection event.
func (m *RoutingMetrics) RecordRouteInjection(latencySeconds float64, success bool) {
	m.subscriberRoutesInjected.Inc()
	m.routeInjectionLatency.Observe(latencySeconds)
	if !success {
		m.routeInjectionErrors.WithLabelValues("injection_failed").Inc()
	}
}

// RecordRouteWithdrawal records a route withdrawal event.
func (m *RoutingMetrics) RecordRouteWithdrawal(latencySeconds float64, success bool) {
	m.subscriberRoutesWithdrawn.Inc()
	m.routeWithdrawalLatency.Observe(latencySeconds)
	if !success {
		m.routeWithdrawalErrors.WithLabelValues("withdrawal_failed").Inc()
	}
}

// RecordRouteInjectionError records a route injection error.
func (m *RoutingMetrics) RecordRouteInjectionError(errorType string) {
	m.routeInjectionErrors.WithLabelValues(errorType).Inc()
}

// RecordRouteWithdrawalError records a route withdrawal error.
func (m *RoutingMetrics) RecordRouteWithdrawalError(errorType string) {
	m.routeWithdrawalErrors.WithLabelValues(errorType).Inc()
}

// SetBGPNeighborStats sets BGP neighbor statistics.
func (m *RoutingMetrics) SetBGPNeighborStats(total, established int) {
	m.bgpNeighborsTotal.Set(float64(total))
	m.bgpNeighborsEstablished.Set(float64(established))
}

// SetBGPPrefixesAnnounced sets the number of announced prefixes.
func (m *RoutingMetrics) SetBGPPrefixesAnnounced(count int) {
	m.bgpPrefixesAnnounced.Set(float64(count))
}

// SetBGPPrefixesReceived sets the number of prefixes received from a peer.
func (m *RoutingMetrics) SetBGPPrefixesReceived(peerIP, addressFamily string, count int) {
	m.bgpPrefixesReceived.WithLabelValues(peerIP, addressFamily).Set(float64(count))
}

// RecordBGPStateChange records a BGP session state change.
func (m *RoutingMetrics) RecordBGPStateChange(peerIP, fromState, toState string) {
	m.bgpSessionStateChanges.WithLabelValues(peerIP, fromState, toState).Inc()
}

// SetBFDPeerStats sets BFD peer statistics.
func (m *RoutingMetrics) SetBFDPeerStats(total, up, down int) {
	m.bfdPeersTotal.Set(float64(total))
	m.bfdPeersUp.Set(float64(up))
	m.bfdPeersDown.Set(float64(down))
}

// RecordBFDStateChange records a BFD session state change.
func (m *RoutingMetrics) RecordBFDStateChange(peerIP, fromState, toState string) {
	m.bfdStateChanges.WithLabelValues(peerIP, fromState, toState).Inc()
}

// RecordBFDPackets records BFD packet counts.
func (m *RoutingMetrics) RecordBFDPackets(peerIP string, tx, rx uint64) {
	m.bfdPacketsTx.WithLabelValues(peerIP).Add(float64(tx))
	m.bfdPacketsRx.WithLabelValues(peerIP).Add(float64(rx))
}

// RecordFRRCommand records an FRR command execution.
func (m *RoutingMetrics) RecordFRRCommand(commandType, result string, latencySeconds float64) {
	m.frrCommandsTotal.WithLabelValues(commandType, result).Inc()
	m.frrCommandLatency.Observe(latencySeconds)
}

// RecordFRRError records an FRR command error.
func (m *RoutingMetrics) RecordFRRError() {
	m.frrCommandErrors.Inc()
}

// RecordFRRReconnection records an FRR reconnection attempt.
func (m *RoutingMetrics) RecordFRRReconnection() {
	m.frrReconnections.Inc()
}

// UpdateFromRouteManager updates metrics from a SubscriberRouteManager.
func (m *RoutingMetrics) UpdateFromRouteManager(rm *SubscriberRouteManager) {
	if rm == nil {
		return
	}

	stats := rm.Stats()
	m.subscriberRoutesActive.Set(float64(stats.RoutesActive))
}

// UpdateFromBGPController updates metrics from a BGPController.
func (m *RoutingMetrics) UpdateFromBGPController(bgp *BGPController) {
	if bgp == nil {
		return
	}

	stats := bgp.Stats()
	m.bgpNeighborsTotal.Set(float64(stats.TotalNeighbors))
	m.bgpNeighborsEstablished.Set(float64(stats.EstablishedNeighbors))
	m.bgpPrefixesAnnounced.Set(float64(stats.TotalAnnouncements))
}

// UpdateFromBFDManager updates metrics from a BFDManager.
func (m *RoutingMetrics) UpdateFromBFDManager(bfd *BFDManager) {
	if bfd == nil {
		return
	}

	stats := bfd.Stats()
	m.bfdPeersTotal.Set(float64(stats.TotalPeers))
	m.bfdPeersUp.Set(float64(stats.PeersUp))
	m.bfdPeersDown.Set(float64(stats.PeersDown))
}

// Collect updates all routing metrics from the provided components.
func (m *RoutingMetrics) Collect(rm *SubscriberRouteManager, bgp *BGPController, bfd *BFDManager) {
	m.UpdateFromRouteManager(rm)
	m.UpdateFromBGPController(bgp)
	m.UpdateFromBFDManager(bfd)
}

// Global metrics instance for convenience
var globalMetrics *RoutingMetrics
var metricsOnce sync.Once

// GlobalMetrics returns a singleton RoutingMetrics instance.
func GlobalMetrics() *RoutingMetrics {
	metricsOnce.Do(func() {
		globalMetrics = NewRoutingMetrics()
	})
	return globalMetrics
}
