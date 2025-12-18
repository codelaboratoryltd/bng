package metrics

import (
	"fmt"
	"net/http"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/dhcp"
	"github.com/codelaboratoryltd/bng/pkg/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Metrics holds all Prometheus metrics
type Metrics struct {
	// DHCP metrics
	dhcpRequestsTotal  *prometheus.CounterVec
	dhcpLatencySeconds *prometheus.HistogramVec
	dhcpCacheHitRate   prometheus.Gauge
	dhcpActiveLeases   prometheus.Gauge

	// eBPF metrics
	ebpfFastpathHits   prometheus.Counter
	ebpfFastpathMisses prometheus.Counter
	ebpfErrors         prometheus.Counter
	ebpfCacheExpired   prometheus.Counter

	// Pool metrics
	poolUtilization *prometheus.GaugeVec
	poolAvailable   *prometheus.GaugeVec
	poolAllocated   *prometheus.GaugeVec

	// System metrics
	ebpfMapEntries *prometheus.GaugeVec

	// Session metrics
	sessionActive   *prometheus.GaugeVec
	sessionTotal    *prometheus.CounterVec
	sessionDuration *prometheus.HistogramVec
	sessionBytesIn  *prometheus.CounterVec
	sessionBytesOut *prometheus.CounterVec

	// NAT metrics
	natBindingsActive prometheus.Gauge
	natTranslations   *prometheus.CounterVec
	natPortsUsed      *prometheus.GaugeVec

	// RADIUS metrics
	radiusRequests *prometheus.CounterVec
	radiusLatency  *prometheus.HistogramVec
	radiusTimeouts *prometheus.CounterVec

	// QoS metrics
	qosPoliciesActive prometheus.Gauge
	qosPacketsDropped *prometheus.CounterVec
	qosBytesDropped   *prometheus.CounterVec

	// PPPoE metrics
	pppoeSessionsActive prometheus.Gauge
	pppoeNegotiations   *prometheus.CounterVec

	// Routing metrics
	routesActive        *prometheus.GaugeVec
	bgpPeersUp          prometheus.Gauge
	bgpPrefixesReceived *prometheus.GaugeVec

	// Subscriber metrics
	subscriberTotal   prometheus.Gauge
	subscriberByClass *prometheus.GaugeVec
	subscriberByISP   *prometheus.GaugeVec

	// References for collection
	loader  *ebpf.Loader
	poolMgr *dhcp.PoolManager
	server  *dhcp.Server
	logger  *zap.Logger
}

// New creates a new Metrics instance
func New(loader *ebpf.Loader, poolMgr *dhcp.PoolManager, server *dhcp.Server, logger *zap.Logger) *Metrics {
	m := &Metrics{
		loader:  loader,
		poolMgr: poolMgr,
		server:  server,
		logger:  logger,

		dhcpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_dhcp_requests_total",
				Help: "Total DHCP requests by path and result",
			},
			[]string{"path", "result"},
		),

		dhcpLatencySeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "bng_dhcp_latency_seconds",
				Help:    "DHCP request latency by path",
				Buckets: []float64{.00001, .00005, .0001, .0005, .001, .005, .01, .05, .1},
			},
			[]string{"path"},
		),

		dhcpCacheHitRate: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_dhcp_cache_hit_rate",
				Help: "Ratio of DHCP requests served by fast path",
			},
		),

		dhcpActiveLeases: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_dhcp_active_leases",
				Help: "Number of active DHCP leases",
			},
		),

		ebpfFastpathHits: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_ebpf_fastpath_hits_total",
				Help: "Total DHCP requests served by eBPF fast path",
			},
		),

		ebpfFastpathMisses: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_ebpf_fastpath_misses_total",
				Help: "Total DHCP requests passed to slow path",
			},
		),

		ebpfErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_ebpf_errors_total",
				Help: "Total eBPF processing errors",
			},
		),

		ebpfCacheExpired: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_ebpf_cache_expired_total",
				Help: "Total expired cache entries in eBPF",
			},
		),

		poolUtilization: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_pool_utilization_ratio",
				Help: "IP pool utilization ratio (0-1)",
			},
			[]string{"pool_id", "pool_name"},
		),

		poolAvailable: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_pool_available_ips",
				Help: "Available IPs in pool",
			},
			[]string{"pool_id", "pool_name"},
		),

		poolAllocated: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_pool_allocated_ips",
				Help: "Allocated IPs in pool",
			},
			[]string{"pool_id", "pool_name"},
		),

		ebpfMapEntries: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_ebpf_map_entries",
				Help: "Number of entries in eBPF maps",
			},
			[]string{"map_name"},
		),

		// Session metrics
		sessionActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_session_active",
				Help: "Number of active sessions",
			},
			[]string{"type", "state"},
		),

		sessionTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_session_total",
				Help: "Total sessions by outcome",
			},
			[]string{"type", "outcome"},
		),

		sessionDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "bng_session_duration_seconds",
				Help:    "Session duration in seconds",
				Buckets: []float64{60, 300, 600, 1800, 3600, 7200, 14400, 28800, 43200, 86400},
			},
			[]string{"type"},
		),

		sessionBytesIn: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_session_bytes_in_total",
				Help: "Total bytes received by session type",
			},
			[]string{"type", "isp_id"},
		),

		sessionBytesOut: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_session_bytes_out_total",
				Help: "Total bytes sent by session type",
			},
			[]string{"type", "isp_id"},
		),

		// NAT metrics
		natBindingsActive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_nat_bindings_active",
				Help: "Number of active NAT bindings",
			},
		),

		natTranslations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_nat_translations_total",
				Help: "Total NAT translations by direction",
			},
			[]string{"direction", "protocol"},
		),

		natPortsUsed: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_nat_ports_used",
				Help: "NAT ports in use per public IP",
			},
			[]string{"public_ip"},
		),

		// RADIUS metrics
		radiusRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_radius_requests_total",
				Help: "Total RADIUS requests by type and result",
			},
			[]string{"type", "result", "server"},
		),

		radiusLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "bng_radius_latency_seconds",
				Help:    "RADIUS request latency",
				Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
			},
			[]string{"type", "server"},
		),

		radiusTimeouts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_radius_timeouts_total",
				Help: "Total RADIUS timeouts by server",
			},
			[]string{"server"},
		),

		// QoS metrics
		qosPoliciesActive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_qos_policies_active",
				Help: "Number of active QoS policies",
			},
		),

		qosPacketsDropped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_qos_packets_dropped_total",
				Help: "Total packets dropped by QoS",
			},
			[]string{"policy_id", "direction"},
		),

		qosBytesDropped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_qos_bytes_dropped_total",
				Help: "Total bytes dropped by QoS",
			},
			[]string{"policy_id", "direction"},
		),

		// PPPoE metrics
		pppoeSessionsActive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_pppoe_sessions_active",
				Help: "Number of active PPPoE sessions",
			},
		),

		pppoeNegotiations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_pppoe_negotiations_total",
				Help: "Total PPPoE negotiations by result",
			},
			[]string{"stage", "result"},
		),

		// Routing metrics
		routesActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_routes_active",
				Help: "Number of active routes by table",
			},
			[]string{"table"},
		),

		bgpPeersUp: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_bgp_peers_up",
				Help: "Number of BGP peers in established state",
			},
		),

		bgpPrefixesReceived: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_bgp_prefixes_received",
				Help: "Number of prefixes received from BGP peer",
			},
			[]string{"peer_ip", "afi"},
		),

		// Subscriber metrics
		subscriberTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_subscriber_total",
				Help: "Total number of subscribers",
			},
		),

		subscriberByClass: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_subscriber_by_class",
				Help: "Number of subscribers by class",
			},
			[]string{"class"},
		),

		subscriberByISP: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_subscriber_by_isp",
				Help: "Number of subscribers by ISP",
			},
			[]string{"isp_id"},
		),
	}

	return m
}

// Register registers all metrics with Prometheus
func (m *Metrics) Register() error {
	collectors := []prometheus.Collector{
		// DHCP metrics
		m.dhcpRequestsTotal,
		m.dhcpLatencySeconds,
		m.dhcpCacheHitRate,
		m.dhcpActiveLeases,
		// eBPF metrics
		m.ebpfFastpathHits,
		m.ebpfFastpathMisses,
		m.ebpfErrors,
		m.ebpfCacheExpired,
		m.ebpfMapEntries,
		// Pool metrics
		m.poolUtilization,
		m.poolAvailable,
		m.poolAllocated,
		// Session metrics
		m.sessionActive,
		m.sessionTotal,
		m.sessionDuration,
		m.sessionBytesIn,
		m.sessionBytesOut,
		// NAT metrics
		m.natBindingsActive,
		m.natTranslations,
		m.natPortsUsed,
		// RADIUS metrics
		m.radiusRequests,
		m.radiusLatency,
		m.radiusTimeouts,
		// QoS metrics
		m.qosPoliciesActive,
		m.qosPacketsDropped,
		m.qosBytesDropped,
		// PPPoE metrics
		m.pppoeSessionsActive,
		m.pppoeNegotiations,
		// Routing metrics
		m.routesActive,
		m.bgpPeersUp,
		m.bgpPrefixesReceived,
		// Subscriber metrics
		m.subscriberTotal,
		m.subscriberByClass,
		m.subscriberByISP,
	}

	for _, c := range collectors {
		if err := prometheus.Register(c); err != nil {
			// Ignore already registered errors
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				return err
			}
		}
	}

	return nil
}

// --- Metric update methods ---

// RecordSessionCreated records a new session being created.
func (m *Metrics) RecordSessionCreated(sessionType, ispID string) {
	m.sessionTotal.WithLabelValues(sessionType, "created").Inc()
}

// RecordSessionTerminated records a session being terminated.
func (m *Metrics) RecordSessionTerminated(sessionType, ispID string, duration float64, bytesIn, bytesOut uint64) {
	m.sessionTotal.WithLabelValues(sessionType, "terminated").Inc()
	m.sessionDuration.WithLabelValues(sessionType).Observe(duration)
	m.sessionBytesIn.WithLabelValues(sessionType, ispID).Add(float64(bytesIn))
	m.sessionBytesOut.WithLabelValues(sessionType, ispID).Add(float64(bytesOut))
}

// SetActiveSessions sets the count of active sessions by type and state.
func (m *Metrics) SetActiveSessions(sessionType, state string, count int) {
	m.sessionActive.WithLabelValues(sessionType, state).Set(float64(count))
}

// RecordNATTranslation records a NAT translation.
func (m *Metrics) RecordNATTranslation(direction, protocol string) {
	m.natTranslations.WithLabelValues(direction, protocol).Inc()
}

// SetNATBindings sets the count of active NAT bindings.
func (m *Metrics) SetNATBindings(count int) {
	m.natBindingsActive.Set(float64(count))
}

// SetNATPortsUsed sets the count of NAT ports used per public IP.
func (m *Metrics) SetNATPortsUsed(publicIP string, count int) {
	m.natPortsUsed.WithLabelValues(publicIP).Set(float64(count))
}

// RecordRADIUSRequest records a RADIUS request.
func (m *Metrics) RecordRADIUSRequest(reqType, result, server string, latencySeconds float64) {
	m.radiusRequests.WithLabelValues(reqType, result, server).Inc()
	m.radiusLatency.WithLabelValues(reqType, server).Observe(latencySeconds)
}

// RecordRADIUSTimeout records a RADIUS timeout.
func (m *Metrics) RecordRADIUSTimeout(server string) {
	m.radiusTimeouts.WithLabelValues(server).Inc()
}

// SetQoSPoliciesActive sets the count of active QoS policies.
func (m *Metrics) SetQoSPoliciesActive(count int) {
	m.qosPoliciesActive.Set(float64(count))
}

// RecordQoSDropped records dropped packets/bytes by QoS.
func (m *Metrics) RecordQoSDropped(policyID, direction string, packets, bytes uint64) {
	m.qosPacketsDropped.WithLabelValues(policyID, direction).Add(float64(packets))
	m.qosBytesDropped.WithLabelValues(policyID, direction).Add(float64(bytes))
}

// SetPPPoESessions sets the count of active PPPoE sessions.
func (m *Metrics) SetPPPoESessions(count int) {
	m.pppoeSessionsActive.Set(float64(count))
}

// RecordPPPoENegotiation records a PPPoE negotiation.
func (m *Metrics) RecordPPPoENegotiation(stage, result string) {
	m.pppoeNegotiations.WithLabelValues(stage, result).Inc()
}

// SetRoutesActive sets the count of active routes per table.
func (m *Metrics) SetRoutesActive(table string, count int) {
	m.routesActive.WithLabelValues(table).Set(float64(count))
}

// SetBGPPeersUp sets the count of BGP peers in established state.
func (m *Metrics) SetBGPPeersUp(count int) {
	m.bgpPeersUp.Set(float64(count))
}

// SetBGPPrefixes sets the count of prefixes received from a BGP peer.
func (m *Metrics) SetBGPPrefixes(peerIP, afi string, count int) {
	m.bgpPrefixesReceived.WithLabelValues(peerIP, afi).Set(float64(count))
}

// SetSubscriberCount sets subscriber counts.
func (m *Metrics) SetSubscriberCount(total int, byClass map[string]int, byISP map[string]int) {
	m.subscriberTotal.Set(float64(total))
	for class, count := range byClass {
		m.subscriberByClass.WithLabelValues(class).Set(float64(count))
	}
	for ispID, count := range byISP {
		m.subscriberByISP.WithLabelValues(ispID).Set(float64(count))
	}
}

// Handler returns the Prometheus HTTP handler
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

// Collect updates metrics from eBPF and DHCP server
func (m *Metrics) Collect() {
	// Collect eBPF stats
	if m.loader != nil {
		stats, err := m.loader.GetStats()
		if err == nil {
			// Update counters (using Add since we're tracking deltas)
			m.updateEBPFStats(stats)

			// Calculate cache hit rate
			total := float64(stats.FastpathHits + stats.FastpathMisses)
			if total > 0 {
				m.dhcpCacheHitRate.Set(float64(stats.FastpathHits) / total)
			}
		}
	}

	// Collect pool stats
	if m.poolMgr != nil {
		for _, ps := range m.poolMgr.AllStats() {
			poolID := fmt.Sprintf("%d", ps.ID)

			if ps.Total > 0 {
				m.poolUtilization.WithLabelValues(poolID, ps.Name).Set(
					float64(ps.Allocated) / float64(ps.Total),
				)
			}
			m.poolAvailable.WithLabelValues(poolID, ps.Name).Set(float64(ps.Available))
			m.poolAllocated.WithLabelValues(poolID, ps.Name).Set(float64(ps.Allocated))
		}
	}

	// Collect DHCP server stats
	if m.server != nil {
		m.dhcpActiveLeases.Set(float64(m.server.ActiveLeases()))
	}
}

// lastStats stores the last eBPF stats for delta calculation
var lastStats *ebpf.DHCPStats

// updateEBPFStats updates eBPF-related metrics
func (m *Metrics) updateEBPFStats(stats *ebpf.DHCPStats) {
	if lastStats == nil {
		lastStats = &ebpf.DHCPStats{}
	}

	// Calculate deltas and add to counters
	if delta := stats.FastpathHits - lastStats.FastpathHits; delta > 0 {
		m.ebpfFastpathHits.Add(float64(delta))
	}
	if delta := stats.FastpathMisses - lastStats.FastpathMisses; delta > 0 {
		m.ebpfFastpathMisses.Add(float64(delta))
	}
	if delta := stats.Errors - lastStats.Errors; delta > 0 {
		m.ebpfErrors.Add(float64(delta))
	}
	if delta := stats.CacheExpired - lastStats.CacheExpired; delta > 0 {
		m.ebpfCacheExpired.Add(float64(delta))
	}

	*lastStats = *stats
}

// StartCollector starts a background goroutine that collects metrics
func (m *Metrics) StartCollector(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			m.Collect()
		}
	}
}
