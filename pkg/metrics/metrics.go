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
	}

	return m
}

// Register registers all metrics with Prometheus
func (m *Metrics) Register() error {
	collectors := []prometheus.Collector{
		m.dhcpRequestsTotal,
		m.dhcpLatencySeconds,
		m.dhcpCacheHitRate,
		m.dhcpActiveLeases,
		m.ebpfFastpathHits,
		m.ebpfFastpathMisses,
		m.ebpfErrors,
		m.ebpfCacheExpired,
		m.poolUtilization,
		m.poolAvailable,
		m.poolAllocated,
		m.ebpfMapEntries,
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
