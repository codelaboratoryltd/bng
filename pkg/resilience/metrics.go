package resilience

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for resilience monitoring.
type Metrics struct {
	// Partition state metrics
	partitionState     *prometheus.GaugeVec
	partitionDuration  prometheus.Gauge
	partitionsTotal    prometheus.Counter
	partitionTimeTotal prometheus.Counter
	lastPartitionTime  prometheus.Gauge

	// Pool utilization metrics
	poolUtilization        *prometheus.GaugeVec
	poolLevel              *prometheus.GaugeVec
	poolWarningsTotal      *prometheus.CounterVec
	poolCriticalsTotal     *prometheus.CounterVec
	poolExhaustionsTotal   *prometheus.CounterVec
	shortLeasesActive      *prometheus.GaugeVec
	shortLeasesIssuedTotal prometheus.Counter

	// Request queue metrics
	queueLength        prometheus.Gauge
	queuedTotal        prometheus.Counter
	dequeuedTotal      prometheus.Counter
	expiredTotal       prometheus.Counter
	queueHighWaterMark prometheus.Gauge

	// Conflict detection metrics
	conflictsDetected    prometheus.Counter
	conflictsResolved    prometheus.Counter
	conflictsPending     prometheus.Gauge
	localWinsTotal       prometheus.Counter
	remoteWinsTotal      prometheus.Counter
	partitionAllocations prometheus.Gauge

	// RADIUS resilience metrics
	degradedAuthsIssued prometheus.Counter
	cachedProfilesTotal prometheus.Gauge
	reauthQueueLength   prometheus.Gauge
	reauthsCompleted    prometheus.Counter
	reauthsFailed       prometheus.Counter
	acctBufferLength    prometheus.Gauge
	acctRecordsBuffered prometheus.Counter
	acctRecordsSynced   prometheus.Counter
	acctRecordsDropped  prometheus.Counter

	// References
	manager *Manager

	// Previous counter values for delta calculation
	prevCounterValues map[prometheus.Counter]float64
}

// NewMetrics creates new resilience metrics.
func NewMetrics(manager *Manager) *Metrics {
	m := &Metrics{
		manager:           manager,
		prevCounterValues: make(map[prometheus.Counter]float64),

		partitionState: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_resilience_partition_state",
				Help: "Current partition state (0=online, 1=partitioned, 2=recovering)",
			},
			[]string{"state"},
		),

		partitionDuration: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_resilience_partition_duration_seconds",
				Help: "Duration of current partition in seconds (0 if online)",
			},
		),

		partitionsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_partitions_total",
				Help: "Total number of network partitions",
			},
		),

		partitionTimeTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_partition_time_seconds_total",
				Help: "Total time spent in partitioned state",
			},
		),

		lastPartitionTime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_resilience_last_partition_timestamp",
				Help: "Timestamp of last partition (unix seconds)",
			},
		),

		poolUtilization: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_resilience_pool_utilization_ratio",
				Help: "Pool utilization ratio (0-1)",
			},
			[]string{"pool_id", "pool_name"},
		),

		poolLevel: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_resilience_pool_level",
				Help: "Pool utilization level (0=normal, 1=warning, 2=critical, 3=exhausted)",
			},
			[]string{"pool_id", "pool_name"},
		),

		poolWarningsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_resilience_pool_warnings_total",
				Help: "Total pool warning alerts",
			},
			[]string{"pool_id"},
		),

		poolCriticalsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_resilience_pool_criticals_total",
				Help: "Total pool critical alerts",
			},
			[]string{"pool_id"},
		),

		poolExhaustionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bng_resilience_pool_exhaustions_total",
				Help: "Total pool exhaustion alerts",
			},
			[]string{"pool_id"},
		),

		shortLeasesActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bng_resilience_short_leases_active",
				Help: "Whether short lease mode is active for pool (0 or 1)",
			},
			[]string{"pool_id"},
		),

		shortLeasesIssuedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_short_leases_issued_total",
				Help: "Total short leases issued",
			},
		),

		queueLength: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_resilience_queue_length",
				Help: "Current number of queued requests",
			},
		),

		queuedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_requests_queued_total",
				Help: "Total requests queued during partition",
			},
		),

		dequeuedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_requests_dequeued_total",
				Help: "Total requests dequeued and processed",
			},
		),

		expiredTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_requests_expired_total",
				Help: "Total requests expired from queue",
			},
		),

		queueHighWaterMark: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_resilience_queue_high_water_mark",
				Help: "Maximum queue length reached",
			},
		),

		conflictsDetected: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_conflicts_detected_total",
				Help: "Total IP allocation conflicts detected",
			},
		),

		conflictsResolved: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_conflicts_resolved_total",
				Help: "Total IP allocation conflicts resolved",
			},
		),

		conflictsPending: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_resilience_conflicts_pending",
				Help: "Current number of unresolved conflicts",
			},
		),

		localWinsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_conflicts_local_wins_total",
				Help: "Total conflicts resolved with local allocation winning",
			},
		),

		remoteWinsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_conflicts_remote_wins_total",
				Help: "Total conflicts resolved with remote allocation winning",
			},
		),

		partitionAllocations: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_resilience_partition_allocations",
				Help: "Current number of allocations made during partition",
			},
		),

		degradedAuthsIssued: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_degraded_auths_total",
				Help: "Total degraded mode authentications issued",
			},
		),

		cachedProfilesTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_resilience_cached_profiles",
				Help: "Current number of cached subscriber profiles",
			},
		),

		reauthQueueLength: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_resilience_reauth_queue_length",
				Help: "Current number of sessions queued for re-authentication",
			},
		),

		reauthsCompleted: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_reauths_completed_total",
				Help: "Total re-authentications completed",
			},
		),

		reauthsFailed: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_reauths_failed_total",
				Help: "Total re-authentications failed",
			},
		),

		acctBufferLength: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bng_resilience_acct_buffer_length",
				Help: "Current number of buffered accounting records",
			},
		),

		acctRecordsBuffered: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_acct_records_buffered_total",
				Help: "Total accounting records buffered during partition",
			},
		),

		acctRecordsSynced: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_acct_records_synced_total",
				Help: "Total buffered accounting records synced",
			},
		),

		acctRecordsDropped: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bng_resilience_acct_records_dropped_total",
				Help: "Total accounting records dropped (buffer full or too many retries)",
			},
		),
	}

	return m
}

// Register registers all metrics with Prometheus.
func (m *Metrics) Register() error {
	collectors := []prometheus.Collector{
		m.partitionState,
		m.partitionDuration,
		m.partitionsTotal,
		m.partitionTimeTotal,
		m.lastPartitionTime,
		m.poolUtilization,
		m.poolLevel,
		m.poolWarningsTotal,
		m.poolCriticalsTotal,
		m.poolExhaustionsTotal,
		m.shortLeasesActive,
		m.shortLeasesIssuedTotal,
		m.queueLength,
		m.queuedTotal,
		m.dequeuedTotal,
		m.expiredTotal,
		m.queueHighWaterMark,
		m.conflictsDetected,
		m.conflictsResolved,
		m.conflictsPending,
		m.localWinsTotal,
		m.remoteWinsTotal,
		m.partitionAllocations,
		m.degradedAuthsIssued,
		m.cachedProfilesTotal,
		m.reauthQueueLength,
		m.reauthsCompleted,
		m.reauthsFailed,
		m.acctBufferLength,
		m.acctRecordsBuffered,
		m.acctRecordsSynced,
		m.acctRecordsDropped,
	}

	for _, c := range collectors {
		if err := prometheus.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				return err
			}
		}
	}

	return nil
}

// Collect updates all metrics from the manager.
func (m *Metrics) Collect() {
	if m.manager == nil {
		return
	}

	// Update partition state
	state := m.manager.State()
	m.partitionState.Reset()
	m.partitionState.WithLabelValues(state.String()).Set(1)

	// Update partition duration
	m.partitionDuration.Set(m.manager.PartitionDuration().Seconds())

	// Get stats from manager
	stats := m.manager.Stats()

	// Update partition counters and track the new values
	partitionsValue := float64(stats.TotalPartitions)
	m.partitionsTotal.Add(partitionsValue - m.getCounterValue(m.partitionsTotal))
	m.updateCounterValue(m.partitionsTotal, partitionsValue)

	partitionTimeValue := stats.TotalPartitionTime.Seconds()
	m.partitionTimeTotal.Add(partitionTimeValue - m.getCounterValue(m.partitionTimeTotal))
	m.updateCounterValue(m.partitionTimeTotal, partitionTimeValue)

	if !stats.LastPartitionTime.IsZero() {
		m.lastPartitionTime.Set(float64(stats.LastPartitionTime.Unix()))
	}

	// Update pool metrics
	poolStatuses := m.manager.PoolMonitor().GetAllPoolStatuses()
	for _, pool := range poolStatuses {
		m.poolUtilization.WithLabelValues(pool.PoolID, pool.PoolName).Set(pool.Utilization)
		m.poolLevel.WithLabelValues(pool.PoolID, pool.PoolName).Set(float64(pool.Level))

		shortLeaseVal := 0.0
		if pool.ShortLeaseActive {
			shortLeaseVal = 1.0
		}
		m.shortLeasesActive.WithLabelValues(pool.PoolID).Set(shortLeaseVal)
	}

	// Update queue metrics
	enqueued, dequeued, expired, current := m.manager.requestQueue.Stats()
	m.queueLength.Set(float64(current))

	enqueuedValue := float64(enqueued)
	m.queuedTotal.Add(enqueuedValue - m.getCounterValue(m.queuedTotal))
	m.updateCounterValue(m.queuedTotal, enqueuedValue)

	dequeuedValue := float64(dequeued)
	m.dequeuedTotal.Add(dequeuedValue - m.getCounterValue(m.dequeuedTotal))
	m.updateCounterValue(m.dequeuedTotal, dequeuedValue)

	expiredValue := float64(expired)
	m.expiredTotal.Add(expiredValue - m.getCounterValue(m.expiredTotal))
	m.updateCounterValue(m.expiredTotal, expiredValue)

	m.queueHighWaterMark.Set(float64(stats.QueueHighWaterMark))

	// Update conflict metrics
	_, partitionCount, conflictCount := m.manager.ConflictDetector().Stats()

	conflictsDetectedValue := float64(stats.ConflictsDetected)
	m.conflictsDetected.Add(conflictsDetectedValue - m.getCounterValue(m.conflictsDetected))
	m.updateCounterValue(m.conflictsDetected, conflictsDetectedValue)

	conflictsResolvedValue := float64(stats.ConflictsResolved)
	m.conflictsResolved.Add(conflictsResolvedValue - m.getCounterValue(m.conflictsResolved))
	m.updateCounterValue(m.conflictsResolved, conflictsResolvedValue)

	m.conflictsPending.Set(float64(len(m.manager.ConflictDetector().GetUnresolvedConflicts())))

	localWinsValue := float64(stats.LocalWins)
	m.localWinsTotal.Add(localWinsValue - m.getCounterValue(m.localWinsTotal))
	m.updateCounterValue(m.localWinsTotal, localWinsValue)

	remoteWinsValue := float64(stats.RemoteWins)
	m.remoteWinsTotal.Add(remoteWinsValue - m.getCounterValue(m.remoteWinsTotal))
	m.updateCounterValue(m.remoteWinsTotal, remoteWinsValue)

	m.partitionAllocations.Set(float64(partitionCount))
	_ = conflictCount // Already tracked via stats

	// Update RADIUS metrics
	degradedAuths, reauthsCompleted, reauthsFailed,
		acctBuffered, acctSynced, acctDropped := m.manager.RADIUSHandler().Stats()

	degradedAuthsValue := float64(degradedAuths)
	m.degradedAuthsIssued.Add(degradedAuthsValue - m.getCounterValue(m.degradedAuthsIssued))
	m.updateCounterValue(m.degradedAuthsIssued, degradedAuthsValue)

	m.cachedProfilesTotal.Set(float64(m.manager.RADIUSHandler().GetCachedProfileCount()))
	m.reauthQueueLength.Set(float64(m.manager.RADIUSHandler().GetReauthQueueLength()))

	reauthsCompletedValue := float64(reauthsCompleted)
	m.reauthsCompleted.Add(reauthsCompletedValue - m.getCounterValue(m.reauthsCompleted))
	m.updateCounterValue(m.reauthsCompleted, reauthsCompletedValue)

	reauthsFailedValue := float64(reauthsFailed)
	m.reauthsFailed.Add(reauthsFailedValue - m.getCounterValue(m.reauthsFailed))
	m.updateCounterValue(m.reauthsFailed, reauthsFailedValue)

	m.acctBufferLength.Set(float64(m.manager.RADIUSHandler().GetBufferedAccountingCount()))

	acctBufferedValue := float64(acctBuffered)
	m.acctRecordsBuffered.Add(acctBufferedValue - m.getCounterValue(m.acctRecordsBuffered))
	m.updateCounterValue(m.acctRecordsBuffered, acctBufferedValue)

	acctSyncedValue := float64(acctSynced)
	m.acctRecordsSynced.Add(acctSyncedValue - m.getCounterValue(m.acctRecordsSynced))
	m.updateCounterValue(m.acctRecordsSynced, acctSyncedValue)

	acctDroppedValue := float64(acctDropped)
	m.acctRecordsDropped.Add(acctDroppedValue - m.getCounterValue(m.acctRecordsDropped))
	m.updateCounterValue(m.acctRecordsDropped, acctDroppedValue)

	// Update short leases
	shortLeasesValue := float64(stats.ShortLeasesIssued)
	m.shortLeasesIssuedTotal.Add(shortLeasesValue - m.getCounterValue(m.shortLeasesIssuedTotal))
	m.updateCounterValue(m.shortLeasesIssuedTotal, shortLeasesValue)
}

// getCounterValue gets the previously recorded value of a counter for delta calculation.
// This allows us to compute the delta between the current stat value and what we've
// already added to the Prometheus counter.
func (m *Metrics) getCounterValue(c prometheus.Counter) float64 {
	if val, ok := m.prevCounterValues[c]; ok {
		return val
	}
	return 0
}

// updateCounterValue updates the tracked previous value for a counter after adding a delta.
func (m *Metrics) updateCounterValue(c prometheus.Counter, newValue float64) {
	m.prevCounterValues[c] = newValue
}

// RecordPoolAlert records a pool alert.
func (m *Metrics) RecordPoolAlert(poolID string, level PoolUtilizationLevel) {
	switch level {
	case LevelWarning:
		m.poolWarningsTotal.WithLabelValues(poolID).Inc()
	case LevelCritical:
		m.poolCriticalsTotal.WithLabelValues(poolID).Inc()
	case LevelExhausted:
		m.poolExhaustionsTotal.WithLabelValues(poolID).Inc()
	}
}

// StartCollector starts background metrics collection.
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
