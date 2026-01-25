// Package load provides load testing utilities for BNG DHCP performance validation.
//
// This package implements a comprehensive load testing framework for validating
// DHCP performance against the project targets:
//   - 50,000+ DHCP requests/sec total throughput
//   - <100us P99 latency for fast path (eBPF)
//   - <10ms P99 latency for slow path (Go userspace)
//   - >95% cache hit rate
package load

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// BenchmarkConfig configures the DHCP load test
type BenchmarkConfig struct {
	// Target is the DHCP server address (e.g., "192.168.1.1:67")
	Target string

	// Interface is the network interface to use for sending packets
	Interface string

	// Concurrency is the number of concurrent workers
	Concurrency int

	// Duration is how long to run the test
	Duration time.Duration

	// RequestsPerSecond is the target RPS (0 for unlimited)
	RequestsPerSecond int

	// UniqueMACs is the number of unique MAC addresses to use
	// Higher values test slow path more, lower values test cache hits
	UniqueMACs int

	// WarmupDuration is the time to warm up before measuring
	WarmupDuration time.Duration

	// EnableRenewals enables DHCP RENEW testing after initial allocation
	EnableRenewals bool

	// RenewalRatio is the percentage of requests that are renewals (0.0-1.0)
	RenewalRatio float64
}

// DefaultConfig returns a default benchmark configuration
func DefaultConfig() *BenchmarkConfig {
	return &BenchmarkConfig{
		Target:            "127.0.0.1:67",
		Interface:         "lo",
		Concurrency:       100,
		Duration:          30 * time.Second,
		RequestsPerSecond: 0, // Unlimited
		UniqueMACs:        10000,
		WarmupDuration:    5 * time.Second,
		EnableRenewals:    true,
		RenewalRatio:      0.8, // 80% renewals after warmup
	}
}

// BenchmarkResult contains the results of a DHCP load test
type BenchmarkResult struct {
	// Test parameters
	Config *BenchmarkConfig

	// Duration is the actual test duration (excluding warmup)
	Duration time.Duration

	// Requests is the total number of requests sent
	Requests uint64

	// Responses is the total number of responses received
	Responses uint64

	// Errors is the count of errors
	Errors uint64

	// Timeouts is the count of timeouts
	Timeouts uint64

	// RequestsPerSecond is the achieved RPS
	RequestsPerSecond float64

	// Latencies contains all measured latencies
	Latencies []time.Duration

	// LatencyP50 is the median latency
	LatencyP50 time.Duration

	// LatencyP95 is the 95th percentile latency
	LatencyP95 time.Duration

	// LatencyP99 is the 99th percentile latency
	LatencyP99 time.Duration

	// LatencyMax is the maximum latency
	LatencyMax time.Duration

	// LatencyMin is the minimum latency
	LatencyMin time.Duration

	// LatencyAvg is the average latency
	LatencyAvg time.Duration

	// FastPathHits is the estimated fast path hits (latency < 1ms)
	FastPathHits uint64

	// SlowPathHits is the estimated slow path hits (latency >= 1ms)
	SlowPathHits uint64

	// CacheHitRate is the estimated cache hit rate (fast path / total)
	CacheHitRate float64
}

// Benchmark runs a DHCP load test
type Benchmark struct {
	config *BenchmarkConfig
	logger Logger

	// Statistics
	requests  uint64
	responses uint64
	errors    uint64
	timeouts  uint64

	// Latency tracking
	latencies   []time.Duration
	latenciesMu sync.Mutex

	// MAC address pool
	macPool []net.HardwareAddr

	// Active leases for renewal testing
	leases   map[string]net.IP // MAC string -> allocated IP
	leasesMu sync.RWMutex

	// Control
	stopCh chan struct{}
}

// Logger interface for benchmark logging
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// DefaultLogger is a simple stdout logger
type DefaultLogger struct{}

func (l *DefaultLogger) Info(msg string, args ...interface{}) {
	fmt.Printf("[INFO] "+msg+"\n", args...)
}
func (l *DefaultLogger) Error(msg string, args ...interface{}) {
	fmt.Printf("[ERROR] "+msg+"\n", args...)
}
func (l *DefaultLogger) Debug(msg string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+msg+"\n", args...)
}

// NewBenchmark creates a new DHCP benchmark
func NewBenchmark(config *BenchmarkConfig, logger Logger) *Benchmark {
	if logger == nil {
		logger = &DefaultLogger{}
	}
	if config == nil {
		config = DefaultConfig()
	}

	b := &Benchmark{
		config:  config,
		logger:  logger,
		macPool: generateMACs(config.UniqueMACs),
		leases:  make(map[string]net.IP),
		stopCh:  make(chan struct{}),
	}

	return b
}

// generateMACs generates a pool of unique MAC addresses
func generateMACs(count int) []net.HardwareAddr {
	macs := make([]net.HardwareAddr, count)
	for i := 0; i < count; i++ {
		mac := make(net.HardwareAddr, 6)
		// Use locally administered unicast MAC (bit 1 of first octet = 1)
		mac[0] = 0x02 // Locally administered
		mac[1] = byte(i >> 24)
		mac[2] = byte(i >> 16)
		mac[3] = byte(i >> 8)
		mac[4] = byte(i)
		mac[5] = byte(rand.Intn(256))
		macs[i] = mac
	}
	return macs
}

// Run executes the benchmark
func (b *Benchmark) Run(ctx context.Context) (*BenchmarkResult, error) {
	b.logger.Info("Starting DHCP benchmark with %d concurrent workers", b.config.Concurrency)
	b.logger.Info("Target: %s, Duration: %s, Unique MACs: %d",
		b.config.Target, b.config.Duration, b.config.UniqueMACs)

	// Parse target address
	targetAddr, err := net.ResolveUDPAddr("udp4", b.config.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, b.config.Duration+b.config.WarmupDuration+time.Minute)
	defer cancel()

	// Reset counters
	atomic.StoreUint64(&b.requests, 0)
	atomic.StoreUint64(&b.responses, 0)
	atomic.StoreUint64(&b.errors, 0)
	atomic.StoreUint64(&b.timeouts, 0)
	b.latencies = make([]time.Duration, 0, 100000)

	// Start workers
	var wg sync.WaitGroup
	workerCtx, workerCancel := context.WithCancel(ctx)

	// Rate limiter if configured
	var rateLimiter <-chan time.Time
	if b.config.RequestsPerSecond > 0 {
		interval := time.Second / time.Duration(b.config.RequestsPerSecond/b.config.Concurrency)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	// Start workers
	for i := 0; i < b.config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			b.worker(workerCtx, workerID, targetAddr, rateLimiter)
		}(i)
	}

	// Warmup phase
	if b.config.WarmupDuration > 0 {
		b.logger.Info("Warmup phase: %s", b.config.WarmupDuration)
		select {
		case <-time.After(b.config.WarmupDuration):
		case <-ctx.Done():
			workerCancel()
			wg.Wait()
			return nil, ctx.Err()
		}
		// Reset counters after warmup
		atomic.StoreUint64(&b.requests, 0)
		atomic.StoreUint64(&b.responses, 0)
		atomic.StoreUint64(&b.errors, 0)
		atomic.StoreUint64(&b.timeouts, 0)
		b.latenciesMu.Lock()
		b.latencies = make([]time.Duration, 0, 100000)
		b.latenciesMu.Unlock()
		b.logger.Info("Warmup complete, starting measurement phase")
	}

	// Measurement phase
	startTime := time.Now()
	select {
	case <-time.After(b.config.Duration):
	case <-ctx.Done():
	}

	// Stop workers
	workerCancel()
	wg.Wait()

	duration := time.Since(startTime)

	// Calculate results
	result := b.calculateResults(duration)
	return result, nil
}

// worker runs a single benchmark worker
func (b *Benchmark) worker(ctx context.Context, id int, target *net.UDPAddr, rateLimiter <-chan time.Time) {
	// Create UDP connection
	conn, err := net.DialUDP("udp4", nil, target)
	if err != nil {
		b.logger.Error("Worker %d failed to connect: %v", id, err)
		return
	}
	defer conn.Close()

	// Set timeouts
	conn.SetDeadline(time.Now().Add(time.Second))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Rate limiting
		if rateLimiter != nil {
			select {
			case <-rateLimiter:
			case <-ctx.Done():
				return
			}
		}

		// Select a random MAC
		mac := b.macPool[rand.Intn(len(b.macPool))]

		// Decide if this is a renewal or new request
		isRenewal := false
		var existingIP net.IP
		if b.config.EnableRenewals && rand.Float64() < b.config.RenewalRatio {
			b.leasesMu.RLock()
			if ip, ok := b.leases[mac.String()]; ok {
				isRenewal = true
				existingIP = ip
			}
			b.leasesMu.RUnlock()
		}

		// Send request and measure latency
		start := time.Now()
		var respIP net.IP
		var sendErr error

		if isRenewal {
			respIP, sendErr = b.sendRenewal(conn, mac, existingIP, target)
		} else {
			respIP, sendErr = b.sendDiscover(conn, mac, target)
		}

		latency := time.Since(start)

		atomic.AddUint64(&b.requests, 1)

		if sendErr != nil {
			if isTimeout(sendErr) {
				atomic.AddUint64(&b.timeouts, 1)
			} else {
				atomic.AddUint64(&b.errors, 1)
			}
			continue
		}

		atomic.AddUint64(&b.responses, 1)

		// Record latency
		b.latenciesMu.Lock()
		b.latencies = append(b.latencies, latency)
		b.latenciesMu.Unlock()

		// Store lease for future renewals
		if respIP != nil && !isRenewal {
			b.leasesMu.Lock()
			b.leases[mac.String()] = respIP
			b.leasesMu.Unlock()
		}

		// Reset deadline for next request
		conn.SetDeadline(time.Now().Add(time.Second))
	}
}

// sendDiscover sends a DHCP DISCOVER and waits for OFFER
func (b *Benchmark) sendDiscover(conn *net.UDPConn, mac net.HardwareAddr, _ *net.UDPAddr) (net.IP, error) {
	// Build DISCOVER packet
	discover, err := dhcpv4.NewDiscovery(mac)
	if err != nil {
		return nil, fmt.Errorf("failed to create DISCOVER: %w", err)
	}

	// Send
	if _, err := conn.Write(discover.ToBytes()); err != nil {
		return nil, fmt.Errorf("failed to send DISCOVER: %w", err)
	}

	// Wait for OFFER
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	offer, err := dhcpv4.FromBytes(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to parse OFFER: %w", err)
	}

	if offer.MessageType() != dhcpv4.MessageTypeOffer {
		return nil, fmt.Errorf("expected OFFER, got %s", offer.MessageType())
	}

	return offer.YourIPAddr, nil
}

// sendRenewal sends a DHCP REQUEST (renewal) and waits for ACK
func (b *Benchmark) sendRenewal(conn *net.UDPConn, mac net.HardwareAddr, existingIP net.IP, _ *net.UDPAddr) (net.IP, error) {
	// Build REQUEST packet (renewal)
	request, err := dhcpv4.New(
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithClientIP(existingIP),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(existingIP)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create REQUEST: %w", err)
	}

	// Send
	if _, err := conn.Write(request.ToBytes()); err != nil {
		return nil, fmt.Errorf("failed to send REQUEST: %w", err)
	}

	// Wait for ACK
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	ack, err := dhcpv4.FromBytes(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ACK: %w", err)
	}

	if ack.MessageType() != dhcpv4.MessageTypeAck {
		return nil, fmt.Errorf("expected ACK, got %s", ack.MessageType())
	}

	return ack.YourIPAddr, nil
}

// calculateResults calculates benchmark results from collected data
func (b *Benchmark) calculateResults(duration time.Duration) *BenchmarkResult {
	requests := atomic.LoadUint64(&b.requests)
	responses := atomic.LoadUint64(&b.responses)
	errors := atomic.LoadUint64(&b.errors)
	timeouts := atomic.LoadUint64(&b.timeouts)

	result := &BenchmarkResult{
		Config:            b.config,
		Duration:          duration,
		Requests:          requests,
		Responses:         responses,
		Errors:            errors,
		Timeouts:          timeouts,
		RequestsPerSecond: float64(requests) / duration.Seconds(),
	}

	// Copy and sort latencies
	b.latenciesMu.Lock()
	latencies := make([]time.Duration, len(b.latencies))
	copy(latencies, b.latencies)
	b.latenciesMu.Unlock()

	if len(latencies) == 0 {
		return result
	}

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	result.Latencies = latencies
	result.LatencyMin = latencies[0]
	result.LatencyMax = latencies[len(latencies)-1]
	result.LatencyP50 = percentile(latencies, 0.50)
	result.LatencyP95 = percentile(latencies, 0.95)
	result.LatencyP99 = percentile(latencies, 0.99)

	// Calculate average
	var total time.Duration
	for _, l := range latencies {
		total += l
	}
	result.LatencyAvg = total / time.Duration(len(latencies))

	// Estimate fast path vs slow path
	// Fast path: <1ms (typically <100us for eBPF)
	// Slow path: >=1ms (Go userspace)
	fastPathThreshold := time.Millisecond
	for _, l := range latencies {
		if l < fastPathThreshold {
			result.FastPathHits++
		} else {
			result.SlowPathHits++
		}
	}

	if responses > 0 {
		result.CacheHitRate = float64(result.FastPathHits) / float64(responses)
	}

	return result
}

// percentile calculates the nth percentile of sorted latencies
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

// isTimeout checks if an error is a timeout
func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// PrintReport prints a human-readable report of the benchmark results
func (r *BenchmarkResult) PrintReport() {
	fmt.Println("=" + "==========================================================")
	fmt.Println("DHCP Load Test Results")
	fmt.Println("=" + "==========================================================")
	fmt.Println()
	fmt.Printf("Test Duration:     %s\n", r.Duration)
	fmt.Printf("Concurrency:       %d workers\n", r.Config.Concurrency)
	fmt.Printf("Unique MACs:       %d\n", r.Config.UniqueMACs)
	fmt.Println()
	fmt.Println("--- Throughput ---")
	fmt.Printf("Total Requests:    %d\n", r.Requests)
	fmt.Printf("Total Responses:   %d\n", r.Responses)
	fmt.Printf("Errors:            %d\n", r.Errors)
	fmt.Printf("Timeouts:          %d\n", r.Timeouts)
	fmt.Printf("Requests/sec:      %.2f\n", r.RequestsPerSecond)
	fmt.Println()
	fmt.Println("--- Latency ---")
	fmt.Printf("Min:               %s\n", r.LatencyMin)
	fmt.Printf("Avg:               %s\n", r.LatencyAvg)
	fmt.Printf("P50 (median):      %s\n", r.LatencyP50)
	fmt.Printf("P95:               %s\n", r.LatencyP95)
	fmt.Printf("P99:               %s\n", r.LatencyP99)
	fmt.Printf("Max:               %s\n", r.LatencyMax)
	fmt.Println()
	fmt.Println("--- Path Analysis ---")
	fmt.Printf("Fast Path (<1ms):  %d (%.2f%%)\n", r.FastPathHits, r.CacheHitRate*100)
	fmt.Printf("Slow Path (>=1ms): %d (%.2f%%)\n", r.SlowPathHits, (1-r.CacheHitRate)*100)
	fmt.Printf("Cache Hit Rate:    %.2f%%\n", r.CacheHitRate*100)
	fmt.Println()
	fmt.Println("--- Target Validation ---")
	passRPS := r.RequestsPerSecond >= 50000
	passP99Fast := r.LatencyP99 < 100*time.Microsecond
	passP99Slow := r.LatencyP99 < 10*time.Millisecond
	passCacheHit := r.CacheHitRate >= 0.95

	fmt.Printf("RPS >= 50,000:     %s (%.2f)\n", passFailStr(passRPS), r.RequestsPerSecond)
	fmt.Printf("P99 < 100us:       %s (%s) [Fast path target]\n", passFailStr(passP99Fast), r.LatencyP99)
	fmt.Printf("P99 < 10ms:        %s (%s) [Slow path target]\n", passFailStr(passP99Slow), r.LatencyP99)
	fmt.Printf("Cache Hit >= 95%%:  %s (%.2f%%)\n", passFailStr(passCacheHit), r.CacheHitRate*100)
	fmt.Println("=" + "==========================================================")
}

func passFailStr(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

// MeetsTargets checks if the results meet performance targets
func (r *BenchmarkResult) MeetsTargets() bool {
	// Target: 50,000+ RPS
	if r.RequestsPerSecond < 50000 {
		return false
	}

	// Target: P99 < 10ms for overall (slow path target)
	if r.LatencyP99 >= 10*time.Millisecond {
		return false
	}

	// Target: >95% cache hit rate
	if r.CacheHitRate < 0.95 {
		return false
	}

	return true
}

// MeetsFastPathTarget checks if fast path meets <100us P99
func (r *BenchmarkResult) MeetsFastPathTarget() bool {
	// Need to analyze only fast path latencies
	var fastLatencies []time.Duration
	for _, l := range r.Latencies {
		if l < time.Millisecond {
			fastLatencies = append(fastLatencies, l)
		}
	}

	if len(fastLatencies) == 0 {
		return false
	}

	sort.Slice(fastLatencies, func(i, j int) bool {
		return fastLatencies[i] < fastLatencies[j]
	})

	p99 := percentile(fastLatencies, 0.99)
	return p99 < 100*time.Microsecond
}
