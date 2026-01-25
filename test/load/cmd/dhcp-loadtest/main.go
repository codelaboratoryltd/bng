// Command dhcp-loadtest runs DHCP load tests against a BNG DHCP server.
//
// Usage:
//
//	dhcp-loadtest -target 192.168.1.1:67 -duration 60s -concurrency 100
//
// This tool validates DHCP performance against the project targets:
//   - 50,000+ DHCP requests/sec total throughput
//   - <100us P99 latency for fast path (eBPF)
//   - <10ms P99 latency for slow path (Go userspace)
//   - >95% cache hit rate
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/codelaboratoryltd/bng/test/load"
)

func main() {
	// Parse flags
	target := flag.String("target", "127.0.0.1:67", "DHCP server address (host:port)")
	iface := flag.String("interface", "lo", "Network interface to use")
	concurrency := flag.Int("concurrency", 100, "Number of concurrent workers")
	duration := flag.Duration("duration", 30*time.Second, "Test duration")
	rps := flag.Int("rps", 0, "Target requests per second (0 = unlimited)")
	macs := flag.Int("macs", 10000, "Number of unique MAC addresses")
	warmup := flag.Duration("warmup", 5*time.Second, "Warmup duration")
	renewals := flag.Bool("renewals", true, "Enable DHCP renewal testing")
	renewalRatio := flag.Float64("renewal-ratio", 0.8, "Ratio of renewals vs new requests (0.0-1.0)")
	jsonOutput := flag.Bool("json", false, "Output results as JSON")
	validateTargets := flag.Bool("validate", false, "Exit with non-zero if targets not met")

	flag.Parse()

	// Build config
	cfg := &load.BenchmarkConfig{
		Target:            *target,
		Interface:         *iface,
		Concurrency:       *concurrency,
		Duration:          *duration,
		RequestsPerSecond: *rps,
		UniqueMACs:        *macs,
		WarmupDuration:    *warmup,
		EnableRenewals:    *renewals,
		RenewalRatio:      *renewalRatio,
	}

	// Create benchmark
	benchmark := load.NewBenchmark(cfg, nil)

	// Handle interrupt
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping benchmark...")
		cancel()
	}()

	// Run benchmark
	fmt.Println("Starting DHCP Load Test")
	fmt.Printf("Target: %s\n", cfg.Target)
	fmt.Printf("Duration: %s (+ %s warmup)\n", cfg.Duration, cfg.WarmupDuration)
	fmt.Printf("Concurrency: %d workers\n", cfg.Concurrency)
	fmt.Printf("Unique MACs: %d\n", cfg.UniqueMACs)
	fmt.Println()

	result, err := benchmark.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Benchmark failed: %v\n", err)
		os.Exit(1)
	}

	// Output results
	if *jsonOutput {
		printJSON(result)
	} else {
		result.PrintReport()
	}

	// Validate targets if requested
	if *validateTargets {
		if !result.MeetsTargets() {
			fmt.Println("\nWARNING: Performance targets not met!")
			os.Exit(1)
		}
		fmt.Println("\nAll performance targets met!")
	}
}

func printJSON(result *load.BenchmarkResult) {
	fmt.Printf(`{
  "duration_seconds": %.2f,
  "requests": %d,
  "responses": %d,
  "errors": %d,
  "timeouts": %d,
  "requests_per_second": %.2f,
  "latency": {
    "min_us": %.2f,
    "avg_us": %.2f,
    "p50_us": %.2f,
    "p95_us": %.2f,
    "p99_us": %.2f,
    "max_us": %.2f
  },
  "fast_path_hits": %d,
  "slow_path_hits": %d,
  "cache_hit_rate": %.4f,
  "targets": {
    "rps_met": %t,
    "latency_met": %t,
    "cache_hit_met": %t,
    "all_met": %t
  }
}
`,
		result.Duration.Seconds(),
		result.Requests,
		result.Responses,
		result.Errors,
		result.Timeouts,
		result.RequestsPerSecond,
		float64(result.LatencyMin.Microseconds()),
		float64(result.LatencyAvg.Microseconds()),
		float64(result.LatencyP50.Microseconds()),
		float64(result.LatencyP95.Microseconds()),
		float64(result.LatencyP99.Microseconds()),
		float64(result.LatencyMax.Microseconds()),
		result.FastPathHits,
		result.SlowPathHits,
		result.CacheHitRate,
		result.RequestsPerSecond >= 50000,
		result.LatencyP99 < 10*time.Millisecond,
		result.CacheHitRate >= 0.95,
		result.MeetsTargets(),
	)
}
