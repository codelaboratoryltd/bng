package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/codelaboratoryltd/bng/pkg/ebpf"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "bng",
	Short: "eBPF-accelerated Broadband Network Gateway",
	Long: `BNG - High-performance DHCP and subscriber management
using eBPF/XDP for kernel-level packet processing.

Designed for ISP edge deployments with 10-40 Gbps throughput.`,
	Version: fmt.Sprintf("%s (commit: %s)", version, commit),
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start BNG server",
	RunE:  runBNG,
}

var (
	iface      string
	configFile string
	logLevel   string
)

func init() {
	runCmd.Flags().StringVarP(&iface, "interface", "i", "eth1",
		"Network interface for subscriber traffic")
	runCmd.Flags().StringVarP(&configFile, "config", "c", "/etc/bng/config.yaml",
		"Configuration file path")
	runCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info",
		"Log level (debug, info, warn, error)")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("BNG version %s\n", version)
		fmt.Printf("Commit: %s\n", commit)
	},
}

func runBNG(cmd *cobra.Command, args []string) error {
	// Initialize logger
	logger, err := initLogger(logLevel)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Sync()

	logger.Info("Starting BNG",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("interface", iface),
	)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("Received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	// Load eBPF program (Phase 2 - stub implementation)
	logger.Info("Loading eBPF program", zap.String("interface", iface))

	loader, err := ebpf.NewLoader(iface, logger)
	if err != nil {
		return fmt.Errorf("failed to create eBPF loader: %w", err)
	}
	defer loader.Close()

	if err := loader.Load(ctx); err != nil {
		return fmt.Errorf("failed to load eBPF program: %w", err)
	}

	logger.Info("BNG started successfully")
	logger.Info("Press Ctrl+C to stop")

	// Wait for context cancellation
	<-ctx.Done()

	logger.Info("BNG stopped")
	return nil
}

func initLogger(level string) (*zap.Logger, error) {
	var zapLevel zap.AtomicLevel
	switch level {
	case "debug":
		zapLevel = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		zapLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		zapLevel = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		zapLevel = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		return nil, fmt.Errorf("invalid log level: %s", level)
	}

	config := zap.NewProductionConfig()
	config.Level = zapLevel
	config.Encoding = "json"

	return config.Build()
}
