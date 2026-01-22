package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/deviceauth"
	"github.com/codelaboratoryltd/bng/pkg/dhcp"
	"github.com/codelaboratoryltd/bng/pkg/ebpf"
	"github.com/codelaboratoryltd/bng/pkg/metrics"
	"github.com/codelaboratoryltd/bng/pkg/nat"
	"github.com/codelaboratoryltd/bng/pkg/qos"
	"github.com/codelaboratoryltd/bng/pkg/radius"
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
	iface       string
	configFile  string
	logLevel    string
	bpfPath     string
	serverIP    string
	metricsAddr string
	poolNetwork string
	poolGateway string
	poolDNS     string
	leaseTime   time.Duration

	// RADIUS configuration
	radiusServers string
	radiusSecret  string
	radiusNASID   string
	radiusTimeout time.Duration
	radiusEnabled bool

	// QoS configuration
	qosBPFPath string
	qosEnabled bool

	// NAT configuration
	natEnabled     bool
	natBPFPath     string
	natPublicIPs   string
	natPortsPerSub int
	natLogEnabled  bool
	natLogPath     string

	// Device authentication configuration
	authMode           string
	authPSK            string
	authPSKFile        string
	authMTLSCert       string
	authMTLSKey        string
	authMTLSCA         string
	authMTLSServerName string
	authMTLSInsecure   bool
)

func init() {
	runCmd.Flags().StringVarP(&iface, "interface", "i", "eth1",
		"Network interface for subscriber traffic")
	runCmd.Flags().StringVarP(&configFile, "config", "c", "/etc/bng/config.yaml",
		"Configuration file path")
	runCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info",
		"Log level (debug, info, warn, error)")
	runCmd.Flags().StringVar(&bpfPath, "bpf-path", "bpf/dhcp_fastpath.bpf.o",
		"Path to compiled eBPF program")
	runCmd.Flags().StringVar(&serverIP, "server-ip", "",
		"DHCP server IP address (defaults to interface IP)")
	runCmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":9090",
		"Prometheus metrics listen address")
	runCmd.Flags().StringVar(&poolNetwork, "pool-network", "10.0.1.0/24",
		"Default IP pool network (CIDR)")
	runCmd.Flags().StringVar(&poolGateway, "pool-gateway", "10.0.1.1",
		"Default pool gateway")
	runCmd.Flags().StringVar(&poolDNS, "pool-dns", "8.8.8.8,8.8.4.4",
		"DNS servers (comma-separated)")
	runCmd.Flags().DurationVar(&leaseTime, "lease-time", 24*time.Hour,
		"Default DHCP lease time")

	// RADIUS flags
	runCmd.Flags().StringVar(&radiusServers, "radius-servers", "",
		"RADIUS server addresses (comma-separated, e.g., 'radius1.example.com:1812,radius2.example.com:1812')")
	runCmd.Flags().StringVar(&radiusSecret, "radius-secret", "",
		"RADIUS shared secret")
	runCmd.Flags().StringVar(&radiusNASID, "radius-nas-id", "bng",
		"RADIUS NAS-Identifier")
	runCmd.Flags().DurationVar(&radiusTimeout, "radius-timeout", 3*time.Second,
		"RADIUS request timeout")
	runCmd.Flags().BoolVar(&radiusEnabled, "radius-enabled", false,
		"Enable RADIUS authentication")

	// QoS flags
	runCmd.Flags().StringVar(&qosBPFPath, "qos-bpf-path", "bpf/qos_ratelimit.bpf.o",
		"Path to compiled QoS eBPF program")
	runCmd.Flags().BoolVar(&qosEnabled, "qos-enabled", false,
		"Enable QoS rate limiting via eBPF TC")

	// NAT flags
	runCmd.Flags().BoolVar(&natEnabled, "nat-enabled", false,
		"Enable NAT44/CGNAT via eBPF TC")
	runCmd.Flags().StringVar(&natBPFPath, "nat-bpf-path", "bpf/nat44.bpf.o",
		"Path to compiled NAT44 eBPF program")
	runCmd.Flags().StringVar(&natPublicIPs, "nat-public-ips", "",
		"Public IP addresses for NAT pool (comma-separated)")
	runCmd.Flags().IntVar(&natPortsPerSub, "nat-ports-per-sub", 1024,
		"Number of ports allocated per subscriber")
	runCmd.Flags().BoolVar(&natLogEnabled, "nat-log-enabled", false,
		"Enable NAT translation logging (required for legal compliance)")
	runCmd.Flags().StringVar(&natLogPath, "nat-log-path", "",
		"Path to NAT log file (empty for stdout)")

	// Device authentication flags
	runCmd.Flags().StringVar(&authMode, "auth-mode", "none",
		"Device authentication mode: none, psk, mtls (default: none)")
	runCmd.Flags().StringVar(&authPSK, "auth-psk", "",
		"Pre-shared key for device authentication (use --auth-psk-file for production)")
	runCmd.Flags().StringVar(&authPSKFile, "auth-psk-file", "",
		"Path to file containing pre-shared key")
	runCmd.Flags().StringVar(&authMTLSCert, "auth-mtls-cert", "",
		"Path to device certificate (PEM format) for mTLS")
	runCmd.Flags().StringVar(&authMTLSKey, "auth-mtls-key", "",
		"Path to device private key (PEM format) for mTLS")
	runCmd.Flags().StringVar(&authMTLSCA, "auth-mtls-ca", "",
		"Path to CA certificate bundle (PEM format) for mTLS server verification")
	runCmd.Flags().StringVar(&authMTLSServerName, "auth-mtls-server-name", "",
		"Expected server hostname for mTLS verification")
	runCmd.Flags().BoolVar(&authMTLSInsecure, "auth-mtls-insecure", false,
		"Skip TLS server verification (INSECURE - testing only)")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(statsCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("BNG version %s\n", version)
		fmt.Printf("Commit: %s\n", commit)
	},
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show eBPF statistics",
	RunE:  showStats,
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

	// Determine server IP
	srvIP := net.ParseIP(serverIP)
	if srvIP == nil {
		// Try to get IP from interface
		ifaceObj, err := net.InterfaceByName(iface)
		if err == nil {
			addrs, _ := ifaceObj.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					srvIP = ipnet.IP
					break
				}
			}
		}
		if srvIP == nil {
			srvIP = net.ParseIP(poolGateway) // Fallback to gateway
		}
	}

	logger.Info("Using server IP", zap.String("ip", srvIP.String()))

	// Load eBPF program
	logger.Info("Loading eBPF program", zap.String("path", bpfPath))

	loader, err := ebpf.NewLoader(iface, logger, ebpf.WithBPFPath(bpfPath))
	if err != nil {
		return fmt.Errorf("failed to create eBPF loader: %w", err)
	}
	defer loader.Close()

	if err := loader.Load(ctx); err != nil {
		return fmt.Errorf("failed to load eBPF program: %w", err)
	}

	// Create pool manager
	poolMgr := dhcp.NewPoolManager(loader, logger)

	// Parse DNS servers
	var dnsServers []string
	if poolDNS != "" {
		dnsServers = splitAndTrim(poolDNS)
	}

	// Create default pool
	defaultPool, err := dhcp.NewPool(dhcp.PoolConfig{
		ID:            1,
		Name:          "default",
		Network:       poolNetwork,
		Gateway:       poolGateway,
		DNSServers:    dnsServers,
		LeaseTime:     leaseTime,
		ClientClass:   dhcp.ClientClassResidential,
		VlanID:        0,
		ReservedStart: 10, // Reserve .1-.10
		ReservedEnd:   5,  // Reserve last 5 IPs
	})
	if err != nil {
		return fmt.Errorf("failed to create default pool: %w", err)
	}

	if err := poolMgr.AddPool(defaultPool); err != nil {
		return fmt.Errorf("failed to add default pool: %w", err)
	}

	// Create DHCP slow path server
	dhcpServer, err := dhcp.NewServer(dhcp.ServerConfig{
		Interface:         iface,
		ServerIP:          srvIP,
		RADIUSAuthEnabled: radiusEnabled,
	}, loader, poolMgr, logger)
	if err != nil {
		return fmt.Errorf("failed to create DHCP server: %w", err)
	}

	// Initialize RADIUS client if enabled
	var radiusClient *radius.Client
	var policyMgr *radius.PolicyManager
	if radiusEnabled && radiusServers != "" && radiusSecret != "" {
		servers := parseRADIUSServers(radiusServers, radiusSecret)
		if len(servers) > 0 {
			radiusClient, err = radius.NewClient(radius.ClientConfig{
				Servers: servers,
				NASID:   radiusNASID,
				Timeout: radiusTimeout,
				Retries: 3,
			}, logger)
			if err != nil {
				return fmt.Errorf("failed to create RADIUS client: %w", err)
			}
			dhcpServer.SetRADIUSClient(radiusClient)
			logger.Info("RADIUS client initialized",
				zap.Int("servers", len(servers)),
				zap.String("nas_id", radiusNASID),
			)
		}
	}

	// Initialize policy manager with default policies
	policyMgr = radius.NewPolicyManager()
	dhcpServer.SetPolicyManager(policyMgr)
	logger.Info("QoS policy manager initialized",
		zap.Int("policies", len(policyMgr.ListPolicies())),
	)

	// Initialize QoS manager if enabled
	var qosMgr *qos.Manager
	if qosEnabled {
		qosMgr, err = qos.NewManager(qos.ManagerConfig{
			Interface: iface,
			BPFPath:   qosBPFPath,
		}, policyMgr, logger)
		if err != nil {
			logger.Warn("Failed to create QoS manager", zap.Error(err))
		} else {
			if err := qosMgr.Start(ctx); err != nil {
				logger.Warn("Failed to start QoS manager", zap.Error(err))
			} else {
				dhcpServer.SetQoSManager(qosMgr)
				logger.Info("QoS manager started",
					zap.String("interface", iface),
					zap.String("bpf_path", qosBPFPath),
				)
			}
		}
	}

	// Initialize NAT manager if enabled
	var natMgr *nat.Manager
	var natLogger *nat.Logger
	if natEnabled {
		natMgr, err = nat.NewManager(nat.ManagerConfig{
			Interface:          iface,
			BPFPath:            natBPFPath,
			PortsPerSubscriber: natPortsPerSub,
		}, logger)
		if err != nil {
			logger.Warn("Failed to create NAT manager", zap.Error(err))
		} else {
			// Add public IPs to pool
			if natPublicIPs != "" {
				for _, ipStr := range splitAndTrim(natPublicIPs) {
					ip := net.ParseIP(ipStr)
					if ip != nil {
						if err := natMgr.AddPublicIP(ip); err != nil {
							logger.Warn("Failed to add NAT public IP",
								zap.String("ip", ipStr),
								zap.Error(err),
							)
						}
					}
				}
			}

			if err := natMgr.Start(ctx); err != nil {
				logger.Warn("Failed to start NAT manager", zap.Error(err))
			} else {
				dhcpServer.SetNATManager(natMgr)
				logger.Info("NAT44 manager started",
					zap.String("interface", iface),
					zap.Int("public_ips", len(natMgr.GetPoolStats())),
					zap.Int("ports_per_sub", natPortsPerSub),
				)
			}

			// Initialize NAT logging if enabled
			if natLogEnabled {
				natLogger, err = nat.NewLogger(nat.LoggerConfig{
					Enabled:  true,
					FilePath: natLogPath,
					Format:   "json",
				}, logger)
				if err != nil {
					logger.Warn("Failed to create NAT logger", zap.Error(err))
				} else {
					natLogger.Start()
					logger.Info("NAT logging enabled",
						zap.String("path", natLogPath),
					)
				}
			}
		}
	}

	// Create and register metrics
	metricsCollector := metrics.New(loader, poolMgr, dhcpServer, logger)
	if err := metricsCollector.Register(); err != nil {
		logger.Warn("Failed to register metrics", zap.Error(err))
	}

	// Start metrics HTTP server
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metricsCollector.Handler())
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		})

		logger.Info("Starting metrics server", zap.String("addr", metricsAddr))
		if err := http.ListenAndServe(metricsAddr, mux); err != nil {
			logger.Error("Metrics server error", zap.Error(err))
		}
	}()

	// Start metrics collector
	stopMetrics := make(chan struct{})
	go metricsCollector.StartCollector(5*time.Second, stopMetrics)

	// Start DHCP server
	go func() {
		if err := dhcpServer.Start(ctx); err != nil {
			logger.Error("DHCP server error", zap.Error(err))
		}
	}()

	logger.Info("BNG started successfully",
		zap.String("interface", iface),
		zap.String("pool", poolNetwork),
		zap.String("metrics", metricsAddr),
	)
	logger.Info("Press Ctrl+C to stop")

	// Wait for context cancellation
	<-ctx.Done()

	// Cleanup
	close(stopMetrics)
	if qosMgr != nil {
		qosMgr.Stop()
	}
	if natMgr != nil {
		natMgr.Stop()
	}
	if natLogger != nil {
		natLogger.Stop()
	}
	logger.Info("BNG stopped")
	return nil
}

func showStats(cmd *cobra.Command, args []string) error {
	logger, _ := zap.NewDevelopment()

	loader, err := ebpf.NewLoader(iface, logger, ebpf.WithBPFPath(bpfPath))
	if err != nil {
		return err
	}
	defer loader.Close()

	// Just try to read the maps (won't attach XDP)
	// This is a placeholder - in production you'd read from pinned maps
	fmt.Println("Stats command not yet implemented for running BNG instance")
	fmt.Println("Use the /metrics endpoint for Prometheus metrics")
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

func splitAndTrim(s string) []string {
	var result []string
	for _, part := range split(s, ",") {
		trimmed := trim(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func split(s, sep string) []string {
	var result []string
	for len(s) > 0 {
		idx := indexOf(s, sep)
		if idx < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return result
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// parseRADIUSServers parses comma-separated RADIUS server addresses
func parseRADIUSServers(servers, secret string) []radius.ServerConfig {
	var result []radius.ServerConfig
	for _, s := range splitAndTrim(servers) {
		host, port := parseHostPort(s, 1812)
		result = append(result, radius.ServerConfig{
			Host:   host,
			Port:   port,
			Secret: secret,
		})
	}
	return result
}

// parseHostPort parses a host:port string, returning default port if not specified
func parseHostPort(s string, defaultPort int) (string, int) {
	colonIdx := -1
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			colonIdx = i
			break
		}
	}
	if colonIdx < 0 {
		return s, defaultPort
	}
	host := s[:colonIdx]
	portStr := s[colonIdx+1:]
	port := parsePort(portStr, defaultPort)
	return host, port
}

// parsePort parses a port string, returning default if invalid
func parsePort(s string, defaultPort int) int {
	port := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return defaultPort
		}
		port = port*10 + int(c-'0')
	}
	if port <= 0 || port > 65535 {
		return defaultPort
	}
	return port
}

// buildAuthConfig creates device authentication configuration from CLI flags.
// The logger parameter is used to warn about unknown auth modes.
func buildAuthConfig(logger *zap.Logger) deviceauth.Config {
	config := deviceauth.DefaultConfig()

	switch authMode {
	case "none", "":
		config.Mode = deviceauth.AuthModeNone

	case "psk":
		config.Mode = deviceauth.AuthModePSK
		config.PSK = &deviceauth.PSKConfig{
			Key:     authPSK,
			KeyFile: authPSKFile,
		}

	case "mtls":
		config.Mode = deviceauth.AuthModeMTLS
		config.MTLS = &deviceauth.MTLSConfig{
			CertFile:           authMTLSCert,
			KeyFile:            authMTLSKey,
			CAFile:             authMTLSCA,
			ServerName:         authMTLSServerName,
			InsecureSkipVerify: authMTLSInsecure,
		}

	default:
		logger.Warn("Unknown auth mode, defaulting to none", zap.String("mode", authMode))
		config.Mode = deviceauth.AuthModeNone
	}

	return config
}
