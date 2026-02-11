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

	"github.com/codelaboratoryltd/bng/pkg/dhcp"
	"github.com/codelaboratoryltd/bng/pkg/dhcpv6"
	"github.com/codelaboratoryltd/bng/pkg/ebpf"
	"github.com/codelaboratoryltd/bng/pkg/ha"
	"github.com/codelaboratoryltd/bng/pkg/metrics"
	"github.com/codelaboratoryltd/bng/pkg/nat"
	"github.com/codelaboratoryltd/bng/pkg/nexus"
	"github.com/codelaboratoryltd/bng/pkg/pool"
	"github.com/codelaboratoryltd/bng/pkg/qos"
	"github.com/codelaboratoryltd/bng/pkg/radius"
	"github.com/codelaboratoryltd/bng/pkg/slaac"
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

	// Advanced NAT44 configuration (Issue #67)
	natInsideInterface  string // Inside interface for NAT (subscriber-facing)
	natOutsideInterface string // Outside interface for NAT (public-facing)
	natEIM              bool   // Endpoint-Independent Mapping (RFC 4787)
	natEIF              bool   // Endpoint-Independent Filtering (RFC 4787)
	natHairpin          bool   // Enable hairpinning for internal-to-internal NAT traffic
	natALGFTP           bool   // Enable FTP ALG
	natALGSIP           bool   // Enable SIP ALG
	natBulkLogging      bool   // Enable RFC 6908 bulk logging format

	// Device authentication configuration
	authMode           string
	authPSK            string
	authPSKFile        string
	authMTLSCert       string
	authMTLSKey        string
	authMTLSCA         string
	authMTLSServerName string
	authMTLSInsecure   bool

	// DHCPv6 configuration
	dhcpv6Enabled           bool
	dhcpv6AddressPool       string
	dhcpv6PrefixPool        string
	dhcpv6DelegationLength  uint8
	dhcpv6DNSServers        string
	dhcpv6DomainSearch      string
	dhcpv6PreferredLifetime uint32
	dhcpv6ValidLifetime     uint32

	// SLAAC/RA configuration
	slaacEnabled     bool
	slaacPrefixes    string
	slaacManaged     bool // M flag - use DHCPv6 for addresses
	slaacOther       bool // O flag - use DHCPv6 for other config (DNS, etc.)
	slaacMTU         uint32
	slaacDNSServers  string
	slaacDNSDomains  string
	slaacMinInterval time.Duration
	slaacMaxInterval time.Duration
	slaacLifetime    uint16

	// Nexus integration (Demo E - RADIUS-less mode)
	nexusURL    string
	nexusPoolID string

	// Peer Pool (Demo G - distributed allocation without central Nexus)
	peerAddrs      []string // Static list of peer addresses
	peerDiscovery  string   // Discovery method: static, dns
	peerService    string   // DNS service name for discovery
	peerNodeID     string   // This node's ID for hashring (defaults to hostname)
	peerListenAddr string   // Listen address for peer API

	// HA Pair (Demo H - active/standby with P2P sync)
	haPeerURL    string // HA peer URL for P2P state sync
	haRole       string // HA role: active or standby
	haListenAddr string // HA sync listen address

	// Resilience configuration (Issue #65)
	healthCheckInterval time.Duration // Interval for checking Nexus/peer health
	healthCheckRetries  int           // Number of failed checks before declaring partition
	radiusPartitionMode string        // Behavior during RADIUS unavailability: reject, cached, allow
	shortLeaseEnabled   bool          // Enable short leases when pool utilization is high
	shortLeaseThreshold float64       // Pool utilization threshold to trigger short leases (0.0-1.0)
	shortLeaseDuration  time.Duration // Duration of short leases

	// TTL/Epoch lease mode configuration (Issue #66)
	poolMode    string        // Allocation mode: static or lease
	epochPeriod time.Duration // Duration of each epoch for lease mode
	epochGrace  int           // Number of grace epochs before reclaiming IPs

	// PPPoE configuration
	pppoeEnabled        bool          // Enable PPPoE server
	pppoeInterface      string        // Interface for PPPoE (defaults to main interface)
	pppoeACName         string        // Access Concentrator name
	pppoeServiceName    string        // Service name to advertise
	pppoeAuthType       string        // Authentication type: pap, chap, or both
	pppoeSessionTimeout time.Duration // Session idle timeout
	pppoeMRU            uint16        // Maximum Receive Unit
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

	// Advanced NAT44 flags (Issue #67)
	runCmd.Flags().StringVar(&natInsideInterface, "nat-inside-interface", "",
		"Inside interface for NAT (subscriber-facing, defaults to main interface)")
	runCmd.Flags().StringVar(&natOutsideInterface, "nat-outside-interface", "",
		"Outside interface for NAT (public-facing, defaults to main interface)")
	runCmd.Flags().BoolVar(&natEIM, "nat-eim", true,
		"Enable Endpoint-Independent Mapping per RFC 4787")
	runCmd.Flags().BoolVar(&natEIF, "nat-eif", true,
		"Enable Endpoint-Independent Filtering per RFC 4787")
	runCmd.Flags().BoolVar(&natHairpin, "nat-hairpin", true,
		"Enable hairpinning for internal-to-internal NAT traffic")
	runCmd.Flags().BoolVar(&natALGFTP, "nat-alg-ftp", true,
		"Enable FTP Application Layer Gateway")
	runCmd.Flags().BoolVar(&natALGSIP, "nat-alg-sip", false,
		"Enable SIP Application Layer Gateway")
	runCmd.Flags().BoolVar(&natBulkLogging, "nat-bulk-logging", false,
		"Enable RFC 6908 bulk port allocation logging format")

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

	// DHCPv6 flags (Issue #26)
	runCmd.Flags().BoolVar(&dhcpv6Enabled, "dhcpv6-enabled", false,
		"Enable DHCPv6 server for IPv6 address assignment")
	runCmd.Flags().StringVar(&dhcpv6AddressPool, "dhcpv6-address-pool", "",
		"DHCPv6 address pool (CIDR, e.g., '2001:db8:1::/64')")
	runCmd.Flags().StringVar(&dhcpv6PrefixPool, "dhcpv6-prefix-pool", "",
		"DHCPv6 prefix delegation pool (CIDR, e.g., '2001:db8:2::/48')")
	runCmd.Flags().Uint8Var(&dhcpv6DelegationLength, "dhcpv6-delegation-length", 60,
		"Prefix length to delegate to customers (e.g., 56, 60, 64)")
	runCmd.Flags().StringVar(&dhcpv6DNSServers, "dhcpv6-dns", "",
		"DHCPv6 DNS servers (comma-separated IPv6 addresses)")
	runCmd.Flags().StringVar(&dhcpv6DomainSearch, "dhcpv6-domain-search", "",
		"DHCPv6 domain search list (comma-separated)")
	runCmd.Flags().Uint32Var(&dhcpv6PreferredLifetime, "dhcpv6-preferred-lifetime", 3600,
		"DHCPv6 preferred lifetime in seconds")
	runCmd.Flags().Uint32Var(&dhcpv6ValidLifetime, "dhcpv6-valid-lifetime", 7200,
		"DHCPv6 valid lifetime in seconds")

	// SLAAC/RA flags (Issue #27)
	runCmd.Flags().BoolVar(&slaacEnabled, "slaac-enabled", false,
		"Enable SLAAC Router Advertisement daemon")
	runCmd.Flags().StringVar(&slaacPrefixes, "slaac-prefixes", "",
		"Prefixes to advertise via SLAAC (comma-separated CIDR)")
	runCmd.Flags().BoolVar(&slaacManaged, "slaac-managed", false,
		"Set M flag - use DHCPv6 for addresses (disables SLAAC address generation)")
	runCmd.Flags().BoolVar(&slaacOther, "slaac-other", false,
		"Set O flag - use DHCPv6 for other config (DNS, etc.)")
	runCmd.Flags().Uint32Var(&slaacMTU, "slaac-mtu", 0,
		"MTU to advertise (0 = don't advertise)")
	runCmd.Flags().StringVar(&slaacDNSServers, "slaac-dns", "",
		"DNS servers to advertise via RDNSS (comma-separated IPv6 addresses)")
	runCmd.Flags().StringVar(&slaacDNSDomains, "slaac-dns-domains", "",
		"DNS search domains to advertise via DNSSL (comma-separated)")
	runCmd.Flags().DurationVar(&slaacMinInterval, "slaac-min-interval", 200*time.Second,
		"Minimum RA interval")
	runCmd.Flags().DurationVar(&slaacMaxInterval, "slaac-max-interval", 600*time.Second,
		"Maximum RA interval")
	runCmd.Flags().Uint16Var(&slaacLifetime, "slaac-lifetime", 1800,
		"Router lifetime in seconds (0 = not a default router)")

	// Nexus integration flags (Demo E - RADIUS-less mode)
	runCmd.Flags().StringVar(&nexusURL, "nexus-url", "",
		"Nexus server URL for distributed IP allocation (e.g., http://nexus:9000)")
	runCmd.Flags().StringVar(&nexusPoolID, "nexus-pool", "default",
		"Nexus pool ID to use for IP allocation")

	// Peer Pool flags (Demo G - distributed allocation without central Nexus)
	runCmd.Flags().StringSliceVar(&peerAddrs, "peers", nil,
		"Peer BNG addresses for distributed pool (comma-separated, e.g., 'bng-0:8080,bng-1:8080')")
	runCmd.Flags().StringVar(&peerDiscovery, "peer-discovery", "static",
		"Peer discovery method: static (use --peers), dns (use --peer-service)")
	runCmd.Flags().StringVar(&peerService, "peer-service", "",
		"DNS service name for peer discovery (e.g., 'bng-peers.demo.svc')")
	runCmd.Flags().StringVar(&peerNodeID, "node-id", "",
		"This node's ID for hashring (defaults to hostname)")
	runCmd.Flags().StringVar(&peerListenAddr, "peer-listen", ":8081",
		"Listen address for peer pool API")

	// HA Pair flags (Demo H - active/standby with P2P sync)
	runCmd.Flags().StringVar(&haPeerURL, "ha-peer", "",
		"HA peer URL for P2P state sync (e.g., 'bng-standby:9000' or 'http://bng-active:9000')")
	runCmd.Flags().StringVar(&haRole, "ha-role", "",
		"HA role: active or standby (empty = no HA)")
	runCmd.Flags().StringVar(&haListenAddr, "ha-listen", ":9000",
		"HA sync listen address (active node only)")

	// Resilience flags (Issue #65)
	runCmd.Flags().DurationVar(&healthCheckInterval, "health-check-interval", 5*time.Second,
		"Interval for checking Nexus/peer health")
	runCmd.Flags().IntVar(&healthCheckRetries, "health-check-retries", 3,
		"Number of failed health checks before declaring partition")
	runCmd.Flags().StringVar(&radiusPartitionMode, "radius-partition-mode", "cached",
		"Behavior during RADIUS unavailability: reject, cached, allow")
	runCmd.Flags().BoolVar(&shortLeaseEnabled, "short-lease-enabled", false,
		"Enable short leases when pool utilization is high")
	runCmd.Flags().Float64Var(&shortLeaseThreshold, "short-lease-threshold", 0.90,
		"Pool utilization threshold to trigger short leases (0.0-1.0)")
	runCmd.Flags().DurationVar(&shortLeaseDuration, "short-lease-duration", 5*time.Minute,
		"Duration of short leases when threshold is exceeded")

	// TTL/Epoch lease mode flags (Issue #66)
	runCmd.Flags().StringVar(&poolMode, "pool-mode", "static",
		"Allocation mode: static or lease")
	runCmd.Flags().DurationVar(&epochPeriod, "epoch-period", 5*time.Minute,
		"Duration of each epoch for lease mode")
	runCmd.Flags().IntVar(&epochGrace, "epoch-grace", 1,
		"Number of grace epochs before reclaiming IPs")

	// PPPoE flags
	runCmd.Flags().BoolVar(&pppoeEnabled, "pppoe-enabled", false,
		"Enable PPPoE server")
	runCmd.Flags().StringVar(&pppoeInterface, "pppoe-interface", "",
		"Interface for PPPoE (defaults to main interface)")
	runCmd.Flags().StringVar(&pppoeACName, "pppoe-ac-name", "BNG-AC",
		"Access Concentrator name")
	runCmd.Flags().StringVar(&pppoeServiceName, "pppoe-service-name", "internet",
		"Service name to advertise")
	runCmd.Flags().StringVar(&pppoeAuthType, "pppoe-auth-type", "pap",
		"Authentication type: pap, chap, or both")
	runCmd.Flags().DurationVar(&pppoeSessionTimeout, "pppoe-session-timeout", 30*time.Minute,
		"Session idle timeout")
	runCmd.Flags().Uint16Var(&pppoeMRU, "pppoe-mru", 1492,
		"Maximum Receive Unit")

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

	// Initialize Nexus HTTPAllocator if configured (Demo E - RADIUS-less mode)
	if nexusURL != "" {
		httpAllocator := nexus.NewHTTPAllocator(nexusURL)

		// Verify connectivity to Nexus
		if err := httpAllocator.HealthCheck(ctx); err != nil {
			return fmt.Errorf("cannot connect to Nexus at %s: %w", nexusURL, err)
		}

		dhcpServer.SetHTTPAllocator(httpAllocator, nexusPoolID)
		logger.Info("Connected to Nexus for distributed IP allocation",
			zap.String("url", nexusURL),
			zap.String("pool_id", nexusPoolID),
		)
	}

	// Initialize Peer Pool if peers are configured (Demo G - distributed allocation)
	var peerPool *pool.PeerPool
	var peerServer *http.Server
	if len(peerAddrs) > 0 || peerDiscovery == "dns" {
		// Determine node ID
		nodeID := peerNodeID
		if nodeID == "" {
			hostname, _ := os.Hostname()
			nodeID = hostname
		}

		// Resolve peers if using DNS discovery
		var peers []string
		if peerDiscovery == "dns" && peerService != "" {
			// DNS-based discovery - resolve SRV records
			// For now, use static list - full DNS discovery can be added later
			logger.Warn("DNS peer discovery not yet implemented, using static peers")
			peers = peerAddrs
		} else {
			peers = peerAddrs
		}

		// Parse DNS servers
		var dnsServers []string
		if poolDNS != "" {
			dnsServers = append(dnsServers, splitAndTrim(poolDNS)...)
		}

		peerPool, err = pool.NewPeerPool(pool.PeerPoolConfig{
			NodeID:     nodeID,
			Peers:      peers,
			Network:    poolNetwork,
			Gateway:    poolGateway,
			DNSServers: dnsServers,
			LeaseTime:  leaseTime,
			ListenAddr: peerListenAddr,
			Logger:     logger,
		})
		if err != nil {
			return fmt.Errorf("failed to create peer pool: %w", err)
		}

		dhcpServer.SetPeerPool(peerPool)
		logger.Info("Peer Pool initialized for distributed allocation",
			zap.String("node_id", nodeID),
			zap.Int("peers", len(peers)),
			zap.String("listen", peerListenAddr),
		)

		// Start peer pool HTTP API server
		mux := http.NewServeMux()
		peerPool.RegisterHandlers(mux)
		peerServer = &http.Server{
			Addr:    peerListenAddr,
			Handler: mux,
		}
		go func() {
			logger.Info("Starting peer pool API server", zap.String("addr", peerListenAddr))
			if err := peerServer.ListenAndServe(); err != http.ErrServerClosed {
				logger.Error("Peer pool API server error", zap.Error(err))
			}
		}()
	}

	// Initialize HA Syncer if configured (Demo H - active/standby with P2P sync)
	var haSyncer *ha.HASyncer
	if haRole != "" {
		// Create session store for HA
		haSessionStore := ha.NewInMemorySessionStore()

		// Configure HA syncer
		haConfig := ha.DefaultSyncConfig()
		haConfig.ListenAddr = haListenAddr

		// Determine node ID for HA
		haNodeID := peerNodeID
		if haNodeID == "" {
			hostname, _ := os.Hostname()
			haNodeID = hostname
		}
		haConfig.NodeID = haNodeID

		switch haRole {
		case "active":
			haConfig.Role = ha.RoleActive
			logger.Info("HA mode: active",
				zap.String("node_id", haNodeID),
				zap.String("listen", haListenAddr),
			)

		case "standby":
			haConfig.Role = ha.RoleStandby
			if haPeerURL == "" {
				return fmt.Errorf("--ha-peer is required when --ha-role=standby")
			}
			// Parse peer URL - remove http:// prefix if present for endpoint
			endpoint := haPeerURL
			if len(endpoint) > 7 && endpoint[:7] == "http://" {
				endpoint = endpoint[7:]
			}
			haConfig.Partner = &ha.PartnerInfo{
				NodeID:   "active", // Will be updated on first sync
				Endpoint: endpoint,
			}
			logger.Info("HA mode: standby",
				zap.String("node_id", haNodeID),
				zap.String("peer", endpoint),
			)

		default:
			return fmt.Errorf("invalid --ha-role: %s (must be 'active' or 'standby')", haRole)
		}

		haSyncer = ha.NewHASyncer(haConfig, haSessionStore, logger)
		if err := haSyncer.Start(); err != nil {
			return fmt.Errorf("failed to start HA syncer: %w", err)
		}
		logger.Info("HA syncer started",
			zap.String("role", haRole),
			zap.String("node_id", haNodeID),
		)
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

	// Initialize DHCPv6 server if enabled (Issue #26)
	var dhcpv6Server *dhcpv6.Server
	if dhcpv6Enabled {
		var v6DNSServers []string
		if dhcpv6DNSServers != "" {
			v6DNSServers = splitAndTrim(dhcpv6DNSServers)
		}
		var v6DomainSearch []string
		if dhcpv6DomainSearch != "" {
			v6DomainSearch = splitAndTrim(dhcpv6DomainSearch)
		}

		dhcpv6Server, err = dhcpv6.NewServer(dhcpv6.ServerConfig{
			Interface:         iface,
			AddressPool:       dhcpv6AddressPool,
			PrefixPool:        dhcpv6PrefixPool,
			DelegationLength:  dhcpv6DelegationLength,
			DNSServers:        v6DNSServers,
			DomainSearch:      v6DomainSearch,
			PreferredLifetime: dhcpv6PreferredLifetime,
			ValidLifetime:     dhcpv6ValidLifetime,
		}, logger)
		if err != nil {
			logger.Warn("Failed to create DHCPv6 server", zap.Error(err))
		} else {
			logger.Info("DHCPv6 server configured",
				zap.String("interface", iface),
				zap.String("address_pool", dhcpv6AddressPool),
				zap.String("prefix_pool", dhcpv6PrefixPool),
				zap.Uint8("delegation_length", dhcpv6DelegationLength),
			)
		}
	}

	// Initialize SLAAC/RA daemon if enabled (Issue #27)
	var raServer *slaac.Server
	if slaacEnabled {
		var raDNSServers []string
		if slaacDNSServers != "" {
			raDNSServers = splitAndTrim(slaacDNSServers)
		}
		var raDNSDomains []string
		if slaacDNSDomains != "" {
			raDNSDomains = splitAndTrim(slaacDNSDomains)
		}
		var raPrefixes []string
		if slaacPrefixes != "" {
			raPrefixes = splitAndTrim(slaacPrefixes)
		}

		raServer, err = slaac.NewServer(slaac.Config{
			Interface:       iface,
			Prefixes:        raPrefixes,
			MTU:             slaacMTU,
			Managed:         slaacManaged,
			Other:           slaacOther,
			DNSServers:      raDNSServers,
			DNSDomains:      raDNSDomains,
			DefaultLifetime: slaacLifetime,
			MinRAInterval:   slaacMinInterval,
			MaxRAInterval:   slaacMaxInterval,
		}, logger)
		if err != nil {
			logger.Warn("Failed to create SLAAC/RA daemon", zap.Error(err))
		} else {
			logger.Info("SLAAC/RA daemon configured",
				zap.String("interface", iface),
				zap.Strings("prefixes", raPrefixes),
				zap.Bool("managed", slaacManaged),
				zap.Bool("other", slaacOther),
			)
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
		server := &http.Server{
			Addr:              metricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		if err := server.ListenAndServe(); err != nil {
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

	// Start DHCPv6 server if enabled (Issue #26)
	if dhcpv6Server != nil {
		go func() {
			if err := dhcpv6Server.Start(ctx); err != nil {
				logger.Error("DHCPv6 server error", zap.Error(err))
			}
		}()
		logger.Info("DHCPv6 server started",
			zap.String("interface", iface),
		)
	}

	// Start SLAAC/RA daemon if enabled (Issue #27)
	if raServer != nil {
		if err := raServer.Start(ctx); err != nil {
			logger.Error("Failed to start SLAAC/RA daemon", zap.Error(err))
		} else {
			logger.Info("SLAAC/RA daemon started",
				zap.String("interface", iface),
			)
		}
	}

	logger.Info("BNG started successfully",
		zap.String("interface", iface),
		zap.String("pool", poolNetwork),
		zap.String("metrics", metricsAddr),
		zap.Bool("dhcpv6_enabled", dhcpv6Server != nil),
		zap.Bool("slaac_enabled", raServer != nil),
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
	// Stop DHCPv6 server (Issue #26)
	if dhcpv6Server != nil {
		if err := dhcpv6Server.Stop(); err != nil {
			logger.Warn("Failed to stop DHCPv6 server", zap.Error(err))
		}
	}
	// Stop SLAAC/RA daemon (Issue #27)
	if raServer != nil {
		if err := raServer.Stop(); err != nil {
			logger.Warn("Failed to stop SLAAC/RA daemon", zap.Error(err))
		}
	}
	// Stop peer pool API server (Issue #77)
	if peerServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := peerServer.Shutdown(shutdownCtx); err != nil {
			logger.Warn("Failed to stop peer pool API server", zap.Error(err))
		}
	}
	// Stop HA syncer (Demo H)
	if haSyncer != nil {
		if err := haSyncer.Stop(); err != nil {
			logger.Warn("Failed to stop HA syncer", zap.Error(err))
		}
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
