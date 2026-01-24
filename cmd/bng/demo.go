package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/nexus"
	"github.com/codelaboratoryltd/bng/pkg/pon"
	"github.com/codelaboratoryltd/bng/pkg/subscriber"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	demoSubscribers   int
	demoActivateRatio float64
	demoDuration      time.Duration
	demoAPIPort       int
	demoNexusURL      string
)

func init() {
	demoCmd.Flags().IntVar(&demoSubscribers, "subscribers", 10,
		"Number of ONTs to simulate")
	demoCmd.Flags().Float64Var(&demoActivateRatio, "activate-ratio", 0.7,
		"Ratio of subscribers to activate (0.0-1.0)")
	demoCmd.Flags().DurationVar(&demoDuration, "duration", 60*time.Second,
		"Demo duration before showing final stats")
	demoCmd.Flags().IntVar(&demoAPIPort, "api-port", 8080,
		"HTTP API port for activation")
	demoCmd.Flags().StringVar(&demoNexusURL, "nexus-url", "",
		"External Nexus URL for IP allocation (empty = in-memory)")

	rootCmd.AddCommand(demoCmd)
}

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run BNG demo with simulated ONTs",
	Long: `Run a demonstration of the full BNG subscriber lifecycle.

This simulates:
  1. ONT discovery and provisioning
  2. Walled garden access (pre-activation)
  3. Subscriber activation via HTTP API
  4. Full internet access (post-activation)
  5. Session tracking and metrics

No eBPF required - runs on any platform including macOS.`,
	RunE: runDemo,
}

// DemoAllocator is the interface for IP allocation in demo mode.
type DemoAllocator interface {
	AllocateIPv4(ctx context.Context, session *subscriber.Session, poolID string) (net.IP, net.IPMask, net.IP, error)
	AllocateIPv6(ctx context.Context, session *subscriber.Session, poolID string) (net.IP, *net.IPNet, error)
	ReleaseIPv4(ctx context.Context, ip net.IP) error
	ReleaseIPv6(ctx context.Context, ip net.IP) error
}

// DemoRunner orchestrates the demo scenario
type DemoRunner struct {
	logger  *zap.Logger
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	startAt time.Time

	// Core components
	store         *nexus.MemoryStore
	nexusClient   *nexus.Client
	vlanAlloc     *nexus.VLANAllocator
	ponMgr        *pon.Manager
	sessionMgr    *subscriber.Manager
	stubAuth      *StubAuthenticator
	allocator     DemoAllocator
	httpAllocator *nexus.HTTPAllocator // Only set when using external Nexus

	// Demo state
	mu            sync.RWMutex
	ontSerials    []string
	activatedONTs map[string]bool
	stats         DemoStats

	// HTTP server
	httpServer *http.Server
}

// DemoStats tracks demo statistics
type DemoStats struct {
	ONTsConnected     int       `json:"onts_connected"`
	ONTsProvisioned   int       `json:"onts_provisioned"`
	SessionsCreated   int       `json:"sessions_created"`
	SessionsWGAR      int       `json:"sessions_wgar"`
	SessionsActive    int       `json:"sessions_active"`
	SessionsSuspended int       `json:"sessions_suspended"`
	ActivationsTotal  int       `json:"activations_total"`
	ActivationsFailed int       `json:"activations_failed"`
	StartTime         time.Time `json:"start_time"`
}

// StubAuthenticator provides a simple in-memory authenticator for demo
type StubAuthenticator struct {
	mu      sync.RWMutex
	records map[string]*AuthRecord // MAC -> record
}

type AuthRecord struct {
	SubscriberID string
	ISPID        string
	PoolID       string
	WalledGarden bool
	Activated    bool
	DownloadBps  uint64
	UploadBps    uint64
}

func NewStubAuthenticator() *StubAuthenticator {
	return &StubAuthenticator{
		records: make(map[string]*AuthRecord),
	}
}

func (s *StubAuthenticator) Authenticate(ctx context.Context, req *subscriber.SessionRequest) (*subscriber.AuthResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	mac := req.MAC.String()
	record, exists := s.records[mac]

	if !exists {
		// Unknown subscriber - walled garden
		return &subscriber.AuthResult{
			Success:      true,
			WalledGarden: true,
			WalledReason: "unknown_subscriber",
		}, nil
	}

	return &subscriber.AuthResult{
		Success:         true,
		SubscriberID:    record.SubscriberID,
		ISPID:           record.ISPID,
		IPv4PoolID:      record.PoolID,
		WalledGarden:    record.WalledGarden,
		WalledReason:    "",
		DownloadRateBps: record.DownloadBps,
		UploadRateBps:   record.UploadBps,
	}, nil
}

func (s *StubAuthenticator) SetRecord(mac string, record *AuthRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[mac] = record
}

func (s *StubAuthenticator) GetRecord(mac string) (*AuthRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[mac]
	return r, ok
}

func (s *StubAuthenticator) ActivateSubscriber(mac string, poolID string, downloadBps, uploadBps uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, exists := s.records[mac]; exists {
		record.Activated = true
		record.WalledGarden = false
		record.PoolID = poolID
		record.DownloadBps = downloadBps
		record.UploadBps = uploadBps
	}
}

// StubAllocator provides a simple in-memory IP allocator for demo
type StubAllocator struct {
	mu    sync.Mutex
	pools map[string]*IPPoolState
}

type IPPoolState struct {
	Network net.IPNet
	Gateway net.IP
	Next    int
	Used    map[string]net.IP // sessionID -> IP
}

func NewStubAllocator() *StubAllocator {
	alloc := &StubAllocator{
		pools: make(map[string]*IPPoolState),
	}

	// Add default pools
	alloc.addPool("wgar", "10.255.0.0/16", "10.255.0.1")
	alloc.addPool("isp-residential", "10.0.0.0/16", "10.0.0.1")
	alloc.addPool("isp-business", "10.16.0.0/16", "10.16.0.1")

	return alloc
}

func (s *StubAllocator) addPool(name, cidr, gateway string) {
	_, network, _ := net.ParseCIDR(cidr)
	s.pools[name] = &IPPoolState{
		Network: *network,
		Gateway: net.ParseIP(gateway),
		Next:    10, // Start after .10
		Used:    make(map[string]net.IP),
	}
}

func (s *StubAllocator) AllocateIPv4(ctx context.Context, session *subscriber.Session, poolID string) (net.IP, net.IPMask, net.IP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pool, ok := s.pools[poolID]
	if !ok {
		pool = s.pools["wgar"] // Default to walled garden
	}

	// Simple allocation: just increment
	ip := make(net.IP, 4)
	copy(ip, pool.Network.IP.To4())
	ip[2] = byte(pool.Next / 256)
	ip[3] = byte(pool.Next % 256)
	pool.Next++

	pool.Used[session.ID] = ip

	return ip, pool.Network.Mask, pool.Gateway, nil
}

func (s *StubAllocator) AllocateIPv6(ctx context.Context, session *subscriber.Session, poolID string) (net.IP, *net.IPNet, error) {
	// Not implemented for demo
	return nil, nil, nil
}

func (s *StubAllocator) ReleaseIPv4(ctx context.Context, ip net.IP) error {
	// Not implemented for demo - IPs just stay allocated
	return nil
}

func (s *StubAllocator) ReleaseIPv6(ctx context.Context, ip net.IP) error {
	return nil
}

// HTTPAllocatorAdapter wraps HTTPAllocator to implement the subscriber.AddressAllocator interface.
type HTTPAllocatorAdapter struct {
	allocator *nexus.HTTPAllocator
}

func NewHTTPAllocatorAdapter(allocator *nexus.HTTPAllocator) *HTTPAllocatorAdapter {
	return &HTTPAllocatorAdapter{allocator: allocator}
}

func (h *HTTPAllocatorAdapter) AllocateIPv4(ctx context.Context, session *subscriber.Session, poolID string) (net.IP, net.IPMask, net.IP, error) {
	// Use session ID as subscriber ID for Nexus
	subscriberID := session.ID
	if session.ONUID != "" {
		subscriberID = session.ONUID
	}
	return h.allocator.AllocateIPv4(ctx, subscriberID, poolID)
}

func (h *HTTPAllocatorAdapter) AllocateIPv6(ctx context.Context, session *subscriber.Session, poolID string) (net.IP, *net.IPNet, error) {
	subscriberID := session.ID
	if session.ONUID != "" {
		subscriberID = session.ONUID
	}
	return h.allocator.AllocateIPv6(ctx, subscriberID, poolID)
}

func (h *HTTPAllocatorAdapter) ReleaseIPv4(ctx context.Context, ip net.IP) error {
	// For HTTP allocator, we'd need to track which subscriber owns which IP
	// For now, this is a no-op as Nexus handles cleanup
	return nil
}

func (h *HTTPAllocatorAdapter) ReleaseIPv6(ctx context.Context, ip net.IP) error {
	return nil
}

func runDemo(cmd *cobra.Command, args []string) error {
	// Initialize logger
	logConfig := zap.NewDevelopmentConfig()
	logConfig.EncoderConfig.TimeKey = ""
	logger, err := logConfig.Build()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Sync()

	ctx, cancel := context.WithCancel(context.Background())

	runner := &DemoRunner{
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		startAt:       time.Now(),
		activatedONTs: make(map[string]bool),
		stats: DemoStats{
			StartTime: time.Now(),
		},
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nReceived interrupt, shutting down...")
		cancel()
	}()

	if err := runner.Run(); err != nil {
		return err
	}

	return nil
}

func (d *DemoRunner) Run() error {
	d.printBanner()

	// Initialize components
	if err := d.initComponents(); err != nil {
		return fmt.Errorf("init components: %w", err)
	}

	// Start HTTP API
	d.startHTTPAPI()

	// Start the demo scenario
	d.wg.Add(1)
	go d.runScenario()

	// Wait for duration or interrupt
	select {
	case <-d.ctx.Done():
	case <-time.After(demoDuration):
	}

	// Print final stats
	d.printFinalStats()

	// Cleanup
	d.cancel()
	d.wg.Wait()

	if d.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d.httpServer.Shutdown(ctx)
	}

	return nil
}

func (d *DemoRunner) printBanner() {
	fmt.Print(`
╔══════════════════════════════════════════════════════════════╗
║        BNG Demo: Full Subscriber Lifecycle                   ║
║        eBPF-Accelerated Broadband Network Gateway            ║
╚══════════════════════════════════════════════════════════════╝
`)
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Subscribers:    %d\n", demoSubscribers)
	fmt.Printf("  Activate ratio: %.0f%%\n", demoActivateRatio*100)
	fmt.Printf("  Duration:       %s\n", demoDuration)
	fmt.Printf("  API Port:       %d\n", demoAPIPort)
	if demoNexusURL != "" {
		fmt.Printf("  Nexus URL:      %s\n", demoNexusURL)
	} else {
		fmt.Printf("  Nexus:          in-memory (standalone)\n")
	}
	fmt.Println()
}

func (d *DemoRunner) initComponents() error {
	d.log("[INIT] Initializing components...")

	// Create in-memory store
	d.store = nexus.NewMemoryStore()

	// Create Nexus client
	d.nexusClient = nexus.NewClient(nexus.ClientConfig{
		DeviceID:          "demo-olt-01",
		HeartbeatInterval: 30 * time.Second,
		SyncInterval:      5 * time.Second,
	}, d.store, d.logger)

	if err := d.nexusClient.Start(); err != nil {
		return fmt.Errorf("start nexus client: %w", err)
	}

	// Create VLAN allocator
	d.vlanAlloc = nexus.NewVLANAllocator(nexus.VLANAllocatorConfig{
		STagRange: nexus.VLANRange{Start: 100, End: 200},
		CTagRange: nexus.VLANRange{Start: 1000, End: 2000},
	})

	// Create stub authenticator
	d.stubAuth = NewStubAuthenticator()

	// Create allocator - use HTTP allocator if nexus-url is provided
	if demoNexusURL != "" {
		d.log("[INIT] Connecting to external Nexus at %s", demoNexusURL)
		d.httpAllocator = nexus.NewHTTPAllocator(demoNexusURL)

		// Verify connectivity
		if err := d.httpAllocator.HealthCheck(d.ctx); err != nil {
			return fmt.Errorf("cannot connect to Nexus at %s: %w", demoNexusURL, err)
		}
		d.log("[INIT] Connected to Nexus successfully")

		// Create default pools in Nexus
		d.log("[INIT] Creating pools in Nexus...")
		d.httpAllocator.CreatePool(d.ctx, "wgar", "10.255.0.0/16", 32)
		d.httpAllocator.CreatePool(d.ctx, "isp-residential", "10.0.0.0/16", 32)
		d.httpAllocator.CreatePool(d.ctx, "isp-business", "10.16.0.0/16", 32)

		d.allocator = NewHTTPAllocatorAdapter(d.httpAllocator)
	} else {
		d.allocator = NewStubAllocator()
	}

	// Create session manager
	d.sessionMgr = subscriber.NewManager(
		subscriber.ManagerConfig{
			CleanupInterval:        30 * time.Second,
			DefaultSessionTimeout:  24 * time.Hour,
			DefaultIdleTimeout:     30 * time.Minute,
			AuthTimeout:            10 * time.Second,
			MaxAuthAttempts:        3,
			MaxSessions:            10000,
			DefaultDownloadRateBps: 100_000_000,
			DefaultUploadRateBps:   50_000_000,
		},
		d.stubAuth,
		d.allocator,
		d.logger,
	)

	// Register session event handler
	d.sessionMgr.OnEvent(d.handleSessionEvent)

	if err := d.sessionMgr.Start(); err != nil {
		return fmt.Errorf("start session manager: %w", err)
	}

	// Create PON manager
	d.ponMgr = pon.NewManager(
		pon.ManagerConfig{
			DeviceID:            "demo-olt-01",
			DefaultISPID:        "demo-isp",
			WalledGardenEnabled: true,
			DiscoveryRetries:    1,
			DiscoveryRetryDelay: 1 * time.Second,
		},
		d.nexusClient,
		d.vlanAlloc,
		d.logger,
	)

	// Register PON callbacks
	d.ponMgr.OnNTEDiscovered(d.handleNTEDiscovered)
	d.ponMgr.OnNTEProvisioned(d.handleNTEProvisioned)

	if err := d.ponMgr.Start(); err != nil {
		return fmt.Errorf("start PON manager: %w", err)
	}

	d.log("[INIT] All components initialized")
	d.log("[INIT] HTTP API: http://localhost:%d", demoAPIPort)
	d.log("")

	return nil
}

func (d *DemoRunner) runScenario() {
	defer d.wg.Done()

	// Phase 1: Connect ONTs
	d.log("[PHASE 1] Connecting %d ONTs...", demoSubscribers)
	for i := 0; i < demoSubscribers; i++ {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		serial := fmt.Sprintf("DEMO%08d", i+1)
		d.ontSerials = append(d.ontSerials, serial)

		// Simulate ONT discovery
		d.ponMgr.HandleDiscovery(&pon.DiscoveryEvent{
			SerialNumber: serial,
			PONPort:      fmt.Sprintf("1/1/%d", (i%8)+1),
			Timestamp:    time.Now(),
			State:        pon.NTEStateConnected,
		})

		// Simulate DHCP request (creates session)
		mac := generateMAC(i)
		d.createSession(serial, mac)

		time.Sleep(200 * time.Millisecond)
	}

	d.log("[PHASE 1] All ONTs connected and in walled garden")
	d.log("")
	time.Sleep(2 * time.Second)

	// Phase 2: Activate some subscribers
	toActivate := int(float64(demoSubscribers) * demoActivateRatio)
	d.log("[PHASE 2] Activating %d subscribers...", toActivate)

	for i := 0; i < toActivate; i++ {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		serial := d.ontSerials[i]
		d.activateSubscriber(serial)
		time.Sleep(300 * time.Millisecond)
	}

	d.log("[PHASE 2] Activation complete")
	d.log("")

	// Phase 3: Simulate some traffic
	d.log("[PHASE 3] Simulating traffic...")
	for i := 0; i < 5; i++ {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		// Update activity on random sessions
		sessions := d.sessionMgr.ListSessions()
		if len(sessions) > 0 {
			s := sessions[rand.Intn(len(sessions))]
			bytesIn := uint64(rand.Intn(10_000_000))
			bytesOut := uint64(rand.Intn(50_000_000))
			d.sessionMgr.UpdateActivity(s.ID, bytesIn, bytesOut, bytesIn/1400, bytesOut/1400)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Phase 4: Suspend one subscriber (if any activated)
	if toActivate > 1 {
		d.log("[PHASE 4] Simulating payment failure...")
		serial := d.ontSerials[toActivate-1]
		d.suspendSubscriber(serial)
	}

	d.log("")
	d.log("[DEMO] Scenario complete. Waiting for duration to end...")
	d.log("[DEMO] Try the HTTP API: curl localhost:%d/api/v1/sessions", demoAPIPort)
}

func (d *DemoRunner) createSession(ontSerial string, mac net.HardwareAddr) {
	ctx := context.Background()

	// Create auth record (starts in walled garden)
	d.stubAuth.SetRecord(mac.String(), &AuthRecord{
		SubscriberID: fmt.Sprintf("sub-%s", ontSerial),
		ISPID:        "demo-isp",
		PoolID:       "wgar",
		WalledGarden: true,
		Activated:    false,
		DownloadBps:  10_000_000, // 10 Mbps for walled garden
		UploadBps:    2_000_000,
	})

	// Create session request
	req := &subscriber.SessionRequest{
		MAC:     mac,
		ONUID:   ontSerial,
		PONPort: "1/1/1",
		Type:    subscriber.SessionTypeIPoE,
	}

	// Create session
	session, err := d.sessionMgr.CreateSession(ctx, req)
	if err != nil {
		d.logger.Error("Failed to create session", zap.Error(err))
		return
	}

	// Authenticate (will get walled garden)
	_, err = d.sessionMgr.Authenticate(ctx, session.ID)
	if err != nil {
		d.logger.Error("Failed to authenticate session", zap.Error(err))
		return
	}

	// Assign IP from walled garden pool
	err = d.sessionMgr.AssignAddress(ctx, session.ID, "wgar", "")
	if err != nil {
		d.logger.Error("Failed to assign address", zap.Error(err))
		return
	}

	// Activate session (in walled garden state)
	d.sessionMgr.ActivateSession(session.ID)

	d.mu.Lock()
	d.stats.SessionsCreated++
	d.stats.SessionsWGAR++
	d.mu.Unlock()

	session, _ = d.sessionMgr.GetSession(session.ID)
	d.log("  %s: DHCP %s (wgar pool) - WALLED GARDEN", ontSerial, session.IPv4)
}

func (d *DemoRunner) activateSubscriber(ontSerial string) {
	ctx := context.Background()

	// Find session by ONT serial
	sessions := d.sessionMgr.ListSessions()
	var session *subscriber.Session
	for _, s := range sessions {
		if s.ONUID == ontSerial {
			session = s
			break
		}
	}

	if session == nil {
		d.logger.Warn("Session not found for ONT", zap.String("serial", ontSerial))
		return
	}

	// Update auth record to activate
	mac := session.MAC.String()
	d.stubAuth.ActivateSubscriber(mac, "isp-residential", 100_000_000, 50_000_000)

	// Clear walled garden
	d.sessionMgr.ClearWalledGarden(session.ID)

	// Re-assign IP from ISP pool (simulates DHCP renewal)
	d.sessionMgr.AssignAddress(ctx, session.ID, "isp-residential", "")

	d.mu.Lock()
	d.activatedONTs[ontSerial] = true
	d.stats.ActivationsTotal++
	d.stats.SessionsWGAR--
	d.stats.SessionsActive++
	d.mu.Unlock()

	session, _ = d.sessionMgr.GetSession(session.ID)
	d.log("  %s: Activated -> %s (isp-residential) - FULL ACCESS", ontSerial, session.IPv4)
}

func (d *DemoRunner) suspendSubscriber(ontSerial string) {
	// Find session by ONT serial
	sessions := d.sessionMgr.ListSessions()
	var session *subscriber.Session
	for _, s := range sessions {
		if s.ONUID == ontSerial {
			session = s
			break
		}
	}

	if session == nil {
		return
	}

	// Put back in walled garden
	d.sessionMgr.SetWalledGarden(session.ID, "payment_failed")

	d.mu.Lock()
	d.activatedONTs[ontSerial] = false
	d.stats.SessionsActive--
	d.stats.SessionsSuspended++
	d.mu.Unlock()

	d.log("  %s: SUSPENDED (payment failed) - back to WALLED GARDEN", ontSerial)
}

func (d *DemoRunner) handleNTEDiscovered(event *pon.DiscoveryEvent) {
	d.mu.Lock()
	d.stats.ONTsConnected++
	d.mu.Unlock()
}

func (d *DemoRunner) handleNTEProvisioned(result *pon.ProvisioningResult) {
	if result.Success {
		d.mu.Lock()
		d.stats.ONTsProvisioned++
		d.mu.Unlock()
	}
}

func (d *DemoRunner) handleSessionEvent(event *subscriber.SessionEvent) {
	// Log significant events
	switch event.Type {
	case subscriber.EventSessionActivate:
		d.logger.Debug("Session activated",
			zap.String("session_id", event.SessionID),
			zap.String("state", string(event.NewState)),
		)
	case subscriber.EventSessionTerminate:
		d.logger.Debug("Session terminated",
			zap.String("session_id", event.SessionID),
			zap.String("reason", event.Reason),
		)
	}
}

func (d *DemoRunner) startHTTPAPI() {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// List sessions
	mux.HandleFunc("/api/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		sessions := d.sessionMgr.ListSessions()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"count":    len(sessions),
			"sessions": sessions,
		})
	})

	// Get stats
	mux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		d.mu.RLock()
		stats := d.stats
		d.mu.RUnlock()

		stats.SessionsWGAR = 0
		stats.SessionsActive = 0
		for _, s := range d.sessionMgr.ListSessions() {
			if s.WalledGarden {
				stats.SessionsWGAR++
			} else if s.State == subscriber.StateActive {
				stats.SessionsActive++
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	// Activate subscriber
	mux.HandleFunc("/api/v1/activate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ONTSerial   string `json:"ont_serial"`
			ServiceID   string `json:"service_id"`
			Pool        string `json:"pool"`
			DownloadBps uint64 `json:"download_bps"`
			UploadBps   uint64 `json:"upload_bps"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Find and activate
		d.activateSubscriber(req.ONTSerial)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "success",
			"ont_serial": req.ONTSerial,
		})
	})

	d.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", demoAPIPort),
		Handler: mux,
	}

	go func() {
		if err := d.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			d.logger.Error("HTTP server error", zap.Error(err))
		}
	}()
}

func (d *DemoRunner) printFinalStats() {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("                        FINAL STATISTICS                         ")
	fmt.Println("════════════════════════════════════════════════════════════════")

	// Get live stats
	stats := d.sessionMgr.Stats()
	ponStats := d.ponMgr.Stats()

	fmt.Printf("\nOLT Statistics:\n")
	fmt.Printf("  ONTs Connected:    %d\n", ponStats.ConnectedNTEs)
	fmt.Printf("  ONTs Pending:      %d\n", ponStats.PendingNTEs)

	fmt.Printf("\nSession Statistics:\n")
	fmt.Printf("  Total Created:     %d\n", stats.TotalSessionsCreated)
	fmt.Printf("  Active Sessions:   %d\n", stats.ActiveSessions)
	fmt.Printf("  Walled Garden:     %d\n", stats.WalledGardenSessions)
	fmt.Printf("  Auth Successes:    %d\n", stats.AuthSuccesses)
	fmt.Printf("  Auth Failures:     %d\n", stats.AuthFailures)

	// Pool utilization
	fmt.Printf("\nDHCP Pools:\n")
	fmt.Printf("  wgar:            %d IPs used\n", countPoolUsage(d.sessionMgr.ListSessions(), "wgar"))
	fmt.Printf("  isp-residential: %d IPs used\n", countPoolUsage(d.sessionMgr.ListSessions(), "isp-residential"))

	// Traffic stats
	fmt.Printf("\nTraffic:\n")
	fmt.Printf("  Total Bytes In:    %s\n", formatBytes(uint64(stats.TotalBytesIn)))
	fmt.Printf("  Total Bytes Out:   %s\n", formatBytes(uint64(stats.TotalBytesOut)))

	fmt.Printf("\nDuration: %s\n", time.Since(d.startAt).Round(time.Second))
	fmt.Println()
}

func (d *DemoRunner) log(format string, args ...any) {
	elapsed := time.Since(d.startAt).Round(time.Millisecond)
	fmt.Printf("[%s] %s\n", elapsed, fmt.Sprintf(format, args...))
}

// Helper functions

func generateMAC(index int) net.HardwareAddr {
	return net.HardwareAddr{0x02, 0xDE, 0xD0, byte(index >> 16), byte(index >> 8), byte(index)}
}

func countPoolUsage(sessions []*subscriber.Session, poolHint string) int {
	count := 0
	for _, s := range sessions {
		if s.IPv4 != nil {
			ip := s.IPv4.String()
			if poolHint == "wgar" && len(ip) > 4 && ip[:7] == "10.255." {
				count++
			} else if poolHint == "isp-residential" && len(ip) > 3 && ip[:5] == "10.0." {
				count++
			}
		}
	}
	return count
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
