package routing

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SubscriberRouteManager manages per-subscriber /32 route injection and withdrawal
// into FRR/BGP. It integrates with the session manager to automatically inject
// routes when sessions become active and withdraw them on termination.
type SubscriberRouteManager struct {
	config      SubscriberRouteConfig
	logger      *zap.Logger
	bgp         *BGPController
	frrExecutor FRRExecutor

	mu sync.RWMutex

	// Active subscriber routes: IP -> RouteInfo
	activeRoutes map[string]*SubscriberRoute

	// Pending operations for retry
	pendingOps chan *routeOperation

	// Metrics
	stats SubscriberRouteStats

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// SubscriberRouteConfig holds configuration for subscriber route management.
type SubscriberRouteConfig struct {
	// LocalAS is the BGP AS number for route injection.
	LocalAS uint32

	// NextHop is the next-hop IP for subscriber routes (usually BNG's IP).
	// If nil, uses the session's gateway.
	NextHop net.IP

	// DefaultCommunity is the BGP community to apply to all subscriber routes.
	DefaultCommunity string

	// CommunityByClass maps subscriber class to BGP community.
	CommunityByClass map[string]string

	// RouteMapName is the route-map to apply to subscriber routes.
	RouteMapName string

	// RetryInterval is how long to wait before retrying failed operations.
	RetryInterval time.Duration

	// MaxRetries is the maximum number of retries for failed operations.
	MaxRetries int

	// BulkBatchSize is the number of routes to inject/withdraw per batch.
	BulkBatchSize int

	// BulkBatchDelay is the delay between bulk batches to avoid overwhelming FRR.
	BulkBatchDelay time.Duration

	// WithdrawalDelay is an optional delay before withdrawing routes (for graceful drain).
	WithdrawalDelay time.Duration

	// EnableGracefulShutdown adds GRACEFUL_SHUTDOWN community before withdrawal.
	EnableGracefulShutdown bool
}

// DefaultSubscriberRouteConfig returns sensible defaults.
func DefaultSubscriberRouteConfig() SubscriberRouteConfig {
	return SubscriberRouteConfig{
		RetryInterval:          5 * time.Second,
		MaxRetries:             3,
		BulkBatchSize:          100,
		BulkBatchDelay:         100 * time.Millisecond,
		WithdrawalDelay:        0,
		EnableGracefulShutdown: false,
	}
}

// SubscriberRoute represents an injected subscriber route.
type SubscriberRoute struct {
	IP              net.IP    `json:"ip"`
	SessionID       string    `json:"session_id"`
	SubscriberID    string    `json:"subscriber_id"`
	SubscriberClass string    `json:"subscriber_class,omitempty"`
	Community       string    `json:"community,omitempty"`
	InjectedAt      time.Time `json:"injected_at"`
	LastRefresh     time.Time `json:"last_refresh"`
}

// SubscriberRouteStats holds statistics for subscriber route operations.
type SubscriberRouteStats struct {
	RoutesActive        int   `json:"routes_active"`
	RoutesInjected      int64 `json:"routes_injected"`
	RoutesWithdrawn     int64 `json:"routes_withdrawn"`
	InjectionSuccesses  int64 `json:"injection_successes"`
	InjectionFailures   int64 `json:"injection_failures"`
	WithdrawalSuccesses int64 `json:"withdrawal_successes"`
	WithdrawalFailures  int64 `json:"withdrawal_failures"`
	RetryAttempts       int64 `json:"retry_attempts"`
	BulkInjections      int64 `json:"bulk_injections"`
}

// routeOperation represents a pending route operation.
type routeOperation struct {
	Type      routeOpType
	Route     *SubscriberRoute
	Retries   int
	CreatedAt time.Time
}

type routeOpType int

const (
	routeOpInject routeOpType = iota
	routeOpWithdraw
)

// FRRExecutor executes FRR commands. This interface allows for testing.
type FRRExecutor interface {
	// ExecuteCommand executes a vtysh command and returns the output.
	ExecuteCommand(ctx context.Context, command string) (string, error)
}

// NewSubscriberRouteManager creates a new subscriber route manager.
func NewSubscriberRouteManager(config SubscriberRouteConfig, bgp *BGPController, logger *zap.Logger) *SubscriberRouteManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &SubscriberRouteManager{
		config:       config,
		logger:       logger,
		bgp:          bgp,
		activeRoutes: make(map[string]*SubscriberRoute),
		pendingOps:   make(chan *routeOperation, 10000),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// SetFRRExecutor sets a custom FRR executor (useful for testing).
func (m *SubscriberRouteManager) SetFRRExecutor(executor FRRExecutor) {
	m.frrExecutor = executor
}

// Start begins the subscriber route manager.
func (m *SubscriberRouteManager) Start() error {
	m.logger.Info("Starting subscriber route manager",
		zap.Uint32("local_as", m.config.LocalAS),
		zap.String("default_community", m.config.DefaultCommunity),
	)

	// Start retry worker
	m.wg.Add(1)
	go m.retryWorker()

	m.logger.Info("Subscriber route manager started")
	return nil
}

// Stop shuts down the subscriber route manager.
func (m *SubscriberRouteManager) Stop() error {
	m.logger.Info("Stopping subscriber route manager")
	m.cancel()
	m.wg.Wait()
	m.logger.Info("Subscriber route manager stopped")
	return nil
}

// InjectRoute injects a /32 route for a subscriber session.
// This should be called when a session transitions to ACTIVE state.
func (m *SubscriberRouteManager) InjectRoute(ctx context.Context, sessionID, subscriberID string, ip net.IP, subscriberClass string) error {
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	ipStr := ip.String()

	m.mu.Lock()
	// Check if route already exists
	if existing, exists := m.activeRoutes[ipStr]; exists {
		// Update existing route
		existing.SessionID = sessionID
		existing.SubscriberID = subscriberID
		existing.SubscriberClass = subscriberClass
		existing.LastRefresh = time.Now()
		m.mu.Unlock()
		m.logger.Debug("Route already exists, updated session info",
			zap.String("ip", ipStr),
			zap.String("session_id", sessionID),
		)
		return nil
	}

	// Determine community
	community := m.config.DefaultCommunity
	if m.config.CommunityByClass != nil {
		if classCommunity, ok := m.config.CommunityByClass[subscriberClass]; ok {
			community = classCommunity
		}
	}

	route := &SubscriberRoute{
		IP:              ip,
		SessionID:       sessionID,
		SubscriberID:    subscriberID,
		SubscriberClass: subscriberClass,
		Community:       community,
		InjectedAt:      time.Now(),
		LastRefresh:     time.Now(),
	}

	m.activeRoutes[ipStr] = route
	m.stats.RoutesActive = len(m.activeRoutes)
	m.mu.Unlock()

	// Inject into FRR
	if err := m.injectRouteToFRR(ctx, route); err != nil {
		m.logger.Warn("Failed to inject route, queuing for retry",
			zap.String("ip", ipStr),
			zap.Error(err),
		)

		m.mu.Lock()
		m.stats.InjectionFailures++
		m.mu.Unlock()

		m.queueRetry(&routeOperation{
			Type:      routeOpInject,
			Route:     route,
			Retries:   0,
			CreatedAt: time.Now(),
		})

		return err
	}

	m.mu.Lock()
	m.stats.RoutesInjected++
	m.stats.InjectionSuccesses++
	m.mu.Unlock()

	m.logger.Info("Injected subscriber route",
		zap.String("ip", ipStr),
		zap.String("session_id", sessionID),
		zap.String("subscriber_id", subscriberID),
		zap.String("community", community),
	)

	return nil
}

// WithdrawRoute withdraws a /32 route for a subscriber session.
// This should be called when a session terminates.
func (m *SubscriberRouteManager) WithdrawRoute(ctx context.Context, sessionID string, ip net.IP) error {
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	ipStr := ip.String()

	m.mu.Lock()
	route, exists := m.activeRoutes[ipStr]
	if !exists {
		m.mu.Unlock()
		m.logger.Debug("Route not found for withdrawal (already withdrawn?)",
			zap.String("ip", ipStr),
			zap.String("session_id", sessionID),
		)
		return nil // Idempotent - not an error
	}

	// Verify session ID matches (prevent accidental withdrawal)
	if route.SessionID != sessionID {
		m.mu.Unlock()
		m.logger.Warn("Session ID mismatch for route withdrawal",
			zap.String("ip", ipStr),
			zap.String("expected_session", route.SessionID),
			zap.String("actual_session", sessionID),
		)
		return fmt.Errorf("session ID mismatch: expected %s, got %s", route.SessionID, sessionID)
	}

	// Remove from active routes
	delete(m.activeRoutes, ipStr)
	m.stats.RoutesActive = len(m.activeRoutes)
	m.mu.Unlock()

	// Apply withdrawal delay if configured
	if m.config.WithdrawalDelay > 0 {
		m.logger.Debug("Applying withdrawal delay",
			zap.String("ip", ipStr),
			zap.Duration("delay", m.config.WithdrawalDelay),
		)
		select {
		case <-time.After(m.config.WithdrawalDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Graceful shutdown: add GRACEFUL_SHUTDOWN community before withdrawal
	if m.config.EnableGracefulShutdown {
		if err := m.setGracefulShutdownCommunity(ctx, route); err != nil {
			m.logger.Warn("Failed to set graceful shutdown community",
				zap.String("ip", ipStr),
				zap.Error(err),
			)
			// Continue with withdrawal anyway
		}
	}

	// Withdraw from FRR
	if err := m.withdrawRouteFromFRR(ctx, route); err != nil {
		m.logger.Warn("Failed to withdraw route, queuing for retry",
			zap.String("ip", ipStr),
			zap.Error(err),
		)

		m.mu.Lock()
		m.stats.WithdrawalFailures++
		m.mu.Unlock()

		m.queueRetry(&routeOperation{
			Type:      routeOpWithdraw,
			Route:     route,
			Retries:   0,
			CreatedAt: time.Now(),
		})

		return err
	}

	m.mu.Lock()
	m.stats.RoutesWithdrawn++
	m.stats.WithdrawalSuccesses++
	m.mu.Unlock()

	m.logger.Info("Withdrew subscriber route",
		zap.String("ip", ipStr),
		zap.String("session_id", sessionID),
	)

	return nil
}

// BulkInjectRoutes injects multiple routes in batches.
// This is useful for session recovery during BNG startup.
func (m *SubscriberRouteManager) BulkInjectRoutes(ctx context.Context, routes []*SubscriberRoute) error {
	m.logger.Info("Starting bulk route injection",
		zap.Int("total_routes", len(routes)),
		zap.Int("batch_size", m.config.BulkBatchSize),
	)

	start := time.Now()
	successCount := 0
	failCount := 0

	for i := 0; i < len(routes); i += m.config.BulkBatchSize {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		end := i + m.config.BulkBatchSize
		if end > len(routes) {
			end = len(routes)
		}
		batch := routes[i:end]

		for _, route := range batch {
			err := m.InjectRoute(ctx, route.SessionID, route.SubscriberID, route.IP, route.SubscriberClass)
			if err != nil {
				failCount++
			} else {
				successCount++
			}
		}

		// Delay between batches
		if m.config.BulkBatchDelay > 0 && end < len(routes) {
			time.Sleep(m.config.BulkBatchDelay)
		}
	}

	m.mu.Lock()
	m.stats.BulkInjections++
	m.mu.Unlock()

	duration := time.Since(start)
	m.logger.Info("Bulk route injection completed",
		zap.Int("success", successCount),
		zap.Int("failed", failCount),
		zap.Duration("duration", duration),
		zap.Float64("routes_per_second", float64(successCount)/duration.Seconds()),
	)

	if failCount > 0 {
		return fmt.Errorf("bulk injection completed with %d failures", failCount)
	}
	return nil
}

// BulkWithdrawRoutes withdraws multiple routes in batches.
// This is useful for graceful BNG shutdown.
func (m *SubscriberRouteManager) BulkWithdrawRoutes(ctx context.Context) error {
	m.mu.RLock()
	routes := make([]*SubscriberRoute, 0, len(m.activeRoutes))
	for _, route := range m.activeRoutes {
		routes = append(routes, route)
	}
	m.mu.RUnlock()

	m.logger.Info("Starting bulk route withdrawal",
		zap.Int("total_routes", len(routes)),
	)

	start := time.Now()
	successCount := 0
	failCount := 0

	for i := 0; i < len(routes); i += m.config.BulkBatchSize {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		end := i + m.config.BulkBatchSize
		if end > len(routes) {
			end = len(routes)
		}
		batch := routes[i:end]

		for _, route := range batch {
			err := m.WithdrawRoute(ctx, route.SessionID, route.IP)
			if err != nil {
				failCount++
			} else {
				successCount++
			}
		}

		if m.config.BulkBatchDelay > 0 && end < len(routes) {
			time.Sleep(m.config.BulkBatchDelay)
		}
	}

	duration := time.Since(start)
	m.logger.Info("Bulk route withdrawal completed",
		zap.Int("success", successCount),
		zap.Int("failed", failCount),
		zap.Duration("duration", duration),
	)

	if failCount > 0 {
		return fmt.Errorf("bulk withdrawal completed with %d failures", failCount)
	}
	return nil
}

// GetActiveRoutes returns all active subscriber routes.
func (m *SubscriberRouteManager) GetActiveRoutes() []*SubscriberRoute {
	m.mu.RLock()
	defer m.mu.RUnlock()

	routes := make([]*SubscriberRoute, 0, len(m.activeRoutes))
	for _, route := range m.activeRoutes {
		routes = append(routes, route)
	}
	return routes
}

// GetRouteByIP returns a route by IP address.
func (m *SubscriberRouteManager) GetRouteByIP(ip net.IP) (*SubscriberRoute, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	route, ok := m.activeRoutes[ip.String()]
	return route, ok
}

// Stats returns subscriber route statistics.
func (m *SubscriberRouteManager) Stats() SubscriberRouteStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// injectRouteToFRR injects a route into FRR via vtysh.
func (m *SubscriberRouteManager) injectRouteToFRR(ctx context.Context, route *SubscriberRoute) error {
	// Build /32 prefix
	prefix := fmt.Sprintf("%s/32", route.IP.String())

	// Use BGPController if available
	if m.bgp != nil {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return fmt.Errorf("parse prefix: %w", err)
		}
		return m.bgp.AnnouncePrefix(ipNet)
	}

	// Otherwise use direct vtysh execution
	if m.frrExecutor == nil {
		return fmt.Errorf("no FRR executor configured")
	}

	cmd := fmt.Sprintf(`configure terminal
router bgp %d
address-family ipv4 unicast
network %s
exit-address-family
end`, m.config.LocalAS, prefix)

	_, err := m.frrExecutor.ExecuteCommand(ctx, cmd)
	return err
}

// withdrawRouteFromFRR withdraws a route from FRR via vtysh.
func (m *SubscriberRouteManager) withdrawRouteFromFRR(ctx context.Context, route *SubscriberRoute) error {
	prefix := fmt.Sprintf("%s/32", route.IP.String())

	// Use BGPController if available
	if m.bgp != nil {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return fmt.Errorf("parse prefix: %w", err)
		}
		return m.bgp.WithdrawPrefix(ipNet)
	}

	// Otherwise use direct vtysh execution
	if m.frrExecutor == nil {
		return fmt.Errorf("no FRR executor configured")
	}

	cmd := fmt.Sprintf(`configure terminal
router bgp %d
address-family ipv4 unicast
no network %s
exit-address-family
end`, m.config.LocalAS, prefix)

	_, err := m.frrExecutor.ExecuteCommand(ctx, cmd)
	return err
}

// setGracefulShutdownCommunity applies the GRACEFUL_SHUTDOWN community to a route.
func (m *SubscriberRouteManager) setGracefulShutdownCommunity(ctx context.Context, route *SubscriberRoute) error {
	// GRACEFUL_SHUTDOWN is well-known community 65535:0 (RFC 8326)
	// This requires a route-map, which is more complex to implement dynamically
	// For now, log the intent - full implementation would require:
	// 1. Creating a prefix-list for this specific prefix
	// 2. Creating/updating a route-map to set community
	// 3. Applying the route-map
	m.logger.Debug("Graceful shutdown community would be applied",
		zap.String("ip", route.IP.String()),
		zap.String("community", "65535:0"),
	)
	return nil
}

// queueRetry queues an operation for retry.
func (m *SubscriberRouteManager) queueRetry(op *routeOperation) {
	select {
	case m.pendingOps <- op:
		m.mu.Lock()
		m.stats.RetryAttempts++
		m.mu.Unlock()
	default:
		m.logger.Warn("Retry queue full, dropping operation",
			zap.String("ip", op.Route.IP.String()),
		)
	}
}

// retryWorker processes the retry queue.
func (m *SubscriberRouteManager) retryWorker() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.RetryInterval)
	defer ticker.Stop()

	var pending []*routeOperation

	for {
		select {
		case <-m.ctx.Done():
			return

		case op := <-m.pendingOps:
			pending = append(pending, op)

		case <-ticker.C:
			if len(pending) == 0 {
				continue
			}

			var remaining []*routeOperation
			for _, op := range pending {
				var err error

				switch op.Type {
				case routeOpInject:
					err = m.injectRouteToFRR(m.ctx, op.Route)
					if err == nil {
						m.mu.Lock()
						m.stats.InjectionSuccesses++
						m.mu.Unlock()
					}
				case routeOpWithdraw:
					err = m.withdrawRouteFromFRR(m.ctx, op.Route)
					if err == nil {
						m.mu.Lock()
						m.stats.WithdrawalSuccesses++
						m.mu.Unlock()
					}
				}

				if err != nil {
					op.Retries++
					if op.Retries < m.config.MaxRetries {
						remaining = append(remaining, op)
						m.logger.Debug("Retry failed, will try again",
							zap.String("ip", op.Route.IP.String()),
							zap.Int("attempt", op.Retries),
							zap.Error(err),
						)
					} else {
						m.logger.Error("Max retries exceeded for route operation",
							zap.String("ip", op.Route.IP.String()),
							zap.Int("type", int(op.Type)),
							zap.Error(err),
						)
					}
				} else {
					m.logger.Debug("Retry succeeded",
						zap.String("ip", op.Route.IP.String()),
						zap.Int("attempt", op.Retries),
					)
				}
			}
			pending = remaining
		}
	}
}

// ReconcileRoutes compares active routes with FRR state and reconciles differences.
// This is useful after FRR restarts to ensure consistency.
func (m *SubscriberRouteManager) ReconcileRoutes(ctx context.Context) error {
	m.logger.Info("Starting route reconciliation")

	m.mu.RLock()
	routes := make([]*SubscriberRoute, 0, len(m.activeRoutes))
	for _, route := range m.activeRoutes {
		routes = append(routes, route)
	}
	m.mu.RUnlock()

	// Re-inject all active routes
	successCount := 0
	failCount := 0

	for _, route := range routes {
		err := m.injectRouteToFRR(ctx, route)
		if err != nil {
			failCount++
			m.logger.Warn("Failed to reconcile route",
				zap.String("ip", route.IP.String()),
				zap.Error(err),
			)
		} else {
			successCount++
			route.LastRefresh = time.Now()
		}
	}

	m.logger.Info("Route reconciliation completed",
		zap.Int("success", successCount),
		zap.Int("failed", failCount),
	)

	if failCount > 0 {
		return fmt.Errorf("reconciliation completed with %d failures", failCount)
	}
	return nil
}
