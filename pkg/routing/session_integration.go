package routing

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SessionRouteIntegration integrates the subscriber route manager with
// session lifecycle events. It automatically injects routes when sessions
// become active and withdraws them on termination.
type SessionRouteIntegration struct {
	routeManager *SubscriberRouteManager
	bgp          *BGPController
	bfd          *BFDManager
	logger       *zap.Logger

	mu sync.RWMutex

	// Session tracking
	activeSessions map[string]*trackedSession

	// Configuration
	config SessionRouteConfig

	ctx    context.Context
	cancel context.CancelFunc
}

// SessionRouteConfig holds configuration for session-route integration.
type SessionRouteConfig struct {
	// EnableRouteInjection enables automatic route injection on session activation.
	EnableRouteInjection bool

	// EnableRouteWithdrawal enables automatic route withdrawal on session termination.
	EnableRouteWithdrawal bool

	// InjectionTimeout is the maximum time to wait for route injection.
	InjectionTimeout time.Duration

	// WithdrawalTimeout is the maximum time to wait for route withdrawal.
	WithdrawalTimeout time.Duration

	// DefaultSubscriberClass is the default subscriber class for route communities.
	DefaultSubscriberClass string
}

// DefaultSessionRouteConfig returns sensible defaults.
func DefaultSessionRouteConfig() SessionRouteConfig {
	return SessionRouteConfig{
		EnableRouteInjection:  true,
		EnableRouteWithdrawal: true,
		InjectionTimeout:      5 * time.Second,
		WithdrawalTimeout:     5 * time.Second,
	}
}

// trackedSession represents a session being tracked for routing.
type trackedSession struct {
	SessionID       string
	SubscriberID    string
	SubscriberClass string
	IPv4            net.IP
	IPv6            net.IP
	RouteInjected   bool
	InjectedAt      time.Time
}

// NewSessionRouteIntegration creates a new session-route integration.
func NewSessionRouteIntegration(
	routeManager *SubscriberRouteManager,
	bgp *BGPController,
	bfd *BFDManager,
	config SessionRouteConfig,
	logger *zap.Logger,
) *SessionRouteIntegration {
	ctx, cancel := context.WithCancel(context.Background())

	return &SessionRouteIntegration{
		routeManager:   routeManager,
		bgp:            bgp,
		bfd:            bfd,
		logger:         logger,
		activeSessions: make(map[string]*trackedSession),
		config:         config,
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start begins the session-route integration.
func (i *SessionRouteIntegration) Start() error {
	i.logger.Info("Starting session-route integration",
		zap.Bool("injection_enabled", i.config.EnableRouteInjection),
		zap.Bool("withdrawal_enabled", i.config.EnableRouteWithdrawal),
	)
	return nil
}

// Stop shuts down the session-route integration.
func (i *SessionRouteIntegration) Stop() error {
	i.logger.Info("Stopping session-route integration")
	i.cancel()
	return nil
}

// OnSessionActivate should be called when a subscriber session becomes active.
// It injects a /32 route for the subscriber's IP address.
func (i *SessionRouteIntegration) OnSessionActivate(sessionID, subscriberID string, ipv4, ipv6 net.IP, subscriberClass string) error {
	if !i.config.EnableRouteInjection {
		return nil
	}

	i.mu.Lock()
	// Check if already tracking this session
	if existing, exists := i.activeSessions[sessionID]; exists {
		if existing.RouteInjected {
			i.mu.Unlock()
			i.logger.Debug("Route already injected for session",
				zap.String("session_id", sessionID),
			)
			return nil
		}
	}

	// Track the session
	session := &trackedSession{
		SessionID:       sessionID,
		SubscriberID:    subscriberID,
		SubscriberClass: subscriberClass,
		IPv4:            ipv4,
		IPv6:            ipv6,
	}
	i.activeSessions[sessionID] = session
	i.mu.Unlock()

	// Inject IPv4 route
	if ipv4 != nil && ipv4.To4() != nil {
		ctx, cancel := context.WithTimeout(i.ctx, i.config.InjectionTimeout)
		defer cancel()

		class := subscriberClass
		if class == "" {
			class = i.config.DefaultSubscriberClass
		}

		start := time.Now()
		err := i.routeManager.InjectRoute(ctx, sessionID, subscriberID, ipv4, class)
		duration := time.Since(start)

		if err != nil {
			i.logger.Error("Failed to inject route for session",
				zap.String("session_id", sessionID),
				zap.String("ipv4", ipv4.String()),
				zap.Duration("duration", duration),
				zap.Error(err),
			)
			return fmt.Errorf("inject route for %s: %w", ipv4.String(), err)
		}

		i.mu.Lock()
		if tracked, ok := i.activeSessions[sessionID]; ok {
			tracked.RouteInjected = true
			tracked.InjectedAt = time.Now()
		}
		i.mu.Unlock()

		i.logger.Info("Route injected for session activation",
			zap.String("session_id", sessionID),
			zap.String("subscriber_id", subscriberID),
			zap.String("ipv4", ipv4.String()),
			zap.String("class", class),
			zap.Duration("duration", duration),
		)
	}

	// TODO: Add IPv6 route injection when supported

	return nil
}

// OnSessionTerminate should be called when a subscriber session terminates.
// It withdraws the /32 route for the subscriber's IP address.
func (i *SessionRouteIntegration) OnSessionTerminate(sessionID string, reason string) error {
	if !i.config.EnableRouteWithdrawal {
		return nil
	}

	i.mu.Lock()
	session, exists := i.activeSessions[sessionID]
	if !exists {
		i.mu.Unlock()
		i.logger.Debug("No tracked route for terminated session",
			zap.String("session_id", sessionID),
		)
		return nil
	}

	// Remove from tracking
	delete(i.activeSessions, sessionID)
	i.mu.Unlock()

	// Withdraw IPv4 route
	if session.IPv4 != nil && session.IPv4.To4() != nil && session.RouteInjected {
		ctx, cancel := context.WithTimeout(i.ctx, i.config.WithdrawalTimeout)
		defer cancel()

		start := time.Now()
		err := i.routeManager.WithdrawRoute(ctx, sessionID, session.IPv4)
		duration := time.Since(start)

		if err != nil {
			i.logger.Error("Failed to withdraw route for session",
				zap.String("session_id", sessionID),
				zap.String("ipv4", session.IPv4.String()),
				zap.Duration("duration", duration),
				zap.Error(err),
			)
			return fmt.Errorf("withdraw route for %s: %w", session.IPv4.String(), err)
		}

		i.logger.Info("Route withdrawn for session termination",
			zap.String("session_id", sessionID),
			zap.String("ipv4", session.IPv4.String()),
			zap.String("reason", reason),
			zap.Duration("duration", duration),
		)
	}

	return nil
}

// OnSessionStateChange handles session state transitions.
// This is a convenience method that routes to the appropriate handler.
func (i *SessionRouteIntegration) OnSessionStateChange(
	sessionID, subscriberID string,
	oldState, newState string,
	ipv4, ipv6 net.IP,
	subscriberClass, reason string,
) error {
	switch newState {
	case "active":
		return i.OnSessionActivate(sessionID, subscriberID, ipv4, ipv6, subscriberClass)
	case "terminated", "error", "timeout":
		return i.OnSessionTerminate(sessionID, reason)
	default:
		// Intermediate states - no route changes
		return nil
	}
}

// RecoverRoutes re-injects routes for all tracked sessions.
// This should be called after FRR restarts to reconcile state.
func (i *SessionRouteIntegration) RecoverRoutes(ctx context.Context) error {
	i.mu.RLock()
	sessionCount := len(i.activeSessions)
	i.mu.RUnlock()

	i.logger.Info("Recovering routes for active sessions",
		zap.Int("session_count", sessionCount),
	)

	// Use ReconcileRoutes which re-injects all routes regardless of cache state
	return i.routeManager.ReconcileRoutes(ctx)
}

// GetTrackedSessions returns all tracked sessions.
func (i *SessionRouteIntegration) GetTrackedSessions() []*trackedSession {
	i.mu.RLock()
	defer i.mu.RUnlock()

	sessions := make([]*trackedSession, 0, len(i.activeSessions))
	for _, s := range i.activeSessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// Stats returns integration statistics.
func (i *SessionRouteIntegration) Stats() SessionRouteIntegrationStats {
	i.mu.RLock()
	defer i.mu.RUnlock()

	stats := SessionRouteIntegrationStats{
		TrackedSessions: len(i.activeSessions),
	}

	for _, s := range i.activeSessions {
		if s.RouteInjected {
			stats.InjectedRoutes++
		}
	}

	if i.routeManager != nil {
		routeStats := i.routeManager.Stats()
		stats.RouteManagerStats = routeStats
	}

	return stats
}

// SessionRouteIntegrationStats contains integration statistics.
type SessionRouteIntegrationStats struct {
	TrackedSessions   int                  `json:"tracked_sessions"`
	InjectedRoutes    int                  `json:"injected_routes"`
	RouteManagerStats SubscriberRouteStats `json:"route_manager_stats"`
}

// SessionEventHandler returns an event handler function compatible with
// the subscriber.Manager.OnEvent interface.
func (i *SessionRouteIntegration) SessionEventHandler() func(event interface{}) {
	return func(event interface{}) {
		// Type assertion based on expected event structure
		// This allows integration with the subscriber package without
		// creating a direct dependency
		if e, ok := event.(interface {
			GetType() string
			GetSessionID() string
			GetOldState() string
			GetNewState() string
			GetReason() string
		}); ok {
			eventType := e.GetType()
			sessionID := e.GetSessionID()
			oldState := e.GetOldState()
			newState := e.GetNewState()
			reason := e.GetReason()

			switch eventType {
			case "session_activate":
				// Need additional info (IP, subscriber details) - log for now
				i.logger.Debug("Session activate event received",
					zap.String("session_id", sessionID),
				)
			case "session_terminate":
				i.OnSessionTerminate(sessionID, reason)
			default:
				i.logger.Debug("Unhandled session event",
					zap.String("type", eventType),
					zap.String("session_id", sessionID),
					zap.String("old_state", oldState),
					zap.String("new_state", newState),
				)
			}
		}
	}
}

// CreateEventAdapter creates an adapter that converts subscriber.SessionEvent
// to routing events. This allows clean integration between packages.
type SessionEventAdapter struct {
	integration *SessionRouteIntegration
	logger      *zap.Logger
}

// NewSessionEventAdapter creates a new session event adapter.
func NewSessionEventAdapter(integration *SessionRouteIntegration, logger *zap.Logger) *SessionEventAdapter {
	return &SessionEventAdapter{
		integration: integration,
		logger:      logger,
	}
}

// HandleActivation handles a session activation event with full details.
func (a *SessionEventAdapter) HandleActivation(sessionID, subscriberID string, ipv4, ipv6 net.IP, subscriberClass string) {
	if err := a.integration.OnSessionActivate(sessionID, subscriberID, ipv4, ipv6, subscriberClass); err != nil {
		a.logger.Error("Route injection failed on session activation",
			zap.String("session_id", sessionID),
			zap.Error(err),
		)
	}
}

// HandleTermination handles a session termination event.
func (a *SessionEventAdapter) HandleTermination(sessionID, reason string) {
	if err := a.integration.OnSessionTerminate(sessionID, reason); err != nil {
		a.logger.Error("Route withdrawal failed on session termination",
			zap.String("session_id", sessionID),
			zap.Error(err),
		)
	}
}
