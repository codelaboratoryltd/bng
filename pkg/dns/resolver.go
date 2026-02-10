package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

// Resolver handles DNS resolution with caching and interception.
type Resolver struct {
	config Config
	logger *zap.Logger

	mu sync.RWMutex

	// Cache
	cache *Cache

	// Interception rules
	rules []*InterceptRule

	// Walled garden clients (IP -> client info)
	walledGardenClients map[string]*WalledGardenClient

	// Rate limiting (IP -> last query count)
	rateLimiter map[string]*rateLimitEntry

	// Upstream connections
	upstreamIndex int32 // For round-robin

	// Statistics
	stats ServerStats

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type rateLimitEntry struct {
	count     int64
	resetTime time.Time
}

// NewResolver creates a new DNS resolver.
func NewResolver(config Config, logger *zap.Logger) *Resolver {
	ctx, cancel := context.WithCancel(context.Background())

	r := &Resolver{
		config:              config,
		logger:              logger,
		rules:               make([]*InterceptRule, 0),
		walledGardenClients: make(map[string]*WalledGardenClient),
		rateLimiter:         make(map[string]*rateLimitEntry),
		ctx:                 ctx,
		cancel:              cancel,
		stats: ServerStats{
			QueryTypeStats: make(map[uint16]int64),
		},
	}

	// Initialize cache if enabled
	if config.CacheEnabled {
		r.cache = NewCache(
			config.CacheSize,
			config.CacheMinTTL,
			config.CacheMaxTTL,
			config.CacheNegativeTTL,
		)
	}

	return r
}

// Start starts the DNS resolver.
func (r *Resolver) Start() error {
	r.logger.Info("Starting DNS resolver",
		zap.String("address", r.config.ListenAddress),
		zap.Bool("cache", r.config.CacheEnabled),
		zap.Bool("dns64", r.config.DNS64Enabled),
	)

	// Start cache cleanup
	if r.config.CacheEnabled {
		r.wg.Add(1)
		go r.cacheCleanupLoop()
	}

	// Start rate limit cleanup
	if r.config.RateLimitEnabled {
		r.wg.Add(1)
		go r.rateLimitCleanupLoop()
	}

	r.logger.Info("DNS resolver started")
	return nil
}

// Stop stops the DNS resolver.
func (r *Resolver) Stop() error {
	r.logger.Info("Stopping DNS resolver")

	r.cancel()
	r.wg.Wait()

	r.logger.Info("DNS resolver stopped")
	return nil
}

// Resolve handles a DNS query.
func (r *Resolver) Resolve(ctx context.Context, query *Query) (*Response, error) {
	start := time.Now()

	r.mu.Lock()
	r.stats.QueriesReceived++
	r.stats.QueryTypeStats[query.Type]++
	r.mu.Unlock()

	// Check rate limit
	if r.config.RateLimitEnabled && !r.checkRateLimit(query.Source) {
		r.mu.Lock()
		r.stats.QueriesRateLimited++
		r.mu.Unlock()

		return &Response{
			Query: query,
			Rcode: RcodeRefused,
		}, nil
	}

	// Check walled garden
	if r.config.WalledGardenEnabled && r.isInWalledGarden(query.Source) {
		return r.handleWalledGardenQuery(query)
	}

	// Check interception rules
	if action, response := r.checkInterceptionRules(query); action != ActionAllow {
		r.mu.Lock()
		r.stats.QueriesBlocked++
		r.mu.Unlock()
		return response, nil
	}

	// Check cache
	if r.config.CacheEnabled {
		cacheKey := CacheKey(query.Name, query.Type, query.Class)
		if entry, hit := r.cache.Get(cacheKey); hit {
			r.mu.Lock()
			r.stats.QueriesFromCache++
			r.mu.Unlock()

			response := &Response{
				Query:     query,
				Answers:   entry.Records,
				FromCache: true,
				Latency:   time.Since(start),
			}

			if entry.Negative {
				response.Rcode = RcodeNameError
			} else {
				response.Rcode = RcodeSuccess
			}

			return response, nil
		}
	}

	// Forward to upstream
	response, err := r.forwardQuery(ctx, query)
	if err != nil {
		r.mu.Lock()
		r.stats.Errors++
		r.mu.Unlock()
		return nil, err
	}

	response.Latency = time.Since(start)

	// Apply DNS64 if needed
	if r.config.DNS64Enabled && query.Type == TypeAAAA && len(response.Answers) == 0 {
		dns64Response, err := r.applyDNS64(ctx, query)
		if err == nil && len(dns64Response.Answers) > 0 {
			r.mu.Lock()
			r.stats.DNS64Translations++
			r.mu.Unlock()
			response = dns64Response
		}
	}

	// Cache the response
	if r.config.CacheEnabled && len(response.Answers) > 0 {
		r.cacheResponse(query, response)
	} else if r.config.CacheEnabled && response.Rcode == RcodeNameError {
		// Cache negative response
		cacheKey := CacheKey(query.Name, query.Type, query.Class)
		r.cache.SetNegative(cacheKey)
	}

	// Update stats
	r.updateLatencyStats(response.Latency)

	return response, nil
}

// AddInterceptRule adds a DNS interception rule.
func (r *Resolver) AddInterceptRule(rule *InterceptRule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, rule)

	r.logger.Info("Added DNS intercept rule",
		zap.String("domain", rule.Domain),
		zap.Int("action", int(rule.Action)),
	)
}

// RemoveInterceptRule removes a DNS interception rule.
func (r *Resolver) RemoveInterceptRule(domain string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, rule := range r.rules {
		if rule.Domain == domain {
			r.rules = append(r.rules[:i], r.rules[i+1:]...)
			return true
		}
	}
	return false
}

// AddWalledGardenClient adds a client to the walled garden.
func (r *Resolver) AddWalledGardenClient(client *WalledGardenClient) {
	r.mu.Lock()
	defer r.mu.Unlock()

	client.AddedAt = time.Now()
	r.walledGardenClients[client.IP.String()] = client

	r.logger.Info("Added client to walled garden",
		zap.String("ip", client.IP.String()),
		zap.String("subscriber", client.SubscriberID),
		zap.String("reason", client.Reason),
	)
}

// RemoveWalledGardenClient removes a client from the walled garden.
func (r *Resolver) RemoveWalledGardenClient(ip net.IP) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := ip.String()
	if _, exists := r.walledGardenClients[key]; exists {
		delete(r.walledGardenClients, key)
		r.logger.Info("Removed client from walled garden", zap.String("ip", key))
		return true
	}
	return false
}

// IsInWalledGarden checks if an IP is in the walled garden.
func (r *Resolver) IsInWalledGarden(ip net.IP) bool {
	return r.isInWalledGarden(ip)
}

// Stats returns resolver statistics.
func (r *Resolver) Stats() ServerStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := r.stats

	if r.cache != nil {
		stats.Cache = r.cache.Stats()
	}

	// Copy map
	stats.QueryTypeStats = make(map[uint16]int64)
	for k, v := range r.stats.QueryTypeStats {
		stats.QueryTypeStats[k] = v
	}

	return stats
}

// forwardQuery forwards a query to an upstream resolver.
func (r *Resolver) forwardQuery(ctx context.Context, query *Query) (*Response, error) {
	// Select upstream (round-robin)
	if len(r.config.Upstreams) == 0 {
		return nil, fmt.Errorf("no upstream resolvers configured")
	}

	idx := atomic.AddInt32(&r.upstreamIndex, 1) % int32(len(r.config.Upstreams))
	upstream := r.config.Upstreams[idx]

	r.mu.Lock()
	r.stats.QueriesForwarded++
	r.mu.Unlock()

	// Build DNS message
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(time.Now().UnixNano() & 0xFFFF),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  mustParseName(query.Name),
				Type:  dnsmessage.Type(query.Type),
				Class: dnsmessage.Class(query.Class),
			},
		},
	}

	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS message: %w", err)
	}

	// Send query
	var conn net.Conn
	switch upstream.Protocol {
	case "udp", "":
		conn, err = net.DialTimeout("udp", upstream.Address, upstream.Timeout)
	case "tcp":
		conn, err = net.DialTimeout("tcp", upstream.Address, upstream.Timeout)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", upstream.Protocol)
	}

	if err != nil {
		return nil, fmt.Errorf("connect to upstream %s: %w", upstream.Address, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(upstream.Timeout))

	// For TCP, prepend length
	if upstream.Protocol == "tcp" {
		lenBuf := make([]byte, 2)
		lenBuf[0] = byte(len(packed) >> 8)
		lenBuf[1] = byte(len(packed))
		_, err = conn.Write(append(lenBuf, packed...))
	} else {
		_, err = conn.Write(packed)
	}

	if err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	// Read response
	buf := make([]byte, 4096)
	var n int

	if upstream.Protocol == "tcp" {
		// Read length first
		_, err = conn.Read(buf[:2])
		if err != nil {
			return nil, fmt.Errorf("read response length: %w", err)
		}
		respLen := int(buf[0])<<8 | int(buf[1])
		n, err = conn.Read(buf[:respLen])
	} else {
		n, err = conn.Read(buf)
	}

	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Parse response
	var respMsg dnsmessage.Message
	if err := respMsg.Unpack(buf[:n]); err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	// Convert to our Response type
	response := &Response{
		Query:     query,
		Rcode:     int(respMsg.RCode),
		FromCache: false,
	}

	// Parse answers
	for _, ans := range respMsg.Answers {
		record := r.resourceToRecord(ans)
		response.Answers = append(response.Answers, record)
	}

	// Parse authorities
	for _, auth := range respMsg.Authorities {
		record := r.resourceToRecord(auth)
		response.Authorities = append(response.Authorities, record)
	}

	// Parse additionals
	for _, add := range respMsg.Additionals {
		record := r.resourceToRecord(add)
		response.Additionals = append(response.Additionals, record)
	}

	return response, nil
}

// resourceToRecord converts a DNS resource to our Record type.
func (r *Resolver) resourceToRecord(res dnsmessage.Resource) Record {
	record := Record{
		Name:  res.Header.Name.String(),
		Type:  uint16(res.Header.Type),
		Class: uint16(res.Header.Class),
		TTL:   res.Header.TTL,
	}

	switch body := res.Body.(type) {
	case *dnsmessage.AResource:
		record.IPv4 = net.IP(body.A[:])
	case *dnsmessage.AAAAResource:
		record.IPv6 = net.IP(body.AAAA[:])
	case *dnsmessage.CNAMEResource:
		record.Target = body.CNAME.String()
	case *dnsmessage.MXResource:
		record.Target = body.MX.String()
		record.MXPref = body.Pref
	case *dnsmessage.NSResource:
		record.Target = body.NS.String()
	case *dnsmessage.PTRResource:
		record.Target = body.PTR.String()
	case *dnsmessage.TXTResource:
		for _, txt := range body.TXT {
			record.TXT += txt
		}
	}

	return record
}

// checkInterceptionRules checks if a query matches any interception rules.
func (r *Resolver) checkInterceptionRules(query *Query) (InterceptAction, *Response) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, rule := range r.rules {
		if r.matchRule(rule, query.Name) {
			switch rule.Action {
			case ActionBlock:
				return ActionBlock, &Response{
					Query: query,
					Rcode: RcodeNameError,
				}
			case ActionRedirect:
				return ActionRedirect, r.createRedirectResponse(query, rule.RedirectIP)
			case ActionCNAME:
				return ActionCNAME, r.createCNAMEResponse(query, rule.CNAME)
			}
		}
	}

	return ActionAllow, nil
}

// matchRule checks if a domain matches a rule.
func (r *Resolver) matchRule(rule *InterceptRule, domain string) bool {
	if rule.Exact {
		return domain == rule.Domain || domain == rule.Domain+"."
	}

	if rule.DomainSuffix != "" {
		return len(domain) >= len(rule.DomainSuffix) &&
			domain[len(domain)-len(rule.DomainSuffix):] == rule.DomainSuffix
	}

	// Simple wildcard matching
	if rule.Domain != "" {
		// Check exact match
		if domain == rule.Domain || domain == rule.Domain+"." {
			return true
		}
		// Check subdomain match
		suffix := "." + rule.Domain
		return len(domain) > len(suffix) && domain[len(domain)-len(suffix):] == suffix
	}

	return false
}

// createRedirectResponse creates a response that redirects to a different IP.
func (r *Resolver) createRedirectResponse(query *Query, ip net.IP) *Response {
	record := Record{
		Name:  query.Name,
		Class: query.Class,
		TTL:   300,
	}

	if query.Type == TypeA && ip.To4() != nil {
		record.Type = TypeA
		record.IPv4 = ip.To4()
	} else if query.Type == TypeAAAA && ip.To16() != nil {
		record.Type = TypeAAAA
		record.IPv6 = ip.To16()
	}

	return &Response{
		Query:   query,
		Answers: []Record{record},
		Rcode:   RcodeSuccess,
	}
}

// createCNAMEResponse creates a CNAME response.
func (r *Resolver) createCNAMEResponse(query *Query, target string) *Response {
	record := Record{
		Name:   query.Name,
		Type:   TypeCNAME,
		Class:  query.Class,
		TTL:    300,
		Target: target,
	}

	return &Response{
		Query:   query,
		Answers: []Record{record},
		Rcode:   RcodeSuccess,
	}
}

// isInWalledGarden checks if an IP is in the walled garden.
func (r *Resolver) isInWalledGarden(ip net.IP) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.walledGardenClients[ip.String()]
	return exists
}

// handleWalledGardenQuery handles DNS queries from walled garden clients.
func (r *Resolver) handleWalledGardenQuery(query *Query) (*Response, error) {
	// Redirect all queries to the walled garden portal IP
	if query.Type == TypeA || query.Type == TypeAAAA {
		return r.createRedirectResponse(query, r.config.WalledGardenRedirectIP), nil
	}

	// For other query types, return NXDOMAIN
	return &Response{
		Query: query,
		Rcode: RcodeNameError,
	}, nil
}

// applyDNS64 applies DNS64 translation (synthesize AAAA from A).
func (r *Resolver) applyDNS64(ctx context.Context, query *Query) (*Response, error) {
	// Query for A record instead
	aQuery := &Query{
		Name:   query.Name,
		Type:   TypeA,
		Class:  query.Class,
		Source: query.Source,
	}

	aResponse, err := r.forwardQuery(ctx, aQuery)
	if err != nil || len(aResponse.Answers) == 0 {
		return nil, err
	}

	// Synthesize AAAA records from A records
	response := &Response{
		Query: query,
		Rcode: RcodeSuccess,
	}

	for _, ans := range aResponse.Answers {
		if ans.Type == TypeA && ans.IPv4 != nil {
			// Synthesize IPv6 address: prefix + IPv4
			ipv6 := make(net.IP, 16)
			copy(ipv6, r.config.DNS64Prefix.IP)
			copy(ipv6[12:], ans.IPv4.To4())

			record := Record{
				Name:  ans.Name,
				Type:  TypeAAAA,
				Class: ans.Class,
				TTL:   ans.TTL,
				IPv6:  ipv6,
			}
			response.Answers = append(response.Answers, record)
		}
	}

	return response, nil
}

// cacheResponse caches a DNS response.
func (r *Resolver) cacheResponse(query *Query, response *Response) {
	if len(response.Answers) == 0 {
		return
	}

	// Find minimum TTL
	minTTL := uint32(86400) // 1 day default
	for _, ans := range response.Answers {
		if ans.TTL < minTTL {
			minTTL = ans.TTL
		}
	}

	cacheKey := CacheKey(query.Name, query.Type, query.Class)
	entry := &CacheEntry{
		Key:       cacheKey,
		Records:   response.Answers,
		ExpiresAt: time.Now().Add(time.Duration(minTTL) * time.Second),
		CreatedAt: time.Now(),
	}

	r.cache.Set(entry)
}

// checkRateLimit checks if a client is rate limited.
func (r *Resolver) checkRateLimit(ip net.IP) bool {
	key := ip.String()
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.rateLimiter[key]
	if !exists || now.After(entry.resetTime) {
		r.rateLimiter[key] = &rateLimitEntry{
			count:     1,
			resetTime: now.Add(time.Second),
		}
		return true
	}

	entry.count++
	return entry.count <= int64(r.config.RateLimitQPS)
}

// updateLatencyStats updates average latency statistics.
func (r *Resolver) updateLatencyStats(latency time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Simple moving average
	total := r.stats.QueriesReceived
	if total > 1 {
		r.stats.AvgLatencyMS = (r.stats.AvgLatencyMS*float64(total-1) + float64(latency.Milliseconds())) / float64(total)
	} else {
		r.stats.AvgLatencyMS = float64(latency.Milliseconds())
	}
}

// cacheCleanupLoop periodically cleans up expired cache entries.
func (r *Resolver) cacheCleanupLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			if r.cache != nil {
				removed := r.cache.Cleanup()
				if removed > 0 {
					r.logger.Debug("Cache cleanup", zap.Int("removed", removed))
				}
			}
		}
	}
}

// rateLimitCleanupLoop periodically cleans up old rate limit entries.
func (r *Resolver) rateLimitCleanupLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.cleanupRateLimiter()
		}
	}
}

// cleanupRateLimiter removes old rate limit entries.
func (r *Resolver) cleanupRateLimiter() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for key, entry := range r.rateLimiter {
		if now.After(entry.resetTime.Add(10 * time.Second)) {
			delete(r.rateLimiter, key)
		}
	}
}

// mustParseName parses a domain name, panicking on error.
func mustParseName(s string) dnsmessage.Name {
	if len(s) == 0 || s[len(s)-1] != '.' {
		s = s + "."
	}
	return dnsmessage.MustNewName(s)
}
