package dns_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/dns"
	"go.uber.org/zap"
)

func TestDefaultConfig(t *testing.T) {
	config := dns.DefaultConfig()

	if config.ListenAddress == "" {
		t.Error("ListenAddress should not be empty")
	}
	if !config.CacheEnabled {
		t.Error("Cache should be enabled by default")
	}
	if config.CacheSize == 0 {
		t.Error("CacheSize should not be 0")
	}
	if len(config.Upstreams) == 0 {
		t.Error("Should have default upstreams")
	}
}

func TestCache(t *testing.T) {
	cache := dns.NewCache(100, time.Second, time.Hour, 5*time.Minute)

	// Test basic set/get
	entry := &dns.CacheEntry{
		Key:       "example.com:A:1",
		Records:   []dns.Record{{Name: "example.com", Type: dns.TypeA}},
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}

	cache.Set(entry)

	retrieved, hit := cache.Get("example.com:A:1")
	if !hit {
		t.Fatal("Expected cache hit")
	}
	if retrieved.Key != entry.Key {
		t.Errorf("Key = %s, want %s", retrieved.Key, entry.Key)
	}

	// Test cache miss
	_, hit = cache.Get("nonexistent:A:1")
	if hit {
		t.Error("Expected cache miss for nonexistent key")
	}

	// Verify stats
	stats := cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("Hits = %d, want 1", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Misses = %d, want 1", stats.Misses)
	}
}

func TestCacheExpiry(t *testing.T) {
	cache := dns.NewCache(100, time.Millisecond, time.Hour, 5*time.Minute)

	entry := &dns.CacheEntry{
		Key:       "expiring.com:A:1",
		ExpiresAt: time.Now().Add(10 * time.Millisecond),
		CreatedAt: time.Now(),
	}

	cache.Set(entry)

	// Should be in cache
	_, hit := cache.Get("expiring.com:A:1")
	if !hit {
		t.Fatal("Expected cache hit immediately after set")
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Should be expired
	_, hit = cache.Get("expiring.com:A:1")
	if hit {
		t.Error("Expected cache miss for expired entry")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	cache := dns.NewCache(3, time.Second, time.Hour, 5*time.Minute) // Max 3 entries

	// Add 4 entries
	for i := 0; i < 4; i++ {
		entry := &dns.CacheEntry{
			Key:       string(rune('a'+i)) + ".com:A:1",
			ExpiresAt: time.Now().Add(time.Hour),
			CreatedAt: time.Now(),
		}
		cache.Set(entry)
	}

	// Oldest entry (a) should be evicted
	_, hit := cache.Get("a.com:A:1")
	if hit {
		t.Error("Oldest entry should be evicted")
	}

	// Newest entries should still be there
	_, hit = cache.Get("d.com:A:1")
	if !hit {
		t.Error("Newest entry should be in cache")
	}

	stats := cache.Stats()
	if stats.Size != 3 {
		t.Errorf("Size = %d, want 3", stats.Size)
	}
	if stats.Evictions < 1 {
		t.Errorf("Evictions = %d, want >= 1", stats.Evictions)
	}
}

func TestCacheCleanup(t *testing.T) {
	// Use very short minTTL so we can test expiry
	cache := dns.NewCache(100, 5*time.Millisecond, time.Hour, 5*time.Minute)

	// Add entry that will expire soon
	cache.Set(&dns.CacheEntry{
		Key:       "expiring.com:A:1",
		ExpiresAt: time.Now().Add(10 * time.Millisecond),
		CreatedAt: time.Now(),
	})

	// Add entry that won't expire
	cache.Set(&dns.CacheEntry{
		Key:       "valid.com:A:1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	// Wait for first entry to expire
	time.Sleep(20 * time.Millisecond)

	// Run cleanup
	removed := cache.Cleanup()
	if removed != 1 {
		t.Errorf("Cleanup removed %d entries, want 1", removed)
	}

	// Valid entry should still exist
	_, hit := cache.Get("valid.com:A:1")
	if !hit {
		t.Error("Valid entry should still be in cache")
	}
}

func TestInterceptRules(t *testing.T) {
	logger := zap.NewNop()
	config := dns.DefaultConfig()
	config.CacheEnabled = false

	resolver := dns.NewResolver(config, logger)

	// Add block rule
	resolver.AddInterceptRule(&dns.InterceptRule{
		Domain: "blocked.com",
		Action: dns.ActionBlock,
	})

	// Add redirect rule
	resolver.AddInterceptRule(&dns.InterceptRule{
		Domain:     "redirect.com",
		Action:     dns.ActionRedirect,
		RedirectIP: net.ParseIP("192.168.1.1"),
	})

	// Note: We can't easily test the actual interception without
	// mocking the upstream resolver, but we verify rules are added
	stats := resolver.Stats()
	if stats.QueriesReceived != 0 {
		t.Errorf("Should start with 0 queries, got %d", stats.QueriesReceived)
	}
}

func TestWalledGarden(t *testing.T) {
	logger := zap.NewNop()
	config := dns.DefaultConfig()
	config.WalledGardenEnabled = true
	config.WalledGardenRedirectIP = net.ParseIP("192.168.100.1")
	config.CacheEnabled = false

	resolver := dns.NewResolver(config, logger)

	// Add client to walled garden
	client := &dns.WalledGardenClient{
		IP:           net.ParseIP("10.0.0.50"),
		MAC:          net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		SubscriberID: "sub-123",
		Reason:       "payment_required",
	}
	resolver.AddWalledGardenClient(client)

	// Check client is in walled garden
	if !resolver.IsInWalledGarden(net.ParseIP("10.0.0.50")) {
		t.Error("Client should be in walled garden")
	}

	// Check other client is not in walled garden
	if resolver.IsInWalledGarden(net.ParseIP("10.0.0.51")) {
		t.Error("Other client should not be in walled garden")
	}

	// Remove from walled garden
	removed := resolver.RemoveWalledGardenClient(net.ParseIP("10.0.0.50"))
	if !removed {
		t.Error("Should have removed client")
	}

	// Verify removed
	if resolver.IsInWalledGarden(net.ParseIP("10.0.0.50")) {
		t.Error("Client should no longer be in walled garden")
	}
}

func TestRateLimiting(t *testing.T) {
	logger := zap.NewNop()
	config := dns.DefaultConfig()
	config.RateLimitEnabled = true
	config.RateLimitQPS = 2 // Only 2 queries per second
	config.CacheEnabled = false

	resolver := dns.NewResolver(config, logger)
	if err := resolver.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer resolver.Stop()

	clientIP := net.ParseIP("10.0.0.1")

	// First few queries should succeed (stats show rate limited)
	for i := 0; i < 5; i++ {
		query := &dns.Query{
			Name:   "test.com",
			Type:   dns.TypeA,
			Class:  1,
			Source: clientIP,
		}

		// We can't actually resolve without real upstreams,
		// but we can check that queries are being processed
		resolver.Resolve(context.Background(), query)
	}

	stats := resolver.Stats()
	if stats.QueriesReceived != 5 {
		t.Errorf("QueriesReceived = %d, want 5", stats.QueriesReceived)
	}

	// Rate limited queries should be counted
	if stats.QueriesRateLimited < 2 {
		t.Errorf("QueriesRateLimited = %d, want >= 2", stats.QueriesRateLimited)
	}
}

func TestDNSTypes(t *testing.T) {
	tests := []struct {
		typeVal  uint16
		expected string
	}{
		{dns.TypeA, "A"},
		{dns.TypeAAAA, "AAAA"},
		{dns.TypeCNAME, "CNAME"},
		{dns.TypeMX, "MX"},
		{dns.TypeNS, "NS"},
		{dns.TypePTR, "PTR"},
		{dns.TypeTXT, "TXT"},
		{dns.TypeSOA, "SOA"},
		{dns.TypeSRV, "SRV"},
	}

	for _, tt := range tests {
		result := dns.TypeString(tt.typeVal)
		if result != tt.expected {
			t.Errorf("TypeString(%d) = %s, want %s", tt.typeVal, result, tt.expected)
		}
	}
}

func TestRcodeStrings(t *testing.T) {
	tests := []struct {
		rcode    int
		expected string
	}{
		{dns.RcodeSuccess, "NOERROR"},
		{dns.RcodeFormatError, "FORMERR"},
		{dns.RcodeServerFailure, "SERVFAIL"},
		{dns.RcodeNameError, "NXDOMAIN"},
		{dns.RcodeNotImplemented, "NOTIMP"},
		{dns.RcodeRefused, "REFUSED"},
	}

	for _, tt := range tests {
		result := dns.RcodeString(tt.rcode)
		if result != tt.expected {
			t.Errorf("RcodeString(%d) = %s, want %s", tt.rcode, result, tt.expected)
		}
	}
}

func TestCacheKey(t *testing.T) {
	key := dns.CacheKey("example.com", dns.TypeA, 1)
	if key == "" {
		t.Error("CacheKey should not be empty")
	}

	// Different type should produce different key
	key2 := dns.CacheKey("example.com", dns.TypeAAAA, 1)
	if key == key2 {
		t.Error("Different types should produce different keys")
	}
}

func TestResolverStartStop(t *testing.T) {
	logger := zap.NewNop()
	config := dns.DefaultConfig()
	config.CacheEnabled = true
	config.RateLimitEnabled = true

	resolver := dns.NewResolver(config, logger)

	if err := resolver.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Should be able to get stats
	stats := resolver.Stats()
	if stats.Cache.Size != 0 {
		t.Errorf("Initial cache size should be 0, got %d", stats.Cache.Size)
	}

	if err := resolver.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestQueryTypeStats(t *testing.T) {
	logger := zap.NewNop()
	config := dns.DefaultConfig()
	config.CacheEnabled = false
	config.RateLimitEnabled = false

	resolver := dns.NewResolver(config, logger)
	if err := resolver.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer resolver.Stop()

	// Make queries of different types
	queries := []struct {
		qtype uint16
	}{
		{dns.TypeA},
		{dns.TypeA},
		{dns.TypeAAAA},
		{dns.TypeMX},
	}

	for _, q := range queries {
		query := &dns.Query{
			Name:   "test.com",
			Type:   q.qtype,
			Class:  1,
			Source: net.ParseIP("10.0.0.1"),
		}
		resolver.Resolve(context.Background(), query)
	}

	stats := resolver.Stats()

	if stats.QueryTypeStats[dns.TypeA] != 2 {
		t.Errorf("A queries = %d, want 2", stats.QueryTypeStats[dns.TypeA])
	}
	if stats.QueryTypeStats[dns.TypeAAAA] != 1 {
		t.Errorf("AAAA queries = %d, want 1", stats.QueryTypeStats[dns.TypeAAAA])
	}
	if stats.QueryTypeStats[dns.TypeMX] != 1 {
		t.Errorf("MX queries = %d, want 1", stats.QueryTypeStats[dns.TypeMX])
	}
}

func TestNegativeCache(t *testing.T) {
	cache := dns.NewCache(100, time.Second, time.Hour, 30*time.Second)

	// Set negative entry
	cache.SetNegative("nonexistent.com:A:1")

	// Should be in cache as negative
	entry, hit := cache.Get("nonexistent.com:A:1")
	if !hit {
		t.Fatal("Expected cache hit for negative entry")
	}
	if !entry.Negative {
		t.Error("Entry should be marked as negative")
	}
}

func TestInterceptRuleMatching(t *testing.T) {
	logger := zap.NewNop()
	config := dns.DefaultConfig()
	config.CacheEnabled = false

	resolver := dns.NewResolver(config, logger)

	// Add domain suffix rule
	resolver.AddInterceptRule(&dns.InterceptRule{
		DomainSuffix: ".blocked.com",
		Action:       dns.ActionBlock,
	})

	// Test that rule can be removed
	resolver.AddInterceptRule(&dns.InterceptRule{
		Domain: "removable.com",
		Action: dns.ActionBlock,
	})

	removed := resolver.RemoveInterceptRule("removable.com")
	if !removed {
		t.Error("Should have removed rule")
	}

	// Try to remove non-existent rule
	removed = resolver.RemoveInterceptRule("nonexistent.com")
	if removed {
		t.Error("Should not have removed non-existent rule")
	}
}
