package dns

import (
	"container/list"
	"sync"
	"time"
)

// Cache is an LRU cache for DNS records.
type Cache struct {
	mu sync.RWMutex

	// Configuration
	maxSize     int
	minTTL      time.Duration
	maxTTL      time.Duration
	negativeTTL time.Duration

	// Storage
	entries map[string]*list.Element
	lru     *list.List

	// Statistics
	hits      int64
	misses    int64
	evictions int64
}

// cacheItem wraps a CacheEntry for the LRU list.
type cacheItem struct {
	entry *CacheEntry
}

// NewCache creates a new DNS cache.
func NewCache(maxSize int, minTTL, maxTTL, negativeTTL time.Duration) *Cache {
	return &Cache{
		maxSize:     maxSize,
		minTTL:      minTTL,
		maxTTL:      maxTTL,
		negativeTTL: negativeTTL,
		entries:     make(map[string]*list.Element),
		lru:         list.New(),
	}
}

// Get retrieves a cache entry if it exists and is not expired.
func (c *Cache) Get(key string) (*CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, exists := c.entries[key]
	if !exists {
		c.misses++
		return nil, false
	}

	item := elem.Value.(*cacheItem)

	// Check expiry
	if time.Now().After(item.entry.ExpiresAt) {
		// Entry expired, remove it
		c.removeElement(elem)
		c.misses++
		return nil, false
	}

	// Move to front (most recently used)
	c.lru.MoveToFront(elem)
	item.entry.HitCount++
	c.hits++

	return item.entry, true
}

// Set stores a cache entry.
func (c *Cache) Set(entry *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Apply TTL bounds
	ttl := time.Until(entry.ExpiresAt)
	if ttl < c.minTTL {
		entry.ExpiresAt = time.Now().Add(c.minTTL)
	} else if ttl > c.maxTTL {
		entry.ExpiresAt = time.Now().Add(c.maxTTL)
	}

	// If entry exists, update it
	if elem, exists := c.entries[entry.Key]; exists {
		c.lru.MoveToFront(elem)
		elem.Value.(*cacheItem).entry = entry
		return
	}

	// Evict if at capacity
	for c.lru.Len() >= c.maxSize {
		c.evictOldest()
	}

	// Add new entry
	item := &cacheItem{entry: entry}
	elem := c.lru.PushFront(item)
	c.entries[entry.Key] = elem
}

// SetNegative stores a negative (NXDOMAIN) cache entry.
func (c *Cache) SetNegative(key string) {
	entry := &CacheEntry{
		Key:       key,
		ExpiresAt: time.Now().Add(c.negativeTTL),
		Negative:  true,
		CreatedAt: time.Now(),
	}
	c.Set(entry)
}

// Delete removes a cache entry.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.entries[key]; exists {
		c.removeElement(elem)
	}
}

// Clear removes all cache entries.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*list.Element)
	c.lru.Init()
}

// Size returns the current number of cached entries.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lru.Len()
}

// Stats returns cache statistics.
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CacheStats{
		Size:      c.lru.Len(),
		Hits:      c.hits,
		Misses:    c.misses,
		Evictions: c.evictions,
	}
}

// Cleanup removes expired entries.
func (c *Cache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	// Iterate through all entries and remove expired ones
	var next *list.Element
	for elem := c.lru.Back(); elem != nil; elem = next {
		next = elem.Prev() // Store next before potential deletion

		item := elem.Value.(*cacheItem)
		if now.After(item.entry.ExpiresAt) {
			c.removeElement(elem)
			removed++
		}
	}

	return removed
}

// removeElement removes an element from cache (must hold lock).
func (c *Cache) removeElement(elem *list.Element) {
	item := elem.Value.(*cacheItem)
	delete(c.entries, item.entry.Key)
	c.lru.Remove(elem)
}

// evictOldest removes the least recently used entry (must hold lock).
func (c *Cache) evictOldest() {
	elem := c.lru.Back()
	if elem != nil {
		c.removeElement(elem)
		c.evictions++
	}
}

// CacheKey generates a cache key from query parameters.
func CacheKey(name string, qtype, qclass uint16) string {
	// Simple key format: "name:type:class"
	return name + ":" + TypeString(qtype) + ":" + string(rune(qclass))
}
