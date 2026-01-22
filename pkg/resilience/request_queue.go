package resilience

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RequestHandler processes a queued request.
type RequestHandler func(ctx context.Context, req *QueuedRequest) error

// RequestQueue manages queued requests during network partition.
type RequestQueue struct {
	maxSize int
	timeout time.Duration
	logger  *zap.Logger

	mu       sync.RWMutex
	requests []*QueuedRequest
	byID     map[string]*QueuedRequest
	byMAC    map[string]*QueuedRequest

	// Handler for processing requests
	handler RequestHandler

	// Statistics
	enqueued int64
	dequeued int64
	expired  int64
}

// NewRequestQueue creates a new request queue.
func NewRequestQueue(maxSize int, timeout time.Duration, logger *zap.Logger) *RequestQueue {
	return &RequestQueue{
		maxSize:  maxSize,
		timeout:  timeout,
		logger:   logger,
		requests: make([]*QueuedRequest, 0, maxSize),
		byID:     make(map[string]*QueuedRequest),
		byMAC:    make(map[string]*QueuedRequest),
	}
}

// SetHandler sets the handler for processing requests.
func (q *RequestQueue) SetHandler(handler RequestHandler) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.handler = handler
}

// Enqueue adds a request to the queue.
func (q *RequestQueue) Enqueue(req *QueuedRequest) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Check queue capacity
	if len(q.requests) >= q.maxSize {
		return fmt.Errorf("request queue full (max %d)", q.maxSize)
	}

	// Generate ID if not set
	if req.ID == "" {
		req.ID = uuid.New().String()
	}

	// Set timestamps
	if req.QueuedAt.IsZero() {
		req.QueuedAt = time.Now()
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = req.QueuedAt.Add(q.timeout)
	}

	// Check for existing request for same MAC
	macKey := req.MAC.String()
	if existing, ok := q.byMAC[macKey]; ok {
		// Update existing request instead of adding new one
		existing.Retries++
		existing.Data = req.Data
		existing.RequestedIP = req.RequestedIP
		q.logger.Debug("Updated existing queued request",
			zap.String("id", existing.ID),
			zap.String("mac", macKey),
			zap.Int("retries", existing.Retries),
		)
		return nil
	}

	// Add to queue
	q.requests = append(q.requests, req)
	q.byID[req.ID] = req
	q.byMAC[macKey] = req
	q.enqueued++

	q.logger.Debug("Request queued",
		zap.String("id", req.ID),
		zap.String("mac", macKey),
		zap.String("type", string(req.Type)),
		zap.Time("expires_at", req.ExpiresAt),
	)

	return nil
}

// Dequeue removes and returns the oldest request.
func (q *RequestQueue) Dequeue() *QueuedRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.requests) == 0 {
		return nil
	}

	req := q.requests[0]
	q.requests = q.requests[1:]
	delete(q.byID, req.ID)
	delete(q.byMAC, req.MAC.String())
	q.dequeued++

	return req
}

// Peek returns the oldest request without removing it.
func (q *RequestQueue) Peek() *QueuedRequest {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if len(q.requests) == 0 {
		return nil
	}
	return q.requests[0]
}

// Get returns a request by ID.
func (q *RequestQueue) Get(id string) *QueuedRequest {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.byID[id]
}

// GetByMAC returns a request by MAC address.
func (q *RequestQueue) GetByMAC(mac string) *QueuedRequest {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.byMAC[mac]
}

// Remove removes a specific request.
func (q *RequestQueue) Remove(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	req, ok := q.byID[id]
	if !ok {
		return false
	}

	// Find and remove from slice
	for i, r := range q.requests {
		if r.ID == id {
			q.requests = append(q.requests[:i], q.requests[i+1:]...)
			break
		}
	}

	delete(q.byID, id)
	delete(q.byMAC, req.MAC.String())

	return true
}

// Len returns the number of queued requests.
func (q *RequestQueue) Len() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.requests)
}

// IsFull returns true if the queue is at capacity.
func (q *RequestQueue) IsFull() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.requests) >= q.maxSize
}

// ExpireOld removes expired requests.
func (q *RequestQueue) ExpireOld() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	// Find and remove expired requests
	remaining := make([]*QueuedRequest, 0, len(q.requests))
	for _, req := range q.requests {
		if now.After(req.ExpiresAt) {
			delete(q.byID, req.ID)
			delete(q.byMAC, req.MAC.String())
			expiredCount++
			q.expired++

			q.logger.Debug("Request expired",
				zap.String("id", req.ID),
				zap.String("mac", req.MAC.String()),
				zap.String("type", string(req.Type)),
			)
		} else {
			remaining = append(remaining, req)
		}
	}

	q.requests = remaining

	if expiredCount > 0 {
		q.logger.Info("Expired queued requests",
			zap.Int("count", expiredCount),
			zap.Int("remaining", len(q.requests)),
		)
	}

	return expiredCount
}

// ProcessAll processes all queued requests.
func (q *RequestQueue) ProcessAll(ctx context.Context) int {
	q.mu.RLock()
	handler := q.handler
	q.mu.RUnlock()

	if handler == nil {
		return 0
	}

	processed := 0
	for {
		select {
		case <-ctx.Done():
			return processed
		default:
		}

		req := q.Dequeue()
		if req == nil {
			break
		}

		// Check if expired
		if time.Now().After(req.ExpiresAt) {
			q.mu.Lock()
			q.expired++
			q.mu.Unlock()
			continue
		}

		// Process the request
		if err := handler(ctx, req); err != nil {
			q.logger.Warn("Failed to process queued request",
				zap.String("id", req.ID),
				zap.String("mac", req.MAC.String()),
				zap.Error(err),
			)
			// Re-queue if still valid
			if time.Now().Before(req.ExpiresAt) {
				req.Retries++
				q.Enqueue(req)
			}
			continue
		}

		processed++
		q.logger.Debug("Processed queued request",
			zap.String("id", req.ID),
			zap.String("mac", req.MAC.String()),
			zap.String("type", string(req.Type)),
		)
	}

	return processed
}

// Stats returns queue statistics.
func (q *RequestQueue) Stats() (enqueued, dequeued, expired int64, current int) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.enqueued, q.dequeued, q.expired, len(q.requests)
}

// Clear removes all requests from the queue.
func (q *RequestQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.requests = make([]*QueuedRequest, 0, q.maxSize)
	q.byID = make(map[string]*QueuedRequest)
	q.byMAC = make(map[string]*QueuedRequest)
}

// ListByType returns all requests of a specific type.
func (q *RequestQueue) ListByType(reqType RequestType) []*QueuedRequest {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var result []*QueuedRequest
	for _, req := range q.requests {
		if req.Type == reqType {
			result = append(result, req)
		}
	}
	return result
}

// ListAll returns all queued requests.
func (q *RequestQueue) ListAll() []*QueuedRequest {
	q.mu.RLock()
	defer q.mu.RUnlock()

	result := make([]*QueuedRequest, len(q.requests))
	copy(result, q.requests)
	return result
}
