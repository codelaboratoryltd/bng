package resilience

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestRequestQueueEnqueue(t *testing.T) {
	logger := zap.NewNop()
	queue := NewRequestQueue(10, time.Minute, logger)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	req := &QueuedRequest{
		Type: RequestTypeDHCPDiscover,
		MAC:  mac,
	}

	if err := queue.Enqueue(req); err != nil {
		t.Fatalf("Failed to enqueue request: %v", err)
	}

	if queue.Len() != 1 {
		t.Errorf("Expected queue length 1, got %d", queue.Len())
	}

	// Enqueue same MAC should update existing
	req2 := &QueuedRequest{
		Type: RequestTypeDHCPRequest,
		MAC:  mac,
	}

	if err := queue.Enqueue(req2); err != nil {
		t.Fatalf("Failed to enqueue second request: %v", err)
	}

	// Length should still be 1 (updated existing)
	if queue.Len() != 1 {
		t.Errorf("Expected queue length 1 after update, got %d", queue.Len())
	}

	// Retries should have incremented
	existing := queue.GetByMAC(mac.String())
	if existing.Retries != 1 {
		t.Errorf("Expected 1 retry, got %d", existing.Retries)
	}
}

func TestRequestQueueCapacity(t *testing.T) {
	logger := zap.NewNop()
	queue := NewRequestQueue(5, time.Minute, logger)

	// Fill the queue with different MACs
	for i := 0; i < 5; i++ {
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)}
		req := &QueuedRequest{
			Type: RequestTypeDHCPDiscover,
			MAC:  mac,
		}
		if err := queue.Enqueue(req); err != nil {
			t.Fatalf("Failed to enqueue request %d: %v", i, err)
		}
	}

	if !queue.IsFull() {
		t.Error("Expected queue to be full")
	}

	// Try to add one more
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0xFF}
	req := &QueuedRequest{
		Type: RequestTypeDHCPDiscover,
		MAC:  mac,
	}

	err := queue.Enqueue(req)
	if err == nil {
		t.Error("Expected error when queue is full")
	}
}

func TestRequestQueueDequeue(t *testing.T) {
	logger := zap.NewNop()
	queue := NewRequestQueue(10, time.Minute, logger)

	mac1, _ := net.ParseMAC("00:11:22:33:44:01")
	mac2, _ := net.ParseMAC("00:11:22:33:44:02")

	queue.Enqueue(&QueuedRequest{Type: RequestTypeDHCPDiscover, MAC: mac1})
	queue.Enqueue(&QueuedRequest{Type: RequestTypeDHCPRequest, MAC: mac2})

	// Dequeue should return first in
	req := queue.Dequeue()
	if req == nil {
		t.Fatal("Dequeue returned nil")
	}
	if req.MAC.String() != mac1.String() {
		t.Errorf("Expected MAC %s, got %s", mac1, req.MAC)
	}

	// Queue should have 1 item
	if queue.Len() != 1 {
		t.Errorf("Expected queue length 1, got %d", queue.Len())
	}

	// Can no longer find first request
	if queue.GetByMAC(mac1.String()) != nil {
		t.Error("First request should have been removed from index")
	}
}

func TestRequestQueueExpiry(t *testing.T) {
	logger := zap.NewNop()
	queue := NewRequestQueue(10, 100*time.Millisecond, logger)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	req := &QueuedRequest{
		Type: RequestTypeDHCPDiscover,
		MAC:  mac,
	}

	queue.Enqueue(req)

	// Wait for expiry
	time.Sleep(200 * time.Millisecond)

	expired := queue.ExpireOld()
	if expired != 1 {
		t.Errorf("Expected 1 expired request, got %d", expired)
	}

	if queue.Len() != 0 {
		t.Errorf("Expected empty queue after expiry, got %d", queue.Len())
	}
}

func TestRequestQueueProcess(t *testing.T) {
	logger := zap.NewNop()
	queue := NewRequestQueue(10, time.Minute, logger)

	processedIDs := make([]string, 0)
	queue.SetHandler(func(ctx context.Context, req *QueuedRequest) error {
		processedIDs = append(processedIDs, req.ID)
		return nil
	})

	// Add requests
	for i := 0; i < 3; i++ {
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)}
		queue.Enqueue(&QueuedRequest{
			Type: RequestTypeDHCPDiscover,
			MAC:  mac,
		})
	}

	ctx := context.Background()
	processed := queue.ProcessAll(ctx)

	if processed != 3 {
		t.Errorf("Expected 3 processed, got %d", processed)
	}

	if len(processedIDs) != 3 {
		t.Errorf("Expected 3 processed IDs, got %d", len(processedIDs))
	}

	if queue.Len() != 0 {
		t.Errorf("Expected empty queue after processing, got %d", queue.Len())
	}
}

func TestRequestQueueStats(t *testing.T) {
	logger := zap.NewNop()
	queue := NewRequestQueue(10, time.Minute, logger)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	queue.Enqueue(&QueuedRequest{Type: RequestTypeDHCPDiscover, MAC: mac})
	queue.Dequeue()

	enqueued, dequeued, expired, current := queue.Stats()

	if enqueued != 1 {
		t.Errorf("Expected 1 enqueued, got %d", enqueued)
	}
	if dequeued != 1 {
		t.Errorf("Expected 1 dequeued, got %d", dequeued)
	}
	if expired != 0 {
		t.Errorf("Expected 0 expired, got %d", expired)
	}
	if current != 0 {
		t.Errorf("Expected 0 current, got %d", current)
	}
}

func TestRequestQueueListByType(t *testing.T) {
	logger := zap.NewNop()
	queue := NewRequestQueue(10, time.Minute, logger)

	// Add mixed request types
	queue.Enqueue(&QueuedRequest{
		Type: RequestTypeDHCPDiscover,
		MAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x01},
	})
	queue.Enqueue(&QueuedRequest{
		Type: RequestTypeRADIUSAuth,
		MAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x02},
	})
	queue.Enqueue(&QueuedRequest{
		Type: RequestTypeDHCPDiscover,
		MAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x03},
	})

	dhcpRequests := queue.ListByType(RequestTypeDHCPDiscover)
	if len(dhcpRequests) != 2 {
		t.Errorf("Expected 2 DHCP requests, got %d", len(dhcpRequests))
	}

	radiusRequests := queue.ListByType(RequestTypeRADIUSAuth)
	if len(radiusRequests) != 1 {
		t.Errorf("Expected 1 RADIUS request, got %d", len(radiusRequests))
	}
}

func TestRequestQueueClear(t *testing.T) {
	logger := zap.NewNop()
	queue := NewRequestQueue(10, time.Minute, logger)

	// Add some requests
	for i := 0; i < 5; i++ {
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(i)}
		queue.Enqueue(&QueuedRequest{Type: RequestTypeDHCPDiscover, MAC: mac})
	}

	if queue.Len() != 5 {
		t.Fatalf("Expected 5 requests, got %d", queue.Len())
	}

	queue.Clear()

	if queue.Len() != 0 {
		t.Errorf("Expected empty queue after clear, got %d", queue.Len())
	}
}
