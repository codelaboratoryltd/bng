package direct

import (
	"context"
	"net"
	"testing"

	"github.com/codelaboratoryltd/bng/pkg/subscriber"
	"go.uber.org/zap"
)

func TestAuthenticator_Authenticate(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultConfig()
	config.DefaultISPID = "test-isp"

	auth := NewAuthenticator(config, nil, logger)

	// Set up stub BSS client with test mappings
	bss := NewStubBSSClient()
	bss.AddMapping(&ONTMapping{
		ONTSerial:    "ALCL12345678",
		CircuitID:    "eth1/0/1:100",
		SubscriberID: "sub-001",
		ISPID:        "my-isp",
		QoSPolicy:    "business-500mbps",
		DownloadBps:  500_000_000,
		UploadBps:    100_000_000,
		IPv4Addr:     "10.0.1.100",
		IPv4Pool:     "business-pool",
		Status:       "active",
	})
	auth.SetBSSClient(bss)

	tests := []struct {
		name       string
		req        *subscriber.SessionRequest
		wantOK     bool
		wantSubID  string
		wantIPAddr string
	}{
		{
			name: "auth by circuit ID",
			req: &subscriber.SessionRequest{
				MAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				CircuitID: "eth1/0/1:100",
			},
			wantOK:     true,
			wantSubID:  "sub-001",
			wantIPAddr: "10.0.1.100",
		},
		{
			name: "auth by ONT serial (via ONUID)",
			req: &subscriber.SessionRequest{
				MAC:   net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				ONUID: "ALCL12345678",
			},
			wantOK:    true,
			wantSubID: "sub-001",
		},
		{
			name: "auth by ONT serial (via RemoteID)",
			req: &subscriber.SessionRequest{
				MAC:      net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				RemoteID: "ALCL12345678",
			},
			wantOK:    true,
			wantSubID: "sub-001",
		},
		{
			name: "unknown ONT",
			req: &subscriber.SessionRequest{
				MAC:   net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				ONUID: "UNKNOWN12345",
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := auth.Authenticate(context.Background(), tt.req)
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}

			if result.Success != tt.wantOK {
				t.Errorf("Success = %v, want %v", result.Success, tt.wantOK)
			}

			if tt.wantOK {
				if result.SubscriberID != tt.wantSubID {
					t.Errorf("SubscriberID = %v, want %v", result.SubscriberID, tt.wantSubID)
				}
				if tt.wantIPAddr != "" {
					if result.FramedIPAddress == nil || result.FramedIPAddress.String() != tt.wantIPAddr {
						t.Errorf("FramedIPAddress = %v, want %v", result.FramedIPAddress, tt.wantIPAddr)
					}
				}
			}
		})
	}
}

func TestAuthenticator_SuspendedSubscriber(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultConfig()
	auth := NewAuthenticator(config, nil, logger)

	bss := NewStubBSSClient()
	bss.AddMapping(&ONTMapping{
		ONTSerial:    "SUSPENDED001",
		SubscriberID: "sub-suspended",
		Status:       "suspended",
	})
	auth.SetBSSClient(bss)

	result, err := auth.Authenticate(context.Background(), &subscriber.SessionRequest{
		MAC:   net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		ONUID: "SUSPENDED001",
	})

	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if result.Success {
		t.Error("Expected auth failure for suspended subscriber")
	}

	if !result.WalledGarden {
		t.Error("Expected WalledGarden=true for suspended subscriber")
	}
}

func TestAuthenticator_CachingBehavior(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultConfig()
	auth := NewAuthenticator(config, nil, logger)

	bss := NewStubBSSClient()
	bss.AddMapping(&ONTMapping{
		ONTSerial:    "CACHED001",
		CircuitID:    "eth1/0/1:200",
		SubscriberID: "sub-cached",
		Status:       "active",
	})
	auth.SetBSSClient(bss)

	// First auth - should populate cache
	req := &subscriber.SessionRequest{
		MAC:   net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		ONUID: "CACHED001",
	}
	_, _ = auth.Authenticate(context.Background(), req)

	// Check cache
	stats := auth.Stats()
	if stats.CachedONTMappings != 1 {
		t.Errorf("CachedONTMappings = %d, want 1", stats.CachedONTMappings)
	}

	// Invalidate cache
	auth.InvalidateCache("CACHED001", "")
	stats = auth.Stats()
	if stats.CachedONTMappings != 0 {
		t.Errorf("CachedONTMappings after invalidate = %d, want 0", stats.CachedONTMappings)
	}
}

func TestAuthenticator_ReportBindingEvent(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultConfig()
	auth := NewAuthenticator(config, nil, logger)

	bss := NewStubBSSClient()
	auth.SetBSSClient(bss)

	// Report a binding event
	err := auth.ReportBindingEvent(context.Background(), &BindingEvent{
		EventType:    BindingEventAssign,
		ONTSerial:    "TEST001",
		SubscriberID: "sub-001",
		MAC:          "00:11:22:33:44:55",
		IPv4Addr:     "10.0.1.100",
	})

	if err != nil {
		t.Fatalf("ReportBindingEvent() error = %v", err)
	}

	// Verify event was recorded
	bindings := bss.GetBindings()
	if len(bindings) != 1 {
		t.Fatalf("Expected 1 binding event, got %d", len(bindings))
	}

	if bindings[0].EventType != BindingEventAssign {
		t.Errorf("EventType = %v, want %v", bindings[0].EventType, BindingEventAssign)
	}
}

func TestAuthenticator_SyncFromBSS(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultConfig()
	auth := NewAuthenticator(config, nil, logger)

	bss := NewStubBSSClient()
	bss.AddMapping(&ONTMapping{ONTSerial: "SYNC001", SubscriberID: "sub-001", CircuitID: "circuit-001"})
	bss.AddMapping(&ONTMapping{ONTSerial: "SYNC002", SubscriberID: "sub-002", CircuitID: "circuit-002"})
	bss.AddMapping(&ONTMapping{ONTSerial: "SYNC003", SubscriberID: "sub-003"})
	auth.SetBSSClient(bss)

	err := auth.SyncFromBSS(context.Background())
	if err != nil {
		t.Fatalf("SyncFromBSS() error = %v", err)
	}

	stats := auth.Stats()
	if stats.CachedONTMappings != 3 {
		t.Errorf("CachedONTMappings = %d, want 3", stats.CachedONTMappings)
	}
	if stats.CachedCircuitIDMappings != 2 {
		t.Errorf("CachedCircuitIDMappings = %d, want 2", stats.CachedCircuitIDMappings)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Mode != AuthModeDirect {
		t.Errorf("Mode = %v, want %v", config.Mode, AuthModeDirect)
	}
	if config.DefaultDownloadRateBps == 0 {
		t.Error("DefaultDownloadRateBps should not be 0")
	}
	if config.DefaultUploadRateBps == 0 {
		t.Error("DefaultUploadRateBps should not be 0")
	}
}
