package direct

import (
	"context"
	"sync"
)

// StubBSSClient is a simple in-memory BSS client for testing and development
type StubBSSClient struct {
	mu       sync.RWMutex
	mappings map[string]*ONTMapping // keyed by ONT serial
	bindings []*BindingEvent
}

// NewStubBSSClient creates a new stub BSS client
func NewStubBSSClient() *StubBSSClient {
	return &StubBSSClient{
		mappings: make(map[string]*ONTMapping),
	}
}

// AddMapping adds a mapping to the stub client
func (c *StubBSSClient) AddMapping(mapping *ONTMapping) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mappings[mapping.ONTSerial] = mapping
}

// GetONTMapping retrieves the subscriber mapping for an ONT
func (c *StubBSSClient) GetONTMapping(ctx context.Context, ontSerial string) (*ONTMapping, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if mapping, ok := c.mappings[ontSerial]; ok {
		return mapping, nil
	}
	return nil, ErrONTNotFound
}

// GetONTMappingByCircuitID retrieves mapping by DHCP Option 82 circuit ID
func (c *StubBSSClient) GetONTMappingByCircuitID(ctx context.Context, circuitID string) (*ONTMapping, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, mapping := range c.mappings {
		if mapping.CircuitID == circuitID {
			return mapping, nil
		}
	}
	return nil, ErrONTNotFound
}

// ReportBinding notifies BSS of a DHCP binding event
func (c *StubBSSClient) ReportBinding(ctx context.Context, event *BindingEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bindings = append(c.bindings, event)
	return nil
}

// SyncMappings retrieves all ONT mappings
func (c *StubBSSClient) SyncMappings(ctx context.Context) ([]*ONTMapping, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*ONTMapping, 0, len(c.mappings))
	for _, mapping := range c.mappings {
		result = append(result, mapping)
	}
	return result, nil
}

// GetBindings returns all reported binding events (for testing)
func (c *StubBSSClient) GetBindings() []*BindingEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bindings
}

// ClearBindings clears the binding event history (for testing)
func (c *StubBSSClient) ClearBindings() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bindings = nil
}
