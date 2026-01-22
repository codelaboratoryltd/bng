// Package qinq provides QinQ (802.1ad) double VLAN tagging support for
// European PoI (Point of Interconnect) deployments.
//
// In QinQ deployments, subscribers are identified by a unique combination of:
//   - S-TAG (Service VLAN / outer tag, 802.1ad): Identifies the service provider or PoI
//   - C-TAG (Customer VLAN / inner tag, 802.1Q): Identifies the individual subscriber
//
// This eliminates the need to create thousands of Linux VLAN interfaces, as the
// XDP program parses VLAN tags directly in the kernel.
package qinq

import (
	"fmt"
	"sync"
)

// VLANPair represents a QinQ VLAN tag combination
type VLANPair struct {
	STag uint16 `json:"s_tag"` // Service VLAN (outer, 802.1ad)
	CTag uint16 `json:"c_tag"` // Customer VLAN (inner, 802.1Q)
}

// String returns a string representation of the VLAN pair
func (v VLANPair) String() string {
	if v.STag == 0 {
		return fmt.Sprintf("c%d", v.CTag)
	}
	return fmt.Sprintf("s%d.c%d", v.STag, v.CTag)
}

// IsDoubleTagged returns true if this is a QinQ double-tagged VLAN pair
func (v VLANPair) IsDoubleTagged() bool {
	return v.STag > 0 && v.CTag > 0
}

// IsSingleTagged returns true if this is a single-tagged VLAN (C-TAG only)
func (v VLANPair) IsSingleTagged() bool {
	return v.STag == 0 && v.CTag > 0
}

// IsUntagged returns true if there are no VLAN tags
func (v VLANPair) IsUntagged() bool {
	return v.STag == 0 && v.CTag == 0
}

// Config holds QinQ configuration for a BNG deployment
type Config struct {
	// Enabled indicates whether QinQ mode is active
	Enabled bool `json:"enabled"`

	// STagRanges defines valid S-TAG ranges (per PoI or service provider)
	STagRanges []VLANRange `json:"s_tag_ranges"`

	// CTagRange defines the valid C-TAG range for subscribers
	CTagRange VLANRange `json:"c_tag_range"`

	// DefaultSTag is the default S-TAG when not explicitly specified
	DefaultSTag uint16 `json:"default_s_tag,omitempty"`

	// LookupPriority determines subscriber lookup order
	// "vlan_first": Try VLAN-based lookup first, then MAC
	// "mac_first": Try MAC-based lookup first, then VLAN
	// "vlan_only": Only use VLAN-based lookup (strict QinQ mode)
	LookupPriority string `json:"lookup_priority"`
}

// VLANRange represents a range of VLAN IDs
type VLANRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
	Name  string `json:"name,omitempty"` // Optional name (e.g., ISP name)
}

// Contains checks if a VLAN ID is within this range
func (r VLANRange) Contains(vid uint16) bool {
	return vid >= r.Start && vid <= r.End
}

// Size returns the number of VLANs in this range
func (r VLANRange) Size() int {
	if r.End < r.Start {
		return 0
	}
	return int(r.End - r.Start + 1)
}

// DefaultConfig returns a default QinQ configuration
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		STagRanges: []VLANRange{
			{Start: 100, End: 999, Name: "default"},
		},
		CTagRange:      VLANRange{Start: 100, End: 4094},
		LookupPriority: "vlan_first",
	}
}

// Mapper manages the mapping between VLAN pairs and subscriber identifiers
type Mapper struct {
	config Config
	mu     sync.RWMutex

	// vlanToSubscriber maps VLAN pair to subscriber ID
	vlanToSubscriber map[VLANPair]string

	// subscriberToVLAN maps subscriber ID to VLAN pair
	subscriberToVLAN map[string]VLANPair
}

// NewMapper creates a new QinQ VLAN mapper
func NewMapper(config Config) *Mapper {
	return &Mapper{
		config:           config,
		vlanToSubscriber: make(map[VLANPair]string),
		subscriberToVLAN: make(map[string]VLANPair),
	}
}

// Register associates a VLAN pair with a subscriber ID
func (m *Mapper) Register(vlan VLANPair, subscriberID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate S-TAG is in allowed ranges
	if vlan.STag > 0 {
		valid := false
		for _, r := range m.config.STagRanges {
			if r.Contains(vlan.STag) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("S-TAG %d not in allowed ranges", vlan.STag)
		}
	}

	// Validate C-TAG is in allowed range
	if vlan.CTag > 0 && !m.config.CTagRange.Contains(vlan.CTag) {
		return fmt.Errorf("C-TAG %d not in allowed range [%d-%d]",
			vlan.CTag, m.config.CTagRange.Start, m.config.CTagRange.End)
	}

	// Check for existing mapping
	if existing, ok := m.vlanToSubscriber[vlan]; ok && existing != subscriberID {
		return fmt.Errorf("VLAN pair %s already mapped to subscriber %s", vlan, existing)
	}

	// Remove old VLAN mapping for this subscriber if exists
	if oldVLAN, ok := m.subscriberToVLAN[subscriberID]; ok {
		delete(m.vlanToSubscriber, oldVLAN)
	}

	m.vlanToSubscriber[vlan] = subscriberID
	m.subscriberToVLAN[subscriberID] = vlan

	return nil
}

// Unregister removes a VLAN mapping
func (m *Mapper) Unregister(vlan VLANPair) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if subscriberID, ok := m.vlanToSubscriber[vlan]; ok {
		delete(m.vlanToSubscriber, vlan)
		delete(m.subscriberToVLAN, subscriberID)
	}
}

// UnregisterSubscriber removes a subscriber's VLAN mapping
func (m *Mapper) UnregisterSubscriber(subscriberID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if vlan, ok := m.subscriberToVLAN[subscriberID]; ok {
		delete(m.vlanToSubscriber, vlan)
		delete(m.subscriberToVLAN, subscriberID)
	}
}

// GetSubscriber returns the subscriber ID for a VLAN pair
func (m *Mapper) GetSubscriber(vlan VLANPair) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, ok := m.vlanToSubscriber[vlan]
	return id, ok
}

// GetVLAN returns the VLAN pair for a subscriber ID
func (m *Mapper) GetVLAN(subscriberID string) (VLANPair, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vlan, ok := m.subscriberToVLAN[subscriberID]
	return vlan, ok
}

// Stats returns mapper statistics
func (m *Mapper) Stats() MapperStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return MapperStats{
		TotalMappings: len(m.vlanToSubscriber),
	}
}

// MapperStats holds QinQ mapper statistics
type MapperStats struct {
	TotalMappings int `json:"total_mappings"`
}
