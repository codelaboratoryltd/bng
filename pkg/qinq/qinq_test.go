package qinq

import (
	"testing"
)

func TestVLANPair_String(t *testing.T) {
	tests := []struct {
		name string
		pair VLANPair
		want string
	}{
		{"untagged", VLANPair{0, 0}, "c0"},
		{"single tagged", VLANPair{0, 100}, "c100"},
		{"double tagged", VLANPair{200, 100}, "s200.c100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pair.String(); got != tt.want {
				t.Errorf("VLANPair.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVLANPair_TagTypes(t *testing.T) {
	tests := []struct {
		name         string
		pair         VLANPair
		doubleTagged bool
		singleTagged bool
		untagged     bool
	}{
		{"untagged", VLANPair{0, 0}, false, false, true},
		{"single tagged", VLANPair{0, 100}, false, true, false},
		{"double tagged", VLANPair{200, 100}, true, false, false},
		{"s-tag only", VLANPair{200, 0}, false, false, false}, // Invalid but possible
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pair.IsDoubleTagged(); got != tt.doubleTagged {
				t.Errorf("IsDoubleTagged() = %v, want %v", got, tt.doubleTagged)
			}
			if got := tt.pair.IsSingleTagged(); got != tt.singleTagged {
				t.Errorf("IsSingleTagged() = %v, want %v", got, tt.singleTagged)
			}
			if got := tt.pair.IsUntagged(); got != tt.untagged {
				t.Errorf("IsUntagged() = %v, want %v", got, tt.untagged)
			}
		})
	}
}

func TestVLANRange_Contains(t *testing.T) {
	r := VLANRange{Start: 100, End: 200}

	tests := []struct {
		vid  uint16
		want bool
	}{
		{50, false},
		{99, false},
		{100, true},
		{150, true},
		{200, true},
		{201, false},
		{300, false},
	}

	for _, tt := range tests {
		if got := r.Contains(tt.vid); got != tt.want {
			t.Errorf("VLANRange.Contains(%d) = %v, want %v", tt.vid, got, tt.want)
		}
	}
}

func TestVLANRange_Size(t *testing.T) {
	tests := []struct {
		r    VLANRange
		want int
	}{
		{VLANRange{100, 200, ""}, 101},
		{VLANRange{1, 1, ""}, 1},
		{VLANRange{100, 4094, ""}, 3995},
		{VLANRange{200, 100, ""}, 0}, // Invalid range
	}

	for _, tt := range tests {
		if got := tt.r.Size(); got != tt.want {
			t.Errorf("VLANRange{%d,%d}.Size() = %v, want %v", tt.r.Start, tt.r.End, got, tt.want)
		}
	}
}

func TestMapper_RegisterAndLookup(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	mapper := NewMapper(config)

	// Register a VLAN pair
	vlan := VLANPair{STag: 100, CTag: 500}
	err := mapper.Register(vlan, "sub-001")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Lookup by VLAN
	subID, ok := mapper.GetSubscriber(vlan)
	if !ok {
		t.Error("GetSubscriber() returned false, expected true")
	}
	if subID != "sub-001" {
		t.Errorf("GetSubscriber() = %v, want sub-001", subID)
	}

	// Lookup by subscriber
	gotVLAN, ok := mapper.GetVLAN("sub-001")
	if !ok {
		t.Error("GetVLAN() returned false, expected true")
	}
	if gotVLAN != vlan {
		t.Errorf("GetVLAN() = %v, want %v", gotVLAN, vlan)
	}

	// Non-existent lookups
	_, ok = mapper.GetSubscriber(VLANPair{999, 999})
	if ok {
		t.Error("GetSubscriber() for non-existent should return false")
	}

	_, ok = mapper.GetVLAN("non-existent")
	if ok {
		t.Error("GetVLAN() for non-existent should return false")
	}
}

func TestMapper_DuplicateVLAN(t *testing.T) {
	config := DefaultConfig()
	mapper := NewMapper(config)

	vlan := VLANPair{STag: 100, CTag: 500}

	// Register first subscriber
	err := mapper.Register(vlan, "sub-001")
	if err != nil {
		t.Fatalf("First Register() error = %v", err)
	}

	// Try to register same VLAN to different subscriber
	err = mapper.Register(vlan, "sub-002")
	if err == nil {
		t.Error("Expected error when registering duplicate VLAN, got nil")
	}

	// Same subscriber re-registering same VLAN should work
	err = mapper.Register(vlan, "sub-001")
	if err != nil {
		t.Errorf("Re-registering same VLAN for same subscriber should work: %v", err)
	}
}

func TestMapper_UnregisterByVLAN(t *testing.T) {
	config := DefaultConfig()
	mapper := NewMapper(config)

	vlan := VLANPair{STag: 100, CTag: 500}
	_ = mapper.Register(vlan, "sub-001")

	// Unregister
	mapper.Unregister(vlan)

	// Verify removed
	_, ok := mapper.GetSubscriber(vlan)
	if ok {
		t.Error("GetSubscriber() should return false after Unregister()")
	}

	_, ok = mapper.GetVLAN("sub-001")
	if ok {
		t.Error("GetVLAN() should return false after Unregister()")
	}
}

func TestMapper_UnregisterBySubscriber(t *testing.T) {
	config := DefaultConfig()
	mapper := NewMapper(config)

	vlan := VLANPair{STag: 100, CTag: 500}
	_ = mapper.Register(vlan, "sub-001")

	// Unregister by subscriber
	mapper.UnregisterSubscriber("sub-001")

	// Verify removed
	_, ok := mapper.GetSubscriber(vlan)
	if ok {
		t.Error("GetSubscriber() should return false after UnregisterSubscriber()")
	}
}

func TestMapper_SubscriberVLANUpdate(t *testing.T) {
	config := DefaultConfig()
	mapper := NewMapper(config)

	// Register initial VLAN
	vlan1 := VLANPair{STag: 100, CTag: 500}
	_ = mapper.Register(vlan1, "sub-001")

	// Register new VLAN for same subscriber (should remove old)
	vlan2 := VLANPair{STag: 100, CTag: 600}
	err := mapper.Register(vlan2, "sub-001")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Old VLAN should be unmapped
	_, ok := mapper.GetSubscriber(vlan1)
	if ok {
		t.Error("Old VLAN should be unmapped after subscriber VLAN update")
	}

	// New VLAN should work
	subID, ok := mapper.GetSubscriber(vlan2)
	if !ok || subID != "sub-001" {
		t.Error("New VLAN should be mapped to subscriber")
	}
}

func TestMapper_InvalidSTag(t *testing.T) {
	config := Config{
		Enabled: true,
		STagRanges: []VLANRange{
			{Start: 100, End: 200},
		},
		CTagRange: VLANRange{Start: 1, End: 4094},
	}
	mapper := NewMapper(config)

	// Valid S-TAG
	err := mapper.Register(VLANPair{STag: 150, CTag: 500}, "sub-001")
	if err != nil {
		t.Errorf("Valid S-TAG should succeed: %v", err)
	}

	// Invalid S-TAG
	err = mapper.Register(VLANPair{STag: 500, CTag: 500}, "sub-002")
	if err == nil {
		t.Error("Invalid S-TAG should fail")
	}
}

func TestMapper_InvalidCTag(t *testing.T) {
	config := Config{
		Enabled: true,
		STagRanges: []VLANRange{
			{Start: 100, End: 200},
		},
		CTagRange: VLANRange{Start: 100, End: 500},
	}
	mapper := NewMapper(config)

	// Valid C-TAG
	err := mapper.Register(VLANPair{STag: 150, CTag: 200}, "sub-001")
	if err != nil {
		t.Errorf("Valid C-TAG should succeed: %v", err)
	}

	// Invalid C-TAG (out of range)
	err = mapper.Register(VLANPair{STag: 150, CTag: 600}, "sub-002")
	if err == nil {
		t.Error("Invalid C-TAG should fail")
	}
}

func TestMapper_Stats(t *testing.T) {
	config := DefaultConfig()
	mapper := NewMapper(config)

	stats := mapper.Stats()
	if stats.TotalMappings != 0 {
		t.Errorf("Initial TotalMappings = %d, want 0", stats.TotalMappings)
	}

	_ = mapper.Register(VLANPair{STag: 100, CTag: 500}, "sub-001")
	_ = mapper.Register(VLANPair{STag: 100, CTag: 501}, "sub-002")

	stats = mapper.Stats()
	if stats.TotalMappings != 2 {
		t.Errorf("TotalMappings = %d, want 2", stats.TotalMappings)
	}
}
