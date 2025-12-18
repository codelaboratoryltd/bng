package radius

import (
	"fmt"
	"sync"
)

// QoSPolicy represents a bandwidth policy
type QoSPolicy struct {
	Name        string
	DownloadBPS uint64 // Download rate limit in bits per second
	UploadBPS   uint64 // Upload rate limit in bits per second
	BurstSize   uint32 // Burst size in bytes (0 = default)
	Priority    uint8  // Traffic priority (0-7, higher = more priority)
}

// PolicyManager manages QoS policies
type PolicyManager struct {
	policies map[string]*QoSPolicy
	mu       sync.RWMutex
}

// NewPolicyManager creates a new policy manager
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies: make(map[string]*QoSPolicy),
	}
}

// AddPolicy adds a QoS policy
func (pm *PolicyManager) AddPolicy(policy *QoSPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name required")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.policies[policy.Name] = policy
	return nil
}

// GetPolicy retrieves a policy by name (from Filter-Id)
func (pm *PolicyManager) GetPolicy(name string) *QoSPolicy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.policies[name]
}

// RemovePolicy removes a policy
func (pm *PolicyManager) RemovePolicy(name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.policies, name)
}

// ListPolicies returns all policy names
func (pm *PolicyManager) ListPolicies() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	names := make([]string, 0, len(pm.policies))
	for name := range pm.policies {
		names = append(names, name)
	}
	return names
}

// DefaultPolicies returns a set of common default policies
func DefaultPolicies() []*QoSPolicy {
	return []*QoSPolicy{
		{
			Name:        "residential-50mbps",
			DownloadBPS: 50_000_000, // 50 Mbps
			UploadBPS:   10_000_000, // 10 Mbps
			BurstSize:   1_000_000,  // 1 MB burst
			Priority:    4,
		},
		{
			Name:        "residential-100mbps",
			DownloadBPS: 100_000_000, // 100 Mbps
			UploadBPS:   20_000_000,  // 20 Mbps
			BurstSize:   2_000_000,   // 2 MB burst
			Priority:    4,
		},
		{
			Name:        "residential-500mbps",
			DownloadBPS: 500_000_000, // 500 Mbps
			UploadBPS:   50_000_000,  // 50 Mbps
			BurstSize:   5_000_000,   // 5 MB burst
			Priority:    4,
		},
		{
			Name:        "residential-1gbps",
			DownloadBPS: 1_000_000_000, // 1 Gbps
			UploadBPS:   100_000_000,   // 100 Mbps
			BurstSize:   10_000_000,    // 10 MB burst
			Priority:    4,
		},
		{
			Name:        "business-100mbps",
			DownloadBPS: 100_000_000, // 100 Mbps symmetric
			UploadBPS:   100_000_000,
			BurstSize:   2_000_000,
			Priority:    6, // Higher priority for business
		},
		{
			Name:        "business-1gbps",
			DownloadBPS: 1_000_000_000, // 1 Gbps symmetric
			UploadBPS:   1_000_000_000,
			BurstSize:   10_000_000,
			Priority:    6,
		},
		{
			Name:        "guest",
			DownloadBPS: 10_000_000, // 10 Mbps
			UploadBPS:   5_000_000,  // 5 Mbps
			BurstSize:   500_000,
			Priority:    2, // Lower priority
		},
		{
			Name:        "unlimited",
			DownloadBPS: 0, // 0 = no limit
			UploadBPS:   0,
			BurstSize:   0,
			Priority:    4,
		},
	}
}

// LoadDefaultPolicies loads the default policy set
func (pm *PolicyManager) LoadDefaultPolicies() {
	for _, policy := range DefaultPolicies() {
		pm.AddPolicy(policy)
	}
}
