//go:build !clset

package nexus

import "fmt"

// newCRDTBackend returns an error when built without the clset tag.
// The clset CRDT backend requires the clset module which is not available in CI.
// Use StoreModeMemory for testing, or build with -tags=clset when clset is available.
func newCRDTBackend(config DistributedConfig) (crdtBackend, error) {
	return nil, fmt.Errorf("CRDT backend not available: build with -tags=clset to enable CLSet support")
}
