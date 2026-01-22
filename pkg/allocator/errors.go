package allocator

import "errors"

var (
	// ErrPoolExhausted is returned when no more prefixes are available.
	ErrPoolExhausted = errors.New("pool exhausted")

	// ErrNotFound is returned when an allocation is not found.
	ErrNotFound = errors.New("allocation not found")
)
