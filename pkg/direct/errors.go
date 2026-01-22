package direct

import "errors"

var (
	// ErrONTNotFound is returned when an ONT mapping cannot be found
	ErrONTNotFound = errors.New("ONT not found in BSS")

	// ErrSubscriberSuspended is returned when a subscriber is suspended
	ErrSubscriberSuspended = errors.New("subscriber suspended")

	// ErrBSSUnavailable is returned when BSS is unreachable
	ErrBSSUnavailable = errors.New("BSS unavailable")

	// ErrNexusUnavailable is returned when Nexus is unreachable
	ErrNexusUnavailable = errors.New("Nexus unavailable")
)
