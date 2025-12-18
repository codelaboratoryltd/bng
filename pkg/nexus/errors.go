package nexus

import "errors"

var (
	// ErrNotFound is returned when a key does not exist.
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists is returned when trying to create something that already exists.
	ErrAlreadyExists = errors.New("already exists")

	// ErrNotConnected is returned when operations are attempted before connecting.
	ErrNotConnected = errors.New("not connected to CLSet")

	// ErrDeviceNotRegistered is returned when the device is not registered.
	ErrDeviceNotRegistered = errors.New("device not registered")

	// ErrSubscriberNotFound is returned when a subscriber is not found.
	ErrSubscriberNotFound = errors.New("subscriber not found")

	// ErrNTENotFound is returned when an NTE is not found.
	ErrNTENotFound = errors.New("NTE not found")

	// ErrPoolExhausted is returned when no IPs are available in a pool.
	ErrPoolExhausted = errors.New("IP pool exhausted")

	// ErrVLANExhausted is returned when no VLANs are available.
	ErrVLANExhausted = errors.New("VLAN range exhausted")
)
