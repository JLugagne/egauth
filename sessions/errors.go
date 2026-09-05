package sessions

import "errors"

var (
	// ErrSessionNotFound is returned when a session cannot be found.
	ErrSessionNotFound = errors.New("sessions: session not found")

	// ErrTenantMismatch is returned when a session record's TenantID does not match the
	// tenantID argument supplied to a Save/Update operation.
	ErrTenantMismatch = errors.New("sessions: tenant ID mismatch")

	// ErrDuplicateToken is returned by CreateSession when the (tenant_id, token_hash) pair
	// already exists in the store. A duplicate 256-bit token hash is an integrity violation
	// and must not silently overwrite the existing session.
	ErrDuplicateToken = errors.New("sessions: duplicate token hash")

	// ErrStoreCapacityExceeded is returned by CreateSession when a bounded store has reached
	// maximum capacity and all stored sessions are active (none are expired).
	ErrStoreCapacityExceeded = errors.New("sessions: store capacity exceeded")
)
