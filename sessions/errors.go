package sessions

import "errors"

var (
	// ErrSessionNotFound is returned when a session cannot be found.
	ErrSessionNotFound = errors.New("sessions: session not found")

	// ErrTenantMismatch is returned when a session record's TenantID does not match the
	// tenantID argument supplied to a Save/Update operation.
	ErrTenantMismatch = errors.New("sessions: tenant ID mismatch")
)
