package sessions

import "errors"

var (
	// ErrSessionNotFound is returned when a session cannot be found.
	ErrSessionNotFound = errors.New("sessions: session not found")

	// ErrTenantRequired is returned by a store built WithStrictTenancy when a tenant-scoped
	// operation is performed without a tenant (neither via WithTenant nor carried on the record).
	ErrTenantRequired = errors.New("sessions: tenant ID is required")
)
