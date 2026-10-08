package sessions

import "errors"

var (
	// ErrInvalidRecord reports a record that NewRecord or Restore refuses; stores return it instead
	// of persisting a malformed record.
	ErrInvalidRecord = errors.New("sessions: invalid record")
	// ErrLifetimeExceeded reports a session that would be written at or after the absolute end of
	// its lineage (CreatedAt + MaxLifetime).
	ErrLifetimeExceeded = errors.New("sessions: lineage lifetime exceeded")
)
