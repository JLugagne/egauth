package ceremony

import "errors"

var (
	// ErrInvalidRecord reports a record that NewRecord or Restore refuses; Put returns it instead of
	// persisting a malformed record.
	ErrInvalidRecord = errors.New("ceremony: invalid record")
	// ErrHandleTooShort reports a handle digest shorter than HandleHashLen: the lookup key is never a
	// short code (C-30).
	ErrHandleTooShort = errors.New("ceremony: handle hash too short")
	// ErrStatelessKind reports a stateless kind given to NewRecord or Put; such a kind is never a row.
	ErrStatelessKind = errors.New("ceremony: stateless kind has no record")
	// ErrStoredKind reports a stored kind given to MarkConsumed; its single use is the Consume of its
	// record, never a stateless mark.
	ErrStoredKind = errors.New("ceremony: stored kind has no stateless handle")
	// ErrScopeMismatch reports a scope whose class or tenant differs from what the kind requires.
	ErrScopeMismatch = errors.New("ceremony: scope does not match the kind")
	// ErrExpired reports a record whose sealed Pending, or own lifetime, has already ended at its
	// writing instant.
	ErrExpired = errors.New("ceremony: pending already expired")
)
