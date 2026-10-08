package identity

import "errors"

var (
	// ErrInvalidIdentifier reports a value that is not the canonical form of its identifier kind.
	ErrInvalidIdentifier = errors.New("identity: invalid identifier")
	// ErrInvalidMutation reports a mutation that Validate refuses; Apply returns it and changes
	// nothing.
	ErrInvalidMutation = errors.New("identity: invalid mutation")
	// ErrIdentifierTaken reports an email or phone already owned by another live account of the
	// tenant, or a federated identity already linked to another subject.
	ErrIdentifierTaken = errors.New("identity: identifier already in use")
	// ErrNotTombstoned reports an EraseUser of a subject that Tombstone has not deleted first.
	ErrNotTombstoned = errors.New("identity: user is not tombstoned")
	// ErrTombstoned reports a mutation of a deleted user other than its erasure.
	ErrTombstoned = errors.New("identity: user is deleted")
	// ErrUnknownComponent reports an outbox subscriber name that no Component has.
	ErrUnknownComponent = errors.New("identity: unknown outbox component")
)
