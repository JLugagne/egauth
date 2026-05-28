package sessions

import (
	"context"

	"github.com/google/uuid"
)

// StoreOptions holds options for Store operations, such as Multi-tenancy.
type StoreOptions struct {
	TenantID *string
}

// Option is a function that configures StoreOptions.
type Option func(*StoreOptions)

// WithTenant sets the TenantID for the operation.
func WithTenant(id string) Option {
	return func(o *StoreOptions) {
		o.TenantID = &id
	}
}

// ApplyOptions applies the given options to a new StoreOptions instance.
func ApplyOptions(opts []Option) StoreOptions {
	var o StoreOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Store defines the persistence interface for Sessions.
type Store interface {
	// CreateSession persists a new session.
	CreateSession(ctx context.Context, session *Session, opts ...Option) error

	// FindSessionByHash retrieves a session by its token hash.
	FindSessionByHash(ctx context.Context, tokenHash string, opts ...Option) (*Session, error)

	// DeleteSession removes a session by its ID.
	DeleteSession(ctx context.Context, id uuid.UUID, opts ...Option) error

	// DeleteSessionsByUserID removes all sessions for a user.
	DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID, opts ...Option) error
}
