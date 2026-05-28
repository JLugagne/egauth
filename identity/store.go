package identity

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

// Store defines the persistence interface for User and Identity models.
type Store interface {
	// User operations
	CreateUser(ctx context.Context, email string, opts ...Option) (*User, error)
	FindUserByID(ctx context.Context, id uuid.UUID, opts ...Option) (*User, error)
	FindUserByEmail(ctx context.Context, email string, opts ...Option) (*User, error)
	UpdateUser(ctx context.Context, user *User, opts ...Option) error
	DeleteUser(ctx context.Context, id uuid.UUID, opts ...Option) error

	// Identity operations
	AddIdentity(ctx context.Context, identity *Identity, opts ...Option) error
	FindIdentitiesByUserID(ctx context.Context, userID uuid.UUID, opts ...Option) ([]*Identity, error)
	FindIdentityByProvider(ctx context.Context, provider, providerID string, opts ...Option) (*Identity, error)
}
