package identity

import (
	"context"
	"time"

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

	// UpdateUserEmail atomically changes a live user's email to newEmail, marks it verified
	// (email_verified_at = verifiedAt) and re-keys the user's "password" identity provider_id
	// to newEmail. The password flow looks identities up by email, so the user email and the
	// password identity's provider_id must move together; doing both in one atomic operation
	// means a uniqueness conflict on either the user-email index or the identity
	// (provider, provider_id) index aborts the whole change. It returns ErrEmailAlreadyExists
	// when newEmail is already taken by another account in the tenant and ErrUserNotFound when
	// no live user matches. An account with no password identity (e.g. OAuth-only) simply has
	// its user email updated.
	UpdateUserEmail(ctx context.Context, userID uuid.UUID, newEmail string, verifiedAt time.Time, opts ...Option) error

	DeleteUser(ctx context.Context, id uuid.UUID, opts ...Option) error

	// Identity operations
	AddIdentity(ctx context.Context, identity *Identity, opts ...Option) error
	FindIdentitiesByUserID(ctx context.Context, userID uuid.UUID, opts ...Option) ([]*Identity, error)
	FindIdentityByProvider(ctx context.Context, provider, providerID string, opts ...Option) (*Identity, error)

	// UpdateIdentityPassword sets a new password hash on the user's "password" identity and
	// atomically clears any lockout (failed_attempts and locked_until), since proving control
	// of the reset channel re-establishes trust. Returns ErrIdentityNotFound when the user
	// has no password identity.
	UpdateIdentityPassword(ctx context.Context, userID uuid.UUID, passwordHash string, opts ...Option) error

	// Verification token operations (selector/verifier scheme).

	// CreateVerificationToken mints, persists and returns a single-use plaintext token bound
	// to the user, kind and TTL. Only the selector and the verifier hash are stored. The
	// returned string (selector.verifier) is a credential handed to the user exactly once.
	CreateVerificationToken(ctx context.Context, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte, opts ...Option) (string, error)

	// ConsumeVerificationToken validates and atomically consumes (single-use) a token of the
	// given kind, returning the bound user ID and any stored metadata. It returns
	// ErrVerificationTokenNotFound for an unknown/malformed token or a verifier mismatch, and
	// ErrVerificationTokenExpired for a matching-but-expired token.
	ConsumeVerificationToken(ctx context.Context, token, kind string, opts ...Option) (uuid.UUID, []byte, error)

	// Lockout operations

	// IncrementFailedAttempts increments the failed-attempt counter for an identity.
	// When the counter reaches/exceeds lockThreshold, LockedUntil is set to now + lockDuration.
	IncrementFailedAttempts(ctx context.Context, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration, opts ...Option) error

	// ResetFailedAttempts zeroes the failed-attempt counter and clears LockedUntil.
	ResetFailedAttempts(ctx context.Context, identityID uuid.UUID, opts ...Option) error
}
