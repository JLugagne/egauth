package identity

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Store defines the persistence interface for User and Identity models.
//
// Every operation is scoped to a tenant via a mandatory tenantID argument. An empty
// string is a legal tenant key (the single-tenant default partition); it must still be
// passed explicitly.
type Store interface {
	// User operations

	// CreateUser persists a new user in the given tenant. The created user's TenantID is set
	// to tenantID.
	CreateUser(ctx context.Context, tenantID string, email string) (*User, error)
	FindUserByID(ctx context.Context, tenantID string, id uuid.UUID) (*User, error)
	FindUserByEmail(ctx context.Context, tenantID string, email string) (*User, error)

	// FindUserByPhone finds the live user in the tenant whose phone equals phone (the normalized
	// E.164 form). It returns ErrUserNotFound when none matches. Used by the phone-verification
	// flow's pre-flight uniqueness check.
	FindUserByPhone(ctx context.Context, tenantID string, phone string) (*User, error)

	// UpdateUser persists changes to an existing user. If the user record carries a non-empty
	// TenantID that differs from tenantID, it returns ErrTenantMismatch.
	UpdateUser(ctx context.Context, tenantID string, user *User) error

	// UpdateUserEmail atomically changes a live user's email to newEmail, marks it verified
	// (email_verified_at = verifiedAt) and re-keys the user's "password" identity provider_id
	// to newEmail. The password flow looks identities up by email, so the user email and the
	// password identity's provider_id must move together; doing both in one atomic operation
	// means a uniqueness conflict on either the user-email index or the identity
	// (provider, provider_id) index aborts the whole change. It returns ErrEmailAlreadyExists
	// when newEmail is already taken by another account in the tenant and ErrUserNotFound when
	// no live user matches. An account with no password identity (e.g. OAuth-only) simply has
	// its user email updated.
	UpdateUserEmail(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string, verifiedAt time.Time) error

	// UpdateUserPhone atomically sets a live user's phone to newPhone and marks it verified
	// (phone_verified_at = verifiedAt). Unlike UpdateUserEmail it does not re-key any identity:
	// phone is a contact attribute, never a login key. It returns ErrPhoneAlreadyExists when
	// newPhone is already taken by another live account in the tenant and ErrUserNotFound when no
	// live user matches.
	UpdateUserPhone(ctx context.Context, tenantID string, userID uuid.UUID, newPhone string, verifiedAt time.Time) error

	// UpdateUserRecoveryEmail sets a live user's recovery email to recoveryEmail and marks it
	// verified (recovery_email_verified_at = verifiedAt). The recovery email is a SECONDARY
	// contact channel, not a login key, so it is intentionally NOT globally unique (several
	// accounts may share a recovery contact) and re-keys no identity. It returns ErrUserNotFound
	// when no live user matches.
	UpdateUserRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string, verifiedAt time.Time) error

	DeleteUser(ctx context.Context, tenantID string, id uuid.UUID) error

	// Identity operations

	// AddIdentity persists a new identity in the given tenant. If the identity record carries a
	// non-empty TenantID that differs from tenantID, it returns ErrTenantMismatch.
	AddIdentity(ctx context.Context, tenantID string, identity *Identity) error
	FindIdentitiesByUserID(ctx context.Context, tenantID string, userID uuid.UUID) ([]*Identity, error)
	FindIdentityByProvider(ctx context.Context, tenantID string, provider, providerID string) (*Identity, error)

	// UpdateIdentityPassword sets a new password hash on the user's "password" identity and
	// atomically clears any lockout (failed_attempts and locked_until), since proving control
	// of the reset channel re-establishes trust. Returns ErrIdentityNotFound when the user
	// has no password identity.
	UpdateIdentityPassword(ctx context.Context, tenantID string, userID uuid.UUID, passwordHash string) error

	// Verification token operations (selector/verifier scheme).

	// CreateVerificationToken mints, persists and returns a single-use plaintext token bound
	// to the user, kind and TTL. Only the selector and the verifier hash are stored. The
	// returned string (selector.verifier) is a credential handed to the user exactly once.
	CreateVerificationToken(ctx context.Context, tenantID string, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte) (string, error)

	// ConsumeVerificationToken validates and atomically consumes (single-use) a token of the
	// given kind, returning the bound user ID and any stored metadata. It returns
	// ErrVerificationTokenNotFound for an unknown/malformed token or a verifier mismatch, and
	// ErrVerificationTokenExpired for a matching-but-expired token.
	ConsumeVerificationToken(ctx context.Context, tenantID string, token, kind string) (uuid.UUID, []byte, error)

	// DeleteExpiredVerificationTokens purges verification tokens past their expiry within the
	// given tenant, returning the number deleted. It is the schedulable GC reaper for the
	// (selector/verifier) token table. It scopes to a single tenant; a background job sweeping
	// every tenant must loop over them.
	DeleteExpiredVerificationTokens(ctx context.Context, tenantID string) (int64, error)

	// Lockout operations

	// IncrementFailedAttempts increments the failed-attempt counter for an identity.
	// When the counter reaches/exceeds lockThreshold, LockedUntil is set to now + lockDuration.
	IncrementFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration) error

	// ResetFailedAttempts zeroes the failed-attempt counter and clears LockedUntil.
	ResetFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID) error
}
