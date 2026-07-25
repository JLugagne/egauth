package identity

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Store is the persistence boundary for the identity package.
//
// It is the composition of four capability interfaces — UserStore (user records),
// IdentityStore (per-provider login bindings), VerificationTokenStore (single-use
// selector/verifier tokens) and LockoutStore (brute-force counters). Segmenting the contract
// this way means a future v1.x capability can ship as a NEW optional interface rather than a
// method on this one, which would break every external Store. Both the in-memory and pgx stores
// implement the whole Store.
//
// It defines the operations needed to manage users and their authentication identities
// within a tenant, along with the verification-token, lockout and account-state primitives
// the higher-level flows build on. All methods are tenant-scoped and return the package's
// sentinel errors (e.g. ErrUserNotFound, ErrTenantMismatch) so callers can branch on them.
// Implementations are responsible for enforcing per-tenant isolation; a Postgres-backed
// implementation is provided in the identity/pgx subpackage.
type Store interface {
	UserStore
	IdentityStore
	VerificationTokenStore
	LockoutStore
}

// UserStore is the user-record capability of the identity backend: creating, finding, updating,
// soft-deleting, disabling and enabling user rows.
type UserStore interface {
	// CreateUser persists a new user in the given tenant. The created user's TenantID is set
	// to tenantID.
	CreateUser(ctx context.Context, tenantID string, email string) (*User, error)
	FindUserByID(ctx context.Context, tenantID string, id uuid.UUID) (*User, error)
	FindUserByEmail(ctx context.Context, tenantID string, email string) (*User, error)

	// FindUserByPhone finds the live user in the tenant whose phone equals phone (the normalized
	// E.164 form). It returns ErrUserNotFound when none matches. Used by the phone-verification
	// flow's pre-flight uniqueness check.
	FindUserByPhone(ctx context.Context, tenantID string, phone string) (*User, error)

	// UpdateUser persists ONLY the Email and EmailVerifiedAt fields of an existing live user.
	// Every other column is owned by a dedicated operation (DisableUser/EnableUser,
	// UpdateUserPhone, UpdateUserRecoveryEmail, DeleteUser) and MUST be left untouched: the
	// method takes a whole *User, so a caller holding a copy read before one of those
	// administrative writes would otherwise replay stale values and — worst of all — clear
	// DisabledAt, re-activating a suspended account. It returns ErrTenantMismatch when the record
	// carries a non-empty TenantID that differs from tenantID, and ErrUserNotFound for an unknown,
	// cross-tenant or soft-deleted user (a soft-deleted account is never resurrected).
	UpdateUser(ctx context.Context, tenantID string, user *User) error

	// MarkEmailVerified stamps email_verified_at = verifiedAt on a live user, writing ONLY that
	// column. It is the narrow write behind VerifyEmail: passing a whole *User through UpdateUser
	// made that flow a read-modify-write on the email too, so a ConfirmEmailChange landing between
	// the read and the write was silently lost (the login address reverted while its change token
	// had already been consumed). It is idempotent — re-verifying an already-verified address just
	// re-stamps it — and returns ErrUserNotFound for an unknown, cross-tenant or soft-deleted user.
	MarkEmailVerified(ctx context.Context, tenantID string, userID uuid.UUID, verifiedAt time.Time) error

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

	// DisableUser marks a live user as administratively disabled by setting disabled_at to
	// disabledAt. It is a REVERSIBLE suspension: the row, email slot and all associated data are
	// retained (unlike DeleteUser, which anonymizes). Disabling an already-disabled user is a
	// no-op that succeeds (idempotent). It returns ErrUserNotFound when no live (non-soft-deleted),
	// same-tenant user matches.
	DisableUser(ctx context.Context, tenantID string, id uuid.UUID, disabledAt time.Time) error

	// EnableUser clears a user's disabled_at, re-activating an administratively disabled account.
	// Enabling an account that is not disabled is a no-op that succeeds (idempotent). It returns
	// ErrUserNotFound when no live (non-soft-deleted), same-tenant user matches.
	EnableUser(ctx context.Context, tenantID string, id uuid.UUID) error
}

// IdentityStore is the identity-record capability of the identity backend: the per-provider login
// bindings (password, OAuth, ...) attached to a user.
type IdentityStore interface {
	// AddIdentity persists a new identity in the given tenant. If the identity record carries a
	// non-empty TenantID that differs from tenantID, it returns ErrTenantMismatch.
	AddIdentity(ctx context.Context, tenantID string, identity *Identity) error
	FindIdentitiesByUserID(ctx context.Context, tenantID string, userID uuid.UUID) ([]*Identity, error)
	FindIdentityByProvider(ctx context.Context, tenantID string, provider, providerID string) (*Identity, error)
	// UpdateIdentityPassword sets a new password hash on the user's "password" identity and
	// atomically clears any lockout (failed_attempts and locked_until), since proving control
	// of the reset channel re-establishes trust. It also stamps password_changed_at=changedAt
	// and sets must_change_password=mustChange in the same write, so the rotation policy can
	// flag or clear the credential without a second round-trip.
	//
	// It is gated on the owner being a LIVE, same-tenant user: it returns ErrUserNotFound for an
	// unknown, cross-tenant or SOFT-DELETED account, so a rotation can never re-arm a usable
	// password hash on a deleted one. Returns ErrIdentityNotFound when a live user has no password
	// identity.
	UpdateIdentityPassword(ctx context.Context, tenantID string, userID uuid.UUID, passwordHash string, changedAt time.Time, mustChange bool) error
}

// VerificationTokenStore is the verification-token capability of the identity backend: the
// single-use selector/verifier tokens that back email/phone verification and password reset, plus
// their schedulable GC.
type VerificationTokenStore interface {
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

	// DeleteVerificationTokensForUser purges a single user's pending verification tokens within
	// the tenant. When kinds is empty EVERY kind is purged; otherwise only the listed kinds are.
	//
	// It is the per-user revocation seam the credential-rotating flows depend on: ResetPassword,
	// ChangePassword, SetTemporaryPassword and DisableUser call it so a token minted while the
	// account was under an attacker's control cannot outlive the recovery. Expiry-based GC is not
	// a substitute — a recovery-email or email-change token lives for hours to a day, which is
	// exactly the window an evicted attacker needs.
	//
	// It is idempotent: purging a user with no pending token, or an unknown user, is a success
	// (there is nothing to purge, and the callers already hold the account state they need). A
	// genuine backend failure MUST be reported — a purge that silently succeeds would leave the
	// attacker's foothold intact.
	DeleteVerificationTokensForUser(ctx context.Context, tenantID string, userID uuid.UUID, kinds ...string) error
}

// LockoutStore is the failed-attempt/lockout capability of the identity backend: the counter that
// gates brute-force attempts against an identity.
type LockoutStore interface {
	// IncrementFailedAttempts increments the failed-attempt counter for an identity.
	// When the counter reaches/exceeds lockThreshold, LockedUntil is set to now + lockDuration.
	//
	// justLocked reports whether THIS call's atomic increment is the one that crossed the
	// threshold (the counter went from below lockThreshold to at/above it). It is derived from
	// the post-increment counter inside the same atomic operation, so under concurrent failed
	// logins exactly one caller observes justLocked == true — the request that actually locked
	// the account. Callers use it to emit a once-per-lock audit event with correct attribution;
	// a non-atomic read-then-predict would mis-fire under contention. It is false when
	// lockThreshold <= 0 (lockout disabled) and on every attempt after the account is already
	// locked.
	IncrementFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration) (justLocked bool, err error)

	// ResetFailedAttempts zeroes the failed-attempt counter and clears LockedUntil.
	ResetFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID) error
}
