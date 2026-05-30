package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultTestLockThreshold = 3
	defaultTestLockDuration  = 15 * time.Minute
)

// MockStore is a functional mock of the identity.Store interface.
type MockStore struct {
	CreateUserFunc             func(ctx context.Context, email string, opts ...identity.Option) (*identity.User, error)
	FindUserByIDFunc           func(ctx context.Context, id uuid.UUID, opts ...identity.Option) (*identity.User, error)
	FindUserByEmailFunc        func(ctx context.Context, email string, opts ...identity.Option) (*identity.User, error)
	UpdateUserFunc             func(ctx context.Context, user *identity.User, opts ...identity.Option) error
	UpdateUserEmailFunc        func(ctx context.Context, userID uuid.UUID, newEmail string, verifiedAt time.Time, opts ...identity.Option) error
	DeleteUserFunc             func(ctx context.Context, id uuid.UUID, opts ...identity.Option) error
	AddIdentityFunc            func(ctx context.Context, ident *identity.Identity, opts ...identity.Option) error
	FindIdentitiesByUserIDFunc func(ctx context.Context, userID uuid.UUID, opts ...identity.Option) ([]*identity.Identity, error)
	FindIdentityByProviderFunc func(ctx context.Context, provider, providerID string, opts ...identity.Option) (*identity.Identity, error)

	IncrementFailedAttemptsFunc func(ctx context.Context, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration, opts ...identity.Option) error
	ResetFailedAttemptsFunc     func(ctx context.Context, identityID uuid.UUID, opts ...identity.Option) error

	UpdateIdentityPasswordFunc   func(ctx context.Context, userID uuid.UUID, passwordHash string, opts ...identity.Option) error
	CreateVerificationTokenFunc  func(ctx context.Context, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte, opts ...identity.Option) (string, error)
	ConsumeVerificationTokenFunc func(ctx context.Context, token, kind string, opts ...identity.Option) (uuid.UUID, []byte, error)

	DeleteExpiredVerificationTokensFunc func(ctx context.Context, opts ...identity.Option) (int64, error)
}

var _ identity.Store = (*MockStore)(nil)

func (m *MockStore) UpdateIdentityPassword(ctx context.Context, userID uuid.UUID, passwordHash string, opts ...identity.Option) error {
	if m.UpdateIdentityPasswordFunc == nil {
		panic("called not defined UpdateIdentityPasswordFunc")
	}
	return m.UpdateIdentityPasswordFunc(ctx, userID, passwordHash, opts...)
}

func (m *MockStore) CreateVerificationToken(ctx context.Context, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte, opts ...identity.Option) (string, error) {
	if m.CreateVerificationTokenFunc == nil {
		panic("called not defined CreateVerificationTokenFunc")
	}
	return m.CreateVerificationTokenFunc(ctx, userID, kind, ttl, metadata, opts...)
}

func (m *MockStore) ConsumeVerificationToken(ctx context.Context, token, kind string, opts ...identity.Option) (uuid.UUID, []byte, error) {
	if m.ConsumeVerificationTokenFunc == nil {
		panic("called not defined ConsumeVerificationTokenFunc")
	}
	return m.ConsumeVerificationTokenFunc(ctx, token, kind, opts...)
}

func (m *MockStore) DeleteExpiredVerificationTokens(ctx context.Context, opts ...identity.Option) (int64, error) {
	if m.DeleteExpiredVerificationTokensFunc == nil {
		panic("called not defined DeleteExpiredVerificationTokensFunc")
	}
	return m.DeleteExpiredVerificationTokensFunc(ctx, opts...)
}

func (m *MockStore) IncrementFailedAttempts(ctx context.Context, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration, opts ...identity.Option) error {
	if m.IncrementFailedAttemptsFunc == nil {
		panic("called not defined IncrementFailedAttemptsFunc")
	}
	return m.IncrementFailedAttemptsFunc(ctx, identityID, lockThreshold, lockDuration, opts...)
}

func (m *MockStore) ResetFailedAttempts(ctx context.Context, identityID uuid.UUID, opts ...identity.Option) error {
	if m.ResetFailedAttemptsFunc == nil {
		panic("called not defined ResetFailedAttemptsFunc")
	}
	return m.ResetFailedAttemptsFunc(ctx, identityID, opts...)
}

func (m *MockStore) CreateUser(ctx context.Context, email string, opts ...identity.Option) (*identity.User, error) {
	if m.CreateUserFunc == nil {
		panic("called not defined CreateUserFunc")
	}
	return m.CreateUserFunc(ctx, email, opts...)
}

func (m *MockStore) FindUserByID(ctx context.Context, id uuid.UUID, opts ...identity.Option) (*identity.User, error) {
	if m.FindUserByIDFunc == nil {
		panic("called not defined FindUserByIDFunc")
	}
	return m.FindUserByIDFunc(ctx, id, opts...)
}

func (m *MockStore) FindUserByEmail(ctx context.Context, email string, opts ...identity.Option) (*identity.User, error) {
	if m.FindUserByEmailFunc == nil {
		panic("called not defined FindUserByEmailFunc")
	}
	return m.FindUserByEmailFunc(ctx, email, opts...)
}

func (m *MockStore) UpdateUser(ctx context.Context, user *identity.User, opts ...identity.Option) error {
	if m.UpdateUserFunc == nil {
		panic("called not defined UpdateUserFunc")
	}
	return m.UpdateUserFunc(ctx, user, opts...)
}

func (m *MockStore) UpdateUserEmail(ctx context.Context, userID uuid.UUID, newEmail string, verifiedAt time.Time, opts ...identity.Option) error {
	if m.UpdateUserEmailFunc == nil {
		panic("called not defined UpdateUserEmailFunc")
	}
	return m.UpdateUserEmailFunc(ctx, userID, newEmail, verifiedAt, opts...)
}

func (m *MockStore) DeleteUser(ctx context.Context, id uuid.UUID, opts ...identity.Option) error {
	if m.DeleteUserFunc == nil {
		panic("called not defined DeleteUserFunc")
	}
	return m.DeleteUserFunc(ctx, id, opts...)
}

func (m *MockStore) AddIdentity(ctx context.Context, ident *identity.Identity, opts ...identity.Option) error {
	if m.AddIdentityFunc == nil {
		panic("called not defined AddIdentityFunc")
	}
	return m.AddIdentityFunc(ctx, ident, opts...)
}

func (m *MockStore) FindIdentitiesByUserID(ctx context.Context, userID uuid.UUID, opts ...identity.Option) ([]*identity.Identity, error) {
	if m.FindIdentitiesByUserIDFunc == nil {
		panic("called not defined FindIdentitiesByUserIDFunc")
	}
	return m.FindIdentitiesByUserIDFunc(ctx, userID, opts...)
}

func (m *MockStore) FindIdentityByProvider(ctx context.Context, provider, providerID string, opts ...identity.Option) (*identity.Identity, error) {
	if m.FindIdentityByProviderFunc == nil {
		panic("called not defined FindIdentityByProviderFunc")
	}
	return m.FindIdentityByProviderFunc(ctx, provider, providerID, opts...)
}

// StoreContractTesting runs a comprehensive suite of tests against any identity.Store implementation.
// It verifies single-tenant CRUD operations, multi-tenant isolation, and soft delete mechanics.
func StoreContractTesting(t *testing.T, store identity.Store, useMultiTenant bool) {
	ctx := context.Background()

	var tenantA, tenantB string
	if useMultiTenant {
		tenantA = "tenant-A"
		tenantB = "tenant-B"
	}

	t.Run("Contract: empty tenant is the default partition", func(t *testing.T) {
		// Without WithTenant, every backend must operate on the default (empty) tenant
		// partition rather than rejecting the call. A forgotten tenant is only an error under
		// the explicit WithStrictTenancy opt-in (see StrictTenancyTesting). This pins the
		// cross-backend agreement the audit (I19) flagged: the pgx backend historically
		// rejected an empty tenant on its write paths while the memory backend accepted it.
		email := "default_partition@example.com"
		user, err := store.CreateUser(ctx, email)
		require.NoError(t, err, "empty tenant must be the valid default partition, not rejected")
		require.NotNil(t, user)
		assert.Equal(t, "", user.TenantID)

		got, err := store.FindUserByID(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, user.ID, got.ID)

		// Writes that previously rejected an empty tenant must now succeed on the default
		// partition: adding an identity and minting/consuming a verification token.
		hash := "h"
		ident := &identity.Identity{UserID: user.ID, Provider: "password", ProviderID: email, PasswordHash: &hash}
		require.NoError(t, store.AddIdentity(ctx, ident))

		tok, err := store.CreateVerificationToken(ctx, user.ID, identity.KindPasswordReset, time.Hour, nil)
		require.NoError(t, err)
		uid, _, err := store.ConsumeVerificationToken(ctx, tok, identity.KindPasswordReset)
		require.NoError(t, err)
		assert.Equal(t, user.ID, uid)
	})

	t.Run("Contract: User CRUD", func(t *testing.T) {
		email := "test_crud@example.com"
		user, err := store.CreateUser(ctx, email, identity.WithTenant(tenantA))
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, email, user.Email)
		assert.NotEqual(t, uuid.Nil, user.ID)
		if useMultiTenant {
			assert.Equal(t, tenantA, user.TenantID)
		}

		// Find By ID
		foundByID, err := store.FindUserByID(ctx, user.ID, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, user.ID, foundByID.ID)

		// Find By Email
		foundByEmail, err := store.FindUserByEmail(ctx, email, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, user.ID, foundByEmail.ID)

		// Create same email in same tenant should fail
		_, err = store.CreateUser(ctx, email, identity.WithTenant(tenantA))
		assert.Error(t, err)
		assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)

		// Update
		now := time.Now()
		user.EmailVerifiedAt = &now
		err = store.UpdateUser(ctx, user, identity.WithTenant(tenantA))
		require.NoError(t, err)

		foundByID, _ = store.FindUserByID(ctx, user.ID, identity.WithTenant(tenantA))
		require.NotNil(t, foundByID.EmailVerifiedAt)
		assert.Equal(t, now.Unix(), foundByID.EmailVerifiedAt.Unix())

		// Delete (Soft delete & anonymize)
		err = store.DeleteUser(ctx, user.ID, identity.WithTenant(tenantA))
		require.NoError(t, err)

		// Finding by old email should fail because it was anonymized
		_, err = store.FindUserByEmail(ctx, email, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrUserNotFound)

		// Finding by ID should still work, but show DeletedAt and modified email
		deletedUser, err := store.FindUserByID(ctx, user.ID, identity.WithTenant(tenantA))
		require.NoError(t, err)
		require.NotNil(t, deletedUser.DeletedAt)
		assert.NotEqual(t, email, deletedUser.Email)

		// Deleting an already-deleted (or unknown / cross-tenant) user reports ErrUserNotFound,
		// not a silent no-op success — both backends must agree.
		err = store.DeleteUser(ctx, user.ID, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrUserNotFound, "re-deleting a soft-deleted user must report not found")
		err = store.DeleteUser(ctx, uuid.New(), identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrUserNotFound, "deleting an unknown user must report not found")
	})

	t.Run("Contract: Delete purges verification tokens", func(t *testing.T) {
		user, err := store.CreateUser(ctx, "test_delete_purge@example.com", identity.WithTenant(tenantA))
		require.NoError(t, err)

		token, err := store.CreateVerificationToken(ctx, user.ID, identity.KindMagicLink, time.Hour, []byte("meta"), identity.WithTenant(tenantA))
		require.NoError(t, err)

		require.NoError(t, store.DeleteUser(ctx, user.ID, identity.WithTenant(tenantA)))

		// The pending token must be GONE (not merely inert): its row carried the user_id and any
		// metadata PII, which the soft delete must erase.
		_, _, err = store.ConsumeVerificationToken(ctx, token, identity.KindMagicLink, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "deletion must purge the user's verification tokens")
	})

	t.Run("Contract: Identity CRUD", func(t *testing.T) {
		email := "test_identity@example.com"
		user, err := store.CreateUser(ctx, email, identity.WithTenant(tenantA))
		require.NoError(t, err)

		hash := "hashed_pass"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   email,
			PasswordHash: &hash,
		}

		err = store.AddIdentity(ctx, ident, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, ident.ID)

		// Find By Provider
		foundIdent, err := store.FindIdentityByProvider(ctx, "password", email, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, ident.ID, foundIdent.ID)
		assert.Equal(t, user.ID, foundIdent.UserID)

		// Find By User ID
		idents, err := store.FindIdentitiesByUserID(ctx, user.ID, identity.WithTenant(tenantA))
		require.NoError(t, err)
		require.Len(t, idents, 1)
		assert.Equal(t, ident.ID, idents[0].ID)

		// Add same identity should fail
		err = store.AddIdentity(ctx, ident, identity.WithTenant(tenantA))
		assert.Error(t, err)
		assert.ErrorIs(t, err, identity.ErrIdentityAlreadyExists)
	})

	t.Run("Contract: Lockout Attempts", func(t *testing.T) {
		email := "test_lockout@example.com"
		user, err := store.CreateUser(ctx, email, identity.WithTenant(tenantA))
		require.NoError(t, err)

		hash := "hashed_pass"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   email,
			PasswordHash: &hash,
		}
		require.NoError(t, store.AddIdentity(ctx, ident, identity.WithTenant(tenantA)))

		// Increment below threshold: counter rises, no lock.
		for i := 1; i < defaultTestLockThreshold; i++ {
			err = store.IncrementFailedAttempts(ctx, ident.ID, defaultTestLockThreshold, defaultTestLockDuration, identity.WithTenant(tenantA))
			require.NoError(t, err)

			found, err := store.FindIdentityByProvider(ctx, "password", email, identity.WithTenant(tenantA))
			require.NoError(t, err)
			assert.Equal(t, i, found.FailedAttempts, "failed attempts must be persisted")
			assert.Nil(t, found.LockedUntil, "must not be locked below threshold")
		}

		// Crossing the threshold sets LockedUntil.
		err = store.IncrementFailedAttempts(ctx, ident.ID, defaultTestLockThreshold, defaultTestLockDuration, identity.WithTenant(tenantA))
		require.NoError(t, err)

		found, err := store.FindIdentityByProvider(ctx, "password", email, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, defaultTestLockThreshold, found.FailedAttempts)
		require.NotNil(t, found.LockedUntil, "must be locked at threshold")
		assert.True(t, found.LockedUntil.After(time.Now()), "lock must be in the future")

		// Reset clears both counter and lock.
		err = store.ResetFailedAttempts(ctx, ident.ID, identity.WithTenant(tenantA))
		require.NoError(t, err)

		found, err = store.FindIdentityByProvider(ctx, "password", email, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, 0, found.FailedAttempts)
		assert.Nil(t, found.LockedUntil)
	})

	t.Run("Contract: Password Update", func(t *testing.T) {
		email := "test_pwupdate@example.com"
		user, err := store.CreateUser(ctx, email, identity.WithTenant(tenantA))
		require.NoError(t, err)

		oldHash := "old_hash"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   email,
			PasswordHash: &oldHash,
		}
		require.NoError(t, store.AddIdentity(ctx, ident, identity.WithTenant(tenantA)))

		// Lock the account, then update the password: lockout must be cleared atomically.
		require.NoError(t, store.IncrementFailedAttempts(ctx, ident.ID, 1, defaultTestLockDuration, identity.WithTenant(tenantA)))

		err = store.UpdateIdentityPassword(ctx, user.ID, "new_hash", identity.WithTenant(tenantA))
		require.NoError(t, err)

		found, err := store.FindIdentityByProvider(ctx, "password", email, identity.WithTenant(tenantA))
		require.NoError(t, err)
		require.NotNil(t, found.PasswordHash)
		assert.Equal(t, "new_hash", *found.PasswordHash)
		assert.Equal(t, 0, found.FailedAttempts, "password update must clear failed attempts")
		assert.Nil(t, found.LockedUntil, "password update must clear the lock")

		// Updating a user without a password identity fails.
		ghost, err := store.CreateUser(ctx, "ghost@example.com", identity.WithTenant(tenantA))
		require.NoError(t, err)
		err = store.UpdateIdentityPassword(ctx, ghost.ID, "x", identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrIdentityNotFound)
	})

	t.Run("Contract: Change Email", func(t *testing.T) {
		const oldEmail = "change_old@example.com"
		const newEmail = "change_new@example.com"
		user, err := store.CreateUser(ctx, oldEmail, identity.WithTenant(tenantA))
		require.NoError(t, err)

		hash := "hashed_pass"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   oldEmail, // password identities are keyed by email
			PasswordHash: &hash,
		}
		require.NoError(t, store.AddIdentity(ctx, ident, identity.WithTenant(tenantA)))

		verifiedAt := time.Now()
		require.NoError(t, store.UpdateUserEmail(ctx, user.ID, newEmail, verifiedAt, identity.WithTenant(tenantA)))

		// The user now resolves by the new email and is marked verified; the old email is gone.
		found, err := store.FindUserByEmail(ctx, newEmail, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, user.ID, found.ID)
		require.NotNil(t, found.EmailVerifiedAt, "the confirmed new address must be verified")
		assert.Equal(t, verifiedAt.Unix(), found.EmailVerifiedAt.Unix())

		_, err = store.FindUserByEmail(ctx, oldEmail, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrUserNotFound)

		// The password identity must have been re-keyed to the new email, so password login by
		// the new email keeps working (and the old key no longer resolves).
		reIdent, err := store.FindIdentityByProvider(ctx, "password", newEmail, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, user.ID, reIdent.UserID)
		_, err = store.FindIdentityByProvider(ctx, "password", oldEmail, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrIdentityNotFound)

		// Changing to an address held by another live account is rejected.
		other, err := store.CreateUser(ctx, "change_other@example.com", identity.WithTenant(tenantA))
		require.NoError(t, err)
		err = store.UpdateUserEmail(ctx, other.ID, newEmail, time.Now(), identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)

		// An unknown user is reported as not found.
		err = store.UpdateUserEmail(ctx, uuid.New(), "nobody_new@example.com", time.Now(), identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrUserNotFound)

		// An account with no password identity (e.g. OAuth-only) can still change its email; only
		// the user row moves and a non-password identity is left untouched (not re-keyed).
		oauthUser, err := store.CreateUser(ctx, "oauth_old@example.com", identity.WithTenant(tenantA))
		require.NoError(t, err)
		oauthIdent := &identity.Identity{
			UserID:     oauthUser.ID,
			Provider:   "google",
			ProviderID: "google-sub-123",
		}
		require.NoError(t, store.AddIdentity(ctx, oauthIdent, identity.WithTenant(tenantA)))

		require.NoError(t, store.UpdateUserEmail(ctx, oauthUser.ID, "oauth_new@example.com", time.Now(), identity.WithTenant(tenantA)))
		movedOAuth, err := store.FindUserByEmail(ctx, "oauth_new@example.com", identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, oauthUser.ID, movedOAuth.ID)
		// The OAuth identity must still resolve by its original provider key (never re-keyed).
		gotOAuth, err := store.FindIdentityByProvider(ctx, "google", "google-sub-123", identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, oauthUser.ID, gotOAuth.UserID)
	})

	t.Run("Contract: Verification Tokens", func(t *testing.T) {
		user, err := store.CreateUser(ctx, "test_verif@example.com", identity.WithTenant(tenantA))
		require.NoError(t, err)

		meta := []byte("payload-123")
		token, err := store.CreateVerificationToken(ctx, user.ID, identity.KindPasswordReset, time.Hour, meta, identity.WithTenant(tenantA))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Wrong kind must not match.
		_, _, err = store.ConsumeVerificationToken(ctx, token, identity.KindEmailVerification, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

		// Tampered verifier must not match.
		_, _, err = store.ConsumeVerificationToken(ctx, token+"x", identity.KindPasswordReset, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

		// Malformed token (no separator) must not match.
		_, _, err = store.ConsumeVerificationToken(ctx, "garbage", identity.KindPasswordReset, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

		// Happy path: returns the bound user and metadata.
		gotUser, gotMeta, err := store.ConsumeVerificationToken(ctx, token, identity.KindPasswordReset, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, user.ID, gotUser)
		assert.Equal(t, meta, gotMeta)

		// Single-use: a second consumption fails.
		_, _, err = store.ConsumeVerificationToken(ctx, token, identity.KindPasswordReset, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

		// Expired token: genuine token, past expiry, reports expiry.
		expiredToken, err := store.CreateVerificationToken(ctx, user.ID, identity.KindEmailVerification, -time.Minute, nil, identity.WithTenant(tenantA))
		require.NoError(t, err)
		_, _, err = store.ConsumeVerificationToken(ctx, expiredToken, identity.KindEmailVerification, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrVerificationTokenExpired)

		// A cross-tenant target must not be mintable (both backends enforce same-tenant).
		if useMultiTenant {
			_, err = store.CreateVerificationToken(ctx, user.ID, identity.KindPasswordReset, time.Hour, nil, identity.WithTenant(tenantB))
			assert.ErrorIs(t, err, identity.ErrUserNotFound, "must not mint a token for a user in another tenant")
		}

		// A soft-deleted user must not be mintable.
		require.NoError(t, store.DeleteUser(ctx, user.ID, identity.WithTenant(tenantA)))
		_, err = store.CreateVerificationToken(ctx, user.ID, identity.KindPasswordReset, time.Hour, nil, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrUserNotFound, "must not mint a token for a soft-deleted user")
	})

	t.Run("Contract: DeleteExpiredVerificationTokens purges only expired", func(t *testing.T) {
		user, err := store.CreateUser(ctx, "reaper_verif@example.com", identity.WithTenant(tenantA))
		require.NoError(t, err)

		expired, err := store.CreateVerificationToken(ctx, user.ID, identity.KindPasswordReset, -time.Minute, nil, identity.WithTenant(tenantA))
		require.NoError(t, err)
		live, err := store.CreateVerificationToken(ctx, user.ID, identity.KindEmailVerification, time.Hour, nil, identity.WithTenant(tenantA))
		require.NoError(t, err)

		n, err := store.DeleteExpiredVerificationTokens(ctx, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, int64(1))

		// The expired token is GONE (reaped), so consume reports not-found rather than expired.
		_, _, err = store.ConsumeVerificationToken(ctx, expired, identity.KindPasswordReset, identity.WithTenant(tenantA))
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "expired token must be reaped")

		// The live token still consumes.
		uid, _, err := store.ConsumeVerificationToken(ctx, live, identity.KindEmailVerification, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, user.ID, uid)
	})

	if useMultiTenant {
		t.Run("Contract: Multi-Tenant Isolation", func(t *testing.T) {
			sharedEmail := "isolated@example.com"

			// Create in Tenant A
			userA, err := store.CreateUser(ctx, sharedEmail, identity.WithTenant(tenantA))
			require.NoError(t, err)
			assert.Equal(t, tenantA, userA.TenantID)

			// Create in Tenant B (should succeed because isolation)
			userB, err := store.CreateUser(ctx, sharedEmail, identity.WithTenant(tenantB))
			require.NoError(t, err)
			assert.Equal(t, tenantB, userB.TenantID)

			// Add identical identities in different tenants
			hashA := "hashA"
			identA := &identity.Identity{
				UserID:       userA.ID,
				Provider:     "password",
				ProviderID:   sharedEmail,
				PasswordHash: &hashA,
			}
			err = store.AddIdentity(ctx, identA, identity.WithTenant(tenantA))
			require.NoError(t, err)

			hashB := "hashB"
			identB := &identity.Identity{
				UserID:       userB.ID,
				Provider:     "password",
				ProviderID:   sharedEmail,
				PasswordHash: &hashB,
			}
			err = store.AddIdentity(ctx, identB, identity.WithTenant(tenantB))
			require.NoError(t, err)

			// Cross-tenant querying should fail
			_, err = store.FindUserByID(ctx, userA.ID, identity.WithTenant(tenantB))
			assert.ErrorIs(t, err, identity.ErrUserNotFound, "Tenant B should not see Tenant A's user")

			_, err = store.FindIdentityByProvider(ctx, "password", sharedEmail, identity.WithTenant(tenantB))
			require.NoError(t, err)
			assert.Equal(t, userB.ID, identB.UserID, "Should find the identity specific to Tenant B")
		})
	}
}

// StrictTenancyTesting asserts that a store built WithStrictTenancy rejects every tenant-scoped
// operation performed without a tenant (no WithTenant) via identity.ErrTenantRequired, and that
// the same operations succeed once a tenant is supplied. DeleteExpiredVerificationTokens is
// intentionally NOT asserted here: it is an exempt maintenance sweep that spans all tenants when
// no tenant is given. Pass a store constructed WithStrictTenancy.
func StrictTenancyTesting(t *testing.T, strict identity.Store) {
	ctx := context.Background()
	uid := uuid.New()

	t.Run("strict: every tenant-scoped op rejects an empty tenant", func(t *testing.T) {
		_, err := strict.CreateUser(ctx, "strict@example.com")
		assert.ErrorIs(t, err, identity.ErrTenantRequired, "CreateUser without a tenant must be rejected in strict mode")

		_, err = strict.FindUserByID(ctx, uid)
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		_, err = strict.FindUserByEmail(ctx, "strict@example.com")
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		err = strict.UpdateUser(ctx, &identity.User{ID: uid})
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		err = strict.UpdateUserEmail(ctx, uid, "new@example.com", time.Now())
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		err = strict.DeleteUser(ctx, uid)
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		err = strict.AddIdentity(ctx, &identity.Identity{UserID: uid, Provider: "password", ProviderID: "strict@example.com"})
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		_, err = strict.FindIdentitiesByUserID(ctx, uid)
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		_, err = strict.FindIdentityByProvider(ctx, "password", "strict@example.com")
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		err = strict.UpdateIdentityPassword(ctx, uid, "hash")
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		_, err = strict.CreateVerificationToken(ctx, uid, identity.KindPasswordReset, time.Hour, nil)
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		_, _, err = strict.ConsumeVerificationToken(ctx, "selector.verifier", identity.KindPasswordReset)
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		err = strict.IncrementFailedAttempts(ctx, uid, defaultTestLockThreshold, defaultTestLockDuration)
		assert.ErrorIs(t, err, identity.ErrTenantRequired)

		err = strict.ResetFailedAttempts(ctx, uid)
		assert.ErrorIs(t, err, identity.ErrTenantRequired)
	})

	t.Run("strict: the same ops succeed once a tenant is supplied", func(t *testing.T) {
		const tenant = "strict-tenant"
		user, err := strict.CreateUser(ctx, "ok@example.com", identity.WithTenant(tenant))
		require.NoError(t, err)
		require.NotNil(t, user)

		got, err := strict.FindUserByID(ctx, user.ID, identity.WithTenant(tenant))
		require.NoError(t, err)
		assert.Equal(t, user.ID, got.ID)

		hash := "h"
		ident := &identity.Identity{UserID: user.ID, Provider: "password", ProviderID: "ok@example.com", PasswordHash: &hash}
		require.NoError(t, strict.AddIdentity(ctx, ident, identity.WithTenant(tenant)))

		tok, err := strict.CreateVerificationToken(ctx, user.ID, identity.KindPasswordReset, time.Hour, nil, identity.WithTenant(tenant))
		require.NoError(t, err)
		gotUID, _, err := strict.ConsumeVerificationToken(ctx, tok, identity.KindPasswordReset, identity.WithTenant(tenant))
		require.NoError(t, err)
		assert.Equal(t, user.ID, gotUID)
	})
}
