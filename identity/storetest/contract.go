package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
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
	CreateUserFunc                      func(ctx context.Context, tenantID string, email string) (*identity.User, error)
	FindUserByIDFunc                    func(ctx context.Context, tenantID string, id uuid.UUID) (*identity.User, error)
	FindUserByEmailFunc                 func(ctx context.Context, tenantID string, email string) (*identity.User, error)
	FindUserByPhoneFunc                 func(ctx context.Context, tenantID string, phone string) (*identity.User, error)
	UpdateUserFunc                      func(ctx context.Context, tenantID string, user *identity.User) error
	UpdateUserEmailFunc                 func(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string, verifiedAt time.Time) error
	UpdateUserPhoneFunc                 func(ctx context.Context, tenantID string, userID uuid.UUID, newPhone string, verifiedAt time.Time) error
	UpdateUserRecoveryEmailFunc         func(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string, verifiedAt time.Time) error
	DeleteUserFunc                      func(ctx context.Context, tenantID string, id uuid.UUID) error
	DisableUserFunc                     func(ctx context.Context, tenantID string, id uuid.UUID, disabledAt time.Time) error
	EnableUserFunc                      func(ctx context.Context, tenantID string, id uuid.UUID) error
	AddIdentityFunc                     func(ctx context.Context, tenantID string, ident *identity.Identity) error
	FindIdentitiesByUserIDFunc          func(ctx context.Context, tenantID string, userID uuid.UUID) ([]*identity.Identity, error)
	FindIdentityByProviderFunc          func(ctx context.Context, tenantID string, provider, providerID string) (*identity.Identity, error)
	IncrementFailedAttemptsFunc         func(ctx context.Context, tenantID string, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration) (bool, error)
	ResetFailedAttemptsFunc             func(ctx context.Context, tenantID string, identityID uuid.UUID) error
	UpdateIdentityPasswordFunc          func(ctx context.Context, tenantID string, userID uuid.UUID, passwordHash string, changedAt time.Time, mustChange bool) error
	CreateVerificationTokenFunc         func(ctx context.Context, tenantID string, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte) (string, error)
	ConsumeVerificationTokenFunc        func(ctx context.Context, tenantID string, token, kind string) (uuid.UUID, []byte, error)
	DeleteExpiredVerificationTokensFunc func(ctx context.Context, tenantID string) (int64, error)
}

var _ identity.Store = (*MockStore)(nil)

func (m *MockStore) UpdateIdentityPassword(ctx context.Context, tenantID string, userID uuid.UUID, passwordHash string, changedAt time.Time, mustChange bool) error {
	if m.UpdateIdentityPasswordFunc == nil {
		panic("called not defined UpdateIdentityPasswordFunc")
	}
	return m.UpdateIdentityPasswordFunc(ctx, tenantID, userID, passwordHash, changedAt, mustChange)
}

func (m *MockStore) CreateVerificationToken(ctx context.Context, tenantID string, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte) (string, error) {
	if m.CreateVerificationTokenFunc == nil {
		panic("called not defined CreateVerificationTokenFunc")
	}
	return m.CreateVerificationTokenFunc(ctx, tenantID, userID, kind, ttl, metadata)
}

func (m *MockStore) ConsumeVerificationToken(ctx context.Context, tenantID string, token, kind string) (uuid.UUID, []byte, error) {
	if m.ConsumeVerificationTokenFunc == nil {
		panic("called not defined ConsumeVerificationTokenFunc")
	}
	return m.ConsumeVerificationTokenFunc(ctx, tenantID, token, kind)
}

func (m *MockStore) DeleteExpiredVerificationTokens(ctx context.Context, tenantID string) (int64, error) {
	if m.DeleteExpiredVerificationTokensFunc == nil {
		panic("called not defined DeleteExpiredVerificationTokensFunc")
	}
	return m.DeleteExpiredVerificationTokensFunc(ctx, tenantID)
}

func (m *MockStore) IncrementFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration) (bool, error) {
	if m.IncrementFailedAttemptsFunc == nil {
		panic("called not defined IncrementFailedAttemptsFunc")
	}
	return m.IncrementFailedAttemptsFunc(ctx, tenantID, identityID, lockThreshold, lockDuration)
}

func (m *MockStore) ResetFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID) error {
	if m.ResetFailedAttemptsFunc == nil {
		panic("called not defined ResetFailedAttemptsFunc")
	}
	return m.ResetFailedAttemptsFunc(ctx, tenantID, identityID)
}

func (m *MockStore) CreateUser(ctx context.Context, tenantID string, email string) (*identity.User, error) {
	if m.CreateUserFunc == nil {
		panic("called not defined CreateUserFunc")
	}
	return m.CreateUserFunc(ctx, tenantID, email)
}

func (m *MockStore) FindUserByID(ctx context.Context, tenantID string, id uuid.UUID) (*identity.User, error) {
	if m.FindUserByIDFunc == nil {
		panic("called not defined FindUserByIDFunc")
	}
	return m.FindUserByIDFunc(ctx, tenantID, id)
}

func (m *MockStore) FindUserByEmail(ctx context.Context, tenantID string, email string) (*identity.User, error) {
	if m.FindUserByEmailFunc == nil {
		panic("called not defined FindUserByEmailFunc")
	}
	return m.FindUserByEmailFunc(ctx, tenantID, email)
}

func (m *MockStore) UpdateUser(ctx context.Context, tenantID string, user *identity.User) error {
	if m.UpdateUserFunc == nil {
		panic("called not defined UpdateUserFunc")
	}
	return m.UpdateUserFunc(ctx, tenantID, user)
}

func (m *MockStore) UpdateUserEmail(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string, verifiedAt time.Time) error {
	if m.UpdateUserEmailFunc == nil {
		panic("called not defined UpdateUserEmailFunc")
	}
	return m.UpdateUserEmailFunc(ctx, tenantID, userID, newEmail, verifiedAt)
}

func (m *MockStore) DeleteUser(ctx context.Context, tenantID string, id uuid.UUID) error {
	if m.DeleteUserFunc == nil {
		panic("called not defined DeleteUserFunc")
	}
	return m.DeleteUserFunc(ctx, tenantID, id)
}

func (m *MockStore) AddIdentity(ctx context.Context, tenantID string, ident *identity.Identity) error {
	if m.AddIdentityFunc == nil {
		panic("called not defined AddIdentityFunc")
	}
	return m.AddIdentityFunc(ctx, tenantID, ident)
}

func (m *MockStore) FindIdentitiesByUserID(ctx context.Context, tenantID string, userID uuid.UUID) ([]*identity.Identity, error) {
	if m.FindIdentitiesByUserIDFunc == nil {
		panic("called not defined FindIdentitiesByUserIDFunc")
	}
	return m.FindIdentitiesByUserIDFunc(ctx, tenantID, userID)
}

func (m *MockStore) FindIdentityByProvider(ctx context.Context, tenantID string, provider, providerID string) (*identity.Identity, error) {
	if m.FindIdentityByProviderFunc == nil {
		panic("called not defined FindIdentityByProviderFunc")
	}
	return m.FindIdentityByProviderFunc(ctx, tenantID, provider, providerID)
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
		// The empty string "" is a legal tenant key: every backend must operate on it (the
		// default single-tenant partition) rather than rejecting the call. The tenant is now a
		// mandatory explicit argument, so "" is passed deliberately. This pins the cross-backend
		// agreement the audit (I19) flagged: the pgx backend historically rejected an empty
		// tenant on its write paths while the memory backend accepted it.
		email := "default_partition@example.com"
		user, err := store.CreateUser(ctx, "", email)
		require.NoError(t, err, "empty tenant must be the valid default partition, not rejected")
		require.NotNil(t, user)
		assert.Equal(t, "", user.TenantID)

		got, err := store.FindUserByID(ctx, "", user.ID)
		require.NoError(t, err)
		assert.Equal(t, user.ID, got.ID)

		// Writes that previously rejected an empty tenant must now succeed on the default
		// partition: adding an identity and minting/consuming a verification token.
		hash := "h"
		ident := &identity.Identity{UserID: user.ID, Provider: "password", ProviderID: email, PasswordHash: &hash}
		require.NoError(t, store.AddIdentity(ctx, "", ident))

		tok, err := store.CreateVerificationToken(ctx, "", user.ID, identity.KindPasswordReset, time.Hour, nil)
		require.NoError(t, err)
		uid, _, err := store.ConsumeVerificationToken(ctx, "", tok, identity.KindPasswordReset)
		require.NoError(t, err)
		assert.Equal(t, user.ID, uid)
	})

	t.Run("Contract: AddIdentity requires a live, same-tenant user", func(t *testing.T) {
		// AddIdentity must reject an identity whose UserID is not a live user in the target tenant.
		// Otherwise a cross-tenant or soft-deleted UserID could acquire a linked identity,
		// corrupting tenant isolation of the identities table. The memory backend enforces this;
		// the pgx backend must match (a bare foreign key only proves the user exists SOMEWHERE, not
		// that it is live and in this tenant).
		hash := "h"

		if useMultiTenant {
			// (a) UserID owned by another tenant.
			foreignUser, err := store.CreateUser(ctx, tenantB, "foreign_owner@example.com")
			require.NoError(t, err)
			crossIdent := &identity.Identity{UserID: foreignUser.ID, Provider: "password", ProviderID: "cross_tenant@example.com", PasswordHash: &hash}
			assert.ErrorIs(t, store.AddIdentity(ctx, tenantA, crossIdent), identity.ErrUserNotFound,
				"AddIdentity must reject a UserID owned by another tenant")
		}

		// (b) UserID of a soft-deleted user in the same tenant.
		delUser, err := store.CreateUser(ctx, tenantA, "to_delete@example.com")
		require.NoError(t, err)
		require.NoError(t, store.DeleteUser(ctx, tenantA, delUser.ID))
		delIdent := &identity.Identity{UserID: delUser.ID, Provider: "password", ProviderID: "after_delete@example.com", PasswordHash: &hash}
		assert.ErrorIs(t, store.AddIdentity(ctx, tenantA, delIdent), identity.ErrUserNotFound,
			"AddIdentity must reject a soft-deleted user's UserID")

		// (c) Unknown UserID.
		unknownIdent := &identity.Identity{UserID: uuid.Must(uuid.NewV7()), Provider: "password", ProviderID: "unknown_owner@example.com", PasswordHash: &hash}
		assert.ErrorIs(t, store.AddIdentity(ctx, tenantA, unknownIdent), identity.ErrUserNotFound,
			"AddIdentity must reject an unknown UserID")
	})

	t.Run("Contract: ErrTenantMismatch when record tenant differs", func(t *testing.T) {
		// A Save/Create path that receives a record already carrying a non-empty TenantID that
		// differs from the tenantID argument must reject it with ErrTenantMismatch rather than
		// silently writing to the wrong partition.
		user, err := store.CreateUser(ctx, tenantA, "mismatch_user@example.com")
		require.NoError(t, err)

		// AddIdentity with a record pinned to a foreign tenant.
		hash := "h"
		ident := &identity.Identity{UserID: user.ID, TenantID: "other-tenant", Provider: "password", ProviderID: "mismatch_user@example.com", PasswordHash: &hash}
		err = store.AddIdentity(ctx, tenantA, ident)
		assert.ErrorIs(t, err, identity.ErrTenantMismatch, "identity record tenant != argument must be rejected")

		// UpdateUser with a record pinned to a foreign tenant.
		foreign := *user
		foreign.TenantID = "other-tenant"
		err = store.UpdateUser(ctx, tenantA, &foreign)
		assert.ErrorIs(t, err, identity.ErrTenantMismatch, "user record tenant != argument must be rejected")
	})

	t.Run("Contract: User CRUD", func(t *testing.T) {
		email := "test_crud@example.com"
		user, err := store.CreateUser(ctx, tenantA, email)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, email, user.Email)
		assert.NotEqual(t, uuid.Nil, user.ID)
		if useMultiTenant {
			assert.Equal(t, tenantA, user.TenantID)
		}

		// Find By ID
		foundByID, err := store.FindUserByID(ctx, tenantA, user.ID)
		require.NoError(t, err)
		assert.Equal(t, user.ID, foundByID.ID)

		// Find By Email
		foundByEmail, err := store.FindUserByEmail(ctx, tenantA, email)
		require.NoError(t, err)
		assert.Equal(t, user.ID, foundByEmail.ID)

		// Create same email in same tenant should fail
		_, err = store.CreateUser(ctx, tenantA, email)
		assert.Error(t, err)
		assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)

		// Update
		now := time.Now()
		user.EmailVerifiedAt = &now
		err = store.UpdateUser(ctx, tenantA, user)
		require.NoError(t, err)

		foundByID, _ = store.FindUserByID(ctx, tenantA, user.ID)
		require.NotNil(t, foundByID.EmailVerifiedAt)
		assert.Equal(t, now.Unix(), foundByID.EmailVerifiedAt.Unix())

		phone := "+33612345678"
		recEmail := "recovery@example.com"
		require.NoError(t, store.UpdateUserPhone(ctx, tenantA, user.ID, phone, now))
		require.NoError(t, store.UpdateUserRecoveryEmail(ctx, tenantA, user.ID, recEmail, now))

		// Delete (Soft delete & anonymize)
		err = store.DeleteUser(ctx, tenantA, user.ID)
		require.NoError(t, err)

		// Finding by old email should fail because it was anonymized
		_, err = store.FindUserByEmail(ctx, tenantA, email)
		assert.ErrorIs(t, err, identity.ErrUserNotFound)

		// Finding by ID should still work, but show DeletedAt and modified email
		deletedUser, err := store.FindUserByID(ctx, tenantA, user.ID)
		require.NoError(t, err)
		require.NotNil(t, deletedUser.DeletedAt)
		assert.NotEqual(t, email, deletedUser.Email)
		assert.Nil(t, deletedUser.Phone, "phone must be cleared on deletion")
		assert.Nil(t, deletedUser.PhoneVerifiedAt, "phone_verified_at must be cleared on deletion")
		assert.Nil(t, deletedUser.RecoveryEmail, "recovery_email must be cleared on deletion")
		assert.Nil(t, deletedUser.RecoveryEmailVerifiedAt, "recovery_email_verified_at must be cleared on deletion")

		// Deleting an already-deleted (or unknown / cross-tenant) user reports ErrUserNotFound,
		// not a silent no-op success — both backends must agree.
		err = store.DeleteUser(ctx, tenantA, user.ID)
		assert.ErrorIs(t, err, identity.ErrUserNotFound, "re-deleting a soft-deleted user must report not found")
		err = store.DeleteUser(ctx, tenantA, uuid.Must(uuid.NewV7()))
		assert.ErrorIs(t, err, identity.ErrUserNotFound, "deleting an unknown user must report not found")
	})

	t.Run("Contract: Delete purges verification tokens", func(t *testing.T) {
		user, err := store.CreateUser(ctx, tenantA, "test_delete_purge@example.com")
		require.NoError(t, err)

		token, err := store.CreateVerificationToken(ctx, tenantA, user.ID, identity.KindMagicLink, time.Hour, []byte("meta"))
		require.NoError(t, err)

		require.NoError(t, store.DeleteUser(ctx, tenantA, user.ID))

		// The pending token must be GONE (not merely inert): its row carried the user_id and any
		// metadata PII, which the soft delete must erase.
		_, _, err = store.ConsumeVerificationToken(ctx, tenantA, token, identity.KindMagicLink)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "deletion must purge the user's verification tokens")
	})

	t.Run("Contract: Identity CRUD", func(t *testing.T) {
		email := "test_identity@example.com"
		user, err := store.CreateUser(ctx, tenantA, email)
		require.NoError(t, err)

		hash := "hashed_pass"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   email,
			PasswordHash: &hash,
		}

		err = store.AddIdentity(ctx, tenantA, ident)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, ident.ID)

		// Find By Provider
		foundIdent, err := store.FindIdentityByProvider(ctx, tenantA, "password", email)
		require.NoError(t, err)
		assert.Equal(t, ident.ID, foundIdent.ID)
		assert.Equal(t, user.ID, foundIdent.UserID)

		// Find By User ID
		idents, err := store.FindIdentitiesByUserID(ctx, tenantA, user.ID)
		require.NoError(t, err)
		require.Len(t, idents, 1)
		assert.Equal(t, ident.ID, idents[0].ID)

		// Add same identity should fail
		err = store.AddIdentity(ctx, tenantA, ident)
		assert.Error(t, err)
		assert.ErrorIs(t, err, identity.ErrIdentityAlreadyExists)
	})

	t.Run("Contract: Lockout Attempts", func(t *testing.T) {
		email := "test_lockout@example.com"
		user, err := store.CreateUser(ctx, tenantA, email)
		require.NoError(t, err)

		hash := "hashed_pass"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   email,
			PasswordHash: &hash,
		}
		require.NoError(t, store.AddIdentity(ctx, tenantA, ident))

		// Increment below threshold: counter rises, no lock, and justLocked stays false.
		for i := 1; i < defaultTestLockThreshold; i++ {
			justLocked, err := store.IncrementFailedAttempts(ctx, tenantA, ident.ID, defaultTestLockThreshold, defaultTestLockDuration)
			require.NoError(t, err)
			assert.False(t, justLocked, "must not report justLocked below threshold")

			found, err := store.FindIdentityByProvider(ctx, tenantA, "password", email)
			require.NoError(t, err)
			assert.Equal(t, i, found.FailedAttempts, "failed attempts must be persisted")
			assert.Nil(t, found.LockedUntil, "must not be locked below threshold")
		}

		// Crossing the threshold sets LockedUntil and reports justLocked exactly once.
		justLocked, err := store.IncrementFailedAttempts(ctx, tenantA, ident.ID, defaultTestLockThreshold, defaultTestLockDuration)
		require.NoError(t, err)
		assert.True(t, justLocked, "the increment that crosses the threshold must report justLocked")

		found, err := store.FindIdentityByProvider(ctx, tenantA, "password", email)
		require.NoError(t, err)
		assert.Equal(t, defaultTestLockThreshold, found.FailedAttempts)
		require.NotNil(t, found.LockedUntil, "must be locked at threshold")
		assert.True(t, found.LockedUntil.After(time.Now()), "lock must be in the future")

		// A further failed attempt on an already-locked account must NOT report justLocked
		// again — the lock event fires only on the crossing transition.
		justLocked, err = store.IncrementFailedAttempts(ctx, tenantA, ident.ID, defaultTestLockThreshold, defaultTestLockDuration)
		require.NoError(t, err)
		assert.False(t, justLocked, "must not re-report justLocked once already locked")

		// Reset clears both counter and lock.
		err = store.ResetFailedAttempts(ctx, tenantA, ident.ID)
		require.NoError(t, err)

		found, err = store.FindIdentityByProvider(ctx, tenantA, "password", email)
		require.NoError(t, err)
		assert.Equal(t, 0, found.FailedAttempts)
		assert.Nil(t, found.LockedUntil)
	})

	t.Run("Contract: Re-lock after lock expiry re-reports justLocked", func(t *testing.T) {
		email := "test_relock@example.com"
		user, err := store.CreateUser(ctx, tenantA, email)
		require.NoError(t, err)

		hash := "hashed_pass"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   email,
			PasswordHash: &hash,
		}
		require.NoError(t, store.AddIdentity(ctx, tenantA, ident))

		// First lockout with an already-elapsed duration: the crossing reports justLocked and
		// leaves LockedUntil in the past, standing in for a lock whose window has expired.
		justLocked, err := store.IncrementFailedAttempts(ctx, tenantA, ident.ID, 1, -time.Minute)
		require.NoError(t, err)
		require.True(t, justLocked, "the first crossing must report justLocked")

		found, err := store.FindIdentityByProvider(ctx, tenantA, "password", email)
		require.NoError(t, err)
		require.NotNil(t, found.LockedUntil, "the account must be locked after the first crossing")
		require.False(t, found.LockedUntil.After(time.Now()), "the first lock must already be expired for this case")

		// Once the prior lock has expired, a fresh failed attempt that re-crosses the threshold
		// must report justLocked AGAIN, restart the counter and produce a new live lock.
		justLocked, err = store.IncrementFailedAttempts(ctx, tenantA, ident.ID, 1, defaultTestLockDuration)
		require.NoError(t, err)
		assert.True(t, justLocked, "re-crossing the threshold after an expired lock must re-report justLocked")

		found, err = store.FindIdentityByProvider(ctx, tenantA, "password", email)
		require.NoError(t, err)
		assert.Equal(t, 1, found.FailedAttempts, "an expired lock must restart the failed-attempt counter")
		require.NotNil(t, found.LockedUntil, "a fresh lock must be set")
		assert.True(t, found.LockedUntil.After(time.Now()), "the fresh lock must be in the future")
	})

	t.Run("Contract: Failed attempts decay after lockout duration when account was not locked", func(t *testing.T) {
		email := "test_lockout_decay@example.com"
		user, err := store.CreateUser(ctx, tenantA, email)
		require.NoError(t, err)

		hash := "hashed_pass"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   email,
			PasswordHash: &hash,
		}
		require.NoError(t, store.AddIdentity(ctx, tenantA, ident))

		const shortThreshold = 5
		const shortWindow = 20 * time.Millisecond

		// Record 2 failed attempts within the window.
		for i := 1; i <= 2; i++ {
			justLocked, err := store.IncrementFailedAttempts(ctx, tenantA, ident.ID, shortThreshold, shortWindow)
			require.NoError(t, err)
			assert.False(t, justLocked)
		}

		found, err := store.FindIdentityByProvider(ctx, tenantA, "password", email)
		require.NoError(t, err)
		assert.Equal(t, 2, found.FailedAttempts)
		assert.Nil(t, found.LockedUntil)

		// Wait for the sliding window to elapse.
		time.Sleep(30 * time.Millisecond)

		// A subsequent failed attempt must decay stale attempts and reset to 1 instead of incrementing to 3.
		justLocked, err := store.IncrementFailedAttempts(ctx, tenantA, ident.ID, shortThreshold, shortWindow)
		require.NoError(t, err)
		assert.False(t, justLocked, "must not lock the account on decayed attempt")

		found, err = store.FindIdentityByProvider(ctx, tenantA, "password", email)
		require.NoError(t, err)
		assert.Equal(t, 1, found.FailedAttempts, "stale failed attempts must decay and reset to 1 after sliding window has elapsed")
		assert.Nil(t, found.LockedUntil, "account must remain unlocked")
	})

	t.Run("Contract: Password Update", func(t *testing.T) {
		email := "test_pwupdate@example.com"
		user, err := store.CreateUser(ctx, tenantA, email)
		require.NoError(t, err)

		oldHash := "old_hash"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   email,
			PasswordHash: &oldHash,
		}
		require.NoError(t, store.AddIdentity(ctx, tenantA, ident))

		// Lock the account, then update the password: lockout must be cleared atomically.
		_, err = store.IncrementFailedAttempts(ctx, tenantA, ident.ID, 1, defaultTestLockDuration)
		require.NoError(t, err)

		changedAt := time.Now().UTC().Truncate(time.Second)
		err = store.UpdateIdentityPassword(ctx, tenantA, user.ID, "new_hash", changedAt, true)
		require.NoError(t, err)

		found, err := store.FindIdentityByProvider(ctx, tenantA, "password", email)
		require.NoError(t, err)
		require.NotNil(t, found.PasswordHash)
		assert.Equal(t, "new_hash", *found.PasswordHash)
		assert.Equal(t, 0, found.FailedAttempts, "password update must clear failed attempts")
		assert.Nil(t, found.LockedUntil, "password update must clear the lock")
		assert.WithinDuration(t, changedAt, found.PasswordChangedAt, time.Second, "password update must stamp PasswordChangedAt")
		assert.True(t, found.MustChangePassword, "password update must set the must-change flag when requested")

		// A subsequent update with mustChange=false clears the flag again.
		err = store.UpdateIdentityPassword(ctx, tenantA, user.ID, "newer_hash", time.Now().UTC(), false)
		require.NoError(t, err)
		found, err = store.FindIdentityByProvider(ctx, tenantA, "password", email)
		require.NoError(t, err)
		assert.False(t, found.MustChangePassword, "password update must clear the must-change flag when not requested")

		// Updating a user without a password identity fails.
		ghost, err := store.CreateUser(ctx, tenantA, "ghost@example.com")
		require.NoError(t, err)
		err = store.UpdateIdentityPassword(ctx, tenantA, ghost.ID, "x", time.Now(), false)
		assert.ErrorIs(t, err, identity.ErrIdentityNotFound)
	})

	t.Run("Contract: Change Email", func(t *testing.T) {
		const oldEmail = "change_old@example.com"
		const newEmail = "change_new@example.com"
		user, err := store.CreateUser(ctx, tenantA, oldEmail)
		require.NoError(t, err)

		hash := "hashed_pass"
		ident := &identity.Identity{
			UserID:       user.ID,
			Provider:     "password",
			ProviderID:   oldEmail, // password identities are keyed by email
			PasswordHash: &hash,
		}
		require.NoError(t, store.AddIdentity(ctx, tenantA, ident))

		verifiedAt := time.Now()
		require.NoError(t, store.UpdateUserEmail(ctx, tenantA, user.ID, newEmail, verifiedAt))

		// The user now resolves by the new email and is marked verified; the old email is gone.
		found, err := store.FindUserByEmail(ctx, tenantA, newEmail)
		require.NoError(t, err)
		assert.Equal(t, user.ID, found.ID)
		require.NotNil(t, found.EmailVerifiedAt, "the confirmed new address must be verified")
		assert.Equal(t, verifiedAt.Unix(), found.EmailVerifiedAt.Unix())

		_, err = store.FindUserByEmail(ctx, tenantA, oldEmail)
		assert.ErrorIs(t, err, identity.ErrUserNotFound)

		// The password identity must have been re-keyed to the new email, so password login by
		// the new email keeps working (and the old key no longer resolves).
		reIdent, err := store.FindIdentityByProvider(ctx, tenantA, "password", newEmail)
		require.NoError(t, err)
		assert.Equal(t, user.ID, reIdent.UserID)
		_, err = store.FindIdentityByProvider(ctx, tenantA, "password", oldEmail)
		assert.ErrorIs(t, err, identity.ErrIdentityNotFound)

		// Changing to an address held by another live account is rejected.
		other, err := store.CreateUser(ctx, tenantA, "change_other@example.com")
		require.NoError(t, err)
		err = store.UpdateUserEmail(ctx, tenantA, other.ID, newEmail, time.Now())
		assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)

		// An unknown user is reported as not found.
		err = store.UpdateUserEmail(ctx, tenantA, uuid.Must(uuid.NewV7()), "nobody_new@example.com", time.Now())
		assert.ErrorIs(t, err, identity.ErrUserNotFound)

		// An account with no password identity (e.g. OAuth-only) can still change its email; only
		// the user row moves and a non-password identity is left untouched (not re-keyed).
		oauthUser, err := store.CreateUser(ctx, tenantA, "oauth_old@example.com")
		require.NoError(t, err)
		oauthIdent := &identity.Identity{
			UserID:     oauthUser.ID,
			Provider:   "google",
			ProviderID: "google-sub-123",
		}
		require.NoError(t, store.AddIdentity(ctx, tenantA, oauthIdent))

		require.NoError(t, store.UpdateUserEmail(ctx, tenantA, oauthUser.ID, "oauth_new@example.com", time.Now()))
		movedOAuth, err := store.FindUserByEmail(ctx, tenantA, "oauth_new@example.com")
		require.NoError(t, err)
		assert.Equal(t, oauthUser.ID, movedOAuth.ID)
		// The OAuth identity must still resolve by its original provider key (never re-keyed).
		gotOAuth, err := store.FindIdentityByProvider(ctx, tenantA, "google", "google-sub-123")
		require.NoError(t, err)
		assert.Equal(t, oauthUser.ID, gotOAuth.UserID)
	})

	t.Run("Contract: Phone (FindUserByPhone/UpdateUserPhone)", func(t *testing.T) {
		const phone = "+15557770001"
		user, err := store.CreateUser(ctx, tenantA, "phone_contract@example.com")
		require.NoError(t, err)
		assert.Nil(t, user.Phone, "a freshly created user has no phone")

		// No user owns the number yet.
		_, err = store.FindUserByPhone(ctx, tenantA, phone)
		assert.ErrorIs(t, err, identity.ErrUserNotFound)

		// Set + verify the number atomically.
		verifiedAt := time.Now()
		require.NoError(t, store.UpdateUserPhone(ctx, tenantA, user.ID, phone, verifiedAt))

		found, err := store.FindUserByPhone(ctx, tenantA, phone)
		require.NoError(t, err)
		assert.Equal(t, user.ID, found.ID)
		require.NotNil(t, found.Phone)
		assert.Equal(t, phone, *found.Phone)
		require.NotNil(t, found.PhoneVerifiedAt, "the confirmed number must be marked verified")
		assert.Equal(t, verifiedAt.Unix(), found.PhoneVerifiedAt.Unix())

		// The email lookup is unaffected and now carries the phone too (same row).
		byEmail, err := store.FindUserByEmail(ctx, tenantA, "phone_contract@example.com")
		require.NoError(t, err)
		require.NotNil(t, byEmail.Phone)
		assert.Equal(t, phone, *byEmail.Phone)

		// A second live account cannot take the same number (per-tenant uniqueness).
		other, err := store.CreateUser(ctx, tenantA, "phone_other@example.com")
		require.NoError(t, err)
		err = store.UpdateUserPhone(ctx, tenantA, other.ID, phone, time.Now())
		assert.ErrorIs(t, err, identity.ErrPhoneAlreadyExists)

		// An unknown user is reported as not found.
		err = store.UpdateUserPhone(ctx, tenantA, uuid.Must(uuid.NewV7()), "+15557770999", time.Now())
		assert.ErrorIs(t, err, identity.ErrUserNotFound)
	})

	t.Run("Contract: Recovery Email (UpdateUserRecoveryEmail)", func(t *testing.T) {
		user, err := store.CreateUser(ctx, tenantA, "rec_contract@example.com")
		require.NoError(t, err)
		assert.Nil(t, user.RecoveryEmail, "a freshly created user has no recovery email")

		verifiedAt := time.Now()
		require.NoError(t, store.UpdateUserRecoveryEmail(ctx, tenantA, user.ID, "backup@elsewhere.example", verifiedAt))

		found, err := store.FindUserByID(ctx, tenantA, user.ID)
		require.NoError(t, err)
		require.NotNil(t, found.RecoveryEmail)
		assert.Equal(t, "backup@elsewhere.example", *found.RecoveryEmail)
		require.NotNil(t, found.RecoveryEmailVerifiedAt, "the confirmed recovery email must be marked verified")
		assert.Equal(t, verifiedAt.Unix(), found.RecoveryEmailVerifiedAt.Unix())

		// The recovery email is NOT a login key and is intentionally not unique: a second account
		// may carry the same recovery contact.
		other, err := store.CreateUser(ctx, tenantA, "rec_other@example.com")
		require.NoError(t, err)
		require.NoError(t, store.UpdateUserRecoveryEmail(ctx, tenantA, other.ID, "backup@elsewhere.example", time.Now()),
			"a recovery email need not be unique across accounts")

		// An unknown user is reported as not found.
		err = store.UpdateUserRecoveryEmail(ctx, tenantA, uuid.Must(uuid.NewV7()), "x@elsewhere.example", time.Now())
		assert.ErrorIs(t, err, identity.ErrUserNotFound)
	})

	t.Run("Contract: Verification Tokens", func(t *testing.T) {
		user, err := store.CreateUser(ctx, tenantA, "test_verif@example.com")
		require.NoError(t, err)

		meta := []byte("payload-123")
		token, err := store.CreateVerificationToken(ctx, tenantA, user.ID, identity.KindPasswordReset, time.Hour, meta)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Wrong kind must not match.
		_, _, err = store.ConsumeVerificationToken(ctx, tenantA, token, identity.KindEmailVerification)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

		// Tampered verifier must not match.
		_, _, err = store.ConsumeVerificationToken(ctx, tenantA, token+"x", identity.KindPasswordReset)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

		// Malformed token (no separator) must not match.
		_, _, err = store.ConsumeVerificationToken(ctx, tenantA, "garbage", identity.KindPasswordReset)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

		// Happy path: returns the bound user and metadata.
		gotUser, gotMeta, err := store.ConsumeVerificationToken(ctx, tenantA, token, identity.KindPasswordReset)
		require.NoError(t, err)
		assert.Equal(t, user.ID, gotUser)
		assert.Equal(t, meta, gotMeta)

		// Single-use: a second consumption fails.
		_, _, err = store.ConsumeVerificationToken(ctx, tenantA, token, identity.KindPasswordReset)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

		// Expired token: genuine token, past expiry, reports expiry.
		expiredToken, err := store.CreateVerificationToken(ctx, tenantA, user.ID, identity.KindEmailVerification, -time.Minute, nil)
		require.NoError(t, err)
		_, _, err = store.ConsumeVerificationToken(ctx, tenantA, expiredToken, identity.KindEmailVerification)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenExpired)

		// A cross-tenant target must not be mintable (both backends enforce same-tenant).
		if useMultiTenant {
			_, err = store.CreateVerificationToken(ctx, tenantB, user.ID, identity.KindPasswordReset, time.Hour, nil)
			assert.ErrorIs(t, err, identity.ErrUserNotFound, "must not mint a token for a user in another tenant")
		}

		// A soft-deleted user must not be mintable.
		require.NoError(t, store.DeleteUser(ctx, tenantA, user.ID))
		_, err = store.CreateVerificationToken(ctx, tenantA, user.ID, identity.KindPasswordReset, time.Hour, nil)
		assert.ErrorIs(t, err, identity.ErrUserNotFound, "must not mint a token for a soft-deleted user")
	})

	t.Run("Contract: DeleteExpiredVerificationTokens purges only expired", func(t *testing.T) {
		user, err := store.CreateUser(ctx, tenantA, "reaper_verif@example.com")
		require.NoError(t, err)

		expired, err := store.CreateVerificationToken(ctx, tenantA, user.ID, identity.KindPasswordReset, -time.Minute, nil)
		require.NoError(t, err)
		live, err := store.CreateVerificationToken(ctx, tenantA, user.ID, identity.KindEmailVerification, time.Hour, nil)
		require.NoError(t, err)

		n, err := store.DeleteExpiredVerificationTokens(ctx, tenantA)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, int64(1))

		// The expired token is GONE (reaped), so consume reports not-found rather than expired.
		_, _, err = store.ConsumeVerificationToken(ctx, tenantA, expired, identity.KindPasswordReset)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "expired token must be reaped")

		// The live token still consumes.
		uid, _, err := store.ConsumeVerificationToken(ctx, tenantA, live, identity.KindEmailVerification)
		require.NoError(t, err)
		assert.Equal(t, user.ID, uid)
	})

	if useMultiTenant {
		t.Run("Contract: Multi-Tenant Isolation", func(t *testing.T) {
			sharedEmail := "isolated@example.com"

			// Create in Tenant A
			userA, err := store.CreateUser(ctx, tenantA, sharedEmail)
			require.NoError(t, err)
			assert.Equal(t, tenantA, userA.TenantID)

			// Create in Tenant B (should succeed because isolation)
			userB, err := store.CreateUser(ctx, tenantB, sharedEmail)
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
			err = store.AddIdentity(ctx, tenantA, identA)
			require.NoError(t, err)

			hashB := "hashB"
			identB := &identity.Identity{
				UserID:       userB.ID,
				Provider:     "password",
				ProviderID:   sharedEmail,
				PasswordHash: &hashB,
			}
			err = store.AddIdentity(ctx, tenantB, identB)
			require.NoError(t, err)

			// Cross-tenant querying should fail
			_, err = store.FindUserByID(ctx, tenantB, userA.ID)
			assert.ErrorIs(t, err, identity.ErrUserNotFound, "Tenant B should not see Tenant A's user")

			_, err = store.FindIdentityByProvider(ctx, tenantB, "password", sharedEmail)
			require.NoError(t, err)
			assert.Equal(t, userB.ID, identB.UserID, "Should find the identity specific to Tenant B")
		})
	}
}

func (m *MockStore) FindUserByPhone(ctx context.Context, tenantID string, phone string) (*identity.User, error) {
	if m.FindUserByPhoneFunc == nil {
		panic("called not defined FindUserByPhoneFunc")
	}
	return m.FindUserByPhoneFunc(ctx, tenantID, phone)
}

func (m *MockStore) UpdateUserPhone(ctx context.Context, tenantID string, userID uuid.UUID, newPhone string, verifiedAt time.Time) error {
	if m.UpdateUserPhoneFunc == nil {
		panic("called not defined UpdateUserPhoneFunc")
	}
	return m.UpdateUserPhoneFunc(ctx, tenantID, userID, newPhone, verifiedAt)
}

func (m *MockStore) UpdateUserRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string, verifiedAt time.Time) error {
	if m.UpdateUserRecoveryEmailFunc == nil {
		panic("called not defined UpdateUserRecoveryEmailFunc")
	}
	return m.UpdateUserRecoveryEmailFunc(ctx, tenantID, userID, recoveryEmail, verifiedAt)
}

func (m *MockStore) DisableUser(ctx context.Context, tenantID string, id uuid.UUID, disabledAt time.Time) error {
	if m.DisableUserFunc == nil {
		panic("called not defined DisableUserFunc")
	}
	return m.DisableUserFunc(ctx, tenantID, id, disabledAt)
}

func (m *MockStore) EnableUser(ctx context.Context, tenantID string, id uuid.UUID) error {
	if m.EnableUserFunc == nil {
		panic("called not defined EnableUserFunc")
	}
	return m.EnableUserFunc(ctx, tenantID, id)
}

// StoreDisableEnableContract verifies the administrative disable/enable lifecycle: DisableUser
// stamps DisabledAt while retaining the (findable) row and email slot, EnableUser clears it, both
// are idempotent, and both reject unknown or soft-deleted accounts. It is part of the Store
// contract; each backend's test runs it alongside StoreContractTesting.
func StoreDisableEnableContract(t *testing.T, store identity.Store, tenant string) {
	t.Helper()
	ctx := context.Background()

	user, err := store.CreateUser(ctx, tenant, "disable_contract@example.com")
	require.NoError(t, err)
	assert.Nil(t, user.DisabledAt, "a freshly created user is not disabled")

	// Disable stamps DisabledAt; the row stays findable (unlike soft delete) and the email is
	// retained.
	disabledAt := time.Now()
	require.NoError(t, store.DisableUser(ctx, tenant, user.ID, disabledAt))

	found, err := store.FindUserByID(ctx, tenant, user.ID)
	require.NoError(t, err)
	require.NotNil(t, found.DisabledAt, "DisableUser must set DisabledAt")
	assert.Equal(t, disabledAt.Unix(), found.DisabledAt.Unix())
	assert.Equal(t, "disable_contract@example.com", found.Email, "disable retains the email slot")

	// A disabled account is still reachable by email so admin tooling can inspect it.
	byEmail, err := store.FindUserByEmail(ctx, tenant, "disable_contract@example.com")
	require.NoError(t, err)
	assert.Equal(t, user.ID, byEmail.ID)
	require.NotNil(t, byEmail.DisabledAt)

	// Disabling an already-disabled user is an idempotent success.
	require.NoError(t, store.DisableUser(ctx, tenant, user.ID, time.Now()))

	// Enable clears DisabledAt.
	require.NoError(t, store.EnableUser(ctx, tenant, user.ID))
	found, err = store.FindUserByID(ctx, tenant, user.ID)
	require.NoError(t, err)
	assert.Nil(t, found.DisabledAt, "EnableUser must clear DisabledAt")

	// Enabling an account that is not disabled is an idempotent success.
	require.NoError(t, store.EnableUser(ctx, tenant, user.ID))

	// Unknown users are reported as not found on both operations.
	assert.ErrorIs(t, store.DisableUser(ctx, tenant, uuid.Must(uuid.NewV7()), time.Now()), identity.ErrUserNotFound)
	assert.ErrorIs(t, store.EnableUser(ctx, tenant, uuid.Must(uuid.NewV7())), identity.ErrUserNotFound)

	// A soft-deleted user cannot be disabled or enabled: it is not a live account.
	gone, err := store.CreateUser(ctx, tenant, "disable_gone@example.com")
	require.NoError(t, err)
	require.NoError(t, store.DeleteUser(ctx, tenant, gone.ID))
	assert.ErrorIs(t, store.DisableUser(ctx, tenant, gone.ID, time.Now()), identity.ErrUserNotFound)
	assert.ErrorIs(t, store.EnableUser(ctx, tenant, gone.ID), identity.ErrUserNotFound)
}

// StoreDeleteAuthGateContract verifies that DeleteUser correctly sets up the authorization
// invariant relied upon by the service layer (FindUserByID + DeletedAt check). Specifically:
//
//   - FindUserByID must still return the deleted user (inspection contract: the service's
//     consumeForLiveUser and LinkOrCreateIdentity already-linked branch depend on this).
//   - FindUserByEmail must NOT return the deleted user (email was anonymized).
//   - The password-provider identity's ProviderID must be anonymized (it held the email, which is PII).
//   - Non-password (OAuth/OIDC) identity ProviderIDs must be preserved intact, so that
//     FindIdentityByProvider can still locate the identity and the service-layer DeletedAt gate
//     can refuse it. Without this, a re-auth with the same OAuth credentials would fall through
//     to the JIT-provision path and create a new account for the deleted user.
//
// Each backend's test must run this alongside StoreContractTesting.
func StoreDeleteAuthGateContract(t *testing.T, store identity.Store, tenant string) {
	t.Helper()
	ctx := context.Background()

	const email = "authgate_del@example.com"
	const oauthProvider = "google"
	const oauthSub = "google-sub-authgate"

	user, err := store.CreateUser(ctx, tenant, email)
	require.NoError(t, err)

	// Add a password identity (ProviderID = email, which is PII and must be anonymized).
	passwordHash := "hash"
	pwIdent := &identity.Identity{
		UserID:       user.ID,
		Provider:     "password",
		ProviderID:   email,
		PasswordHash: &passwordHash,
	}
	require.NoError(t, store.AddIdentity(ctx, tenant, pwIdent))

	// Add a non-password OAuth identity (ProviderID = opaque subject ID, must be preserved).
	oauthIdent := &identity.Identity{
		UserID:     user.ID,
		Provider:   oauthProvider,
		ProviderID: oauthSub,
	}
	require.NoError(t, store.AddIdentity(ctx, tenant, oauthIdent))

	// Soft-delete the user.
	require.NoError(t, store.DeleteUser(ctx, tenant, user.ID))

	// 1. FindUserByID must still return the row (inspection contract).
	deleted, err := store.FindUserByID(ctx, tenant, user.ID)
	require.NoError(t, err, "FindUserByID must still return a soft-deleted user (inspection contract)")
	require.NotNil(t, deleted.DeletedAt, "deleted user must have DeletedAt set")

	// 2. FindUserByEmail must not return the deleted user (email was anonymized).
	_, err = store.FindUserByEmail(ctx, tenant, email)
	assert.ErrorIs(t, err, identity.ErrUserNotFound,
		"FindUserByEmail must not find a soft-deleted user (email was anonymized)")

	// 3. Password identity ProviderID must be anonymized (it was the email address, PII).
	_, err = store.FindIdentityByProvider(ctx, tenant, "password", email)
	assert.ErrorIs(t, err, identity.ErrIdentityNotFound,
		"password identity ProviderID must be anonymized after deletion")

	// 4. OAuth identity ProviderID must be PRESERVED so the service-layer DeletedAt gate fires.
	//    Without this, LinkOrCreateIdentity's already-linked branch cannot detect the deleted
	//    account and would fall through to JIT-provisioning a new account.
	foundOAuth, err := store.FindIdentityByProvider(ctx, tenant, oauthProvider, oauthSub)
	require.NoError(t, err,
		"non-password identity ProviderID must be preserved after deletion so the auth gate fires")
	assert.Equal(t, user.ID, foundOAuth.UserID,
		"preserved OAuth identity must still reference the (now-deleted) user")
}

// StoreUpdateUserSoftDeleteContract verifies that UpdateUser rejects a soft-deleted user with
// ErrUserNotFound, matching the pgx behaviour (WHERE deleted_at IS NULL). Both the memory and pgx
// backends must agree: calling UpdateUser on a soft-deleted account must not resurrect it.
// Each backend's test must run this alongside StoreContractTesting.
func StoreUpdateUserSoftDeleteContract(t *testing.T, store identity.Store, tenant string) {
	t.Helper()
	ctx := context.Background()

	user, err := store.CreateUser(ctx, tenant, "update_softdel_contract@example.com")
	require.NoError(t, err)

	// Verify UpdateUser works on a live user.
	now := time.Now()
	user.EmailVerifiedAt = &now
	require.NoError(t, store.UpdateUser(ctx, tenant, user), "UpdateUser must succeed on a live user")

	// Soft-delete the user.
	require.NoError(t, store.DeleteUser(ctx, tenant, user.ID))

	// UpdateUser on a soft-deleted user must return ErrUserNotFound, not silently resurrect it.
	err = store.UpdateUser(ctx, tenant, user)
	assert.ErrorIs(t, err, identity.ErrUserNotFound,
		"UpdateUser on a soft-deleted user must return ErrUserNotFound (resurrection gate)")
}
