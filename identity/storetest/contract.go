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
	DeleteUserFunc             func(ctx context.Context, id uuid.UUID, opts ...identity.Option) error
	AddIdentityFunc            func(ctx context.Context, ident *identity.Identity, opts ...identity.Option) error
	FindIdentitiesByUserIDFunc func(ctx context.Context, userID uuid.UUID, opts ...identity.Option) ([]*identity.Identity, error)
	FindIdentityByProviderFunc func(ctx context.Context, provider, providerID string, opts ...identity.Option) (*identity.Identity, error)

	IncrementFailedAttemptsFunc func(ctx context.Context, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration, opts ...identity.Option) error
	ResetFailedAttemptsFunc     func(ctx context.Context, identityID uuid.UUID, opts ...identity.Option) error
}

var _ identity.Store = (*MockStore)(nil)

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
