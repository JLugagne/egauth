package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/identity/storetest"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// SetTemporaryPassword
// ----------------------------------------------------------------------------

func TestSetTemporaryPassword_SetsFlag(t *testing.T) {
	// After SetTemporaryPassword, PasswordChangeRequired must return true.
	ctx := context.Background()
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc:    func(ctx context.Context, p string) (string, error) { return "hashed-" + p, nil },
		CompareFunc: func(ctx context.Context, hash, pw string) error { return nil },
	}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
	svc := identity.NewService(store, hasher, policy)

	// Register a normal account first.
	user, err := svc.Register(ctx, "tenant", "admin_test@example.com", "OriginalPass1!")
	require.NoError(t, err)

	// Confirm the flag is not yet set.
	required, err := svc.PasswordChangeRequired(ctx, "tenant", user.ID)
	require.NoError(t, err)
	assert.False(t, required, "flag must not be set before SetTemporaryPassword")

	// Set a temporary password.
	err = svc.SetTemporaryPassword(ctx, "tenant", user.ID, "TempPass1!")
	require.NoError(t, err)

	// The flag must now be set.
	required, err = svc.PasswordChangeRequired(ctx, "tenant", user.ID)
	require.NoError(t, err)
	assert.True(t, required, "PasswordChangeRequired must return true after SetTemporaryPassword")
}

func TestSetTemporaryPassword_RunsErasers(t *testing.T) {
	// SetTemporaryPassword must invoke every registered AccountEraser.
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV7())

	hash := "stored"
	store := &storetest.MockStore{
		UpdateIdentityPasswordFunc: func(_ context.Context, tenantID string, uid uuid.UUID, h string, changedAt time.Time, mustChange bool) error {
			assert.True(t, mustChange, "mustChange must be true")
			assert.Equal(t, userID, uid)
			return nil
		},
	}
	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) { return hash, nil },
	}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}

	eraser1Called := false
	eraser2Called := false
	e1 := func(ctx context.Context, tenantID string, uid uuid.UUID) error {
		assert.Equal(t, userID, uid)
		eraser1Called = true
		return nil
	}
	e2 := func(ctx context.Context, tenantID string, uid uuid.UUID) error {
		assert.Equal(t, userID, uid)
		eraser2Called = true
		return nil
	}

	svc := identity.NewService(store, hasher, policy, identity.WithAccountErasers(e1, e2))
	err := svc.SetTemporaryPassword(ctx, "", userID, "TempPass1!")
	require.NoError(t, err)
	assert.True(t, eraser1Called, "first eraser must be invoked")
	assert.True(t, eraser2Called, "second eraser must be invoked")
}

func TestSetTemporaryPassword_PolicyRejection(t *testing.T) {
	// A tempPassword that fails the policy must be rejected and the store must not be written.
	ctx := context.Background()
	written := false
	store := &storetest.MockStore{
		UpdateIdentityPasswordFunc: func(_ context.Context, _ string, _ uuid.UUID, _ string, _ time.Time, _ bool) error {
			written = true
			return nil
		},
	}
	hasher := &hashertest.MockHasher{HashFunc: func(ctx context.Context, p string) (string, error) { return "h", nil }}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return passwords.ErrPasswordTooShort }}

	svc := identity.NewService(store, hasher, policy)
	err := svc.SetTemporaryPassword(ctx, "", uuid.Must(uuid.NewV7()), "weak")
	assert.ErrorIs(t, err, passwords.ErrPasswordTooShort)
	assert.False(t, written, "store must not be written when the policy rejects the password")
}

func TestSetTemporaryPassword_NilPolicyReturnsError(t *testing.T) {
	// SetTemporaryPassword on a service with no policy must return ErrPasswordPolicyRequired.
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), &hashertest.MockHasher{}, nil)
	err := svc.SetTemporaryPassword(ctx, "", uuid.Must(uuid.NewV7()), "whatever")
	assert.ErrorIs(t, err, identity.ErrPasswordPolicyRequired)
}

func TestSetTemporaryPassword_EraserErrorsCollected(t *testing.T) {
	// All eraser errors are collected and returned joined; one failure must not suppress the others.
	ctx := context.Background()
	sentinelA := errors.New("eraser-A failed")
	sentinelB := errors.New("eraser-B failed")

	store := &storetest.MockStore{
		UpdateIdentityPasswordFunc: func(_ context.Context, _ string, _ uuid.UUID, _ string, _ time.Time, _ bool) error {
			return nil
		},
	}
	hasher := &hashertest.MockHasher{HashFunc: func(ctx context.Context, p string) (string, error) { return "h", nil }}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}

	eA := func(ctx context.Context, tenantID string, uid uuid.UUID) error { return sentinelA }
	eB := func(ctx context.Context, tenantID string, uid uuid.UUID) error { return sentinelB }

	svc := identity.NewService(store, hasher, policy, identity.WithAccountErasers(eA, eB))
	err := svc.SetTemporaryPassword(ctx, "", uuid.Must(uuid.NewV7()), "TempPass1!")
	assert.ErrorIs(t, err, sentinelA, "sentinelA must appear in the joined error")
	assert.ErrorIs(t, err, sentinelB, "sentinelB must appear in the joined error")
}

// ----------------------------------------------------------------------------
// AdminCreateUser
// ----------------------------------------------------------------------------

func TestAdminCreateUser_CreatesUserWithFlag(t *testing.T) {
	// AdminCreateUser must return a non-nil user and the password identity must carry MustChangePassword=true.
	ctx := context.Background()
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) { return "hashed-" + p, nil },
	}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
	svc := identity.NewService(store, hasher, policy)

	user, err := svc.AdminCreateUser(ctx, "tenant", "newuser@example.com", "TempPass1!")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "newuser@example.com", user.Email)

	// The identity must carry the must-change flag.
	required, err := svc.PasswordChangeRequired(ctx, "tenant", user.ID)
	require.NoError(t, err)
	assert.True(t, required, "PasswordChangeRequired must be true for an admin-provisioned account")
}

func TestAdminCreateUser_NormalizesEmail(t *testing.T) {
	// Email is trimmed and lowercased by AdminCreateUser.
	ctx := context.Background()
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{HashFunc: func(ctx context.Context, p string) (string, error) { return "h", nil }}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
	svc := identity.NewService(store, hasher, policy)

	user, err := svc.AdminCreateUser(ctx, "", "  Admin@Example.COM  ", "TempPass1!")
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", user.Email, "email must be normalized")
}

func TestAdminCreateUser_InvalidEmailReturnsError(t *testing.T) {
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), &hashertest.MockHasher{}, &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }})
	_, err := svc.AdminCreateUser(ctx, "", "not-an-email", "TempPass1!")
	assert.ErrorIs(t, err, identity.ErrInvalidEmail)
}

func TestAdminCreateUser_PolicyRejectionPreventsCreation(t *testing.T) {
	// A tempPassword that fails the policy must abort before creating the user.
	ctx := context.Background()
	createCalled := false
	store := &storetest.MockStore{
		CreateUserFunc: func(_ context.Context, _ string, _ string) (*identity.User, error) {
			createCalled = true
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	hasher := &hashertest.MockHasher{HashFunc: func(ctx context.Context, p string) (string, error) { return "h", nil }}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return passwords.ErrPasswordTooShort }}

	svc := identity.NewService(store, hasher, policy)
	_, err := svc.AdminCreateUser(ctx, "", "user@example.com", "weak")
	assert.ErrorIs(t, err, passwords.ErrPasswordTooShort)
	assert.False(t, createCalled, "CreateUser must not be called when the policy rejects the password")
}

func TestAdminCreateUser_EmailTaken(t *testing.T) {
	// A second AdminCreateUser with the same email must fail with ErrEmailAlreadyExists.
	ctx := context.Background()
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{HashFunc: func(ctx context.Context, p string) (string, error) { return "h", nil }}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
	svc := identity.NewService(store, hasher, policy)

	_, err := svc.AdminCreateUser(ctx, "", "dup@example.com", "TempPass1!")
	require.NoError(t, err)

	_, err = svc.AdminCreateUser(ctx, "", "dup@example.com", "TempPass1!")
	assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)
}

func TestAdminCreateUser_AddIdentityFailureCompensates(t *testing.T) {
	// When AddIdentity fails the orphaned user must be deleted (best-effort compensation).
	ctx := context.Background()
	compensated := false
	created := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "orphan@example.com"}
	store := &storetest.MockStore{
		CreateUserFunc: func(_ context.Context, _ string, _ string) (*identity.User, error) {
			return created, nil
		},
		AddIdentityFunc: func(_ context.Context, _ string, _ *identity.Identity) error {
			return errors.New("db error")
		},
		DeleteUserFunc: func(_ context.Context, _ string, id uuid.UUID) error {
			assert.Equal(t, created.ID, id)
			compensated = true
			return nil
		},
	}
	hasher := &hashertest.MockHasher{HashFunc: func(ctx context.Context, p string) (string, error) { return "h", nil }}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}

	svc := identity.NewService(store, hasher, policy)
	user, err := svc.AdminCreateUser(ctx, "", "orphan@example.com", "TempPass1!")
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.True(t, compensated, "the orphaned user must be soft-deleted to free the email slot")
}

func TestAdminCreateUser_NilPolicyReturnsError(t *testing.T) {
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), &hashertest.MockHasher{}, nil)
	_, err := svc.AdminCreateUser(ctx, "", "user@example.com", "whatever")
	assert.ErrorIs(t, err, identity.ErrPasswordPolicyRequired)
}

func TestAdminCreateUser_PasswordChangedAtIsStamped(t *testing.T) {
	// PasswordChangedAt must be stamped to a non-zero time when the account is created.
	ctx := context.Background()
	fixedTime := time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	var capturedChangedAt time.Time
	var capturedMustChange bool

	store := &storetest.MockStore{
		CreateUserFunc: func(_ context.Context, _ string, email string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7()), Email: email}, nil
		},
		AddIdentityFunc: func(_ context.Context, _ string, ident *identity.Identity) error {
			capturedChangedAt = ident.PasswordChangedAt
			capturedMustChange = ident.MustChangePassword
			return nil
		},
	}
	hasher := &hashertest.MockHasher{HashFunc: func(ctx context.Context, p string) (string, error) { return "h", nil }}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}

	svc := identity.NewService(store, hasher, policy, identity.WithClock(func() time.Time { return fixedTime }))
	_, err := svc.AdminCreateUser(ctx, "", "stamped@example.com", "TempPass1!")
	require.NoError(t, err)
	assert.Equal(t, fixedTime, capturedChangedAt, "PasswordChangedAt must equal s.now()")
	assert.True(t, capturedMustChange, "MustChangePassword must be true")
}
