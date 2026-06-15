package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewService_NilStorePanics(t *testing.T) {
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{}
	policy := &mockPolicy{VerifyFunc: func(context.Context, string) error { return nil }}

	// Store is always required.
	assert.Panics(t, func() { identity.NewService(nil, hasher, policy) }, "nil store must panic")
	// Hasher/policy are optional (OAuth-only deployments use no password flows).
	require.NotPanics(t, func() { identity.NewService(store, nil, nil) })
	require.NotPanics(t, func() { identity.NewService(store, hasher, policy) })
}

// A nil policy is legal (OAuth-only deployments) but the password operations must FAIL FAST with
// a clear sentinel error instead of panicking with a nil-pointer deref deep inside the request.

func TestRegisterNilPolicy(t *testing.T) {
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), &hashertest.MockHasher{}, nil)

	_, err := svc.Register(ctx, "", "user@example.com", "pw")
	assert.ErrorIs(t, err, identity.ErrPasswordPolicyRequired,
		"a password Register with a nil policy must return a clear error, not panic")
}

func TestResetPasswordNilPolicy(t *testing.T) {
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), &hashertest.MockHasher{}, nil)

	err := svc.ResetPassword(ctx, "", "some-token", "NewValidPass123!")
	assert.ErrorIs(t, err, identity.ErrPasswordPolicyRequired,
		"a password ResetPassword with a nil policy must return a clear error, not panic")
}

func TestChangePasswordNilPolicy(t *testing.T) {
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), &hashertest.MockHasher{}, nil)

	err := svc.ChangePassword(ctx, "", uuid.Must(uuid.NewV7()), "current", "NewValidPass123!")
	assert.ErrorIs(t, err, identity.ErrPasswordPolicyRequired,
		"a password ChangePassword with a nil policy must return a clear error, not panic")
}

// With a policy present but a nil hasher, the password operations must likewise fail fast with a
// clear sentinel error rather than panic when they reach the hashing step.

func TestRegisterNilHasher(t *testing.T) {
	ctx := context.Background()
	policy := &mockPolicy{VerifyFunc: func(context.Context, string) error { return nil }}
	svc := identity.NewService(identitymemory.NewStore(), nil, policy)

	_, err := svc.Register(ctx, "", "user@example.com", "pw")
	assert.ErrorIs(t, err, identity.ErrPasswordHasherRequired,
		"a password Register with a nil hasher must return a clear error, not panic")
}

func TestResetPasswordNilHasher(t *testing.T) {
	ctx := context.Background()
	policy := &mockPolicy{VerifyFunc: func(context.Context, string) error { return nil }}
	svc := identity.NewService(identitymemory.NewStore(), nil, policy)

	err := svc.ResetPassword(ctx, "", "some-token", "NewValidPass123!")
	assert.ErrorIs(t, err, identity.ErrPasswordHasherRequired,
		"a password ResetPassword with a nil hasher must return a clear error, not panic")
}

func TestChangePasswordNilHasher(t *testing.T) {
	ctx := context.Background()
	policy := &mockPolicy{VerifyFunc: func(context.Context, string) error { return nil }}
	svc := identity.NewService(identitymemory.NewStore(), nil, policy)

	err := svc.ChangePassword(ctx, "", uuid.Must(uuid.NewV7()), "current", "NewValidPass123!")
	assert.ErrorIs(t, err, identity.ErrPasswordHasherRequired,
		"a password ChangePassword with a nil hasher must return a clear error, not panic")
}
