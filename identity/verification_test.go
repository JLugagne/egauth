package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/identity/storetest"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newVerificationService builds a Service backed by the in-memory store, a real argon2
// hasher and a length-only policy, plus the registered user it returns for convenience.
func newVerificationService(t *testing.T, opts ...identity.ServiceOption) (identity.Service, *memory.Store) {
	t.Helper()
	store := memory.NewStore()
	hasher := argon2.NewHasher()
	policy := &mockPolicy{VerifyFunc: func(_ context.Context, p string) error {
		if len(p) < 8 {
			return assert.AnError
		}
		return nil
	}}
	return identity.NewService(store, hasher, policy, opts...), store
}

func TestVerification_PasswordResetRoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "reset@example.com"
	_, err := svc.Register(ctx, email, "OldPassw0rd!")
	require.NoError(t, err)

	token, user, err := svc.RequestPasswordReset(ctx, email)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotNil(t, user)
	assert.Equal(t, email, user.Email)

	require.NoError(t, svc.ResetPassword(ctx, token, "NewPassw0rd!"))

	// New password authenticates; old one no longer does.
	_, err = svc.Authenticate(ctx, "password", email, "NewPassw0rd!")
	require.NoError(t, err)
	_, err = svc.Authenticate(ctx, "password", email, "OldPassw0rd!")
	assert.ErrorIs(t, err, identity.ErrInvalidCredentials)

	// The reset token is single-use.
	err = svc.ResetPassword(ctx, token, "Another0ne!")
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
}

func TestVerification_RequestPasswordReset_UnknownEmailIsSilent(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	token, user, err := svc.RequestPasswordReset(ctx, "nobody@example.com")
	require.NoError(t, err, "must not reveal that the account is unknown")
	assert.Empty(t, token)
	assert.Nil(t, user)
}

func TestVerification_ResetPassword_WeakPasswordDoesNotConsumeToken(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "weak@example.com"
	_, err := svc.Register(ctx, email, "OldPassw0rd!")
	require.NoError(t, err)

	token, _, err := svc.RequestPasswordReset(ctx, email)
	require.NoError(t, err)

	// A policy rejection must NOT burn the single-use token.
	assert.Error(t, svc.ResetPassword(ctx, token, "short"))
	require.NoError(t, svc.ResetPassword(ctx, token, "NewPassw0rd!"))
}

func TestVerification_ResetPassword_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t, identity.WithPasswordResetTTL(-time.Minute))

	const email = "expired@example.com"
	_, err := svc.Register(ctx, email, "OldPassw0rd!")
	require.NoError(t, err)

	token, _, err := svc.RequestPasswordReset(ctx, email)
	require.NoError(t, err)

	err = svc.ResetPassword(ctx, token, "NewPassw0rd!")
	assert.ErrorIs(t, err, identity.ErrVerificationTokenExpired)
}

func TestVerification_EmailVerificationRoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "verify@example.com"
	user, err := svc.Register(ctx, email, "OldPassw0rd!")
	require.NoError(t, err)
	require.Nil(t, user.EmailVerifiedAt)

	token, err := svc.RequestEmailVerification(ctx, user.ID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	verified, err := svc.VerifyEmail(ctx, token)
	require.NoError(t, err)
	require.NotNil(t, verified.EmailVerifiedAt)

	// Single-use.
	_, err = svc.VerifyEmail(ctx, token)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
}

func TestVerification_KindsAreNotInterchangeable(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "kinds@example.com"
	_, err := svc.Register(ctx, email, "OldPassw0rd!")
	require.NoError(t, err)

	// A password-reset token must not satisfy email verification.
	resetToken, _, err := svc.RequestPasswordReset(ctx, email)
	require.NoError(t, err)
	_, err = svc.VerifyEmail(ctx, resetToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
}

func TestLinkOrCreateIdentity(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	// First sight of (google, sub-1): JIT-provision a verified user.
	user, err := svc.LinkOrCreateIdentity(ctx, "google", "sub-1", "oauth@example.com", true)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "oauth@example.com", user.Email)
	require.NotNil(t, user.EmailVerifiedAt, "verified provider email marks the account verified")

	// Same provider identity returns the same user (idempotent login).
	again, err := svc.LinkOrCreateIdentity(ctx, "google", "sub-1", "oauth@example.com", true)
	require.NoError(t, err)
	assert.Equal(t, user.ID, again.ID)

	// A different provider sharing the email must NOT silently link (takeover guard).
	_, err = svc.LinkOrCreateIdentity(ctx, "github", "gh-1", "oauth@example.com", true)
	assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)
}

func TestVerification_RequestPasswordReset_OAuthOnlyAccountIsSilent(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	// JIT-provision an OAuth-only account (no password identity).
	user, err := svc.LinkOrCreateIdentity(ctx, "google", "sub-9", "oauth-only@example.com", true)
	require.NoError(t, err)
	require.NotNil(t, user)

	// A reset request must not mint a token that ResetPassword could never apply; it stays
	// uniform with the unknown-account case.
	token, gotUser, err := svc.RequestPasswordReset(ctx, "oauth-only@example.com")
	require.NoError(t, err)
	assert.Empty(t, token, "must not mint a reset token for an account with no password")
	assert.Nil(t, gotUser)
}

func TestVerification_MagicLinkRoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "magic@example.com"
	registered, err := svc.Register(ctx, email, "OldPassw0rd!")
	require.NoError(t, err)

	token, user, err := svc.RequestMagicLink(ctx, email)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotNil(t, user)

	loggedIn, err := svc.LoginWithMagicLink(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, registered.ID, loggedIn.ID)

	// Single-use.
	_, err = svc.LoginWithMagicLink(ctx, token)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
}

func TestVerification_RequestMagicLink_UnknownEmailIsSilent(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	token, user, err := svc.RequestMagicLink(ctx, "nobody@example.com")
	require.NoError(t, err)
	assert.Empty(t, token)
	assert.Nil(t, user)
}

func TestVerification_MagicLinkWorksForOAuthOnlyAccount(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	// Magic-link grants a session without a password, so it must work for OAuth-only accounts
	// (unlike password reset).
	user, err := svc.LinkOrCreateIdentity(ctx, "google", "sub-ml", "ml-oauth@example.com", true)
	require.NoError(t, err)

	token, gotUser, err := svc.RequestMagicLink(ctx, "ml-oauth@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotNil(t, gotUser)

	loggedIn, err := svc.LoginWithMagicLink(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, user.ID, loggedIn.ID)
}

func TestVerification_TokensDoNotResurrectDeactivatedUsers(t *testing.T) {
	ctx := context.Background()

	// Deleting a user PURGES its pending verification tokens (GDPR erasure), so a token minted
	// before deletion no longer exists afterwards — consuming it reports ErrVerificationToken
	// NotFound. (The service also keeps a liveness gate in consumeForLiveUser as belt-and-
	// suspenders, but with the purge the token is gone before that gate is reached.)
	t.Run("magic-link", func(t *testing.T) {
		svc, store := newVerificationService(t)
		user, err := svc.Register(ctx, "ml-dead@example.com", "OldPassw0rd!")
		require.NoError(t, err)
		token, _, err := svc.RequestMagicLink(ctx, "ml-dead@example.com")
		require.NoError(t, err)

		require.NoError(t, store.DeleteUser(ctx, user.ID))

		_, err = svc.LoginWithMagicLink(ctx, token)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "a magic-link must not log in a deactivated account")
	})

	t.Run("password reset", func(t *testing.T) {
		svc, store := newVerificationService(t)
		user, err := svc.Register(ctx, "pr-dead@example.com", "OldPassw0rd!")
		require.NoError(t, err)
		token, _, err := svc.RequestPasswordReset(ctx, "pr-dead@example.com")
		require.NoError(t, err)

		require.NoError(t, store.DeleteUser(ctx, user.ID))

		err = svc.ResetPassword(ctx, token, "NewPassw0rd!")
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "a reset token must not act on a deactivated account")
	})

	t.Run("email verification", func(t *testing.T) {
		svc, store := newVerificationService(t)
		user, err := svc.Register(ctx, "ev-dead@example.com", "OldPassw0rd!")
		require.NoError(t, err)
		token, err := svc.RequestEmailVerification(ctx, user.ID)
		require.NoError(t, err)

		require.NoError(t, store.DeleteUser(ctx, user.ID))

		_, err = svc.VerifyEmail(ctx, token)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "a verification token must not act on a deactivated account")
	})
}

func TestRegister_CompensatesOrphanWhenAddIdentityFails(t *testing.T) {
	ctx := context.Background()
	created := &identity.User{ID: uuid.New(), Email: "orphan@example.com"}
	deleted := false
	store := &storetest.MockStore{
		CreateUserFunc: func(_ context.Context, _ string, _ ...identity.Option) (*identity.User, error) {
			return created, nil
		},
		AddIdentityFunc: func(_ context.Context, _ *identity.Identity, _ ...identity.Option) error {
			return errors.New("transient failure on the second write")
		},
		DeleteUserFunc: func(_ context.Context, id uuid.UUID, _ ...identity.Option) error {
			assert.Equal(t, created.ID, id, "the just-created user must be the one compensated")
			deleted = true
			return nil
		},
	}
	hasher := &hashertest.MockHasher{HashFunc: func(_ context.Context, _ string) (string, error) { return "h", nil }}
	policy := &mockPolicy{VerifyFunc: func(_ context.Context, _ string) error { return nil }}

	svc := identity.NewService(store, hasher, policy)
	_, err := svc.Register(ctx, "orphan@example.com", "Passw0rd!")

	require.Error(t, err)
	assert.True(t, deleted, "a failed AddIdentity must compensate by deleting the orphan user")
}
