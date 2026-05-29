package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/libauth/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteAccount_SoftDeletesAnonymizesAndFreesEmail(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "gone@example.com"
	user, err := svc.Register(ctx, email, "OldPassw0rd!")
	require.NoError(t, err)

	require.NoError(t, svc.DeleteAccount(ctx, user.ID))

	// The account's PII is anonymized: the email no longer resolves and the credentials no
	// longer authenticate.
	_, err = svc.Authenticate(ctx, "password", email, "OldPassw0rd!")
	assert.ErrorIs(t, err, identity.ErrInvalidCredentials, "a deleted account must not authenticate")

	// The email slot is freed for re-registration.
	reReg, err := svc.Register(ctx, email, "BrandNewPass1!")
	require.NoError(t, err, "the email must be re-registerable after deletion")
	assert.NotEqual(t, user.ID, reReg.ID)
}

func TestDeleteAccount_RunsErasersThenDeletes(t *testing.T) {
	ctx := context.Background()

	var sessionsErased, tokensErased uuid.UUID
	sessionsEraser := func(_ context.Context, userID uuid.UUID, _ ...identity.Option) error {
		sessionsErased = userID
		return nil
	}
	tokensEraser := func(_ context.Context, userID uuid.UUID, _ ...identity.Option) error {
		tokensErased = userID
		return nil
	}

	svc, _ := newVerificationService(t, identity.WithAccountErasers(sessionsEraser, tokensEraser))

	user, err := svc.Register(ctx, "cascade@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	require.NoError(t, svc.DeleteAccount(ctx, user.ID))

	// Every registered eraser runs with the deleted user's ID (the cross-module cascade seam).
	assert.Equal(t, user.ID, sessionsErased)
	assert.Equal(t, user.ID, tokensErased)

	// And the identity itself is gone.
	_, err = svc.Authenticate(ctx, "password", "cascade@example.com", "OldPassw0rd!")
	assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
}

func TestDeleteAccount_EraserFailureAbortsBeforeSoftDelete(t *testing.T) {
	ctx := context.Background()

	boom := errors.New("revocation backend down")
	failingEraser := func(_ context.Context, _ uuid.UUID, _ ...identity.Option) error { return boom }

	svc, _ := newVerificationService(t, identity.WithAccountErasers(failingEraser))

	const email = "kept@example.com"
	user, err := svc.Register(ctx, email, "OldPassw0rd!")
	require.NoError(t, err)

	// A failed eraser must surface and must NOT leave a half-deleted account: the identity stays
	// live so the whole operation can be retried cleanly.
	err = svc.DeleteAccount(ctx, user.ID)
	require.ErrorIs(t, err, boom)

	_, err = svc.Authenticate(ctx, "password", email, "OldPassw0rd!")
	require.NoError(t, err, "a failed revocation must not have deleted the account")
}

func TestDeleteAccount_PurgesPendingVerificationTokens(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "purge@example.com"
	user, err := svc.Register(ctx, email, "OldPassw0rd!")
	require.NoError(t, err)

	// Mint a still-pending magic-link token, then delete the account.
	token, _, err := svc.RequestMagicLink(ctx, email)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	require.NoError(t, svc.DeleteAccount(ctx, user.ID))

	// The token row must be GONE (PII erased), not merely inert: a purged token reports
	// ErrVerificationTokenNotFound, whereas a surviving-but-inert token would report
	// ErrUserNotFound (the deactivated-account liveness gate).
	_, err = svc.LoginWithMagicLink(ctx, token)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "deletion must purge pending verification tokens")
}

func TestDeleteAccount_UnknownUserDoesNotRunErasers(t *testing.T) {
	ctx := context.Background()

	called := false
	eraser := func(_ context.Context, _ uuid.UUID, _ ...identity.Option) error {
		called = true
		return nil
	}
	svc, _ := newVerificationService(t, identity.WithAccountErasers(eraser))

	err := svc.DeleteAccount(ctx, uuid.New())
	assert.ErrorIs(t, err, identity.ErrUserNotFound)
	assert.False(t, called, "erasers must not run for a non-existent user")
}

func TestDeleteAccount_AlreadyDeletedIsNotFound(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "twice@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	require.NoError(t, svc.DeleteAccount(ctx, user.ID))
	err = svc.DeleteAccount(ctx, user.ID)
	assert.ErrorIs(t, err, identity.ErrUserNotFound, "deleting an already-deleted account reports not found")
}
