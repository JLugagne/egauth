package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChangeEmail_RoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const oldEmail = "old@example.com"
	const newEmail = "new@example.com"
	user, err := svc.Register(ctx, oldEmail, "OldPassw0rd!")
	require.NoError(t, err)
	require.Nil(t, user.EmailVerifiedAt)

	token, err := svc.RequestEmailChange(ctx, user.ID, newEmail)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// The swap must NOT have happened yet: only requesting the change must leave the old email
	// in place and keep it usable for login.
	_, err = svc.Authenticate(ctx, "password", oldEmail, "OldPassw0rd!")
	require.NoError(t, err, "email must not change until the token is confirmed")

	updated, err := svc.ConfirmEmailChange(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, newEmail, updated.Email)
	// Confirming a token delivered to the new address proves control of it, so the new address
	// is verified.
	require.NotNil(t, updated.EmailVerifiedAt, "the confirmed new address must be marked verified")
	// The returned user must reflect the post-swap state, not the pre-swap snapshot it was
	// loaded from: UpdatedAt is stamped with the same instant as the verification.
	assert.Equal(t, *updated.EmailVerifiedAt, updated.UpdatedAt, "UpdatedAt must reflect the swap")

	// The new email now authenticates; the old one no longer maps to the account.
	_, err = svc.Authenticate(ctx, "password", newEmail, "OldPassw0rd!")
	require.NoError(t, err)
	_, err = svc.Authenticate(ctx, "password", oldEmail, "OldPassw0rd!")
	assert.ErrorIs(t, err, identity.ErrInvalidCredentials, "the old email must stop working after the swap")
}

func TestChangeEmail_NormalizesNewAddress(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "norm@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	// A case-variant / padded new address must be normalized before the swap, so it matches the
	// byte-exact uniqueness the store enforces.
	token, err := svc.RequestEmailChange(ctx, user.ID, "  New.Address@Example.COM ")
	require.NoError(t, err)

	updated, err := svc.ConfirmEmailChange(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, "new.address@example.com", updated.Email)
}

func TestChangeEmail_RejectsMalformedNewAddress(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "bad@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	_, err = svc.RequestEmailChange(ctx, user.ID, "not-an-email")
	assert.ErrorIs(t, err, identity.ErrInvalidEmail)
}

func TestChangeEmail_RejectsAddressTakenByAnotherAccount(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	owner, err := svc.Register(ctx, "owner@example.com", "OwnerPassw0rd!")
	require.NoError(t, err)
	_ = owner

	mover, err := svc.Register(ctx, "mover@example.com", "MoverPassw0rd!")
	require.NoError(t, err)

	// Requesting a change to an address already owned by a live account in the tenant is
	// rejected up front (consistent with registration's email_taken behavior).
	_, err = svc.RequestEmailChange(ctx, mover.ID, "owner@example.com")
	assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)
}

func TestChangeEmail_ConfirmRejectsAddressClaimedInInterim(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	mover, err := svc.Register(ctx, "mover2@example.com", "MoverPassw0rd!")
	require.NoError(t, err)

	// Request the change while the target is free.
	token, err := svc.RequestEmailChange(ctx, mover.ID, "contested@example.com")
	require.NoError(t, err)

	// Another account claims the address before the mover confirms.
	_, err = svc.Register(ctx, "contested@example.com", "OtherPassw0rd!")
	require.NoError(t, err)

	// The atomic swap must fail rather than create a duplicate live email.
	_, err = svc.ConfirmEmailChange(ctx, token)
	assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)
}

func TestChangeEmail_TokenIsSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "single@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	token, err := svc.RequestEmailChange(ctx, user.ID, "single-new@example.com")
	require.NoError(t, err)

	_, err = svc.ConfirmEmailChange(ctx, token)
	require.NoError(t, err)

	_, err = svc.ConfirmEmailChange(ctx, token)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "a change-email token must be single-use")
}

func TestChangeEmail_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t, identity.WithEmailChangeTTL(-time.Minute))

	user, err := svc.Register(ctx, "exp@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	token, err := svc.RequestEmailChange(ctx, user.ID, "exp-new@example.com")
	require.NoError(t, err)

	_, err = svc.ConfirmEmailChange(ctx, token)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenExpired)
}

func TestChangeEmail_KindIsNotInterchangeable(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "kind@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	// A change-email token must not satisfy plain email verification, and vice versa.
	changeToken, err := svc.RequestEmailChange(ctx, user.ID, "kind-new@example.com")
	require.NoError(t, err)
	_, err = svc.VerifyEmail(ctx, changeToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

	verifyToken, err := svc.RequestEmailVerification(ctx, user.ID)
	require.NoError(t, err)
	_, err = svc.ConfirmEmailChange(ctx, verifyToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
}

func TestChangeEmail_DoesNotActOnDeactivatedAccount(t *testing.T) {
	ctx := context.Background()
	svc, store := newVerificationService(t)

	user, err := svc.Register(ctx, "dead@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	token, err := svc.RequestEmailChange(ctx, user.ID, "dead-new@example.com")
	require.NoError(t, err)

	require.NoError(t, store.DeleteUser(ctx, user.ID))

	// Deleting the account purges its pending tokens, so the change-email token is gone.
	_, err = svc.ConfirmEmailChange(ctx, token)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "a change-email token must not act on a deactivated account")
}

func TestChangeEmail_RequestForUnknownUserIsRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	_, err := svc.RequestEmailChange(ctx, uuid.New(), "ghost-new@example.com")
	assert.ErrorIs(t, err, identity.ErrUserNotFound)
}
