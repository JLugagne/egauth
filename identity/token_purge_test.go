package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResetPassword_EndsAccountTakeoverViaRecoveryEmailToken reproduces finding identity/TEN-1 end
// to end. An attacker holding a live session enrolls an attacker-controlled recovery address but
// does NOT confirm it yet; the victim then performs the canonical recovery (password reset). The
// reset must leave the attacker with nothing: the pending recovery-email token is a credential
// minted under the attacker's control, so it must not survive the reset.
func TestResetPassword_EndsAccountTakeoverViaRecoveryEmailToken(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const victim = "victim@example.com"
	user, err := svc.Register(ctx, "", victim, "OldPassw0rd!")
	require.NoError(t, err)

	// Step 1: the attacker, riding the hijacked session, enrolls their own recovery address.
	attackerToken, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "attacker@evil.test")
	require.NoError(t, err)
	require.NotEmpty(t, attackerToken)

	// Step 2: the victim recovers the account.
	resetToken, _, err := svc.RequestPasswordReset(ctx, "", victim)
	require.NoError(t, err)
	require.NoError(t, svc.ResetPassword(ctx, "", resetToken, "BrandNewPass1!"))

	// Step 3: the attacker's pending recovery-email token must be dead.
	_, err = svc.ConfirmRecoveryEmail(ctx, "", attackerToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"a recovery-email token minted before the reset must not still be usable")

	channels, err := svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	assert.False(t, channels.RecoveryEmail,
		"the reset must not leave an attacker-controlled recovery channel enrollable")
}

// TestResetPassword_PurgesPendingEmailChangeToken proves the same for a pending email CHANGE: the
// token moves the account's login identifier, so it must not outlive a password reset.
func TestResetPassword_PurgesPendingEmailChangeToken(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const victim = "change-victim@example.com"
	user, err := svc.Register(ctx, "", victim, "OldPassw0rd!")
	require.NoError(t, err)

	changeToken, err := svc.RequestEmailChange(ctx, "", user.ID, "attacker@evil.test")
	require.NoError(t, err)

	resetToken, _, err := svc.RequestPasswordReset(ctx, "", victim)
	require.NoError(t, err)
	require.NoError(t, svc.ResetPassword(ctx, "", resetToken, "BrandNewPass1!"))

	_, err = svc.ConfirmEmailChange(ctx, "", changeToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"an email-change token minted before the reset must not still be usable")

	// The victim must still own their login address.
	_, err = svc.Authenticate(ctx, "", "password", victim, "BrandNewPass1!")
	assert.NoError(t, err, "the victim must keep their login identifier after the reset")
}

// TestResetPassword_PurgesPendingMagicLink proves a pending magic link — a full login credential —
// does not survive a password reset.
func TestResetPassword_PurgesPendingMagicLink(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const victim = "magic-victim@example.com"
	_, err := svc.Register(ctx, "", victim, "OldPassw0rd!")
	require.NoError(t, err)

	magicToken, _, err := svc.RequestMagicLink(ctx, "", victim)
	require.NoError(t, err)
	require.NotEmpty(t, magicToken)

	resetToken, _, err := svc.RequestPasswordReset(ctx, "", victim)
	require.NoError(t, err)
	require.NoError(t, svc.ResetPassword(ctx, "", resetToken, "BrandNewPass1!"))

	_, err = svc.LoginWithMagicLink(ctx, "", magicToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"attacker must not be able to authenticate after the victim's recovery")
}

// TestResetPassword_PurgesPendingPhoneVerification proves a pending phone-verification token does
// not survive a reset: a verified phone is an independent recovery channel that drives
// RequestPasswordResetViaRecovery.
func TestResetPassword_PurgesPendingPhoneVerification(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const victim = "phone-victim@example.com"
	user, err := svc.Register(ctx, "", victim, "OldPassw0rd!")
	require.NoError(t, err)

	phoneToken, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15553334444")
	require.NoError(t, err)

	resetToken, _, err := svc.RequestPasswordReset(ctx, "", victim)
	require.NoError(t, err)
	require.NoError(t, svc.ResetPassword(ctx, "", resetToken, "BrandNewPass1!"))

	_, err = svc.ConfirmPhoneVerification(ctx, "", phoneToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"a phone-verification token minted before the reset must not still be usable")
}

// TestResetPassword_PurgesOtherPendingResetTokens proves a second, still-pending reset token is
// invalidated by a completed reset: it is a credential that re-sets the password.
func TestResetPassword_PurgesOtherPendingResetTokens(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const victim = "double-reset@example.com"
	_, err := svc.Register(ctx, "", victim, "OldPassw0rd!")
	require.NoError(t, err)

	stale, _, err := svc.RequestPasswordReset(ctx, "", victim)
	require.NoError(t, err)
	used, _, err := svc.RequestPasswordReset(ctx, "", victim)
	require.NoError(t, err)
	require.NotEqual(t, stale, used)

	require.NoError(t, svc.ResetPassword(ctx, "", used, "BrandNewPass1!"))

	err = svc.ResetPassword(ctx, "", stale, "AttackerPass1!")
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"a reset token still pending when another reset completed must be dead")
}

// TestResetPassword_KeepsPendingEmailVerification pins the deliberate exception: a pending
// verification of the account's CURRENT address carries no credential an attacker can profit from
// (the address is already on the account), and purging it would strand a legitimate user who reset
// their password before clicking the welcome link.
func TestResetPassword_KeepsPendingEmailVerification(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const victim = "verify-keep@example.com"
	user, err := svc.Register(ctx, "", victim, "OldPassw0rd!")
	require.NoError(t, err)

	verifyToken, err := svc.RequestEmailVerification(ctx, "", user.ID)
	require.NoError(t, err)

	resetToken, _, err := svc.RequestPasswordReset(ctx, "", victim)
	require.NoError(t, err)
	require.NoError(t, svc.ResetPassword(ctx, "", resetToken, "BrandNewPass1!"))

	verified, err := svc.VerifyEmail(ctx, "", verifyToken)
	require.NoError(t, err, "a pending verification of the current address must survive a reset")
	assert.NotNil(t, verified.EmailVerifiedAt)
}

// TestChangePassword_PurgesPendingTokens proves the authenticated self-service change gets the same
// purge as the token-gated reset: it is the other half of "I think I am compromised".
func TestChangePassword_PurgesPendingTokens(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const victim = "change-purge@example.com"
	user, err := svc.Register(ctx, "", victim, "OldPassw0rd!")
	require.NoError(t, err)

	recoveryToken, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "attacker@evil.test")
	require.NoError(t, err)
	magicToken, _, err := svc.RequestMagicLink(ctx, "", victim)
	require.NoError(t, err)

	require.NoError(t, svc.ChangePassword(ctx, "", user.ID, "OldPassw0rd!", "BrandNewPass1!"))

	_, err = svc.ConfirmRecoveryEmail(ctx, "", recoveryToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"ChangePassword must purge a pending recovery-email token")
	_, err = svc.LoginWithMagicLink(ctx, "", magicToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"ChangePassword must purge a pending magic link")
}

// TestSetTemporaryPassword_PurgesPendingTokens proves the administrative credential override also
// purges: it is the path an operator uses to wrest a compromised account back.
func TestSetTemporaryPassword_PurgesPendingTokens(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const victim = "temp-purge@example.com"
	user, err := svc.Register(ctx, "", victim, "OldPassw0rd!")
	require.NoError(t, err)

	recoveryToken, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "attacker@evil.test")
	require.NoError(t, err)

	require.NoError(t, svc.SetTemporaryPassword(ctx, "", user.ID, "TempPassw0rd!"))

	_, err = svc.ConfirmRecoveryEmail(ctx, "", recoveryToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"SetTemporaryPassword must purge a pending recovery-email token")
}

// TestDisableUser_PurgeSurvivesEnable proves the refuter-found gap on identity/service.go:210: a
// credential-bearing token minted before a suspension must not become usable again once the account
// is re-enabled. DisableUser documents that pending token-gated actions are revoked; revocation that
// silently expires with the suspension is not revocation.
func TestDisableUser_PurgeSurvivesEnable(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "disable-purge@example.com"
	user, err := svc.Register(ctx, "", email, "OldPassw0rd!")
	require.NoError(t, err)

	magicToken, _, err := svc.RequestMagicLink(ctx, "", email)
	require.NoError(t, err)
	changeToken, err := svc.RequestEmailChange(ctx, "", user.ID, "attacker@evil.test")
	require.NoError(t, err)

	require.NoError(t, svc.DisableUser(ctx, "", user.ID))
	require.NoError(t, svc.EnableUser(ctx, "", user.ID))

	_, err = svc.LoginWithMagicLink(ctx, "", magicToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"a magic link minted before a disable must not work again after enable")
	_, err = svc.ConfirmEmailChange(ctx, "", changeToken)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
		"an email-change token minted before a disable must not work again after enable")
}

// purgeFailingStore wraps the in-memory store and fails only the per-user token purge, so a caller
// that ignored the purge error would look successful.
type purgeFailingStore struct {
	*memory.Store
	purgeErr error
}

func (s *purgeFailingStore) DeleteVerificationTokensForUser(context.Context, string, uuid.UUID, ...string) error {
	return s.purgeErr
}

// TestCredentialRotation_PurgeFailureIsNotSilent proves a failing purge is reported rather than
// swallowed on every flow that performs one. Reporting it is what lets the caller retry instead of
// telling a compromised user their recovery succeeded.
func TestCredentialRotation_PurgeFailureIsNotSilent(t *testing.T) {
	newFailing := func(t *testing.T) (identity.Service, *purgeFailingStore) {
		t.Helper()
		store := &purgeFailingStore{Store: memory.NewStore(), purgeErr: assert.AnError}
		policy := &mockPolicy{VerifyFunc: func(_ context.Context, p string) error {
			if len(p) < 8 {
				return assert.AnError
			}
			return nil
		}}
		return identity.NewService(store, argon2.NewHasher(), policy), store
	}

	t.Run("ResetPassword", func(t *testing.T) {
		ctx := context.Background()
		svc, _ := newFailing(t)
		const email = "purge-fail-reset@example.com"
		_, err := svc.Register(ctx, "", email, "OldPassw0rd!")
		require.NoError(t, err)

		token, _, err := svc.RequestPasswordReset(ctx, "", email)
		require.NoError(t, err)
		assert.ErrorIs(t, svc.ResetPassword(ctx, "", token, "BrandNewPass1!"), assert.AnError,
			"a failed token purge must surface, not be swallowed")
	})

	t.Run("ChangePassword", func(t *testing.T) {
		ctx := context.Background()
		svc, _ := newFailing(t)
		user, err := svc.Register(ctx, "", "purge-fail-change@example.com", "OldPassw0rd!")
		require.NoError(t, err)
		assert.ErrorIs(t, svc.ChangePassword(ctx, "", user.ID, "OldPassw0rd!", "BrandNewPass1!"), assert.AnError)
	})

	t.Run("SetTemporaryPassword", func(t *testing.T) {
		ctx := context.Background()
		svc, _ := newFailing(t)
		user, err := svc.Register(ctx, "", "purge-fail-temp@example.com", "OldPassw0rd!")
		require.NoError(t, err)
		assert.ErrorIs(t, svc.SetTemporaryPassword(ctx, "", user.ID, "TempPassw0rd!"), assert.AnError)
	})

	t.Run("DisableUser", func(t *testing.T) {
		ctx := context.Background()
		svc, _ := newFailing(t)
		user, err := svc.Register(ctx, "", "purge-fail-disable@example.com", "OldPassw0rd!")
		require.NoError(t, err)
		assert.ErrorIs(t, svc.DisableUser(ctx, "", user.ID), assert.AnError)

		// The suspension itself must still have landed: the purge is a follow-up, not a gate.
		assert.ErrorIs(t, svc.EnsureActive(ctx, "", user.ID), identity.ErrAccountDisabled)
	})
}
