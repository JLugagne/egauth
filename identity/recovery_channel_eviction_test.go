package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An enrolled recovery channel is a credential, not contact metadata: RequestPasswordResetViaRecovery
// delivers a reset token to whatever address is enrolled, so a channel added by someone else is a
// way back into the account. ResetPassword is the documented remediation after a compromise, so it
// must remove them — otherwise the victim's reset only changes a password the attacker can change
// straight back through the channel that survived.
func TestResetPassword_ClearsRecoveryChannels(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const (
		email    = "victim-recovery@example.com"
		password = "V1ctim-Passw0rd!"
	)
	user, err := svc.Register(ctx, "", email, password)
	require.NoError(t, err)

	// Enrol a recovery email and a phone, as someone with a live session could.
	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "attacker-owned@evil.example")
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)

	phoneToken, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15551234567")
	require.NoError(t, err)
	_, err = svc.ConfirmPhoneVerification(ctx, "", phoneToken)
	require.NoError(t, err)

	channels, err := svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	require.True(t, channels.Any(), "precondition: the account has a verified independent channel")
	require.True(t, channels.RecoveryEmail)

	// The victim resets their password from their own inbox — the canonical remediation.
	resetToken, _, err := svc.RequestPasswordReset(ctx, "", email)
	require.NoError(t, err)
	require.NotEmpty(t, resetToken)
	require.NoError(t, svc.ResetPassword(ctx, "", resetToken, "N3w-Victim-Passw0rd!"))

	// The attacker's channels must be gone.
	after, err := svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	assert.False(t, after.Any(),
		"a password reset must evict recovery channels; otherwise the reset does not evict the attacker")
	assert.False(t, after.RecoveryEmail)
	assert.False(t, after.Phone)

	// And the reset-via-recovery flow must no longer mint a token to the surviving channel.
	viaRecovery, _, _, err := svc.RequestPasswordResetViaRecovery(ctx, "", email)
	require.NoError(t, err)
	assert.Empty(t, viaRecovery,
		"with no recovery channel left, the flow must stay uniform and mint nothing")

	// The victim's new password works, and the old one does not.
	_, err = svc.Authenticate(ctx, "", "password", email, "N3w-Victim-Passw0rd!")
	require.NoError(t, err)
	_, err = svc.Authenticate(ctx, "", "password", email, password)
	assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
}

// The recovery channel must be independent of the primary email in BOTH directions. Enrolling the
// primary address as a recovery address was already refused; moving the primary address onto the
// enrolled recovery address produced the same collapsed end state by the other route, and made
// RecoveryChannels.Any() report a channel that was not independent.
func TestRecoveryChannelIndependence_BothDirections(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const (
		primary  = "primary@example.com"
		recovery = "recovery@example.com"
	)
	user, err := svc.Register(ctx, "", primary, "Passw0rd-Original!")
	require.NoError(t, err)

	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, recovery)
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)

	t.Run("enrolling the primary address as recovery is refused", func(t *testing.T) {
		_, err := svc.RequestRecoveryEmail(ctx, "", user.ID, primary)
		assert.ErrorIs(t, err, identity.ErrRecoveryEmailIsPrimary)
	})

	t.Run("moving the primary address onto the recovery address is refused", func(t *testing.T) {
		_, err := svc.RequestEmailChange(ctx, "", user.ID, recovery)
		assert.ErrorIs(t, err, identity.ErrRecoveryEmailIsPrimary,
			"the primary email must not collapse into the recovery channel")
	})

	t.Run("a non-canonical equivalent of the recovery address is also refused", func(t *testing.T) {
		// Uppercase is the cheapest equivalent form; the comparison canonicalizes both sides, so a
		// byte-exact guard would let this through.
		_, err := svc.RequestEmailChange(ctx, "", user.ID, "RECOVERY@EXAMPLE.COM")
		assert.ErrorIs(t, err, identity.ErrRecoveryEmailIsPrimary)
	})

	t.Run("an unrelated address is still accepted", func(t *testing.T) {
		_, err := svc.RequestEmailChange(ctx, "", user.ID, "unrelated@example.com")
		assert.NoError(t, err)
	})
}

// Clearing an account that never enrolled a channel must stay a no-op rather than an error: the
// reset path calls it unconditionally, and most accounts have no recovery channel.
func TestResetPassword_SucceedsWithoutRecoveryChannels(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "no-channel@example.com"
	_, err := svc.Register(ctx, "", email, "Passw0rd-Original!")
	require.NoError(t, err)

	token, _, err := svc.RequestPasswordReset(ctx, "", email)
	require.NoError(t, err)
	require.NoError(t, svc.ResetPassword(ctx, "", token, "Passw0rd-Rotated!"))
}

// ClearRecoveryChannels must respect tenant and liveness boundaries like every other store write.
func TestClearRecoveryChannels_Scoping(t *testing.T) {
	ctx := context.Background()
	svc, store := newVerificationService(t)

	user, err := svc.Register(ctx, "", "scoped@example.com", "Passw0rd-Original!")
	require.NoError(t, err)

	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "recovery@example.com")
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)

	t.Run("another tenant cannot clear the channel", func(t *testing.T) {
		err := store.ClearRecoveryChannels(ctx, "other-tenant", user.ID)
		assert.ErrorIs(t, err, identity.ErrUserNotFound)

		channels, cerr := svc.RecoveryChannels(ctx, "", user.ID)
		require.NoError(t, cerr)
		assert.True(t, channels.RecoveryEmail, "the channel must survive a cross-tenant clear attempt")
	})

	t.Run("the owning tenant can clear it", func(t *testing.T) {
		require.NoError(t, store.ClearRecoveryChannels(ctx, "", user.ID))
		channels, cerr := svc.RecoveryChannels(ctx, "", user.ID)
		require.NoError(t, cerr)
		assert.False(t, channels.Any())
	})

	t.Run("clearing an unknown user reports not found", func(t *testing.T) {
		unknown := user.ID
		unknown[0] ^= 0xff
		assert.ErrorIs(t, store.ClearRecoveryChannels(ctx, "", unknown), identity.ErrUserNotFound)
	})
}
