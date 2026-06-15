package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/unicode/norm"
)

func TestRecoveryEmail_RoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "primary@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	// No recovery channel before enrollment.
	ch, err := svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	assert.False(t, ch.Any(), "a fresh account has no recovery channel")

	const recovery = "backup@elsewhere.example"
	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, recovery)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Still not enrolled until confirmed.
	ch, err = svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	assert.False(t, ch.RecoveryEmail, "the recovery email must not count until confirmed")

	updated, err := svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)
	require.NotNil(t, updated.RecoveryEmail)
	assert.Equal(t, recovery, *updated.RecoveryEmail)
	require.NotNil(t, updated.RecoveryEmailVerifiedAt)

	ch, err = svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	assert.True(t, ch.RecoveryEmail, "a confirmed recovery email is an available channel")
	assert.True(t, ch.Any())
}

func TestRecoveryEmail_NormalizesAddress(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)
	user, err := svc.Register(ctx, "", "norm-rec@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "  Backup.Addr@Elsewhere.COM ")
	require.NoError(t, err)
	updated, err := svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)
	require.NotNil(t, updated.RecoveryEmail)
	assert.Equal(t, "backup.addr@elsewhere.com", *updated.RecoveryEmail)
}

func TestRecoveryEmail_RejectsMalformed(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)
	user, err := svc.Register(ctx, "", "bad-rec@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	_, err = svc.RequestRecoveryEmail(ctx, "", user.ID, "not-an-email")
	assert.ErrorIs(t, err, identity.ErrInvalidEmail)
}

func TestRecoveryEmail_RejectsPrimaryAddress(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)
	const primary = "same@example.com"
	user, err := svc.Register(ctx, "", primary, "OldPassw0rd!")
	require.NoError(t, err)

	// A recovery channel must be INDEPENDENT — the primary email is not allowed as recovery.
	_, err = svc.RequestRecoveryEmail(ctx, "", user.ID, "Same@Example.com")
	assert.ErrorIs(t, err, identity.ErrRecoveryEmailIsPrimary,
		"normalization must catch a case-variant of the primary email too")
}

func TestRecoveryEmail_TokenIsSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)
	user, err := svc.Register(ctx, "", "single-rec@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "rec@elsewhere.example")
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
}

func TestRecoveryEmail_KindIsolation(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)
	user, err := svc.Register(ctx, "", "kind-rec@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	recTok, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "rec@elsewhere.example")
	require.NoError(t, err)
	// A recovery-email token must not double as an email-verification token.
	_, err = svc.VerifyEmail(ctx, "", recTok)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
}

func TestRecoveryEmail_RejectsUnknownUser(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)
	_, err := svc.RequestRecoveryEmail(ctx, "", uuid.Must(uuid.NewV7()), "rec@elsewhere.example")
	assert.ErrorIs(t, err, identity.ErrUserNotFound)

	_, err = svc.RecoveryChannels(ctx, "", uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, identity.ErrUserNotFound)
}

func TestRecoveryChannels_PhoneCounts(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)
	user, err := svc.Register(ctx, "", "phone-rec@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	// A verified phone (from N9) is itself an independent recovery channel.
	tok, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15553334444")
	require.NoError(t, err)
	_, err = svc.ConfirmPhoneVerification(ctx, "", tok)
	require.NoError(t, err)

	ch, err := svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	assert.True(t, ch.Phone)
	assert.False(t, ch.RecoveryEmail)
	assert.True(t, ch.Any())
}

func TestRequestPasswordResetViaRecovery_RequiresVerifiedChannel(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)
	const primary = "noch@example.com"
	_, err := svc.Register(ctx, "", primary, "OldPassw0rd!")
	require.NoError(t, err)

	// No recovery channel enrolled: stay enumeration-uniform (no token, no error).
	token, user, channels, err := svc.RequestPasswordResetViaRecovery(ctx, "", primary)
	require.NoError(t, err)
	assert.Empty(t, token, "no token without a verified recovery channel")
	assert.Nil(t, user)
	assert.False(t, channels.Any())
}

func TestRequestPasswordResetViaRecovery_DeliversToRecoveryChannel(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)
	const primary = "hasrec@example.com"
	user, err := svc.Register(ctx, "", primary, "OldPassw0rd!")
	require.NoError(t, err)

	// Enroll + verify a recovery email.
	tok, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "rec@elsewhere.example")
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", tok)
	require.NoError(t, err)

	// Now a recovery-channel reset yields a usable token + the channel inventory.
	resetTok, gotUser, channels, err := svc.RequestPasswordResetViaRecovery(ctx, "", primary)
	require.NoError(t, err)
	require.NotEmpty(t, resetTok)
	require.NotNil(t, gotUser)
	assert.True(t, channels.RecoveryEmail)

	// The token is a normal password-reset token: it actually resets the password.
	require.NoError(t, svc.ResetPassword(ctx, "", resetTok, "BrandNewPass1!"))
	_, err = svc.Authenticate(ctx, "", "password", primary, "BrandNewPass1!")
	require.NoError(t, err)
}

func TestRequestPasswordResetViaRecovery_UnknownAccountIsUniform(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	token, user, channels, err := svc.RequestPasswordResetViaRecovery(ctx, "", "nobody@example.com")
	require.NoError(t, err)
	assert.Empty(t, token)
	assert.Nil(t, user)
	assert.False(t, channels.Any())
}

// TestRecoveryEmail_RejectsUnicodeVariantOfPrimary proves the independence guard rejects a
// Unicode/IDN-equivalent of the primary address, not just a byte-exact match. The primary
// email is stored in NFD (decomposed) form — as a legacy or externally provisioned account
// may be — while the recovery candidate is supplied in NFC (composed) form of the SAME
// address. normalizeEmail folds the candidate to NFC, so a byte-exact comparison against the
// raw stored primary would miss it and accept the same physical mailbox as an "independent"
// recovery channel. The guard must canonicalize the primary the same way and reject it.
func TestRecoveryEmail_RejectsUnicodeVariantOfPrimary(t *testing.T) {
	ctx := context.Background()
	svc, store := newVerificationService(t)

	// "josé@example.com" with the accented 'e' in NFD form: 'e' + U+0301 combining acute.
	const nfdPrimary = "josé@example.com"
	// The NFC (precomposed) form of the very same address: 'é' as U+00E9.
	const nfcVariant = "josé@example.com"
	require.NotEqual(t, nfdPrimary, nfcVariant, "test setup: the two forms must differ byte-wise")
	require.Equal(t, nfcVariant, norm.NFC.String(nfdPrimary), "test setup: NFC of the NFD primary is the variant")

	// Provision the user directly with the non-normalized (NFD) primary, modelling an account
	// whose stored email never passed through normalizeEmail.
	user, err := store.CreateUser(ctx, "", nfdPrimary)
	require.NoError(t, err)

	// Enrolling the NFC variant of the primary must be rejected as the primary address.
	_, err = svc.RequestRecoveryEmail(ctx, "", user.ID, nfcVariant)
	assert.ErrorIs(t, err, identity.ErrRecoveryEmailIsPrimary,
		"a Unicode-equivalent of the primary must not be accepted as an independent recovery channel")
}
