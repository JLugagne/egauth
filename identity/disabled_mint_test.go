package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stubTokenGeneration(t *testing.T) *int {
	t.Helper()
	count := 0
	origGen := identity.GenerateVerificationToken
	identity.GenerateVerificationToken = func() (string, string, string, error) {
		count++
		return origGen()
	}
	t.Cleanup(func() { identity.GenerateVerificationToken = origGen })
	return &count
}

// TestRequestMagicLink_DisabledAccountIsUniform is the AS-03 bug-confirming test: a disabled
// account's magic-link request must be indistinguishable from an unknown one — no token, no
// user, no error — with a decoy token still generated to equalize timing. Before the fix the
// disabled account received a live token that was delivered before the consume-time gate
// rejected it, giving callers and suspended users a liveness signal.
func TestRequestMagicLink_DisabledAccountIsUniform(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "suspended@example.com"
	user, err := svc.Register(ctx, "", email, "OldPassw0rd!")
	require.NoError(t, err)
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	gens := stubTokenGeneration(t)

	token, got, err := svc.RequestMagicLink(ctx, "", email)
	require.NoError(t, err, "a disabled account must not be distinguishable from an unknown one")
	assert.Empty(t, token, "no token may be minted for a disabled account")
	assert.Nil(t, got)
	assert.Equal(t, 1, *gens, "a decoy token must be generated to equalize timing with the unknown-account path")

	token, got, err = svc.RequestMagicLink(ctx, "", "nobody@example.com")
	require.NoError(t, err)
	assert.Empty(t, token)
	assert.Nil(t, got)
	assert.Equal(t, 2, *gens, "the unknown-account path keeps its decoy")
}

// TestRequestPasswordReset_DisabledAccountIsUniform mirrors TestRequestMagicLink_DisabledAccountIsUniform
// for the password-reset flow: a disabled account must yield ("", nil, nil) after a decoy token,
// exactly like an unknown email.
func TestRequestPasswordReset_DisabledAccountIsUniform(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "suspendedreset@example.com"
	user, err := svc.Register(ctx, "", email, "OldPassw0rd!")
	require.NoError(t, err)
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	gens := stubTokenGeneration(t)

	token, got, err := svc.RequestPasswordReset(ctx, "", email)
	require.NoError(t, err, "a disabled account must not be distinguishable from an unknown one")
	assert.Empty(t, token, "no token may be minted for a disabled account")
	assert.Nil(t, got)
	assert.Equal(t, 1, *gens, "a decoy token must be generated to equalize timing with the unknown-account path")

	token, got, err = svc.RequestPasswordReset(ctx, "", "nobody@example.com")
	require.NoError(t, err)
	assert.Empty(t, token)
	assert.Nil(t, got)
	assert.Equal(t, 2, *gens, "the unknown-account path keeps its decoy")
}

// TestRequestPasswordResetViaRecovery_DisabledAccountIsUniform verifies that a disabled account
// with a verified recovery channel yields ("", nil, RecoveryChannels{}, nil) after a decoy token:
// without the mint-time gate this account would receive a live reset token.
func TestRequestPasswordResetViaRecovery_DisabledAccountIsUniform(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "suspendedrec@example.com"
	user, err := svc.Register(ctx, "", email, "OldPassw0rd!")
	require.NoError(t, err)

	// Enroll + verify a recovery email so the disabled gate is the only thing standing
	// between the request and a minted token.
	tok, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "rec@elsewhere.example")
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", tok)
	require.NoError(t, err)

	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	gens := stubTokenGeneration(t)

	token, got, channels, err := svc.RequestPasswordResetViaRecovery(ctx, "", email)
	require.NoError(t, err, "a disabled account must not be distinguishable from an unknown one")
	assert.Empty(t, token, "no token may be minted for a disabled account")
	assert.Nil(t, got)
	assert.False(t, channels.Any())
	assert.Equal(t, 1, *gens, "a decoy token must be generated to equalize timing with the unknown-account path")

	token, got, channels, err = svc.RequestPasswordResetViaRecovery(ctx, "", "nobody@example.com")
	require.NoError(t, err)
	assert.Empty(t, token)
	assert.Nil(t, got)
	assert.False(t, channels.Any())
	assert.Equal(t, 2, *gens, "the unknown-account path keeps its decoy")
}

// TestRequestEmailVerification_DisabledAccountIsUniform verifies that email verification cannot
// be minted for a disabled account: the store-level liveness guard reports not-found, which the
// service maps to the silent ("", nil), identical to an unknown user.
func TestRequestEmailVerification_DisabledAccountIsUniform(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "suspendedverif@example.com", "OldPassw0rd!")
	require.NoError(t, err)
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	token, err := svc.RequestEmailVerification(ctx, "", user.ID)
	require.NoError(t, err, "a disabled account must not be distinguishable from an unknown one")
	assert.Empty(t, token, "no token may be minted for a disabled account")

	token, err = svc.RequestEmailVerification(ctx, "", uuid.Must(uuid.NewV7()))
	require.NoError(t, err)
	assert.Empty(t, token)
}

// TestEnableUser_RestoresMinting verifies the disable gate is specifically about DisabledAt:
// once the account is enabled again, token minting works normally.
func TestEnableUser_RestoresMinting(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "reenabled@example.com"
	user, err := svc.Register(ctx, "", email, "OldPassw0rd!")
	require.NoError(t, err)
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))
	require.NoError(t, svc.EnableUser(ctx, "", user.ID))

	token, got, err := svc.RequestMagicLink(ctx, "", email)
	require.NoError(t, err)
	require.NotEmpty(t, token, "a re-enabled account can receive tokens again")
	require.NotNil(t, got)

	token, err = svc.RequestEmailVerification(ctx, "", user.ID)
	require.NoError(t, err)
	require.NotEmpty(t, token, "a re-enabled account can receive tokens again")
}
