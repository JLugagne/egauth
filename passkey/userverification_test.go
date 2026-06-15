package passkey_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUVRequiredService builds a passkey Service that requires user verification (UV) on every
// ceremony, mirroring newPasskeyService but with Config.UserVerification = VerificationRequired.
func newUVRequiredService(t *testing.T) *passkey.Service {
	t.Helper()
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:             testRPID,
		RPDisplayName:    testRPName,
		RPOrigins:        []string{testOrigin},
		UserVerification: protocol.VerificationRequired,
		CookieKey:        testCookieKey,
		ChallengeStore:   passkeymemory.NewChallengeStore(),
	})
	require.NoError(t, err)
	return svc
}

// newUVPreferredService builds a Service that explicitly relaxes user verification to
// VerificationPreferred — the opt-out from the secure default — so a UV-cleared assertion is
// accepted.
func newUVPreferredService(t *testing.T) *passkey.Service {
	t.Helper()
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:             testRPID,
		RPDisplayName:    testRPName,
		RPOrigins:        []string{testOrigin},
		UserVerification: protocol.VerificationPreferred,
		CookieKey:        testCookieKey,
		ChallengeStore:   passkeymemory.NewChallengeStore(),
	})
	require.NoError(t, err)
	return svc
}

// TestUserVerificationRequired_PropagatedIntoCeremonies asserts that when UV is required, the
// requirement is surfaced in the registration and login ceremony options AND carried into the
// SessionData that drives Finish verification.
func TestUserVerificationRequired_PropagatedIntoCeremonies(t *testing.T) {
	ctx := context.Background()
	svc := newUVRequiredService(t)
	userID := uuid.Must(uuid.NewV7())

	cc, regSession, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationRequired, cc.Response.AuthenticatorSelection.UserVerification,
		"registration options must request user verification")
	assert.Equal(t, protocol.VerificationRequired, regSession.UserVerification,
		"registration SessionData must carry the UV requirement to Finish")

	// Enrol a credential so a login ceremony can be started.
	auth := register(t, svc, userID)

	assertion, loginSession, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationRequired, assertion.Response.UserVerification,
		"login options must request user verification")
	assert.Equal(t, protocol.VerificationRequired, loginSession.UserVerification,
		"login SessionData must carry the UV requirement to Finish")

	_ = auth
}

// TestUserVerificationRequired_RejectsUVUnsetLogin is the core security assertion: with UV
// required, an assertion whose User Verified flag is NOT set must be rejected at FinishLogin,
// while a UV-set assertion succeeds.
func TestUserVerificationRequired_RejectsUVUnsetLogin(t *testing.T) {
	ctx := context.Background()
	svc := newUVRequiredService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	// A login presenting only the User Present bit (UV cleared) must be rejected.
	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	_, err = svc.FinishLogin(ctx, "", userID, *session,
		auth.assertionWithFlags(t, session.Challenge, nil, 1, flagUP))
	require.Error(t, err, "UV-required login must reject an assertion without the User Verified flag")

	// A login presenting the User Verified bit succeeds.
	_, session2, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	cred, err := svc.FinishLogin(ctx, "", userID, *session2,
		auth.assertionWithFlags(t, session2.Challenge, nil, 2, flagUP|flagUV))
	require.NoError(t, err, "UV-required login must accept an assertion with the User Verified flag")
	assert.Equal(t, auth.credID, cred.ID)
}

// TestUserVerificationRequired_RejectsUVUnsetDiscoverableLogin checks the discoverable
// (usernameless) login path enforces UV too, since it shares the same validateLogin core.
func TestUserVerificationRequired_RejectsUVUnsetDiscoverableLogin(t *testing.T) {
	ctx := context.Background()
	svc := newUVRequiredService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginDiscoverableLogin()
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationRequired, session.UserVerification,
		"discoverable login SessionData must carry the UV requirement")

	_, _, err = svc.FinishDiscoverableLogin(ctx, "", *session,
		auth.assertionWithFlags(t, session.Challenge, userHandleOf(userID), 1, flagUP))
	require.Error(t, err, "UV-required discoverable login must reject an assertion without the User Verified flag")
}

// TestUserVerificationDefault_RequiresUV is the secure-by-default assertion: a zero-value
// Config.UserVerification now means VerificationRequired, so the ceremony carries the UV
// requirement and a UV-cleared assertion is REJECTED — without the caller opting into it.
func TestUserVerificationDefault_RequiresUV(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t) // zero-value UserVerification
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationRequired, session.UserVerification,
		"the default config must require user verification")

	_, err = svc.FinishLogin(ctx, "", userID, *session,
		auth.assertionWithFlags(t, session.Challenge, nil, 1, flagUP))
	require.Error(t, err, "by default a UV-cleared assertion must be rejected")
}

// TestUserVerificationPreferred_AcceptsUVUnset documents the explicit opt-out: setting
// VerificationPreferred relaxes the default so a UV-cleared assertion is accepted again (e.g. a
// second-factor flow where another factor already authenticated the user).
func TestUserVerificationPreferred_AcceptsUVUnset(t *testing.T) {
	ctx := context.Background()
	svc := newUVPreferredService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationPreferred, session.UserVerification,
		"an explicit Preferred requirement must be carried into the ceremony")

	cred, err := svc.FinishLogin(ctx, "", userID, *session,
		auth.assertionWithFlags(t, session.Challenge, nil, 1, flagUP))
	require.NoError(t, err, "with UV preferred, a UV-cleared assertion must be accepted")
	assert.Equal(t, auth.credID, cred.ID)
}
