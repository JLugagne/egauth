package passkey_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRPID    = "example.com"
	testOrigin  = "https://example.com"
	testRPName  = "Example Inc"
)

// newPasskeyService builds a Service with the secure-by-default requirements satisfied (a cookie
// key and a challenge store), so it can be used by tests that only exercise the Service-level
// ceremonies. UserVerification is left at the zero value, which is now VerificationRequired.
func newPasskeyService(t *testing.T) *passkey.Service {
	t.Helper()
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:           testRPID,
		RPDisplayName:  testRPName,
		RPOrigins:      []string{testOrigin},
		CookieKey:      testCookieKey,
		ChallengeStore: passkeymemory.NewChallengeStore(),
	})
	require.NoError(t, err)
	return svc
}

// register enrolls a fresh credential for userID and returns the authenticator backing it.
func register(t *testing.T, svc *passkey.Service, userID uuid.UUID) *softAuthenticator {
	t.Helper()
	ctx := context.Background()
	auth := newSoftAuthenticator(t, testRPID, testOrigin)

	cc, session, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.NoError(t, err)
	require.NotNil(t, cc)

	cred, err := svc.FinishRegistration(ctx, "", userID, "user@example.com", "User", *session,
		auth.registrationRequest(t, session.Challenge))
	require.NoError(t, err)
	require.Equal(t, auth.credID, cred.ID)
	return auth
}

func TestBeginDiscoverableLogin_NoAllowCredentials(t *testing.T) {
	svc := newPasskeyService(t)

	assertion, session, err := svc.BeginDiscoverableLogin()
	require.NoError(t, err)
	require.NotNil(t, assertion)
	// Usernameless: the RP must not restrict to specific credentials, and no user is bound yet.
	assert.Empty(t, assertion.Response.AllowedCredentials, "discoverable login must not list credentials")
	assert.NotEmpty(t, session.Challenge)
	assert.Empty(t, session.UserID, "no user is known at the start of a discoverable login")
}

func TestFinishDiscoverableLogin_ResolvesUserFromUserHandle(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)

	userID := uuid.New()
	auth := register(t, svc, userID)

	// Usernameless login: the service is given no userID up front.
	_, session, err := svc.BeginDiscoverableLogin()
	require.NoError(t, err)

	cred, resolvedID, err := svc.FinishDiscoverableLogin(ctx, "", *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
	require.NoError(t, err)
	assert.Equal(t, userID, resolvedID, "the user must be resolved from the credential's user handle")
	assert.Equal(t, auth.credID, cred.ID)
	// The signature counter advanced and was persisted.
	assert.Equal(t, uint32(1), cred.SignCount)
}

func TestFinishDiscoverableLogin_UnknownUserHandleRejected(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)

	userID := uuid.New()
	auth := register(t, svc, userID)

	_, session, err := svc.BeginDiscoverableLogin()
	require.NoError(t, err)

	// Present a user handle for an account with no credentials: verification must fail.
	_, _, err = svc.FinishDiscoverableLogin(ctx, "", *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(uuid.New())))
	require.Error(t, err)
}
