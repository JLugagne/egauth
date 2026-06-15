package passkey_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFinishRegistration_StoresCredential(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())

	auth := register(t, svc, userID)

	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1, "the verified credential must be persisted")
	assert.Equal(t, auth.credID, creds[0].ID)
	assert.NotEmpty(t, creds[0].PublicKey, "the public key must be stored")
	assert.Equal(t, uint32(0), creds[0].SignCount, "fresh credential starts at counter 0")
}

func TestFinishLogin_VerifiesAssertionAndAdvancesCounter(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)

	cred, err := svc.FinishLogin(ctx, "", userID, *session,
		auth.loginRequest(t, session.Challenge, nil))
	require.NoError(t, err)
	assert.Equal(t, auth.credID, cred.ID)
	assert.Equal(t, uint32(1), cred.SignCount, "the signature counter advanced")

	// Persisted: the stored credential reflects the new counter.
	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), creds[0].SignCount)
}

func TestFinishLogin_SignCountPersistsAcrossLogins(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	for want := uint32(1); want <= 3; want++ {
		_, session, err := svc.BeginLogin(ctx, "", userID)
		require.NoError(t, err)
		cred, err := svc.FinishLogin(ctx, "", userID, *session, auth.loginRequest(t, session.Challenge, nil))
		require.NoError(t, err)
		assert.Equal(t, want, cred.SignCount, "counter must advance and persist each login")
	}
}

func TestFinishLogin_CloneDetection(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	// One legitimate login moves the stored counter to 1.
	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	_, err = svc.FinishLogin(ctx, "", userID, *session, auth.loginRequest(t, session.Challenge, nil))
	require.NoError(t, err)

	// A second authenticator (clone) asserts with a NON-advancing counter (<= stored). WebAuthn
	// clone detection must reject it.
	_, session2, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	_, err = svc.FinishLogin(ctx, "", userID, *session2, auth.assertionAtCount(t, session2.Challenge, nil, 1))
	require.ErrorIs(t, err, passkey.ErrCredentialCloned, "a regressed signature counter must be flagged as a clone")
}

func TestFinishLogin_WrongChallengeRejected(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)

	// Sign over a challenge that does not match the ceremony session.
	_, err = svc.FinishLogin(ctx, "", userID, *session, auth.loginRequest(t, "Zm9yZ2VkLWNoYWxsZW5nZQ", nil))
	require.Error(t, err, "an assertion bound to a different challenge must be rejected")
}
