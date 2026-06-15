package passkeytest_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/passkey/passkeytest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRPID   = "localhost"
	testOrigin = "http://localhost"
)

// newTestService builds a passkey.Service configured for localhost testing.
// The challenge store is in-memory; no network is required.
func newTestService(t *testing.T) *passkey.Service {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	svc, err := passkey.NewService(memory.NewStore(), passkey.Config{
		RPID:                     testRPID,
		RPDisplayName:            "Test",
		RPOrigins:                []string{testOrigin},
		CookieKey:                key,
		ChallengeStore:           memory.NewChallengeStore(),
		InsecureNoChallengeStore: false,
	})
	require.NoError(t, err)
	return svc
}

// TestSoftAuthenticator_RegistrationAndLogin is the canonical self-test for
// passkeytest.SoftAuthenticator: it drives a full registration ceremony followed
// by a login ceremony against a real passkey.Service backed by in-memory stores.
// No network calls are made.
func TestSoftAuthenticator_RegistrationAndLogin(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)
	userID := uuid.Must(uuid.NewV7())
	const tenant = ""

	auth := passkeytest.NewSoftAuthenticator(t, testRPID, testOrigin)

	// --- Registration ---
	cc, session, err := svc.BeginRegistration(ctx, tenant, userID, "alice@example.com", "Alice")
	require.NoError(t, err, "BeginRegistration must succeed")
	require.NotNil(t, cc)

	cred, err := svc.FinishRegistration(ctx, tenant, userID, "alice@example.com", "Alice",
		*session, auth.RegistrationRequest(t, session.Challenge))
	require.NoError(t, err, "FinishRegistration must accept SoftAuthenticator response")
	assert.Equal(t, auth.CredentialID, cred.ID, "credential ID must match")
	assert.NotEmpty(t, cred.PublicKey, "public key must be stored")
	assert.Equal(t, uint32(0), cred.SignCount, "fresh credential starts at counter 0")

	// Confirm the credential is retrievable.
	creds, err := svc.ListCredentials(ctx, tenant, userID)
	require.NoError(t, err)
	require.Len(t, creds, 1, "exactly one credential must be stored")

	// --- Login ---
	ca, session2, err := svc.BeginLogin(ctx, tenant, userID)
	require.NoError(t, err, "BeginLogin must succeed")
	require.NotNil(t, ca)

	loginCred, err := svc.FinishLogin(ctx, tenant, userID,
		*session2, auth.LoginRequest(t, session2.Challenge, passkeytest.UserHandleOf(userID)))
	require.NoError(t, err, "FinishLogin must accept SoftAuthenticator assertion")
	assert.Equal(t, auth.CredentialID, loginCred.ID)
	assert.Equal(t, uint32(1), loginCred.SignCount, "sign counter must advance to 1 on first login")
}

// TestSoftAuthenticator_MultipleLogins verifies that successive LoginRequest calls
// correctly increment the sign counter, which is required for clone detection.
func TestSoftAuthenticator_MultipleLogins(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)
	userID := uuid.Must(uuid.NewV7())
	const tenant = ""

	auth := passkeytest.NewSoftAuthenticator(t, testRPID, testOrigin)

	// Register once.
	cc, session, err := svc.BeginRegistration(ctx, tenant, userID, "bob@example.com", "Bob")
	require.NoError(t, err)
	require.NotNil(t, cc)
	_, err = svc.FinishRegistration(ctx, tenant, userID, "bob@example.com", "Bob",
		*session, auth.RegistrationRequest(t, session.Challenge))
	require.NoError(t, err)

	// First login.
	ca, s, err := svc.BeginLogin(ctx, tenant, userID)
	require.NoError(t, err)
	require.NotNil(t, ca)
	c1, err := svc.FinishLogin(ctx, tenant, userID, *s,
		auth.LoginRequest(t, s.Challenge, passkeytest.UserHandleOf(userID)))
	require.NoError(t, err)
	assert.Equal(t, uint32(1), c1.SignCount)

	// Second login — counter must be 2.
	ca2, s2, err := svc.BeginLogin(ctx, tenant, userID)
	require.NoError(t, err)
	require.NotNil(t, ca2)
	c2, err := svc.FinishLogin(ctx, tenant, userID, *s2,
		auth.LoginRequest(t, s2.Challenge, passkeytest.UserHandleOf(userID)))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), c2.SignCount)
}

// TestSoftAuthenticator_BackupFlags verifies RegistrationRequestWithFlags can set
// backup-eligible (FlagBE) and backup-state (FlagBS) bits that are stored on the credential.
func TestSoftAuthenticator_BackupFlags(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)
	userID := uuid.Must(uuid.NewV7())
	const tenant = ""

	auth := passkeytest.NewSoftAuthenticator(t, testRPID, testOrigin)

	cc, session, err := svc.BeginRegistration(ctx, tenant, userID, "charlie@example.com", "Charlie")
	require.NoError(t, err)
	require.NotNil(t, cc)

	flags := passkeytest.FlagUP | passkeytest.FlagUV | passkeytest.FlagAT | passkeytest.FlagBE | passkeytest.FlagBS
	cred, err := svc.FinishRegistration(ctx, tenant, userID, "charlie@example.com", "Charlie",
		*session, auth.RegistrationRequestWithFlags(t, session.Challenge, flags))
	require.NoError(t, err)
	assert.True(t, cred.BackupEligible, "BackupEligible must be set when FlagBE is present")
	assert.True(t, cred.BackupState, "BackupState must be set when FlagBS is present")
}
