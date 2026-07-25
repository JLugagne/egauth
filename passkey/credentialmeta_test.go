package passkey_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK-011 — registration captures transports + backup-eligible/backup-state flags.
func TestFinishRegistration_CapturesTransportsAndBackupFlags(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := newSoftAuthenticator(t, testRPID, testOrigin)
	auth.transports = []string{"internal", "hybrid"}

	_, session, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.NoError(t, err)

	// Register a synced (backup-eligible + backed-up) passkey.
	_, err = svc.FinishRegistration(ctx, "", userID, "user@example.com", "User", *session,
		auth.registrationRequestWithFlags(t, session.Challenge, flagUP|flagUV|flagAT|flagBE|flagBS))
	require.NoError(t, err)

	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, []string{"internal", "hybrid"}, creds[0].Transports,
		"transports from the attestation response must be captured at registration")
	assert.True(t, creds[0].BackupEligible, "the BE flag must be captured at registration")
	assert.True(t, creds[0].BackupState, "the BS flag must be captured at registration")
}

// TASK-011 — a single-device passkey (no backup flags) records both flags false.
func TestFinishRegistration_SingleDevicePasskeyHasNoBackupFlags(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := newSoftAuthenticator(t, testRPID, testOrigin)

	_, session, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.NoError(t, err)
	_, err = svc.FinishRegistration(ctx, "", userID, "user@example.com", "User", *session,
		auth.registrationRequestWithFlags(t, session.Challenge, flagUP|flagUV|flagAT))
	require.NoError(t, err)

	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.False(t, creds[0].BackupEligible)
	assert.False(t, creds[0].BackupState)
}

// TASK-011 — a successful login stamps LastUsedAt on the stored credential.
func TestFinishLogin_SetsLastUsedAt(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	before := time.Now().UTC()

	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.Nil(t, creds[0].LastUsedAt, "a freshly registered credential has never been used")

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	_, err = svc.FinishLogin(ctx, "", userID, *session, auth.loginRequest(t, session.Challenge, nil))
	require.NoError(t, err)

	creds, err = svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.NotNil(t, creds[0].LastUsedAt, "login must stamp LastUsedAt")
	assert.False(t, creds[0].LastUsedAt.Before(before), "LastUsedAt must be at or after the login time")
}

// TASK-011 — login must NOT wipe the registration-time transports or a user-set nickname, since
// the assertion response carries neither and UpdateCredential is a full-record replace.
func TestFinishLogin_PreservesTransportsAndNickname(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.NotEmpty(t, creds[0].Transports)
	wantTransports := creds[0].Transports

	require.NoError(t, svc.RenameCredential(ctx, "", userID, creds[0].ID, "My phone"))

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	_, err = svc.FinishLogin(ctx, "", userID, *session, auth.loginRequest(t, session.Challenge, nil))
	require.NoError(t, err)

	creds, err = svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, wantTransports, creds[0].Transports, "login must preserve registration-time transports")
	assert.Equal(t, "My phone", creds[0].Nickname, "login must preserve a user-set nickname")
}

// TASK-011 — discoverable login also stamps LastUsedAt.
func TestFinishDiscoverableLogin_SetsLastUsedAt(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginDiscoverableLogin()
	require.NoError(t, err)
	_, _, err = svc.FinishDiscoverableLogin(ctx, "", *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
	require.NoError(t, err)

	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.NotNil(t, creds[0].LastUsedAt, "discoverable login must stamp LastUsedAt")
}

// TASK-012 — RenameCredential sets the nickname and ListCredentials reflects it.
func TestRenameCredential_SetsNickname(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	register(t, svc, userID)

	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.Empty(t, creds[0].Nickname)

	require.NoError(t, svc.RenameCredential(ctx, "", userID, creds[0].ID, "Work laptop"))

	creds, err = svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "Work laptop", creds[0].Nickname)
}

// TASK-012 — renaming an unknown credential returns ErrCredentialNotFound.
func TestRenameCredential_UnknownCredential(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	register(t, svc, userID)

	err := svc.RenameCredential(ctx, "", userID, []byte{0xde, 0xad}, "nope")
	assert.ErrorIs(t, err, passkey.ErrCredentialNotFound)
}

// TASK-012 — ListCredentials surfaces the full management metadata set.
func TestListCredentials_SurfacesMetadata(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	auth := newSoftAuthenticator(t, testRPID, testOrigin)
	auth.transports = []string{"usb"}

	_, session, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.NoError(t, err)
	_, err = svc.FinishRegistration(ctx, "", userID, "user@example.com", "User", *session,
		auth.registrationRequestWithFlags(t, session.Challenge, flagUP|flagUV|flagAT|flagBE))
	require.NoError(t, err)

	require.NoError(t, svc.RenameCredential(ctx, "", userID, auth.credID, "Yubikey"))

	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "Yubikey", creds[0].Nickname)
	assert.Equal(t, []string{"usb"}, creds[0].Transports)
	assert.True(t, creds[0].BackupEligible)
	assert.False(t, creds[0].BackupState)
	assert.False(t, creds[0].CreatedAt.IsZero())
}

// TASK-012 — the rename HTTP handler persists the nickname end-to-end.
func TestRenameCredentialHandler_PersistsNickname(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())
	register(t, svc, userID)

	creds, err := svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)

	h := passkey.RenameCredentialHandler(svc,
		passkey.WithUserResolver(func(*http.Request) (uuid.UUID, string, string, string, bool) {
			return userID, "", "", "", true
		}))

	body := map[string]any{
		"credentialId": base64.RawURLEncoding.EncodeToString(creds[0].ID),
		"nickname":     "Phone via handler",
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	req := postReq("/passkey/credentials/rename", bytes.NewReader(raw))
	h(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)

	creds, err = svc.ListCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "Phone via handler", creds[0].Nickname)
}

// TASK-012 — the rename handler enforces POST-only and the auth resolver.
func TestRenameCredentialHandler_Guards(t *testing.T) {
	svc := newPasskeyService(t)

	t.Run("no resolver -> 401", func(t *testing.T) {
		rec := httptest.NewRecorder()
		passkey.RenameCredentialHandler(svc)(rec, postReq("/", nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("GET -> 405", func(t *testing.T) {
		h := passkey.RenameCredentialHandler(svc,
			passkey.WithUserResolver(func(*http.Request) (uuid.UUID, string, string, string, bool) {
				return uuid.Must(uuid.NewV7()), "", "", "", true
			}))
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}

// TASK-014 — after registering 2 credentials and deleting 1, SignalAllAcceptedCredentials returns
// only the surviving credential id, with the correct rpId and user handle.
func TestSignalAllAcceptedCredentials_ReturnsSurvivors(t *testing.T) {
	ctx := context.Background()
	svc := newPasskeyService(t)
	userID := uuid.Must(uuid.NewV7())

	auth1 := register(t, svc, userID)
	auth2 := register(t, svc, userID) // a second, distinct credential for the same user

	require.NoError(t, svc.DeleteCredential(ctx, "", userID, auth1.credID))

	report, err := svc.SignalAllAcceptedCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, testRPID, report.RPID)
	assert.Equal(t, userHandleOf(userID), []byte(report.UserID), "userId must be the WebAuthn user handle (uuid bytes)")
	require.Len(t, report.AllAcceptedCredentialIDs, 1, "only the surviving credential id must remain")
	assert.Equal(t, auth2.credID, []byte(report.AllAcceptedCredentialIDs[0]))

	// The report marshals to spec-conformant base64url JSON.
	out, err := json.Marshal(report)
	require.NoError(t, err)
	assert.Contains(t, string(out), "allAcceptedCredentialIds")
	assert.Contains(t, string(out), "rpId")
	assert.Contains(t, string(out), "userId")
}

// TASK-014 — SignalUnknownCredential carries the rpId and the credential id.
func TestSignalUnknownCredential_Shape(t *testing.T) {
	svc := newPasskeyService(t)
	credID := []byte{0x01, 0x02, 0x03}

	report := svc.SignalUnknownCredential(credID)
	require.NotNil(t, report)
	assert.Equal(t, testRPID, report.RPID)
	assert.Equal(t, credID, []byte(report.CredentialID))

	out, err := json.Marshal(report)
	require.NoError(t, err)
	assert.Contains(t, string(out), "credentialId")
	assert.Contains(t, string(out), "rpId")
}
