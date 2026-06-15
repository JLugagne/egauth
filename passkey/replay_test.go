// Tests for SEC-05: passkey login replay protection via an optional ChallengeStore.
package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// challengeFromAssertion extracts publicKey.challenge from a BeginLogin JSON response.
func challengeFromAssertion(t *testing.T, raw []byte) string {
	t.Helper()
	var resp struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(raw, &resp))
	require.NotEmpty(t, resp.PublicKey.Challenge, "begin response must carry a challenge")
	return resp.PublicKey.Challenge
}

// registerTenant enrolls a fresh credential for userID under the given tenant and returns the
// backing authenticator. The replay handler tests resolve tenant "t1" (see resolver), so the
// credential must be registered under the same tenant for BeginLogin to offer it.
func registerTenant(t *testing.T, svc *passkey.Service, tenant string, userID uuid.UUID) *softAuthenticator {
	t.Helper()
	ctx := context.Background()
	auth := newSoftAuthenticator(t, testRPID, testOrigin)

	_, session, err := svc.BeginRegistration(ctx, tenant, userID, "user@example.com", "User")
	require.NoError(t, err)

	cred, err := svc.FinishRegistration(ctx, tenant, userID, "user@example.com", "User", *session,
		auth.registrationRequest(t, session.Challenge))
	require.NoError(t, err)
	require.Equal(t, auth.credID, cred.ID)
	return auth
}

// drainBody reads and returns the full body of a request (so it can be replayed verbatim).
func drainBody(t *testing.T, req *http.Request) []byte {
	t.Helper()
	b, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	return b
}

// beginLoginAndCaptureFinish runs Begin through the handler and returns the ceremony cookie
// plus the exact Finish body bytes. The soft authenticator is driven at sign-count 0/0 so the
// clone-counter check is a no-op (0 is not greater than 0) — the precise condition SEC-05
// exploits.
func beginLoginAndCaptureFinish(t *testing.T, svc *passkey.Service, uid uuid.UUID, auth *softAuthenticator, opts ...passkey.HandlerOption) (cookie *http.Cookie, body []byte) {
	t.Helper()

	beginRec := httptest.NewRecorder()
	passkey.BeginLoginHandler(svc, opts...)(beginRec, httptest.NewRequest(http.MethodPost, "/login/begin", nil))
	require.Equal(t, http.StatusOK, beginRec.Code, "begin login should succeed")

	cookie = findCookie(beginRec.Result().Cookies(), passkey.DefaultSessionCookieName)
	require.NotNil(t, cookie, "begin must set the ceremony cookie")

	challenge := challengeFromAssertion(t, beginRec.Body.Bytes())

	assertReq := auth.assertionAtCount(t, challenge, userHandleOf(uid), 0)
	body = drainBody(t, assertReq)
	return cookie, body
}

// cookieOnlyService builds a passkey Service that deliberately opts out of the (now default)
// challenge store, so the only replay defense is the single-use ceremony cookie. It is used to
// document the cookie-only behavior; a default-configured Service requires a ChallengeStore.
func cookieOnlyService(t *testing.T) *passkey.Service {
	t.Helper()
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:                     testRPID,
		RPDisplayName:            testRPName,
		RPOrigins:                []string{testOrigin},
		CookieKey:                testCookieKey,
		InsecureNoChallengeStore: true,
	})
	require.NoError(t, err)
	return svc
}

// TestFinishLogin_Replay_BlockedWithChallengeStore proves SEC-05 is fixed when a
// ChallengeStore is wired: the first Finish succeeds, an identical replayed Finish fails.
func TestFinishLogin_Replay_BlockedWithChallengeStore(t *testing.T) {
	svc := newPasskeyService(t)
	uid := uuid.Must(uuid.NewV7())
	auth := registerTenant(t, svc, "t1", uid)

	cs := passkeymemory.NewChallengeStore()
	opts := []passkey.HandlerOption{
		resolver(uid),
		passkey.WithCookieKey(testCookieKey),
		passkey.WithChallengeStore(cs),
	}

	cookie, body := beginLoginAndCaptureFinish(t, svc, uid, auth, opts...)

	// First Finish: succeeds.
	req1 := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req1.AddCookie(cookie)
	rec1 := httptest.NewRecorder()
	passkey.FinishLoginHandler(svc, opts...)(rec1, req1)
	require.Equal(t, http.StatusNoContent, rec1.Code, "first finish must succeed")

	// Replay the IDENTICAL request (same cookie + same body bytes).
	req2 := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	passkey.FinishLoginHandler(svc, opts...)(rec2, req2)
	assert.Equal(t, http.StatusBadRequest, rec2.Code,
		"a replayed finish must be rejected once the challenge is consumed")
}

// TestFinishLogin_Replay_UnchangedWithoutChallengeStore documents the cookie-only opt-out: a
// Service built with InsecureNoChallengeStore has no server-side single-use consume, so a
// sign-count-0 replay still succeeds. This is why a ChallengeStore is now required by default.
func TestFinishLogin_Replay_UnchangedWithoutChallengeStore(t *testing.T) {
	svc := cookieOnlyService(t)
	uid := uuid.Must(uuid.NewV7())
	auth := registerTenant(t, svc, "t1", uid)

	opts := []passkey.HandlerOption{
		resolver(uid),
		passkey.WithCookieKey(testCookieKey),
	}

	cookie, body := beginLoginAndCaptureFinish(t, svc, uid, auth, opts...)

	req1 := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req1.AddCookie(cookie)
	rec1 := httptest.NewRecorder()
	passkey.FinishLoginHandler(svc, opts...)(rec1, req1)
	require.Equal(t, http.StatusNoContent, rec1.Code, "first finish must succeed")

	// Replay: without a ChallengeStore wired, the sign-count-0 replay still passes.
	req2 := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	passkey.FinishLoginHandler(svc, opts...)(rec2, req2)
	assert.Equal(t, http.StatusNoContent, rec2.Code,
		"without a ChallengeStore the replay is NOT blocked (opt-in gap)")
}
