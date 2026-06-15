package passkey_test

// Regression tests for TASK-064: discoverable (usernameless) login had no challenge-store
// replay protection — BeginDiscoverableLogin never Put the challenge, and FinishDiscoverableLogin
// never consumed it, so a captured Finish request could be replayed within the cookie TTL for
// a sign-count-0 authenticator (e.g. iCloud Keychain) without triggering the clone-counter check.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// beginDiscoverableAndCaptureFinish runs BeginDiscoverableLoginHandler through the HTTP handler
// and returns the ceremony cookie plus the exact Finish body bytes (signed at sign-count 0 so
// the clone-counter check is a no-op — the exact condition the bug exploits).
func beginDiscoverableAndCaptureFinish(t *testing.T, svc *passkey.Service, uid uuid.UUID, auth *softAuthenticator, opts ...passkey.HandlerOption) (cookie *http.Cookie, body []byte) {
	t.Helper()

	beginRec := httptest.NewRecorder()
	passkey.BeginDiscoverableLoginHandler(svc, opts...)(beginRec, httptest.NewRequest(http.MethodPost, "/discoverable/begin", nil))
	require.Equal(t, http.StatusOK, beginRec.Code, "BeginDiscoverableLoginHandler should succeed")

	cookie = findCookie(beginRec.Result().Cookies(), passkey.DefaultSessionCookieName)
	require.NotNil(t, cookie, "begin must set the ceremony cookie")

	challenge := challengeFromAssertion(t, beginRec.Body.Bytes())

	assertReq := auth.assertionAtCount(t, challenge, userHandleOf(uid), 0)
	b, err := io.ReadAll(assertReq.Body)
	require.NoError(t, err)
	return cookie, b
}

// TestDiscoverableLogin_Replay_BlockedWithChallengeStore proves the fix: the first
// FinishDiscoverableLoginHandler call succeeds, an identical replayed call (same cookie +
// same body bytes) must be rejected with 400 once the challenge has been consumed.
func TestDiscoverableLogin_Replay_BlockedWithChallengeStore(t *testing.T) {
	svc := newPasskeyService(t)
	uid := uuid.Must(uuid.NewV7())
	// Register under tenant "t1" so the user handle resolves correctly during discoverable login.
	auth := registerTenant(t, svc, "t1", uid)

	opts := []passkey.HandlerOption{
		passkey.WithLoginSuccess(func(w http.ResponseWriter, _ *http.Request, _ uuid.UUID) {
			w.WriteHeader(http.StatusNoContent)
		}),
		// discoverable login resolves the tenant from the request, not a user resolver; supply
		// tenant "t1" via the tenant extractor option.
		passkey.WithDiscoverableTenant(func(*http.Request) string { return "t1" }),
		passkey.WithCookieKey(testCookieKey),
	}

	cookie, body := beginDiscoverableAndCaptureFinish(t, svc, uid, auth, opts...)

	// First Finish: must succeed.
	req1 := httptest.NewRequest(http.MethodPost, "/discoverable/finish", bytes.NewReader(body))
	req1.AddCookie(cookie)
	rec1 := httptest.NewRecorder()
	passkey.FinishDiscoverableLoginHandler(svc, opts...)(rec1, req1)
	require.Equal(t, http.StatusNoContent, rec1.Code, "first discoverable finish must succeed")

	// Replay the IDENTICAL request (same cookie + same body bytes).
	req2 := httptest.NewRequest(http.MethodPost, "/discoverable/finish", bytes.NewReader(body))
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	passkey.FinishDiscoverableLoginHandler(svc, opts...)(rec2, req2)
	assert.Equal(t, http.StatusBadRequest, rec2.Code,
		"a replayed discoverable finish must be rejected once the challenge is consumed")
}
