package passkey_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passkeyHandlers returns every state-changing passkey handler under test, so the CSRF
// expectations are asserted uniformly across the whole family (mfa/SF-9, http/SF-9, http/HTTP-7).
func passkeyHandlers(t *testing.T, extra ...passkey.HandlerOption) map[string]http.HandlerFunc {
	t.Helper()
	svc, store := testService(t)
	uid := uuid.Must(uuid.NewV7())
	saveTestCredential(t, store, uid, []byte{0x01, 0x02})

	opts := append([]passkey.HandlerOption{resolver(uid), passkey.WithCookieKey(testCookieKey)}, extra...)
	return map[string]http.HandlerFunc{
		"BeginRegistration":       passkey.BeginRegistrationHandler(svc, opts...),
		"FinishRegistration":      passkey.FinishRegistrationHandler(svc, opts...),
		"BeginLogin":              passkey.BeginLoginHandler(svc, opts...),
		"FinishLogin":             passkey.FinishLoginHandler(svc, opts...),
		"BeginDiscoverableLogin":  passkey.BeginDiscoverableLoginHandler(svc, opts...),
		"FinishDiscoverableLogin": passkey.FinishDiscoverableLoginHandler(svc, opts...),
		"RenameCredential":        passkey.RenameCredentialHandler(svc, opts...),
	}
}

func TestPasskeyHandlers_RejectCrossOriginPost(t *testing.T) {
	for name, h := range passkeyHandlers(t) {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/passkey", strings.NewReader(`{}`))
			req.Header.Set("Origin", "https://evil.example.com")
			rec := httptest.NewRecorder()
			h(rec, req)
			assert.Equal(t, http.StatusForbidden, rec.Code,
				"a cross-origin POST must be refused before any state change")
			assert.Contains(t, rec.Body.String(), "cross_site_blocked")
		})
	}
}

func TestPasskeyHandlers_RejectMissingOrigin(t *testing.T) {
	for name, h := range passkeyHandlers(t) {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/passkey", strings.NewReader(`{}`))
			rec := httptest.NewRecorder()
			h(rec, req)
			assert.Equal(t, http.StatusForbidden, rec.Code,
				"a POST asserting no Origin must be treated as untrusted")
		})
	}
}

func TestPasskeyHandlers_AllowSameOrigin(t *testing.T) {
	for name, h := range passkeyHandlers(t) {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/passkey", strings.NewReader(`{}`))
			req.Header.Set("Origin", "https://"+req.Host)
			rec := httptest.NewRecorder()
			h(rec, req)
			assert.NotEqual(t, http.StatusForbidden, rec.Code,
				"a same-origin POST must pass the CSRF check")
		})
	}
}

func TestPasskeyHandlers_WithTrustedOrigins(t *testing.T) {
	for name, h := range passkeyHandlers(t, passkey.WithTrustedOrigins("app.example.com")) {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/passkey", strings.NewReader(`{}`))
			req.Header.Set("Origin", "https://app.example.com")
			rec := httptest.NewRecorder()
			h(rec, req)
			assert.NotEqual(t, http.StatusForbidden, rec.Code,
				"an explicitly trusted origin must be allowed")
		})
	}
}

func TestPasskeyHandlers_WithInsecureNoOriginCheck(t *testing.T) {
	for name, h := range passkeyHandlers(t, passkey.WithInsecureNoOriginCheck()) {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/passkey", strings.NewReader(`{}`))
			req.Header.Set("Origin", "https://evil.example.com")
			rec := httptest.NewRecorder()
			h(rec, req)
			assert.NotEqual(t, http.StatusForbidden, rec.Code,
				"the loud opt-out must restore accept-all behavior")
		})
	}
}

// TestRenameCredentialHandler_CSRFReachable is the focused regression for http/HTTP-7: the
// state-changing rename endpoint must not act on a cross-site POST.
func TestRenameCredentialHandler_CSRFReachable(t *testing.T) {
	svc, store := testService(t)
	uid := uuid.Must(uuid.NewV7())
	saveTestCredential(t, store, uid, []byte{0x0a, 0x0b})

	h := passkey.RenameCredentialHandler(svc, resolver(uid), passkey.WithCookieKey(testCookieKey))
	req := httptest.NewRequest(http.MethodPost, "/passkey/rename", strings.NewReader(`{"credentialId":"Cgs","nickname":"attacker"}`))
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code, "a cross-site rename must be refused")
	creds, err := svc.ListCredentials(req.Context(), "t1", uid)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Empty(t, creds[0].Nickname, "a refused cross-site rename must not have mutated the credential")
}
