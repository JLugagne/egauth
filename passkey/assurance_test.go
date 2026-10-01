// Regression tests for F-COMP-001: credential enrollment must not accept an interim
// (pre-MFA) session. The registration handlers fail closed by default — no assurance gate
// means 403 assurance_required — and an explicit gate decides per request. The explicit
// WithInsecureNoAssuranceCheck opt-out preserves the old behavior for apps without a second
// factor.
package passkey_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestRegistrationHandlers_FailClosedWithoutAssurance is the default-composition invariant:
// with neither a gate nor an opt-out, Begin and Finish refuse before doing any work.
func TestRegistrationHandlers_FailClosedWithoutAssurance(t *testing.T) {
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())

	for name, h := range map[string]http.HandlerFunc{
		"begin":  passkey.BeginRegistrationHandler(svc, resolver(uid), passkey.WithCookieKey(testCookieKey)),
		"finish": passkey.FinishRegistrationHandler(svc, resolver(uid), passkey.WithCookieKey(testCookieKey)),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodPost, "/", nil))
			require.Equal(t, http.StatusForbidden, rec.Code,
				"an un-gated registration handler must fail closed")
			require.Contains(t, rec.Body.String(), "assurance_required")
			require.Nil(t, findCookie(rec.Result().Cookies(), passkey.DefaultSessionCookieName))
		})
	}
}

// TestRegistrationHandlers_DenyingGateRefused proves a wired gate is authoritative: when it
// reports an interim session, both halves refuse with 403 and mint nothing.
func TestRegistrationHandlers_DenyingGateRefused(t *testing.T) {
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())
	deny := func(*http.Request) error { return errors.New("interim session") }
	opts := []passkey.HandlerOption{
		resolver(uid), passkey.WithCookieKey(testCookieKey), passkey.WithCredentialAssurance(deny),
	}

	beginRec := httptest.NewRecorder()
	passkey.BeginRegistrationHandler(svc, opts...)(beginRec, httptest.NewRequest(http.MethodPost, "/", nil))
	require.Equal(t, http.StatusForbidden, beginRec.Code)
	require.Contains(t, beginRec.Body.String(), "assurance_required")
	require.Nil(t, findCookie(beginRec.Result().Cookies(), passkey.DefaultSessionCookieName))

	finishRec := httptest.NewRecorder()
	passkey.FinishRegistrationHandler(svc, opts...)(finishRec, httptest.NewRequest(http.MethodPost, "/", nil))
	require.Equal(t, http.StatusForbidden, finishRec.Code)
	require.Contains(t, finishRec.Body.String(), "assurance_required")
}

// TestRegistrationHandlers_PermissiveGateProceeds proves a gate that allows the session does
// not break the ceremony.
func TestRegistrationHandlers_PermissiveGateProceeds(t *testing.T) {
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())
	opts := []passkey.HandlerOption{
		resolver(uid), passkey.WithCookieKey(testCookieKey),
		passkey.WithCredentialAssurance(func(*http.Request) error { return nil }),
	}

	beginRec := httptest.NewRecorder()
	passkey.BeginRegistrationHandler(svc, opts...)(beginRec, httptest.NewRequest(http.MethodPost, "/", nil))
	require.Equal(t, http.StatusOK, beginRec.Code)
	cookie := findCookie(beginRec.Result().Cookies(), passkey.DefaultSessionCookieName)
	require.NotNil(t, cookie)
	challenge := challengeFromAssertion(t, beginRec.Body.Bytes())

	auth := newSoftAuthenticator(t, testRPID, testOrigin)
	finishReq := auth.registrationRequest(t, challenge)
	finishReq.AddCookie(cookie)
	finishRec := httptest.NewRecorder()
	passkey.FinishRegistrationHandler(svc, opts...)(finishRec, finishReq)
	require.Equal(t, http.StatusNoContent, finishRec.Code)
}

// TestRegistrationHandlers_InsecureNoAssuranceCheckProceeds pins the documented opt-out: an
// application without a second factor keeps the old behavior by opting out explicitly.
func TestRegistrationHandlers_InsecureNoAssuranceCheckProceeds(t *testing.T) {
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())
	opts := []passkey.HandlerOption{
		resolver(uid), passkey.WithCookieKey(testCookieKey), passkey.WithInsecureNoAssuranceCheck(),
	}

	beginRec := httptest.NewRecorder()
	passkey.BeginRegistrationHandler(svc, opts...)(beginRec, httptest.NewRequest(http.MethodPost, "/", nil))
	require.Equal(t, http.StatusOK, beginRec.Code)
}

// TestRegistrationHandlers_DeniedFinishDoesNotBurnChallenge proves the gate runs before the
// challenge is consumed: a refused Finish leaves the ceremony finishable once assurance is
// satisfied, instead of silently invalidating the client's in-flight ceremony.
func TestRegistrationHandlers_DeniedFinishDoesNotBurnChallenge(t *testing.T) {
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())
	allow := []passkey.HandlerOption{
		resolver(uid), passkey.WithCookieKey(testCookieKey),
		passkey.WithCredentialAssurance(func(*http.Request) error { return nil }),
	}

	beginRec := httptest.NewRecorder()
	passkey.BeginRegistrationHandler(svc, allow...)(beginRec, httptest.NewRequest(http.MethodPost, "/", nil))
	require.Equal(t, http.StatusOK, beginRec.Code)
	cookie := findCookie(beginRec.Result().Cookies(), passkey.DefaultSessionCookieName)
	require.NotNil(t, cookie)
	challenge := challengeFromAssertion(t, beginRec.Body.Bytes())

	auth := newSoftAuthenticator(t, testRPID, testOrigin)
	body := drainBody(t, auth.registrationRequest(t, challenge))

	deny := []passkey.HandlerOption{
		resolver(uid), passkey.WithCookieKey(testCookieKey),
		passkey.WithCredentialAssurance(func(*http.Request) error { return errors.New("interim session") }),
	}
	deniedReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	deniedReq.AddCookie(cookie)
	deniedRec := httptest.NewRecorder()
	passkey.FinishRegistrationHandler(svc, deny...)(deniedRec, deniedReq)
	require.Equal(t, http.StatusForbidden, deniedRec.Code)

	// The same challenge is still consumable by an allowed Finish.
	allowReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	allowReq.AddCookie(cookie)
	allowRec := httptest.NewRecorder()
	passkey.FinishRegistrationHandler(svc, allow...)(allowRec, allowReq)
	require.Equal(t, http.StatusNoContent, allowRec.Code,
		"a denied Finish must not consume the ceremony challenge")
}

// TestRegistrationHandlers_CanonicalDenyInterimGate proves the canonical gate value
// (tokens.DenyInterim) is structurally accepted by WithCredentialAssurance and allows a
// request that carries no interim token context.
func TestRegistrationHandlers_CanonicalDenyInterimGate(t *testing.T) {
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())
	opts := []passkey.HandlerOption{
		resolver(uid), passkey.WithCookieKey(testCookieKey),
		passkey.WithCredentialAssurance(tokens.DenyInterim),
	}

	rec := httptest.NewRecorder()
	passkey.BeginRegistrationHandler(svc, opts...)(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	require.Equal(t, http.StatusOK, rec.Code,
		"a request without an interim context must pass the canonical gate")
}
