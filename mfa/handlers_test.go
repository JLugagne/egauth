package mfa_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// steppedUp supplies the assurance of a session that has completed a second factor, which the
// factor-mutating handlers (DisableHandler, RegenerateRecoveryCodesHandler) require. Production
// wiring gets it from tokens.AssuranceResolverFromContext by mounting the handler behind
// tokens.ContextMiddleware.
var steppedUp = mfa.WithAssuranceResolver(func(*http.Request) (tokens.Assurance, bool) {
	return tokens.Assurance{StepUp: true}, true
})

func mfaPost(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Same-origin by default so business-logic tests pass the strict-by-default CSRF check
	// (httptest.NewRequest sets Host to "example.com"). CSRF tests override this header to
	// exercise the cross-origin path explicitly.
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

func TestHandlers_FullFlow(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	// Enroll → JSON secret + uri.
	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver)(rec, mfaPost(url.Values{"account": {"user@example.com"}}))
	require.Equal(t, http.StatusOK, rec.Code)
	var enroll struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &enroll))
	require.NotEmpty(t, enroll.Secret)
	assert.Contains(t, enroll.URI, "otpauth://totp/")

	// Confirm with a valid code → JSON recovery codes.
	code := clk.code(t, enroll.Secret)
	rec = httptest.NewRecorder()
	mfa.ConfirmHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {code}}))
	require.Equal(t, http.StatusOK, rec.Code)
	var confirm struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &confirm))
	require.Len(t, confirm.RecoveryCodes, mfa.DefaultRecoveryCodeCount)

	// Verify a fresh code (advance a period) → 204.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec = httptest.NewRecorder()
	mfa.VerifyHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// Verify a bad code → 401.
	rec = httptest.NewRecorder()
	mfa.VerifyHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {"000000"}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Recovery code works once → 204, reuse → 401.
	rec = httptest.NewRecorder()
	mfa.VerifyRecoveryHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {confirm.RecoveryCodes[0]}}))
	assert.Equal(t, http.StatusNoContent, rec.Code)
	rec = httptest.NewRecorder()
	mfa.VerifyRecoveryHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {confirm.RecoveryCodes[0]}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Disable → 204. The route is factor-mutating, so it requires a credential that proves a second
	// factor (in production that assurance comes from tokens.AssuranceResolverFromContext).
	rec = httptest.NewRecorder()
	mfa.DisableHandler(svc, resolver, steppedUp)(rec, mfaPost(url.Values{}))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestHandlers_RequireResolvedUser(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())

	// No resolver configured → 401.
	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc)(rec, mfaPost(url.Values{}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Resolver reports no user → 401.
	rec = httptest.NewRecorder()
	mfa.VerifyHandler(svc, mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) {
		return uuid.Nil, "", false
	}))(rec, mfaPost(url.Values{"code": {"123456"}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandlers_RejectGET(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())
	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) {
		return uuid.Must(uuid.NewV7()), "t1", true
	}))(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestHandlers_TrustedOrigins verifies CSRF origin enforcement: when WithTrustedOrigins is
// configured, every state-changing handler must reject a request whose Origin header does not
// match the trusted set with 403 "cross_site_blocked", and must accept a request from a
// trusted origin.
func TestHandlers_TrustedOrigins(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	store := memory.NewStore()
	svc := mfa.NewService(store, mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
	trusted := mfa.WithTrustedOrigins("app.example.com")

	// mfaPostOrigin creates a POST with the given Origin header value.
	mfaPostOrigin := func(form url.Values, origin string) *http.Request {
		req := mfaPost(form)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		return req
	}

	// handlers under test: each maps to a handler constructor and the minimal form values needed.
	type tc struct {
		name    string
		handler http.HandlerFunc
		form    url.Values
	}
	handlers := []tc{
		{"EnrollHandler", mfa.EnrollHandler(svc, resolver, trusted), url.Values{"account": {"user@example.com"}}},
		{"ConfirmHandler", mfa.ConfirmHandler(svc, resolver, trusted), url.Values{"code": {"000000"}}},
		{"VerifyHandler", mfa.VerifyHandler(svc, resolver, trusted), url.Values{"code": {"000000"}}},
		{"VerifyRecoveryHandler", mfa.VerifyRecoveryHandler(svc, resolver, trusted), url.Values{"code": {"abc"}}},
		{"RegenerateRecoveryCodesHandler", mfa.RegenerateRecoveryCodesHandler(svc, resolver, trusted, steppedUp), url.Values{}},
		{"DisableHandler", mfa.DisableHandler(svc, resolver, trusted, steppedUp), url.Values{}},
	}

	for _, h := range handlers {
		t.Run(h.name+"/untrusted_origin_blocked", func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handler(rec, mfaPostOrigin(h.form, "https://evil.attacker.com"))
			assert.Equal(t, http.StatusForbidden, rec.Code,
				"expected 403 from untrusted origin; handler performed the action without checking origin")
		})
		t.Run(h.name+"/trusted_origin_allowed", func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handler(rec, mfaPostOrigin(h.form, "https://app.example.com"))
			// The service call may fail (e.g. not enrolled), but the origin check must not block it.
			assert.NotEqual(t, http.StatusForbidden, rec.Code,
				"expected handler to pass origin check for trusted origin")
		})
	}

	t.Run("no_trusted_origins_still_blocks_cross_origin", func(t *testing.T) {
		// Strict by default (TASK-025 parity with tokens/identity): with NO WithTrustedOrigins,
		// a cross-origin POST must still be rejected.
		handlerDefault := mfa.EnrollHandler(svc, resolver)
		rec := httptest.NewRecorder()
		handlerDefault(rec, mfaPostOrigin(url.Values{"account": {"u"}}, "https://anywhere.com"))
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("with_insecure_no_origin_check_passes_any_origin", func(t *testing.T) {
		// The loud opt-out restores the pre-v1 accept-all behavior.
		handlerInsecure := mfa.EnrollHandler(svc, resolver, mfa.WithInsecureNoOriginCheck())
		rec := httptest.NewRecorder()
		handlerInsecure(rec, mfaPostOrigin(url.Values{"account": {"u"}}, "https://anywhere.com"))
		assert.NotEqual(t, http.StatusForbidden, rec.Code)
	})
}
