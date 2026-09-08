// CSRF same-origin tests for authflow.StepUpHandler, pinning parity with the
// identity/tokens/mfa handler families: every state-changing POST is origin-checked by
// default (httputil.OriginAllowed, exact-host matching), a request carrying neither an
// Origin nor a Referer is untrusted, and the only opt-out is the loud insecure one.
package authflow_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// originCheckRequest builds a step-up POST with an explicit Host and Origin header so CSRF
// tests can pin exact-host matching (httptest.NewRequest defaults Host to "example.com").
// The challenged flow token rides the auth_flow_token cookie; viaHeader switches to the
// X-Auth-Flow-Token header path (API-style clients) and drops the cookie.
func originCheckRequest(flowToken, host, origin string, viaHeader bool) *http.Request {
	form := url.Values{"code": {"123456"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/step-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if viaHeader {
		req.Header.Set("X-Auth-Flow-Token", flowToken)
	} else {
		req.AddCookie(&http.Cookie{Name: authflow.DefaultFlowCookieName, Value: flowToken})
	}
	return req
}

// challengedFlow is the shared preamble of the origin-check tests: an engine with an
// always-enrolled MFA gate and a flow parked in StateMFAChallenged.
func challengedFlow(t *testing.T) (*authflow.Engine, *mockSessionMinter, *mockVerifier, string) {
	t.Helper()
	minter := &mockSessionMinter{}
	engine := stepUpEngine(t, minter)
	user := &identity.User{ID: uuid.New(), TenantID: "tenant-1", Email: "u@example.com"}
	flowToken := challengedFlowToken(t, engine, user)
	return engine, minter, &mockVerifier{}, flowToken
}

// TestStepUpHandler_OriginCheck_SiblingSameSiteOriginBlocked proves CSRF-by-default parity
// with the identity/tokens/mfa handlers: a same-site sibling origin (evil.example.com POSTing
// to app.example.com) sends cookies regardless of SameSite, so the handler itself must reject
// it with 403 cross_site_blocked before any second-factor verification runs.
func TestStepUpHandler_OriginCheck_SiblingSameSiteOriginBlocked(t *testing.T) {
	engine, minter, v, flowToken := challengedFlow(t)

	rec := httptest.NewRecorder()
	authflow.StepUpHandler(engine, v)(rec, originCheckRequest(flowToken, "app.example.com", "https://evil.example.com", false))

	assert.Equal(t, http.StatusForbidden, rec.Code, "a sibling same-site origin must be blocked by default")
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
	assert.Zero(t, v.totpCalls, "a cross-origin request must not reach the second-factor verifier")
	assert.Empty(t, minter.mintedFlows, "a cross-origin request must not complete the flow")
}

// TestStepUpHandler_OriginCheck_SameOriginAllowed proves the legitimate path survives: a POST
// whose Origin host equals the request's own Host passes the default check and completes the
// flow.
func TestStepUpHandler_OriginCheck_SameOriginAllowed(t *testing.T) {
	engine, minter, v, flowToken := challengedFlow(t)

	rec := httptest.NewRecorder()
	authflow.StepUpHandler(engine, v)(rec, originCheckRequest(flowToken, "app.example.com", "https://app.example.com", false))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, 1, v.totpCalls)
	require.Len(t, minter.mintedFlows, 1, "a same-origin step-up completes the flow")
}

// TestStepUpHandler_OriginCheck_LookalikeOriginRejected proves exact-host matching: a
// lookalike origin whose host merely ENDS WITH the trusted host (app.example.com.evil.com)
// is not an equality match and must be rejected with 403.
func TestStepUpHandler_OriginCheck_LookalikeOriginRejected(t *testing.T) {
	engine, minter, v, flowToken := challengedFlow(t)

	rec := httptest.NewRecorder()
	authflow.StepUpHandler(engine, v)(rec, originCheckRequest(flowToken, "app.example.com", "https://app.example.com.evil.com", false))

	assert.Equal(t, http.StatusForbidden, rec.Code, "a lookalike origin must not pass exact-host matching")
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
	assert.Zero(t, v.totpCalls)
	assert.Empty(t, minter.mintedFlows)
}

// TestStepUpHandler_OriginCheck_MissingOriginUntrusted proves fail-closed parity: a POST
// carrying neither Origin nor Referer is treated as untrusted and rejected with 403 —
// non-browser API clients must allowlist their host (WithTrustedOrigins) or use the loud
// WithInsecureNoOriginCheck opt-out, exactly like the cookie-driven identity/tokens handlers.
func TestStepUpHandler_OriginCheck_MissingOriginUntrusted(t *testing.T) {
	engine, _, v, flowToken := challengedFlow(t)

	rec := httptest.NewRecorder()
	authflow.StepUpHandler(engine, v)(rec, originCheckRequest(flowToken, "app.example.com", "", false))

	assert.Equal(t, http.StatusForbidden, rec.Code, "a POST with no Origin and no Referer is untrusted by default")
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
	assert.Zero(t, v.totpCalls)
}

// TestStepUpHandler_OriginCheck_NullOriginRejected proves the opaque origin ("null", sent by
// sandboxed iframes and some redirect contexts) is rejected, not validated via Referer.
func TestStepUpHandler_OriginCheck_NullOriginRejected(t *testing.T) {
	engine, _, v, flowToken := challengedFlow(t)

	rec := httptest.NewRecorder()
	authflow.StepUpHandler(engine, v)(rec, originCheckRequest(flowToken, "app.example.com", "null", false))

	assert.Equal(t, http.StatusForbidden, rec.Code, "the opaque null origin must not pass the check")
	assert.Zero(t, v.totpCalls)
}

// TestStepUpHandler_WithTrustedOrigins_WidensAllowlist proves the option semantics: an
// explicitly allowlisted host passes even though it is not the request's own Host, while a
// host outside the allowlist is still rejected.
func TestStepUpHandler_WithTrustedOrigins_WidensAllowlist(t *testing.T) {
	t.Run("allowlisted_host_allowed", func(t *testing.T) {
		engine, minter, v, flowToken := challengedFlow(t)
		h := authflow.StepUpHandler(engine, v, authflow.WithTrustedOrigins("web.example.com"))

		rec := httptest.NewRecorder()
		h(rec, originCheckRequest(flowToken, "app.example.com", "https://web.example.com", false))

		assert.Equal(t, http.StatusNoContent, rec.Code, "an allowlisted host must pass the origin check")
		require.Len(t, minter.mintedFlows, 1)
	})

	t.Run("host_outside_allowlist_still_blocked", func(t *testing.T) {
		engine, _, v, flowToken := challengedFlow(t)
		h := authflow.StepUpHandler(engine, v, authflow.WithTrustedOrigins("web.example.com"))

		rec := httptest.NewRecorder()
		h(rec, originCheckRequest(flowToken, "app.example.com", "https://other.example.com", false))

		assert.Equal(t, http.StatusForbidden, rec.Code, "a host outside the allowlist must still be rejected")
		assert.Zero(t, v.totpCalls)
	})
}

// TestStepUpHandler_WithInsecureNoOriginCheck_RestoresAcceptAll proves the loud opt-out
// restores the pre-v1 accept-all behavior: a cross-origin POST is processed when the check is
// explicitly disabled.
func TestStepUpHandler_WithInsecureNoOriginCheck_RestoresAcceptAll(t *testing.T) {
	engine, minter, v, flowToken := challengedFlow(t)
	h := authflow.StepUpHandler(engine, v, authflow.WithInsecureNoOriginCheck())

	rec := httptest.NewRecorder()
	h(rec, originCheckRequest(flowToken, "app.example.com", "https://evil.example.com", false))

	assert.Equal(t, http.StatusNoContent, rec.Code, "the insecure opt-out disables the origin check")
	require.Len(t, minter.mintedFlows, 1)
}

// TestStepUpHandler_OriginCheck_HeaderTransportSamePolicy proves the check is
// transport-agnostic: the X-Auth-Flow-Token header path (API-style clients on other origins)
// is subject to the same default origin check as the cookie path — mirroring the fail-closed
// decision the cookie-driven identity/tokens handlers make about their credential transport.
func TestStepUpHandler_OriginCheck_HeaderTransportSamePolicy(t *testing.T) {
	t.Run("cross_origin_blocked", func(t *testing.T) {
		engine, _, v, flowToken := challengedFlow(t)

		rec := httptest.NewRecorder()
		authflow.StepUpHandler(engine, v)(rec, originCheckRequest(flowToken, "app.example.com", "https://evil.example.com", true))

		assert.Equal(t, http.StatusForbidden, rec.Code, "the header path must not bypass the origin check")
		assert.Zero(t, v.totpCalls)
	})

	t.Run("same_origin_allowed", func(t *testing.T) {
		engine, _, v, flowToken := challengedFlow(t)

		rec := httptest.NewRecorder()
		authflow.StepUpHandler(engine, v)(rec, originCheckRequest(flowToken, "app.example.com", "https://app.example.com", true))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, 1, v.totpCalls)
	})
}
