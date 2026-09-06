package mfa_test

import (
	"context"
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
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	// Disable → 204.
	rec = httptest.NewRecorder()
	mfa.DisableHandler(svc, resolver, mfa.WithoutStepUp())(rec, mfaPost(url.Values{}))
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
		{"RegenerateRecoveryCodesHandler", mfa.RegenerateRecoveryCodesHandler(svc, resolver, trusted), url.Values{}},
		{"DisableHandler", mfa.DisableHandler(svc, resolver, trusted, mfa.WithoutStepUp()), url.Values{}},
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

func TestDisableHandler_StepUp(t *testing.T) {
	setupEnrolledUser := func(t *testing.T) (mfa.Service, uuid.UUID, *clock) {
		clk := &clock{t: time.Unix(1_700_000_000, 0)}
		svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
		uid := uuid.Must(uuid.NewV7())
		enroll, err := svc.EnrollTOTP(context.Background(), "t1", uid, "user@example.com")
		require.NoError(t, err)
		code := clk.code(t, enroll.Secret)
		_, err = svc.ConfirmTOTP(context.Background(), "t1", uid, code)
		require.NoError(t, err)
		return svc, uid, clk
	}

	t.Run("default requires step-up and rejects unelevated caller with 403", func(t *testing.T) {
		svc, uid, _ := setupEnrolledUser(t)
		resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

		rec := httptest.NewRecorder()
		mfa.DisableHandler(svc, resolver)(rec, mfaPost(url.Values{}))

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "step_up_required")
	})

	t.Run("interim session AMR [pwd] is rejected with 403", func(t *testing.T) {
		svc, uid, _ := setupEnrolledUser(t)
		resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
		amrOpt := mfa.WithAMRResolver(func(*http.Request) []string { return []string{tokens.AMRPassword} })

		rec := httptest.NewRecorder()
		mfa.DisableHandler(svc, resolver, amrOpt)(rec, mfaPost(url.Values{}))

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "step_up_required")
	})

	t.Run("elevated session with AMRMFA succeeds with 204", func(t *testing.T) {
		svc, uid, _ := setupEnrolledUser(t)
		resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
		amrOpt := mfa.WithAMRResolver(func(*http.Request) []string { return []string{tokens.AMRPassword, tokens.AMRMFA} })

		rec := httptest.NewRecorder()
		mfa.DisableHandler(svc, resolver, amrOpt)(rec, mfaPost(url.Values{}))

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("WithoutStepUp allows unelevated caller with 204", func(t *testing.T) {
		svc, uid, _ := setupEnrolledUser(t)
		resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

		rec := httptest.NewRecorder()
		mfa.DisableHandler(svc, resolver, mfa.WithoutStepUp())(rec, mfaPost(url.Values{}))

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("WithStepUpRequired false allows unelevated caller with 204", func(t *testing.T) {
		svc, uid, _ := setupEnrolledUser(t)
		resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

		rec := httptest.NewRecorder()
		mfa.DisableHandler(svc, resolver, mfa.WithStepUpRequired(false))(rec, mfaPost(url.Values{}))

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("ContextMiddleware with AMRMFA succeeds and without AMRMFA is rejected", func(t *testing.T) {
		svc, uid, _ := setupEnrolledUser(t)

		mockVerifier := func(amr []string) tokens.Verifier[struct{}] {
			return &issuertest.MockVerifier[struct{}]{
				VerifyAccessTokenForTenantFunc: func(_ context.Context, _, _ string) (*tokens.Claims[struct{}], error) {
					return &tokens.Claims[struct{}]{
						Subject:  uid,
						TenantID: "t1",
						AMR:      amr,
					}, nil
				},
			}
		}

		handler := mfa.DisableHandler(svc, mfa.WithUserResolver(tokens.UserResolverFromContext))

		// Without AMRMFA in token -> 403
		rec := httptest.NewRecorder()
		req := mfaPost(url.Values{})
		req.Header.Set("Authorization", "Bearer token-pwd")
		tokens.ContextMiddleware[struct{}](mockVerifier([]string{tokens.AMRPassword}), handler).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "step_up_required")

		// With AMRMFA in token -> 204
		rec = httptest.NewRecorder()
		req = mfaPost(url.Values{})
		req.Header.Set("Authorization", "Bearer token-mfa")
		tokens.ContextMiddleware[struct{}](mockVerifier([]string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}), handler).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
}
