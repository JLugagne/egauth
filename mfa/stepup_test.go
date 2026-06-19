package mfa_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func stepUpCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestStepUpHandler_ReissuesFullPairWithAMRMFA proves the completion half of the AMR/step-up
// model: after a correct TOTP, StepUpHandler re-issues the FULL access+refresh pair stamped
// AMR=[pwd, otp, mfa] and writes both cookies, so a route gated with WithRequiredAMR(AMRMFA)
// now passes. This is exactly what was unwireable before the fix.
func TestStepUpHandler_ReissuesFullPairWithAMRMFA(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	// Enroll + confirm a TOTP factor for the user.
	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver)(rec, mfaPost(url.Values{"account": {"user@example.com"}}))
	require.Equal(t, http.StatusOK, rec.Code)
	var enroll struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &enroll))
	rec = httptest.NewRecorder()
	mfa.ConfirmHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))
	require.Equal(t, http.StatusOK, rec.Code)

	var captured tokens.Claims[struct{}]
	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			captured = claims
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "full-access-jwt",
				RefreshToken:          "full-refresh-opaque",
				RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
				Claims:                claims,
			}, nil
		},
	}
	builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	// Step up with a fresh TOTP code (advance one period so it differs from the confirm code).
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec = httptest.NewRecorder()
	h := mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver)
	h(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))

	assert.Equal(t, http.StatusNoContent, rec.Code)

	// The re-issued token carries the full MFA factor set, including the MFA marker that
	// WithRequiredAMR(AMRMFA) enforces.
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, captured.AMR)
	assert.Contains(t, captured.AMR, tokens.AMRMFA, "step-up token must carry the MFA factor")

	// Both cookies are written now: the full session replaces the interim access-only state.
	access := stepUpCookie(rec, tokens.DefaultAccessCookieName)
	refresh := stepUpCookie(rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, access, "step-up must set the access cookie")
	require.NotNil(t, refresh, "step-up must set the refresh cookie (full renewable session)")
	assert.Equal(t, "full-access-jwt", access.Value)
	assert.Equal(t, "full-refresh-opaque", refresh.Value)
}

// TestStepUpHandler_MustChange_FlaggedRenewable proves the forced-change gate survives an MFA
// step-up: when the verified interim token was must-change (surfaced via WithMustChangeResolver),
// the re-issued full pair is stamped MustChangePassword=true and is fully renewable (both cookies
// written). The refresh family persists the flag (Rotate replays it), so the flag cannot be dropped
// by a silent refresh after a second factor.
func TestStepUpHandler_MustChange_FlaggedRenewable(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver)(rec, mfaPost(url.Values{"account": {"user@example.com"}}))
	require.Equal(t, http.StatusOK, rec.Code)
	var enroll struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &enroll))
	rec = httptest.NewRecorder()
	mfa.ConfirmHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))
	require.Equal(t, http.StatusOK, rec.Code)

	var captured tokens.Claims[struct{}]
	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			captured = claims
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "flagged-access-jwt",
				RefreshToken:          "full-refresh-opaque",
				RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
				Claims:                claims,
			}, nil
		},
	}
	builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec = httptest.NewRecorder()
	// The interim token is flagged must-change.
	h := mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver,
		mfa.WithMustChangeResolver(func(*http.Request) bool { return true }))
	h(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	// The flag is carried forward onto the re-issued claims.
	assert.True(t, captured.MustChangePassword, "step-up must preserve the must-change flag")
	// The MFA factor set is still stamped — the user did complete the second factor.
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, captured.AMR)
	// Renewable: both cookies present. The flag is carried by the refresh family (Rotate replays
	// it), so the renewable session stays gated rather than dropping the flag on the next refresh.
	access := stepUpCookie(rec, tokens.DefaultAccessCookieName)
	require.NotNil(t, access, "flagged step-up must set the access cookie")
	assert.Equal(t, "flagged-access-jwt", access.Value)
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName),
		"flagged step-up is renewable: it MUST set a refresh cookie (the flag is carried across refresh)")
}

// TestStepUpHandler_MustChange_NormalUserGetsFullPair proves the gate is opt-in per request: a
// normal (not must-change) user whose interim token is unflagged gets a clean full pair with the
// flag false and both cookies, even when WithMustChangeResolver is wired.
func TestStepUpHandler_MustChange_NormalUserGetsFullPair(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver)(rec, mfaPost(url.Values{"account": {"user@example.com"}}))
	require.Equal(t, http.StatusOK, rec.Code)
	var enroll struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &enroll))
	rec = httptest.NewRecorder()
	mfa.ConfirmHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))
	require.Equal(t, http.StatusOK, rec.Code)

	var captured tokens.Claims[struct{}]
	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			captured = claims
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "full-access-jwt",
				RefreshToken:          "full-refresh-opaque",
				RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
				Claims:                claims,
			}, nil
		},
	}
	builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec = httptest.NewRecorder()
	// Resolver reports false: the interim token is NOT flagged.
	h := mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver,
		mfa.WithMustChangeResolver(func(*http.Request) bool { return false }))
	h(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.False(t, captured.MustChangePassword, "an unflagged step-up token must stay clean")
	// Full renewable pair: both cookies present.
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultAccessCookieName))
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName),
		"a normal step-up must set the refresh cookie (full renewable session)")
}

// TestStepUpHandler_BadCodeMintsNothing confirms a wrong TOTP fails like VerifyHandler and never
// upgrades the interim session: no token is issued and no cookie is written.
func TestStepUpHandler_BadCodeMintsNothing(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver)(rec, mfaPost(url.Values{"account": {"user@example.com"}}))
	var enroll struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &enroll))
	rec = httptest.NewRecorder()
	mfa.ConfirmHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))

	issued := false
	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			issued = true
			return &tokens.TokenPair[struct{}]{}, nil
		},
	}
	builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	rec = httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver)(rec, mfaPost(url.Values{"code": {"000000"}}))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, issued, "no token may be issued on a failed step-up")
	assert.Nil(t, stepUpCookie(rec, tokens.DefaultAccessCookieName), "no cookie on failed step-up")
	assert.Nil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName))
}
