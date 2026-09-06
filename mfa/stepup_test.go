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

// TestStepUpHandler_RecoveryCode_ReissuesFullPairWithAMRMFA verifies that submitting a valid
// backup recovery code in the "code" parameter succeeds, issues the full token pair with AMRMFA,
// sets cookies, and single-use consumes the recovery code so reuse fails.
func TestStepUpHandler_RecoveryCode_ReissuesFullPairWithAMRMFA(t *testing.T) {
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
	var confirm struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &confirm))
	require.NotEmpty(t, confirm.RecoveryCodes)
	validRecoveryCode := confirm.RecoveryCodes[0]

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

	// 1. Submit valid recovery code to StepUpHandler:
	rec = httptest.NewRecorder()
	h := mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver)
	h(rec, mfaPost(url.Values{"code": {validRecoveryCode}}))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, captured.AMR)
	assert.Contains(t, captured.AMR, tokens.AMRMFA)

	access := stepUpCookie(rec, tokens.DefaultAccessCookieName)
	refresh := stepUpCookie(rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, access, "step-up with recovery code must set access cookie")
	require.NotNil(t, refresh, "step-up with recovery code must set refresh cookie")
	assert.Equal(t, "full-access-jwt", access.Value)
	assert.Equal(t, "full-refresh-opaque", refresh.Value)

	// 2. Re-submitting the same consumed code fails:
	rec = httptest.NewRecorder()
	h(rec, mfaPost(url.Values{"code": {validRecoveryCode}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// 3. Second recovery code unformatted (no dashes) also works:
	validRecoveryCode2 := strings.ReplaceAll(confirm.RecoveryCodes[1], "-", "")
	rec = httptest.NewRecorder()
	h(rec, mfaPost(url.Values{"code": {validRecoveryCode2}}))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// TestStepUpHandler_RecoveryCodeParam_ReissuesFullPair verifies that submitting via "recovery_code"
// parameter works identically to "code".
func TestStepUpHandler_RecoveryCodeParam_ReissuesFullPair(t *testing.T) {
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
	var confirm struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &confirm))

	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
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

	rec = httptest.NewRecorder()
	h := mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver)
	h(rec, mfaPost(url.Values{"recovery_code": {confirm.RecoveryCodes[0]}}))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultAccessCookieName))
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName))
}

// TestStepUpHandler_InvalidRecoveryCodeMintsNothing confirms an invalid recovery code fails with 401
// and mints no tokens.
func TestStepUpHandler_InvalidRecoveryCodeMintsNothing(t *testing.T) {
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
	mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver)(rec, mfaPost(url.Values{"code": {"ABCD-EFGH-IJKL-9999"}}))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, issued, "no token may be issued on a failed step-up")
	assert.Nil(t, stepUpCookie(rec, tokens.DefaultAccessCookieName))
	assert.Nil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName))
}

// TestStepUpHandler_PreservesInterimPrimaryAMR proves the SEC-MFA-01 fix: StepUpHandler must NOT
// hardcode AMR=[pwd, otp, mfa]. A magic-link interim session carries AMR=[otp] (no password was
// ever verified); after a TOTP step-up the full pair must preserve that otp primary factor and
// add the MFA marker — asserting a pwd factor that never happened would overstate the assurance
// level to any downstream tokens.WithRequiredAMR(tokens.AMRPassword) gate.
func TestStepUpHandler_PreservesInterimPrimaryAMR(t *testing.T) {
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

	// The interim session came from a magic link: its only factor is otp, no password.
	amrResolver := mfa.WithAMRResolver(func(*http.Request) []string { return []string{tokens.AMROTP} })

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec = httptest.NewRecorder()
	h := mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver, amrResolver)
	h(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Contains(t, captured.AMR, tokens.AMRMFA, "step-up token must carry the MFA marker")
	assert.Contains(t, captured.AMR, tokens.AMROTP, "the verified second factor must be present")
	assert.NotContains(t, captured.AMR, tokens.AMRPassword,
		"SEC-MFA-01: step-up must not assert a password factor the magic-link ceremony never verified")
}

// TestStepUpHandler_NoInterimAMR_FallsBackToPassword proves backward compatibility: when no
// interim AMR is resolvable (the historical wiring, where the resolver/context carries nothing),
// StepUpHandler keeps stamping the password-primary [pwd, otp, mfa] set.
func TestStepUpHandler_NoInterimAMR_FallsBackToPassword(t *testing.T) {
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

	var captured tokens.Claims[struct{}]
	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			captured = claims
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour), Claims: claims}, nil
		},
	}
	builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	// A resolver that reports no factors at all (empty), simulating a request with no interim AMR.
	emptyAMR := mfa.WithAMRResolver(func(*http.Request) []string { return nil })

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec = httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver, emptyAMR)(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, captured.AMR,
		"with no interim AMR the historical password-primary set is preserved")
}
