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

// stepUpFixture enrolls and confirms a TOTP factor and returns everything the step-up handlers
// need: a clock advanced past the confirm code, the shared secret, the recovery codes, the user
// resolver and a capturing issuer.
type stepUpFixture struct {
	clk       *clock
	svc       mfa.Service
	secret    string
	recovery  []string
	resolver  mfa.HandlerOption
	issuer    *issuertest.MockIssuer[struct{}]
	builder   mfa.StepUpClaimsBuilder[struct{}]
	captured  *tokens.Claims[struct{}]
	issuedPtr *bool
}

func newStepUpFixture(t *testing.T) *stepUpFixture {
	t.Helper()
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

	f := &stepUpFixture{
		clk: clk, svc: svc, secret: enroll.Secret, recovery: confirm.RecoveryCodes,
		resolver: resolver, captured: new(tokens.Claims[struct{}]), issuedPtr: new(bool),
	}
	f.issuer = &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(_ context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			*f.captured = claims
			*f.issuedPtr = true
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "full-access-jwt",
				RefreshToken:          "full-refresh-opaque",
				RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
				Claims:                claims,
			}, nil
		},
	}
	f.builder = func(_ context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}
	// Advance one period so the step-up code differs from the confirm code.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	return f
}

// TestStepUpHandler_DoesNotAssertUnpresentedPassword pins mfa/SF-10: the handler unconditionally
// stamped AMR=[pwd, otp, mfa], claiming a password factor for a subject whose first factor may have
// been a magic link or a federated IdP. AMR is a security assertion consumed by
// tokens.WithRequiredAMR, so it must record only what was actually presented.
func TestStepUpHandler_DoesNotAssertUnpresentedPassword(t *testing.T) {
	f := newStepUpFixture(t)

	rec := httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](f.svc, f.issuer, f.builder, f.resolver)(
		rec, mfaPost(url.Values{"code": {f.clk.code(t, f.secret)}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.NotContains(t, f.captured.AMR, tokens.AMRPassword,
		"no password was presented in this ceremony, so AMR must not claim one")
	assert.Contains(t, f.captured.AMR, tokens.AMROTP, "the verified TOTP factor must be recorded")
	assert.Contains(t, f.captured.AMR, tokens.AMRMFA, "the step-up marker must still be recorded")
}

// TestStepUpHandler_CarriesPriorFactorsForward proves the replacement seam: when the application
// surfaces the factors the interim credential already proved, they are carried forward and the
// resulting AMR is the honest union.
func TestStepUpHandler_CarriesPriorFactorsForward(t *testing.T) {
	f := newStepUpFixture(t)

	rec := httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](f.svc, f.issuer, f.builder, f.resolver,
		mfa.WithPriorAMR(func(*http.Request) []string { return []string{tokens.AMRPassword} }),
	)(rec, mfaPost(url.Values{"code": {f.clk.code(t, f.secret)}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, f.captured.AMR,
		"a password-backed interim credential must yield the full factor set, in order")
}

func TestStepUpHandler_PriorFactorsAreDeduplicated(t *testing.T) {
	f := newStepUpFixture(t)

	rec := httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](f.svc, f.issuer, f.builder, f.resolver,
		mfa.WithPriorAMR(func(*http.Request) []string {
			return []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRPassword}
		}),
	)(rec, mfaPost(url.Values{"code": {f.clk.code(t, f.secret)}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, f.captured.AMR)
}

// TestStepUpRecoveryHandler_ConvertsRecoveryCodeIntoSession pins mfa/SF-6: a user who lost their
// authenticator had NO shipped path back in — StepUpHandler is TOTP-only, and VerifyRecoveryHandler
// mints nothing — so recovery-code self-service was unreachable.
func TestStepUpRecoveryHandler_ConvertsRecoveryCodeIntoSession(t *testing.T) {
	f := newStepUpFixture(t)

	rec := httptest.NewRecorder()
	mfa.StepUpRecoveryHandler[struct{}](f.svc, f.issuer, f.builder, f.resolver)(
		rec, mfaPost(url.Values{"code": {f.recovery[0]}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.True(t, *f.issuedPtr, "a valid recovery code must mint a full pair")
	assert.Contains(t, f.captured.AMR, tokens.AMRRecoveryCode, "the recovery factor must be recorded")
	assert.Contains(t, f.captured.AMR, tokens.AMRMFA, "the step-up marker must be recorded")
	assert.NotContains(t, f.captured.AMR, tokens.AMROTP, "no TOTP code was presented")
	assert.False(t, f.captured.Interim, "the re-issued credential is a full session")
	assert.True(t, f.captured.SatisfiesStepUp(), "a recovery-code session must clear the step-up bar")

	require.NotNil(t, stepUpCookie(rec, tokens.DefaultAccessCookieName), "must write the access cookie")
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName), "must write the refresh cookie")
}

func TestStepUpRecoveryHandler_CodeIsSingleUse(t *testing.T) {
	f := newStepUpFixture(t)
	h := mfa.StepUpRecoveryHandler[struct{}](f.svc, f.issuer, f.builder, f.resolver)

	rec := httptest.NewRecorder()
	h(rec, mfaPost(url.Values{"code": {f.recovery[0]}}))
	require.Equal(t, http.StatusNoContent, rec.Code)

	*f.issuedPtr = false
	rec = httptest.NewRecorder()
	h(rec, mfaPost(url.Values{"code": {f.recovery[0]}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "a recovery code is single-use")
	assert.False(t, *f.issuedPtr, "a spent recovery code must mint nothing")
}

func TestStepUpRecoveryHandler_BadCodeMintsNothing(t *testing.T) {
	f := newStepUpFixture(t)

	rec := httptest.NewRecorder()
	mfa.StepUpRecoveryHandler[struct{}](f.svc, f.issuer, f.builder, f.resolver)(
		rec, mfaPost(url.Values{"code": {"not-a-real-recovery-code"}}))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, *f.issuedPtr, "no token may be issued on a failed recovery step-up")
	assert.Nil(t, stepUpCookie(rec, tokens.DefaultAccessCookieName))
	assert.Nil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName))
}

// TestStepUpRecoveryHandler_RejectsCrossOrigin proves the recovery step-up sits behind the same
// CSRF guard as the rest of the MFA family.
func TestStepUpRecoveryHandler_RejectsCrossOrigin(t *testing.T) {
	f := newStepUpFixture(t)

	req := mfaPost(url.Values{"code": {f.recovery[0]}})
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	mfa.StepUpRecoveryHandler[struct{}](f.svc, f.issuer, f.builder, f.resolver)(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, *f.issuedPtr)
}
