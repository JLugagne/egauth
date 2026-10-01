// Regression tests for F-COMP-003: mfa.StepUpHandler must fail closed when no authoritative
// session-state resolver is configured. The legacy default echoed the interim token's own
// subject and tenant, so an account disabled between the password factor and the second
// factor could still complete step-up and receive a full renewable pair.
package mfa_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/issuance"
	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// seedStepUpEnrollment enrolls and confirms a TOTP factor over the handlers, returning the
// shared secret.
func seedStepUpEnrollment(t *testing.T, svc mfa.Service, resolver mfa.HandlerOption, clk *clock) string {
	t.Helper()
	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver, mfa.WithInsecureNoAssuranceCheck())(rec, mfaPost(url.Values{"account": {"user@example.com"}}))
	require.Equal(t, http.StatusOK, rec.Code)
	var enroll struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &enroll))
	rec = httptest.NewRecorder()
	mfa.ConfirmHandler(svc, resolver, mfa.WithInsecureNoAssuranceCheck())(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))
	require.Equal(t, http.StatusOK, rec.Code)
	return enroll.Secret
}

// TestStepUpHandler_FailsClosedWithoutSessionStateResolver is the default-composition
// invariant: with no WithSessionStateResolver the handler must refuse (500 misconfigured)
// instead of minting from the interim token's own subject.
func TestStepUpHandler_FailsClosedWithoutSessionStateResolver(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
	secret := seedStepUpEnrollment(t, svc, resolver, clk)

	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(context.Context, tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	builder := func(_ context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec := httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver)(rec, mfaPost(url.Values{"code": {clk.code(t, secret)}}))

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"step-up without an authoritative resolver must fail closed, not mint from the interim identity")
	require.Contains(t, rec.Body.String(), "misconfigured")
	require.Nil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName), "no renewable pair may be minted")
}

// TestStepUpHandler_AuthoritativeResolver_DeniesDisabledAccount is the composed-system
// property: a resolver that reports the account disabled must stop the step-up.
func TestStepUpHandler_AuthoritativeResolver_DeniesDisabledAccount(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
	secret := seedStepUpEnrollment(t, svc, resolver, clk)

	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(context.Context, tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	builder := func(_ context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}
	disabled := mfa.WithSessionStateResolver(issuance.ResolverFunc(func(_ context.Context, tenantID string, userID uuid.UUID) (issuance.State, error) {
		return issuance.State{UserID: userID, TenantID: tenantID, Disabled: true}, nil
	}))

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec := httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver, disabled)(rec, mfaPost(url.Values{"code": {clk.code(t, secret)}}))

	require.NotEqual(t, http.StatusNoContent, rec.Code, "a disabled account must not complete step-up")
	require.Nil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName))
}

// TestStepUpHandler_AuthoritativeResolver_PermitsLiveAccount proves explicit resolver wiring
// keeps working: a live account completes step-up and receives the full pair.
func TestStepUpHandler_AuthoritativeResolver_PermitsLiveAccount(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
	secret := seedStepUpEnrollment(t, svc, resolver, clk)

	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(context.Context, tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	builder := func(_ context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}
	live := mfa.WithSessionStateResolver(issuance.ResolverFunc(func(_ context.Context, tenantID string, userID uuid.UUID) (issuance.State, error) {
		return issuance.State{UserID: userID, TenantID: tenantID}, nil
	}))

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec := httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver, live)(rec, mfaPost(url.Values{"code": {clk.code(t, secret)}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName), "a live account must receive the full pair")
}

// TestStepUpHandler_InsecureEchoSessionState_RestoresLegacyDefault pins the documented
// opt-out: with it, a valid step-up succeeds using the echoed interim identity (the legacy
// behavior), so applications that enforce account lifecycle outside the library keep working.
func TestStepUpHandler_InsecureEchoSessionState_RestoresLegacyDefault(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
	secret := seedStepUpEnrollment(t, svc, resolver, clk)

	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(context.Context, tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	builder := func(_ context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec := httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver, mfa.WithInsecureEchoSessionState())(rec, mfaPost(url.Values{"code": {clk.code(t, secret)}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName))
}
