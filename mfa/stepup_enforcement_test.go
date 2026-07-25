package mfa_test

import (
	"context"
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

// enrolledService returns a service whose user has a CONFIRMED factor plus that user's resolver.
func enrolledService(t *testing.T) (mfa.Service, uuid.UUID, mfa.HandlerOption) {
	t.Helper()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())

	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true }))(
		rec, mfaPost(url.Values{"account": {"user@example.com"}}))
	require.Equal(t, http.StatusOK, rec.Code, "enrollment must not require step-up: it is how a factor is added")

	enrollment, err := svc.EnrollTOTP(t.Context(), "t1", uid, "user@example.com")
	require.NoError(t, err)
	rec = httptest.NewRecorder()
	mfa.ConfirmHandler(svc, mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true }))(
		rec, mfaPost(url.Values{"code": {clk.code(t, enrollment.Secret)}}))
	require.Equal(t, http.StatusOK, rec.Code, "confirmation must not require step-up either")

	return svc, uid, mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
}

func assuranceOption(a tokens.Assurance, ok bool) mfa.HandlerOption {
	return mfa.WithAssuranceResolver(func(*http.Request) (tokens.Assurance, bool) { return a, ok })
}

// TestDisableHandler_RequiresStepUp proves finding mfa/SF-1: stripping the second factor requires a
// credential that carries one. The handler enforces it itself, so the protection does not depend on
// the consumer remembering to gate the route.
func TestDisableHandler_RequiresStepUp(t *testing.T) {
	cases := []struct {
		name     string
		option   mfa.HandlerOption
		wantCode int
	}{
		{
			name:     "unresolvable assurance fails closed",
			option:   assuranceOption(tokens.Assurance{}, false),
			wantCode: http.StatusForbidden,
		},
		{
			name:     "pre-MFA interim credential is refused",
			option:   assuranceOption(tokens.Assurance{Interim: true}, true),
			wantCode: http.StatusForbidden,
		},
		{
			name:     "password-only session is refused",
			option:   assuranceOption(tokens.Assurance{}, true),
			wantCode: http.StatusForbidden,
		},
		{
			name:     "stepped-up session is allowed",
			option:   assuranceOption(tokens.Assurance{StepUp: true}, true),
			wantCode: http.StatusNoContent,
		},
		{
			name:     "the loud opt-out restores the old behaviour",
			option:   mfa.WithInsecureNoStepUpCheck(),
			wantCode: http.StatusNoContent,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, uid, resolver := enrolledService(t)

			rec := httptest.NewRecorder()
			mfa.DisableHandler(svc, resolver, tc.option)(rec, mfaPost(url.Values{}))
			assert.Equal(t, tc.wantCode, rec.Code)
			if tc.wantCode == http.StatusForbidden {
				assert.Contains(t, rec.Body.String(), "step_up_required")
			}

			enrolled, err := svc.IsEnrolled(t.Context(), "t1", uid)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCode == http.StatusForbidden, enrolled,
				"the factor must survive exactly when the request was refused")
		})
	}
}

// TestDisableHandler_DefaultResolverFailsClosed proves the DEFAULT wiring is safe: with no
// ContextMiddleware in front (so tokens.AssuranceResolverFromContext cannot report an assurance) the
// handler refuses rather than assuming a full session.
func TestDisableHandler_DefaultResolverFailsClosed(t *testing.T) {
	svc, uid, resolver := enrolledService(t)

	rec := httptest.NewRecorder()
	mfa.DisableHandler(svc, resolver)(rec, mfaPost(url.Values{}))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	enrolled, err := svc.IsEnrolled(t.Context(), "t1", uid)
	require.NoError(t, err)
	assert.True(t, enrolled)
}

// TestRegenerateRecoveryCodesHandler_RequiresStepUp proves the same bar on the other
// factor-mutating route: regenerating destroys every existing recovery code.
func TestRegenerateRecoveryCodesHandler_RequiresStepUp(t *testing.T) {
	svc, _, resolver := enrolledService(t)

	rec := httptest.NewRecorder()
	mfa.RegenerateRecoveryCodesHandler(svc, resolver, assuranceOption(tokens.Assurance{Interim: true}, true))(
		rec, mfaPost(url.Values{}))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "step_up_required")

	rec = httptest.NewRecorder()
	mfa.RegenerateRecoveryCodesHandler(svc, resolver, assuranceOption(tokens.Assurance{StepUp: true}, true))(
		rec, mfaPost(url.Values{}))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "recovery_codes")
}

// TestStepUpHandler_ClearsInterimMarker proves the re-issued pair is never stamped as interim, even
// if the application's claims builder hands one back: the handler is authoritative about the factor
// state it just verified, so the full session it mints must be usable everywhere.
func TestStepUpHandler_ClearsInterimMarker(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	enrollment, err := svc.EnrollTOTP(t.Context(), "t1", uid, "user@example.com")
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(t.Context(), "t1", uid, clk.code(t, enrollment.Secret))
	require.NoError(t, err)

	var captured tokens.Claims[struct{}]
	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(_ context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			captured = claims
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", Claims: claims}, nil
		},
	}
	// A builder that (wrongly) carries the interim marker forward.
	builder := func(_ context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant, Interim: true}
	}

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec := httptest.NewRecorder()
	mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver)(rec, mfaPost(url.Values{"code": {clk.code(t, enrollment.Secret)}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.False(t, captured.Interim, "the stepped-up pair must not be an interim credential")
	assert.True(t, captured.SatisfiesStepUp(), "the stepped-up pair must satisfy the step-up bar")
}

// TestVerifyHandlers_DoNotRequireStepUp confirms the enforcement is scoped to the factor-mutating
// routes: the verify endpoints are how a second factor is proven in the first place, so gating them
// on an already-proven factor would deadlock the flow.
func TestVerifyHandlers_DoNotRequireStepUp(t *testing.T) {
	svc, _, resolver := enrolledService(t)

	rec := httptest.NewRecorder()
	mfa.VerifyHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {"000000"}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "a wrong code is 401, never 403 step_up_required")

	rec = httptest.NewRecorder()
	mfa.VerifyRecoveryHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {"nope"}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
