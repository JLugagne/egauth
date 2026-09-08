// Tests for the AS-02 default must-change propagation: StepUpHandler must derive
// Claims.MustChangePassword from the verified interim token's claims when no
// WithMustChangeResolver is wired, instead of dropping the flag on the re-issued pair.

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

// seedConfirmedEnrollment enrolls and confirms a TOTP factor for uid, returning the
// enrollment secret so callers can generate valid codes.
func seedConfirmedEnrollment(t *testing.T, svc mfa.Service, resolver mfa.HandlerOption, clk *clock) string {
	t.Helper()
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
	return enroll.Secret
}

// mustChangeStepUpIssuer returns a MockIssuer that captures the claims it was asked to
// mint (the captured claims drive BOTH the access and the refresh token of the pair).
func mustChangeStepUpIssuer(captured *tokens.Claims[struct{}]) *issuertest.MockIssuer[struct{}] {
	return &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			*captured = claims
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "stepped-up-access-jwt",
				RefreshToken:          "stepped-up-refresh-opaque",
				RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
				Claims:                claims,
			}, nil
		},
	}
}

// interimClaims builds the claims of the interim access token exactly as identity's MFA
// gate mints it for a must-change, password-gated login: AMR=[pwd] plus the flag.
func interimClaims(uid uuid.UUID, tenant string, mustChange bool) *tokens.Claims[struct{}] {
	return &tokens.Claims[struct{}]{
		Subject:            uid,
		TenantID:           tenant,
		AMR:                []string{tokens.AMRPassword},
		MustChangePassword: mustChange,
	}
}

// contextVerifying returns the step-up handler wrapped in tokens.ContextMiddleware with a
// verifier that always accepts as the given interim claims — the production mounting where
// the verified interim token lands in r.Context() before the handler runs.
func contextVerifying(interim *tokens.Claims[struct{}], inner http.Handler) http.Handler {
	verifier := &issuertest.MockVerifier[struct{}]{
		VerifyAccessTokenForTenantFunc: func(ctx context.Context, tenantID string, token string) (*tokens.Claims[struct{}], error) {
			return interim, nil
		},
	}
	return tokens.ContextMiddleware[struct{}](verifier, inner)
}

// TestStepUpHandler_MustChange_DefaultWiring_PreservesInterimFlag proves the AS-02 fix on
// DEFAULT wiring (no WithMustChangeResolver): a must-change, MFA-enrolled user whose verified
// interim token carries MustChangePassword=true must receive a stepped-up pair that stays
// flagged. With the pre-fix behavior the flag was dropped, so the fresh refresh family
// (unbounded by default) replayed flag=false on every silent refresh and the user escaped
// WithPasswordChangeGate until the next interactive login.
func TestStepUpHandler_MustChange_DefaultWiring_PreservesInterimFlag(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
	secret := seedConfirmedEnrollment(t, svc, resolver, clk)

	var captured tokens.Claims[struct{}]
	issuer := mustChangeStepUpIssuer(&captured)
	builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec := httptest.NewRecorder()
	h := contextVerifying(interimClaims(uid, "t1", true),
		mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver))
	req := mfaPost(url.Values{"code": {clk.code(t, secret)}})
	req.Header.Set("Authorization", "Bearer interim-access-jwt")
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, captured.MustChangePassword,
		"AS-02: default wiring must preserve the interim token's must-change flag on the stepped-up pair")
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, captured.AMR,
		"the MFA factor set must still be stamped")
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultAccessCookieName), "flagged step-up must set the access cookie")
	require.NotNil(t, stepUpCookie(rec, tokens.DefaultRefreshCookieName),
		"flagged step-up must set the refresh cookie (the flag is carried across silent refresh)")
}

// TestStepUpHandler_MustChange_DefaultWiring_UnflaggedInterimStaysClean proves default
// propagation mirrors the interim token exactly: an unflagged interim session yields a clean
// stepped-up pair (no blanket flag stamping).
func TestStepUpHandler_MustChange_DefaultWiring_UnflaggedInterimStaysClean(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
	secret := seedConfirmedEnrollment(t, svc, resolver, clk)

	var captured tokens.Claims[struct{}]
	issuer := mustChangeStepUpIssuer(&captured)
	builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec := httptest.NewRecorder()
	h := contextVerifying(interimClaims(uid, "t1", false),
		mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver))
	req := mfaPost(url.Values{"code": {clk.code(t, secret)}})
	req.Header.Set("Authorization", "Bearer interim-access-jwt")
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.False(t, captured.MustChangePassword, "an unflagged interim must produce an unflagged pair")
}

// TestStepUpHandler_MustChange_ResolverOverridesInterim proves WithMustChangeResolver remains
// the explicit override once wired: a true resolver flags the pair even without a flagged
// interim, and a false resolver (the user changed their password in the meantime) drops an
// interim flag.
func TestStepUpHandler_MustChange_ResolverOverridesInterim(t *testing.T) {
	builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	t.Run("resolver true flags the pair even with an unflagged interim", func(t *testing.T) {
		clk := &clock{t: time.Unix(1_700_000_000, 0)}
		svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
		uid := uuid.Must(uuid.NewV7())
		resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
		secret := seedConfirmedEnrollment(t, svc, resolver, clk)

		var captured tokens.Claims[struct{}]
		issuer := mustChangeStepUpIssuer(&captured)

		clk.t = clk.t.Add(mfa.DefaultPeriod)
		rec := httptest.NewRecorder()
		h := contextVerifying(interimClaims(uid, "t1", false),
			mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver,
				mfa.WithMustChangeResolver(func(*http.Request) bool { return true })))
		req := mfaPost(url.Values{"code": {clk.code(t, secret)}})
		req.Header.Set("Authorization", "Bearer interim-access-jwt")
		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, captured.MustChangePassword, "an explicit true resolver must flag the stepped-up pair")
	})

	t.Run("resolver false drops an interim flag (user changed password meanwhile)", func(t *testing.T) {
		clk := &clock{t: time.Unix(1_700_000_000, 0)}
		svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
		uid := uuid.Must(uuid.NewV7())
		resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
		secret := seedConfirmedEnrollment(t, svc, resolver, clk)

		var captured tokens.Claims[struct{}]
		issuer := mustChangeStepUpIssuer(&captured)

		clk.t = clk.t.Add(mfa.DefaultPeriod)
		rec := httptest.NewRecorder()
		h := contextVerifying(interimClaims(uid, "t1", true),
			mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver,
				mfa.WithMustChangeResolver(func(*http.Request) bool { return false })))
		req := mfaPost(url.Values{"code": {clk.code(t, secret)}})
		req.Header.Set("Authorization", "Bearer interim-access-jwt")
		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusNoContent, rec.Code)
		assert.False(t, captured.MustChangePassword, "an explicit false resolver must win over the interim flag")
	})
}
