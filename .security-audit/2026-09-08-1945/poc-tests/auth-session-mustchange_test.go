package mfa_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	mfamemory "github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokenmemory "github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// auditStepUpSetup seeds an MFA service with a confirmed TOTP enrollment and two
// known single-use recovery codes, plus a real JWT issuer/verifier pair.
func auditStepUpSetup(t *testing.T, uid uuid.UUID) (*mfa.Service, *jwt.Service[struct{}]) {
	t.Helper()
	ctx := context.Background()
	mstore := mfamemory.NewStore()
	now := time.Now()
	require.NoError(t, mstore.SaveTOTP(ctx, "", &mfa.TOTPEnrollment{
		UserID:      uid,
		Secret:      "JBSWY3DPEHPK3PXP",
		CreatedAt:   now,
		ConfirmedAt: &now,
	}))
	require.NoError(t, mstore.ReplaceRecoveryCodes(ctx, "", uid, []string{
		mfa.HashRecoveryCode("AAAA-BBBB-CCCC-DDDD"),
		mfa.HashRecoveryCode("EEEE-FFFF-GGGG-HHHH"),
	}))
	msvc := mfa.NewService(mstore)
	issuer := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokenmemory.NewStore[struct{}](),
		SecretKey:  "0123456789abcdef0123456789abcdef",
		Issuer:     "audit-poc",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: time.Hour,
	})
	_ = ctx
	return &msvc, issuer
}

// auditStepUp runs one recovery-code step-up ceremony end-to-end (interim token
// minted exactly as identity.LoginHandler's MFA gate mints it: AMR=[pwd] plus
// the MustChangePassword flag) and returns the verified stepped-up claims.
func auditStepUp(t *testing.T, msvc *mfa.Service, issuer *jwt.Service[struct{}], uid uuid.UUID, recoveryCode string, extraOpts ...mfa.HandlerOption) (int, *tokens.Claims[struct{}]) {
	t.Helper()
	ctx := context.Background()

	// Interim token: what a must-change, MFA-enrolled user holds after the
	// password step (LoginHandler stamps MustChangePassword=true here).
	interim, err := issuer.IssueTokenPair(ctx, tokens.Claims[struct{}]{
		Subject:            uid,
		TenantID:           "",
		AMR:                []string{tokens.AMRPassword},
		MustChangePassword: true,
		ExpiresAt:          time.Now().Add(5 * time.Minute),
	})
	require.NoError(t, err)

	// Typical host claims builder: builds FRESH claims from the user record and
	// does not re-check the forced-change flag (the documented resolver is what
	// is supposed to carry it — and it is nil by default).
	claimsOf := func(context.Context, uuid.UUID, string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: uid, TenantID: ""}
	}
	opts := append([]mfa.HandlerOption{
		mfa.WithUserResolver(tokens.UserResolverFromContext),
	}, extraOpts...)
	inner := mfa.StepUpHandler[struct{}](*msvc, issuer, claimsOf, opts...)
	h := tokens.ContextMiddleware[struct{}](issuer, inner)

	form := url.Values{}
	form.Set("recovery_code", recoveryCode)
	req := httptest.NewRequest(http.MethodPost, "/mfa/step-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+interim.AccessToken)
	req.Header.Set("Origin", "https://"+req.Host)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		return rec.Code, nil
	}
	var access string
	for _, c := range rec.Result().Cookies() {
		if c.Name == tokens.DefaultAccessCookieName {
			access = c.Value
		}
	}
	require.NotEmpty(t, access, "step-up must set an access cookie")
	got, err := issuer.VerifyAccessTokenForTenant(ctx, "", access)
	require.NoError(t, err)
	return rec.Code, got
}

// TestAuditPoc_StepUpDropsMustChangeByDefault demonstrates a forced-password-change
// bypass: the interim token carries MustChangePassword=true, but the stepped-up
// full pair issued by the DEFAULT StepUpHandler wiring (no MustChangeResolver)
// drops the flag. The new refresh family therefore persists flag=false across
// every silent refresh, and WithPasswordChangeGate stops diverting the session.
func TestAuditPoc_StepUpDropsMustChangeByDefault(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	msvc, issuer := auditStepUpSetup(t, uid)

	code, got := auditStepUp(t, msvc, issuer, uid, "AAAA-BBBB-CCCC-DDDD")
	require.Equal(t, http.StatusNoContent, code, "step-up with a valid recovery code must succeed")
	require.NotNil(t, got)
	require.False(t, got.MustChangePassword,
		"VULNERABILITY DEMONSTRATED: stepped-up pair lost MustChangePassword=true from the interim token")
	require.Contains(t, got.AMR, tokens.AMRMFA, "sanity: the pair is the stepped-up one (carries mfa)")
}

// TestAuditPoc_StepUpPreservesMustChangeWithResolver proves the documented
// remediation works: wiring tokens.MustChangeResolverFromContext keeps the flag
// on the stepped-up pair.
func TestAuditPoc_StepUpPreservesMustChangeWithResolver(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	msvc, issuer := auditStepUpSetup(t, uid)

	code, got := auditStepUp(t, msvc, issuer, uid, "AAAA-BBBB-CCCC-DDDD",
		mfa.WithMustChangeResolver(tokens.MustChangeResolverFromContext[struct{}]))
	require.Equal(t, http.StatusNoContent, code)
	require.NotNil(t, got)
	require.True(t, got.MustChangePassword,
		"with the resolver wired, the stepped-up pair must stay flagged")
}
