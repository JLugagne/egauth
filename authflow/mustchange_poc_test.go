package authflow_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokenmemory "github.com/JLugagne/egauth/tokens/memory"
	"github.com/stretchr/testify/require"
)

// A temporary-password user completing a magic-link login through a unified flow engine that was
// NOT configured with WithPasswordPolicyChecker must still receive a session carrying
// Claims.MustChangePassword=true. identity.MagicLinkLoginHandler resolves the flag from the
// credential before delegating and the engine ORs it into the flow, so the email-link path
// cannot silently drop the forced-change gate.
func TestPoC_AuthFlow_DropsMustChangePassword(t *testing.T) {
	ctx := context.Background()

	store := identitymemory.NewStore()
	svc := identity.NewService(store, argon2.NewHasher(), policy.NewDefaultPolicy())

	// Admin provisions an account with a temporary password -> MustChangePassword=true.
	const email = "temp-user@example.com"
	const tempPassword = "TempPassw0rd!"
	user, err := svc.AdminCreateUser(ctx, "", email, tempPassword)
	require.NoError(t, err)

	flagged, err := svc.PasswordChangeRequired(ctx, "", user.ID)
	require.NoError(t, err)
	require.True(t, flagged, "precondition: the credential must be flagged for a forced change")

	// The user can request a magic link for this account (RequestMagicLink works for accounts
	// that have a password identity too).
	magicToken, _, err := svc.RequestMagicLink(ctx, "", email)
	require.NoError(t, err)
	require.NotEmpty(t, magicToken)

	issuer := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokenmemory.NewStore[struct{}](),
		SecretKey:  "authflow-poc-signing-key-at-least-32-bytes!",
		Issuer:     "authflow-poc",
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
	})

	claimsOf := func(u *identity.User) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: u.ID, TenantID: u.TenantID}
	}
	cookies := tokens.Cookies{
		AccessName:  "access_token",
		RefreshName: "refresh_token",
		Path:        "/",
		RefreshPath: "/",
		Insecure:    true,
	}

	// Consumer wiring: a unified flow engine WITHOUT WithPasswordPolicyChecker — the handler is
	// the only source of the forced-change flag on this path.
	engine, err := authflow.NewEngine([]byte("01234567890123456789012345678901"),
		authflow.WithMinter(authflow.NewJWTMinter[struct{}](issuer, claimsOf, cookies, false)),
	)
	require.NoError(t, err)

	handler := identity.MagicLinkLoginHandler[struct{}](svc, issuer, claimsOf,
		identity.WithAuthFlow(authflow.NewHandlerFlow(engine)),
		identity.WithCookies(cookies),
		identity.WithInsecureNoOriginCheck(),
	)

	form := url.Values{"token": {magicToken}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/magic", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "app.example.com"
	rec := httptest.NewRecorder()
	handler(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code, "magic-link login must succeed")

	var accessToken string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "access_token" {
			accessToken = c.Value
		}
	}
	require.NotEmpty(t, accessToken, "authflow mint must write the access cookie")

	claims, err := issuer.VerifyAccessTokenForTenant(ctx, "", accessToken)
	require.NoError(t, err)

	// The gate middleware must block a must-change session.
	gateReq := httptest.NewRequest(http.MethodGet, "/me", nil)
	gateReq.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	gateRec := httptest.NewRecorder()

	tokens.RequireAuth[struct{}](
		issuer,
		func(w http.ResponseWriter, r *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusNoContent)
		},
		tokens.WithCookieAuth[struct{}](cookies),
		tokens.WithPasswordChangeGate[struct{}]("/auth/change-password"),
	)(gateRec, gateReq)

	t.Logf("must-change flag on authflow-minted token: %v; gated route status: %d",
		claims.MustChangePassword, gateRec.Code)

	require.True(t, claims.MustChangePassword,
		"the authflow-minted token must carry the must-change flag of the credential it authenticated")
	// With a reset URL configured the gate soft-redirects (303) instead of invoking the handler;
	// the point is that it must not let the session through.
	require.Equal(t, http.StatusSeeOther, gateRec.Code,
		"the password-change gate must divert the authflow-minted session to the reset flow")
	require.Contains(t, gateRec.Header().Get("Location"), "/auth/change-password",
		"the diverted session must be sent to the configured reset page")
}
