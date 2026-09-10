package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokenmemory "github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pocRedirect = "https://app.example.com/auth/test/callback"

// pocProvider stands up a local provider (token endpoint) and returns a Provider whose
// Exchange yields a fixed, verified email for sub "prov-1". Self-contained so the regression
// test can drive the full callback flow without a userinfo round trip.
func pocProvider(t *testing.T) *Provider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"at-123","token_type":"bearer"}`)
	}))
	t.Cleanup(srv.Close)
	fetch := func(_ context.Context, _ *http.Client, _ string) (*UserInfo, error) {
		return &UserInfo{ProviderID: "prov-1", Email: "dual-identity@example.com", EmailVerified: true}, nil
	}
	return New("test", "cid", "csecret", srv.URL+"/auth", srv.URL+"/token",
		[]string{"email"}, fetch, WithHTTPClient(srv.Client()), WithInsecureURLs())
}

// TestPoC_OAuthCallback_DropsMustChangePassword proves the forced-password-change gate holds on
// the native OAuth callback path (no WithAuthFlow): an account provisioned with a temporary
// password (MustChangePassword=true) that also has a linked OAuth identity must receive a
// session whose Claims.MustChangePassword is true, so the account cannot escape
// tokens.WithPasswordChangeGate by signing in through the provider.
func TestPoC_OAuthCallback_DropsMustChangePassword(t *testing.T) {
	ctx := context.Background()
	stateKey := []byte("01234567890123456789012345678901")

	store := identitymemory.NewStore()
	svc := identity.NewService(store, argon2.NewHasher(), policy.NewDefaultPolicy())

	const email = "dual-identity@example.com"
	user, err := svc.AdminCreateUser(ctx, "", email, "TempPassw0rd!")
	require.NoError(t, err)

	flagged, err := svc.PasswordChangeRequired(ctx, "", user.ID)
	require.NoError(t, err)
	require.True(t, flagged, "precondition: credential flagged for forced change")

	// The account also has an OAuth identity (explicit linking from an authenticated session, or
	// a helpdesk password reset on an OAuth-provisioned account).
	require.NoError(t, store.AddIdentity(ctx, "", &identity.Identity{
		UserID:     user.ID,
		Provider:   "test",
		ProviderID: "prov-1",
	}))

	p := pocProvider(t)

	// Begin: capture the signed state cookie and the state parameter.
	beginRec := httptest.NewRecorder()
	BeginHandler(p, WithStateSigningKey(stateKey), WithRedirectURL(pocRedirect))(
		beginRec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))
	require.Equal(t, http.StatusFound, beginRec.Code)
	var stateCookie *http.Cookie
	for _, c := range beginRec.Result().Cookies() {
		if c.Name == DefaultStateCookieName {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie, "Begin must set the state cookie")
	loc, err := url.Parse(beginRec.Header().Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)

	issuer := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokenmemory.NewStore[struct{}](),
		SecretKey:  "oauth-poc-signing-key-at-least-32-bytes!!",
		Issuer:     "oauth-poc",
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
	})
	claimsOf := func(u *identity.User) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: u.ID, TenantID: u.TenantID}
	}
	cookies := tokens.DefaultCookies()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/auth/test/callback?"+url.Values{"state": {state}, "code": {"auth-code"}}.Encode(), nil)
	req.AddCookie(stateCookie)
	CallbackHandler[struct{}](p, svc, issuer, claimsOf,
		WithStateSigningKey(stateKey), WithRedirectURL(pocRedirect),
	)(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code, "callback must complete")

	var accessToken string
	for _, c := range rec.Result().Cookies() {
		if c.Name == tokens.DefaultAccessCookieName {
			accessToken = c.Value
		}
	}
	require.NotEmpty(t, accessToken)

	claims, err := issuer.VerifyAccessTokenForTenant(ctx, "", accessToken)
	require.NoError(t, err)

	gateReq := httptest.NewRequest(http.MethodGet, "/me", nil)
	gateReq.AddCookie(&http.Cookie{Name: tokens.DefaultAccessCookieName, Value: accessToken})
	gateRec := httptest.NewRecorder()
	tokens.RequireAuth[struct{}](
		issuer,
		func(w http.ResponseWriter, r *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusNoContent)
		},
		tokens.WithCookieAuth[struct{}](cookies),
		tokens.WithPasswordChangeGate[struct{}]("/auth/change-password"),
	)(gateRec, gateReq)

	t.Logf("must-change flag on OAuth callback token: %v; gated route status: %d",
		claims.MustChangePassword, gateRec.Code)

	require.True(t, claims.MustChangePassword,
		"the OAuth callback must stamp the linked credential's must-change flag onto the session")
	// With a reset URL configured the gate soft-redirects (303) instead of invoking the handler;
	// the point is that it must not let the session through.
	require.Equal(t, http.StatusSeeOther, gateRec.Code,
		"the password-change gate must divert the OAuth-issued session to the reset flow")
	require.Contains(t, gateRec.Header().Get("Location"), "/auth/change-password",
		"the diverted session must be sent to the configured reset page")
}

// TestCallbackHandler_PasswordChangeCheckFailsClosed proves the callback aborts without issuing
// any session when the linked credential's forced-change state cannot be resolved: a transient
// store failure must never yield an unflagged session.
func TestCallbackHandler_PasswordChangeCheckFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{
		user:          &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"},
		mustChangeErr: errors.New("identity store unavailable"),
	}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, tokens.DefaultAccessCookieName, c.Name,
			"a failed forced-change lookup must not mint an access cookie")
		assert.NotEqual(t, tokens.DefaultRefreshCookieName, c.Name,
			"a failed forced-change lookup must not mint a refresh cookie")
	}
	assert.Empty(t, issuer.gotClaims.Subject, "no token may be issued when the check fails")
}

// TestCallbackHandler_UnflaggedCredentialIssuesUnflaggedSession proves an account that is not
// flagged for a forced password change is unaffected: the callback completes and the issued
// claims stay unflagged.
func TestCallbackHandler_UnflaggedCredentialIssuesUnflaggedSession(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NotEmpty(t, issuer.gotClaims.Subject)
	assert.False(t, issuer.gotClaims.MustChangePassword,
		"an unflagged credential must not produce a flagged session")
}
