package webapp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/identity"
	identitymem "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/basic"
	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	disableTestEmail    = "victim@example.com"
	disableTestPassword = "Correct horse battery staple 1!"
)

type presetHarness struct {
	handler    http.Handler
	idStore    *identitymem.Store
	idSvc      identity.Service
	tokenStore basic.Store
}

func newPresetHarness(t *testing.T) *presetHarness {
	t.Helper()

	idStore := identitymem.NewStore()
	idSvc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy())
	tokenStore := basic.NewMemoryStore()

	h, err := webapp.NewWebApp(webapp.Config{
		Identity:   idSvc,
		TokenStore: tokenStore,
		SigningKey: "a-high-entropy-secret-kept-out-of-source-control",
		Issuer:     "test-app",
		// The subject here is account deactivation, not CSRF: drive the endpoints with
		// no Origin header (csrf_test.go covers the origin check itself).
		InsecureNoOriginCheck: true,
	})
	require.NoError(t, err)

	return &presetHarness{handler: h, idStore: idStore, idSvc: idSvc, tokenStore: tokenStore}
}

func (h *presetHarness) postForm(t *testing.T, path string, form url.Values, cookies ...*http.Cookie) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec.Result()
}

func refreshCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()

	name := tokens.DefaultCookies().RefreshName
	for _, c := range resp.Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	t.Fatalf("response carries no %q cookie", name)
	return nil
}

// TestPreset_DisabledUserCannotRefresh proves the shipped preset ends access when an account is
// deactivated: after identity.Service.DisableUser, the preset's own /auth/refresh must refuse to
// rotate the refresh cookie it issued at registration. The preset's ClaimsProvider is the only
// seam that can re-check account status on rotation, so a provider that ignores it lets a
// suspended user renew their session forever (each rotation resetting the refresh expiry).
func TestPreset_DisabledUserCannotRefresh(t *testing.T) {
	ctx := context.Background()
	h := newPresetHarness(t)

	resp := h.postForm(t, "/auth/register", url.Values{
		"email":    {disableTestEmail},
		"password": {disableTestPassword},
	})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	rc := refreshCookie(t, resp)

	user, err := h.idStore.FindUserByEmail(ctx, "", disableTestEmail)
	require.NoError(t, err)
	require.NoError(t, h.idSvc.DisableUser(ctx, "", user.ID))

	// Repeat the attempt: a broken preset not only accepts the first refresh, it renews the
	// refresh lifetime on every rotation, so access is retained indefinitely.
	for attempt := range 5 {
		got := h.postForm(t, "/auth/refresh", url.Values{}, rc)
		assert.Equal(t, http.StatusUnauthorized, got.StatusCode,
			"refresh attempt %d after DisableUser must be refused", attempt+1)
		if next := nextRefreshCookie(got); next != nil {
			rc = next
		}
	}
}

func nextRefreshCookie(resp *http.Response) *http.Cookie {
	name := tokens.DefaultCookies().RefreshName
	for _, c := range resp.Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

// TestPreset_ActiveUserCanRefresh is the counterpart guarantee: the account-status re-check must
// refuse only inactive accounts, never break ordinary silent refresh.
func TestPreset_ActiveUserCanRefresh(t *testing.T) {
	h := newPresetHarness(t)

	resp := h.postForm(t, "/auth/register", url.Values{
		"email":    {disableTestEmail},
		"password": {disableTestPassword},
	})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	rc := refreshCookie(t, resp)

	for attempt := range 3 {
		got := h.postForm(t, "/auth/refresh", url.Values{}, rc)
		require.Equal(t, http.StatusNoContent, got.StatusCode,
			"refresh attempt %d on a live account must rotate", attempt+1)
		rc = refreshCookie(t, got)
	}
}

// TestNewWebApp_RefusesIdentityWithoutRevocationSeam proves the preset fails construction rather
// than mounting handlers whose DisableUser cannot revoke the refresh families it issues.
func TestNewWebApp_RefusesIdentityWithoutRevocationSeam(t *testing.T) {
	cfg := baseConfig()
	cfg.Identity = &servicetest.MockService{}
	cfg.InsecureNoOriginCheck = true

	_, err := webapp.NewWebApp(cfg)
	require.ErrorIs(t, err, webapp.ErrIdentityNotRegisterable)
}

// TestPreset_DisableUserRevokesRefreshFamilies proves the preset wires the tokens account revoker
// into the identity service it is handed, so DisableUser cascades into the token store instead of
// leaving the user's refresh rows live and rotatable.
func TestPreset_DisableUserRevokesRefreshFamilies(t *testing.T) {
	ctx := context.Background()
	h := newPresetHarness(t)

	resp := h.postForm(t, "/auth/register", url.Values{
		"email":    {disableTestEmail},
		"password": {disableTestPassword},
	})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	rc := refreshCookie(t, resp)

	user, err := h.idStore.FindUserByEmail(ctx, "", disableTestEmail)
	require.NoError(t, err)
	require.NoError(t, h.idSvc.DisableUser(ctx, "", user.ID))

	_, err = h.tokenStore.FindRefreshToken(ctx, "", tokens.HashToken(rc.Value))
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound,
		"DisableUser must revoke the refresh families the preset issued")
}
