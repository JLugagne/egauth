package tokens_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/tokens"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultCookiesKeepHostPrefix pins that the secure default is untouched: __Host- names, no
// Domain, Path="/" and Secure.
func TestDefaultCookiesKeepHostPrefix(t *testing.T) {
	c := tokens.DefaultCookies()
	assert.Equal(t, "__Host-access_token", c.AccessName)
	assert.Equal(t, "__Host-refresh_token", c.RefreshName)
	assert.NoError(t, c.Validate())
}

// TestCookiesWithDomainDemotesToSecurePrefix proves scoping to a domain yields a VALID value: the
// __Host- prefix is demoted to __Secure-, which browsers accept alongside a Domain.
func TestCookiesWithDomainDemotesToSecurePrefix(t *testing.T) {
	c := tokens.DefaultCookies().WithDomain("example.com")

	assert.Equal(t, "__Secure-access_token", c.AccessName)
	assert.Equal(t, "__Secure-refresh_token", c.RefreshName)
	assert.Equal(t, "example.com", c.Domain)
	assert.False(t, c.Insecure, "demotion must not silently drop Secure")
	assert.NoError(t, c.Validate())
}

// TestCookiesWithPathDemotesToBareName proves a path other than "/" drops the prefix entirely,
// since __Host- requires Path="/".
func TestCookiesWithPathDemotesToBareName(t *testing.T) {
	c := tokens.DefaultCookies().WithPath("/app")

	assert.Equal(t, "access_token", c.AccessName)
	assert.Equal(t, "refresh_token", c.RefreshName)
	assert.Equal(t, "/app", c.Path)
	assert.Equal(t, "/app", c.RefreshPath)
	assert.NoError(t, c.Validate())
}

// TestCookiesWithRefreshPathDemotesRefreshOnly proves scoping only the refresh cookie leaves the
// access cookie's host-lock intact.
func TestCookiesWithRefreshPathDemotesRefreshOnly(t *testing.T) {
	c := tokens.DefaultCookies().WithRefreshPath("/auth/refresh")

	assert.Equal(t, "__Host-access_token", c.AccessName, "the access cookie is still host-locked")
	assert.Equal(t, "refresh_token", c.RefreshName)
	assert.NoError(t, c.Validate())
}

// TestCookiesWithInsecureDemotesBothNames proves the local-dev opt-out yields bare names: browsers
// reject both __Host- and __Secure- on a non-Secure cookie.
func TestCookiesWithInsecureDemotesBothNames(t *testing.T) {
	c := tokens.DefaultCookies().WithInsecure()

	assert.Equal(t, "access_token", c.AccessName)
	assert.Equal(t, "refresh_token", c.RefreshName)
	assert.True(t, c.Insecure)
	assert.NoError(t, c.Validate())
}

// TestCookiesWithDomainThenInsecureStaysValid pins that the demotion is order-independent: a
// __Secure- name produced by WithDomain is demoted again when Secure is later dropped.
func TestCookiesWithDomainThenInsecureStaysValid(t *testing.T) {
	c := tokens.DefaultCookies().WithDomain("example.com").WithInsecure()

	assert.Equal(t, "access_token", c.AccessName)
	assert.Equal(t, "refresh_token", c.RefreshName)
	require.NoError(t, c.Validate())

	c = tokens.DefaultCookies().WithInsecure().WithDomain("example.com")
	assert.Equal(t, "access_token", c.AccessName)
	assert.Equal(t, "refresh_token", c.RefreshName)
	assert.NoError(t, c.Validate())
}

// TestValidateRejectsSecurePrefixWithoutSecure pins the __Secure- rule: the prefix requires the
// Secure attribute, exactly like the browser does.
func TestValidateRejectsSecurePrefixWithoutSecure(t *testing.T) {
	c := tokens.Cookies{
		AccessName:  "__Secure-access_token",
		RefreshName: "__Secure-refresh_token",
		Path:        "/",
		RefreshPath: "/",
		Insecure:    true,
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "__Secure-")
}

// TestCookiesCustomNamesAreNeverRewritten pins that only prefixed names are touched: a caller's own
// name survives every option untouched.
func TestCookiesCustomNamesAreNeverRewritten(t *testing.T) {
	c := tokens.Cookies{AccessName: "at", RefreshName: "rt", Path: "/", RefreshPath: "/"}

	out := c.WithDomain("example.com").WithPath("/app").WithInsecure()
	assert.Equal(t, "at", out.AccessName)
	assert.Equal(t, "rt", out.RefreshName)
	assert.NoError(t, out.Validate())
}

// TestRequireAuthDomainScopedCookiesServeUnauthenticatedGET is the end-to-end shape of the fix on
// the read path: a protected route configured with domain-scoped cookies answers 401 to an
// unauthenticated GET.
func TestRequireAuthDomainScopedCookiesServeUnauthenticatedGET(t *testing.T) {
	handler := tokens.RequireAuth[struct{}](rejectingVerifier(), okNext,
		tokens.WithCookieAuth[struct{}](tokens.DefaultCookies().WithDomain("example.com")),
		tokens.WithoutHeaderAuth[struct{}](),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	require.NotPanics(t, func() { handler.ServeHTTP(rec, req) })
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestRequireAuthReadsDemotedAccessCookie proves the read path uses the demoted name, so a browser
// cookie written by the matching handler configuration is actually found.
func TestRequireAuthReadsDemotedAccessCookie(t *testing.T) {
	cookies := tokens.DefaultCookies().WithInsecure()
	handler := tokens.RequireAuth[struct{}](acceptingVerifier("good"), okNext,
		tokens.WithCookieAuth[struct{}](cookies),
		tokens.WithoutHeaderAuth[struct{}](),
	)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "good"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
