package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// domainScopedHostCookies is the hand-built misconfiguration at the heart of the defect: the
// __Host- default names kept while a Domain is set.
func domainScopedHostCookies() tokens.Cookies {
	c := tokens.DefaultCookies()
	c.Domain = "example.com"
	return c
}

func rejectingVerifier() *issuertest.MockVerifier[struct{}] {
	return &issuertest.MockVerifier[struct{}]{
		VerifyAccessTokenForTenantFunc: func(_ context.Context, _, _ string) (*tokens.Claims[struct{}], error) {
			return nil, tokens.ErrInvalidToken
		},
	}
}

func acceptingVerifier(validToken string) *issuertest.MockVerifier[struct{}] {
	return &issuertest.MockVerifier[struct{}]{
		VerifyAccessTokenForTenantFunc: func(_ context.Context, tenantID, token string) (*tokens.Claims[struct{}], error) {
			if token != validToken {
				return nil, tokens.ErrInvalidToken
			}
			return &tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), TenantID: tenantID}, nil
		},
	}
}

func okNext(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
	w.WriteHeader(http.StatusOK)
}

// TestCookiesReadHelpersNeverPanic pins that the pure READ helpers never panic: reading a cookie
// from a request must be a lookup, whatever the write-side configuration looks like.
func TestCookiesReadHelpersNeverPanic(t *testing.T) {
	c := domainScopedHostCookies()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)

	var accessOK, refreshOK bool
	require.NotPanics(t, func() { _, accessOK = c.Access(req) }, "Access must never panic")
	require.NotPanics(t, func() { _, refreshOK = c.Refresh(req) }, "Refresh must never panic")
	assert.False(t, accessOK, "no cookie on the request means absent, not a panic")
	assert.False(t, refreshOK, "no cookie on the request means absent, not a panic")
}

// TestRequireAuthNeverPanicsAtRequestTime pins the hard contract: a protected route must never
// panic while serving a request because of cookie configuration. A bad configuration may be
// rejected when the middleware is BUILT (startup), never per request.
func TestRequireAuthNeverPanicsAtRequestTime(t *testing.T) {
	var handler http.HandlerFunc
	rejectedAtConstruction := func() (rejected bool) {
		defer func() {
			if recover() != nil {
				rejected = true
			}
		}()
		handler = tokens.RequireAuth[struct{}](rejectingVerifier(), okNext,
			tokens.WithCookieAuth[struct{}](domainScopedHostCookies()),
			tokens.WithoutHeaderAuth[struct{}](),
		)
		return
	}()
	if rejectedAtConstruction {
		t.Log("configuration rejected at construction time, which is the acceptable failure mode")
		return
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	require.NotPanics(t, func() { handler.ServeHTTP(rec, req) },
		"an unauthenticated GET to a protected route must not panic")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestRequireAuthRejectsInvalidCookiesAtConstruction pins that a hand-built Cookies value keeping
// the __Host- prefix alongside a Domain is refused when the middleware is built.
func TestRequireAuthRejectsInvalidCookiesAtConstruction(t *testing.T) {
	assert.Panics(t, func() {
		tokens.RequireAuth[struct{}](rejectingVerifier(), okNext,
			tokens.WithCookieAuth[struct{}](domainScopedHostCookies()),
		)
	}, "an invalid __Host- + Domain configuration must be rejected at construction")
}

// TestRefreshHandlerWithCookieDomainServesRequest proves WithCookieDomain produces a usable
// handler: the cookie names are demoted out of the __Host- namespace and the request is served.
func TestRefreshHandlerWithCookieDomainServesRequest(t *testing.T) {
	h := tokens.RefreshHandler[struct{}](okRotator(),
		tokens.WithCookieDomain("example.com"),
		tokens.WithInsecureNoOriginCheck(),
	)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Secure-refresh_token", Value: "some-refresh"})
	rec := httptest.NewRecorder()

	require.NotPanics(t, func() { h.ServeHTTP(rec, req) })
	require.Equal(t, http.StatusNoContent, rec.Code)

	written := rec.Result().Cookies()
	require.Len(t, written, 2)
	for _, c := range written {
		assert.False(t, strings.HasPrefix(c.Name, "__Host-"), "name %q must be demoted", c.Name)
		assert.Equal(t, "example.com", c.Domain)
		assert.True(t, c.Secure, "demoting __Host- must not drop Secure")
	}
}

// TestRefreshHandlerWithInsecureCookiesServesPlainHTTP proves the documented local-dev option
// works end to end: no panic, no Secure attribute, and a bare cookie name a browser accepts
// over plain HTTP.
func TestRefreshHandlerWithInsecureCookiesServesPlainHTTP(t *testing.T) {
	h := tokens.RefreshHandler[struct{}](okRotator(),
		tokens.WithInsecureCookies(),
		tokens.WithInsecureNoOriginCheck(),
	)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Host = "localhost:8080"
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "some-refresh"})
	rec := httptest.NewRecorder()

	require.NotPanics(t, func() { h.ServeHTTP(rec, req) })
	require.Equal(t, http.StatusNoContent, rec.Code)

	written := rec.Result().Cookies()
	require.Len(t, written, 2)
	names := make([]string, 0, len(written))
	for _, c := range written {
		names = append(names, c.Name)
		assert.False(t, c.Secure, "WithInsecureCookies must clear Secure")
		assert.False(t, strings.HasPrefix(c.Name, "__"), "name %q must carry no browser-enforced prefix", c.Name)
	}
	assert.ElementsMatch(t, []string{"access_token", "refresh_token"}, names)
}
