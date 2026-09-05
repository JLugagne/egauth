package oauth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for SEC-OAU-06: Sanitize Host and X-Forwarded-Proto in redirect_uri derivation.

func TestBeginHandler_UntrustedHostRejected(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	handler := BeginHandler(p, WithAllowedHosts("app.example.com", "auth.example.com"))

	req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
	req.Host = "evil.attacker.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid or untrusted host")
}

func TestBeginHandler_InvalidHostSyntaxRejected(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	handler := BeginHandler(p) // even without WithAllowedHosts, malformed host must be rejected

	invalidHosts := []string{
		"evil.attacker.com/oauth/begin",
		"user@evil.attacker.com",
		"app.example.com evil.com",
		"evil.com:invalidport",
		"evil.com:99999",
		"evil.com?param=value",
		"evil.com#fragment",
		"evil.com\\attacker",
	}

	for _, badHost := range invalidHosts {
		t.Run(badHost, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
			req.Host = badHost
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), "invalid or untrusted host")
		})
	}
}

func TestBeginHandler_AllowedHostSucceeds(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	handler := BeginHandler(p, WithAllowedHosts("app.example.com"))

	cases := []struct {
		name       string
		host       string
		wantHost   string
		proto      string
		wantScheme string
	}{
		{"exact match", "app.example.com", "app.example.com", "https", "https"},
		{"case insensitive", "APP.EXAMPLE.COM", "APP.EXAMPLE.COM", "https", "https"},
		{"with port", "app.example.com:8443", "app.example.com:8443", "https", "https"},
		{"http scheme", "app.example.com", "app.example.com", "http", "http"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
			req.Host = tc.host
			req.Header.Set("X-Forwarded-Proto", tc.proto)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusFound, rec.Code)

			loc, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)

			redirectURI := loc.Query().Get("redirect_uri")
			expected := tc.wantScheme + "://" + tc.wantHost + "/oauth/begin"
			assert.Equal(t, expected, redirectURI)
		})
	}
}

func TestCallbackHandler_UntrustedHostRejected(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	linker := &stubLinker{}
	issuer := &stubIssuer{}
	handler := CallbackHandler[struct{}](p, linker, issuer, claimsOf,
		WithAllowedHosts("app.example.com"))

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state=xyz&code=abc", nil)
	req.Host = "evil.attacker.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "untrusted_host")
}

func TestCallbackHandler_AllowedHostSucceeds(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)

	beginReq := httptest.NewRequest(http.MethodGet, "/auth/test/login", nil)
	beginReq.Host = "app.example.com"
	beginRec := httptest.NewRecorder()
	BeginHandler(p, WithAllowedHosts("app.example.com"))(beginRec, beginReq)
	require.Equal(t, http.StatusFound, beginRec.Code)

	var stateCookie *http.Cookie
	for _, c := range beginRec.Result().Cookies() {
		if c.Name == DefaultStateCookieName {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie)
	loc, err := url.Parse(beginRec.Result().Header.Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/test/callback?state="+state+"&code=auth-code", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	if stateCookie != nil {
		req.AddCookie(stateCookie)
	}

	CallbackHandler[struct{}](p, linker, issuer, claimsOf, WithAllowedHosts("app.example.com"))(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "u@example.com", linker.gotEmail)
}

func TestRequestScheme_Sanitization(t *testing.T) {
	t.Run("TLS connection is always https", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("X-Forwarded-Proto", "http")

		assert.Equal(t, "https", requestScheme(req))
	})

	t.Run("X-Forwarded-Proto https", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Proto", "https")

		assert.Equal(t, "https", requestScheme(req))
	})

	t.Run("X-Forwarded-Proto HTTPS with whitespace", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Proto", "  HTTPS  ")

		assert.Equal(t, "https", requestScheme(req))
	})

	t.Run("X-Forwarded-Proto http", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Proto", "http")

		assert.Equal(t, "http", requestScheme(req))
	})

	t.Run("Arbitrary / malicious scheme falls back to http", func(t *testing.T) {
		maliciousSchemes := []string{
			"javascript:alert(1)",
			"ftp",
			"data",
			"evil://attack",
			"",
			" ",
		}

		for _, s := range maliciousSchemes {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Forwarded-Proto", s)
			assert.Equal(t, "http", requestScheme(req), "scheme %q must fall back to http", s)
		}
	})
}
