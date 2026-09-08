package oauth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebAuditUnsignedStateCookieForgedBindingAccepted(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)

	// WEB-01: with no WithStateSigningKey configured, the state cookie is an
	// unauthenticated 5-field value (packState shape, "."-joined). An attacker
	// who can write cookies (subdomain sharing a parent Domain, or plaintext
	// HTTP when Insecure cookies are on) mints their own binding and the
	// callback treats it as genuine: state comparison, provider binding and
	// tenant binding all pass, and auth cookies are issued.
	forged := "attacker-state" + "." + "" + "." + "" + "." +
		base64.RawURLEncoding.EncodeToString([]byte("test")) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(""))
	forgedCookie := &http.Cookie{Name: DefaultStateCookieName, Value: forged}

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}
	rec := runCallback(t, p, linker, issuer, forgedCookie,
		url.Values{"state": {"attacker-state"}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))
	require.Equal(t, http.StatusNoContent, rec.Code,
		"POOR DEFAULT DEMONSTRATED: self-minted unsigned state cookie drove issuance; want 403 invalid_state")
	assert.Equal(t, "test", linker.gotProvider, "forged provider binding was honored")
}

func TestWebAuditSignedStateCookieRejectsForgery(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)

	forged := "attacker-state" + "." + "" + "." + "" + "." +
		base64.RawURLEncoding.EncodeToString([]byte("test")) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(""))
	forgedCookie := &http.Cookie{Name: DefaultStateCookieName, Value: forged}

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}
	rec := runCallback(t, p, linker, issuer, forgedCookie,
		url.Values{"state": {"attacker-state"}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect),
		WithStateSigningKey([]byte("0123456789abcdef0123456789abcdef")))
	require.Equal(t, http.StatusForbidden, rec.Code,
		"with WithStateSigningKey, a forged state cookie must be rejected")
}

func TestWebAuditStateCookieAttributes(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)

	rec := httptest.NewRecorder()
	BeginHandler(p, WithRedirectURL(testRedirect))(
		rec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))
	require.Equal(t, http.StatusFound, rec.Code)
	res := rec.Result()
	var sc *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == DefaultStateCookieName {
			sc = c
		}
	}
	require.NotNil(t, sc, "begin must set the state cookie")
	assert.True(t, sc.HttpOnly, "state cookie must be HttpOnly")
	assert.True(t, sc.Secure, "state cookie must be Secure by default")
	assert.Equal(t, http.SameSiteLaxMode, sc.SameSite, "state cookie must default to Lax")
	assert.Empty(t, sc.Domain, "default state cookie must stay host-only (no Domain)")
	assert.NotContains(t, sc.Name, "__Host-",
		"state cookie name is not __Host- prefixed, so a shared parent Domain would make it tossable (see WEB-01)")
	assert.Empty(t, res.Header.Get("Access-Control-Allow-Origin"),
		"handlers must not emit CORS headers")
}

func TestWebAuditBeginDerivesRedirectURIFromHostHeader(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)

	// WEB-02: with neither WithRedirectURL nor WithAllowedHosts, the
	// redirect_uri sent to the provider is built from the request Host header
	// (and the spoofable X-Forwarded-Proto header).
	req := httptest.NewRequest(http.MethodGet, "http://evil.example/auth/test/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	BeginHandler(p)(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Result().Header.Get("Location"))
	require.NoError(t, err)
	redirectURI := loc.Query().Get("redirect_uri")
	assert.True(t, strings.HasPrefix(redirectURI, "https://evil.example/"),
		"POOR DEFAULT DEMONSTRATED: untrusted Host/X-Forwarded-Proto flowed into redirect_uri: %s", redirectURI)
}

func TestWebAuditBeginAllowedHostsBlocksEvilHost(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)

	req := httptest.NewRequest(http.MethodGet, "http://evil.example/auth/test/login", nil)
	rec := httptest.NewRecorder()
	BeginHandler(p, WithAllowedHosts("app.example.com"))(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code,
		"WithAllowedHosts must reject a non-allowlisted Host")
}
