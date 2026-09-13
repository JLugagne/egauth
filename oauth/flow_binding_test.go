package oauth

import (
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

// TestCallbackHandler_ExchangeUsesTheAdvertisedRedirectURI pins the redirect binding. Begin
// advertises a redirect_uri derived from the begin path; the callback used to RE-derive one from
// its own path and send that to the token endpoint, so the two legs could disagree and the binding
// rested entirely on the provider's own check. The value is now carried in the signed state and
// reused verbatim.
func TestCallbackHandler_ExchangeUsesTheAdvertisedRedirectURI(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _, tokenEndpoint := stubProviderServerWithRecorder(t, &body)

	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))
	require.NotNil(t, stateCookie)

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}
	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))
	require.Equal(t, http.StatusNoContent, rec.Code)

	posted, ok := tokenEndpoint.lastFormValue("redirect_uri")
	require.True(t, ok, "the token exchange must carry a redirect_uri")
	assert.Equal(t, testRedirect, posted,
		"the exchange must use the URI the provider was given, not one re-derived on the callback path")
}

// TestCallbackHandler_RejectsFlowOlderThanStateTTL covers the server-side validity window. The TTL
// was applied only to the cookie's Max-Age, so the server had no notion of the flow's age and an
// out-of-band copy of a correctly-signed cookie stayed valid indefinitely. The issue time is now
// signed into the payload and enforced on the callback.
func TestCallbackHandler_RejectsFlowOlderThanStateTTL(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`

	t.Run("a fresh flow is accepted", func(t *testing.T) {
		p, _ := stubProviderServer(t, &body)
		stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect), WithStateTTL(time.Hour))
		linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
		issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
			AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour),
		}}
		rec := runCallback(t, p, linker, issuer, stateCookie,
			url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
			WithRedirectURL(testRedirect), WithStateTTL(time.Hour))
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("a flow past its TTL is refused", func(t *testing.T) {
		p, _ := stubProviderServer(t, &body)
		// A zero-length TTL makes any already-issued flow immediately stale, which models an
		// out-of-band cookie replayed long after the flow should have expired.
		stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect), WithStateTTL(time.Hour))
		time.Sleep(2 * time.Millisecond)

		linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
		issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
			AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour),
		}}
		rec := runCallback(t, p, linker, issuer, stateCookie,
			url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
			WithRedirectURL(testRedirect), WithStateTTL(time.Millisecond))
		assert.Equal(t, http.StatusForbidden, rec.Code,
			"a flow older than WithStateTTL must be refused by the server")
		assert.Contains(t, rec.Body.String(), "invalid_state")
	})
}

// TestBeginHandler_AllowedHostsHonoursPort pins the allowlist semantics: an entry naming a port
// admits only that port. Reducing both sides to the hostname admitted any port on the allowed host,
// which is a different service and may be an attacker's own listener.
func TestBeginHandler_AllowedHostsHonoursPort(t *testing.T) {
	body := `{"sub":"prov-1"}`
	p, _ := stubProviderServer(t, &body)

	call := func(t *testing.T, host string, opts ...HandlerOption) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/test/login", nil)
		req.Host = host
		BeginHandler(p, withTestStateKey(opts)...)(rec, req)
		return rec
	}

	t.Run("the allowlisted port is accepted", func(t *testing.T) {
		rec := call(t, "app.example.com:8443", WithAllowedHosts("app.example.com:8443"))
		assert.Equal(t, http.StatusFound, rec.Code)
		loc := rec.Header().Get("Location")
		// requestScheme uses r.TLS, so a plain httptest request is http — the point is that the
		// PORT the allowlist named survives into the advertised redirect_uri.
		assert.Contains(t, loc, url.QueryEscape("http://app.example.com:8443/"),
			"the advertised redirect_uri must keep the allowlisted port")
	})

	t.Run("a different port on the same host is refused", func(t *testing.T) {
		rec := call(t, "app.example.com:9999", WithAllowedHosts("app.example.com:8443"))
		assert.Equal(t, http.StatusBadRequest, rec.Code,
			"a port the allowlist did not name must not be admitted")
	})

	t.Run("an entry without a port stays host-only", func(t *testing.T) {
		rec := call(t, "app.example.com:9999", WithAllowedHosts("app.example.com"))
		assert.Equal(t, http.StatusFound, rec.Code,
			"a host-only entry keeps working for deployments behind a default-port proxy")
	})

	t.Run("a lookalike host is still refused", func(t *testing.T) {
		rec := call(t, "app.example.com.evil.example", WithAllowedHosts("app.example.com"))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
