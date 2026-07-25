package oauth

import (
	"context"
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

// TestCallbackHandler_UnresolvedTenantFailsClosed drives a callback whose configured resolver
// cannot map the request (it returns ""). The state cookie carries the same "" tenant, so the
// tenant-binding gate passes and the identity would be linked into the single-tenant ("")
// partition — where bootstrap/operator accounts live. The callback must refuse instead.
func TestCallbackHandler_UnresolvedTenantFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)

	// A begin flow with no resolver at all (single-tenant) mints a state cookie bound to "".
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &countingLinker{
		stubLinker: stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}},
	}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithTenantResolver(func(*http.Request) string { return "" }))

	assert.Equal(t, http.StatusForbidden, rec.Code, "an unresolvable tenant must be refused")
	assert.Zero(t, linker.calls, "LinkOrCreateIdentity must not run for an unresolved tenant")
	assert.Nil(t, cookieNamed(rec, tokens.DefaultAccessCookieName), "no session may be issued")
}

// TestBeginHandler_UnresolvedTenantFailsClosed proves the flow is refused at its start rather
// than minting a state cookie bound to the "" partition.
func TestBeginHandler_UnresolvedTenantFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)

	rec := httptest.NewRecorder()
	BeginHandler(p, WithRedirectURL(testRedirect),
		WithTenantResolver(func(*http.Request) string { return "" }))(
		rec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, cookieNamed(rec, DefaultStateCookieName), "no state cookie may be minted")
}

// TestDynamicCallbackHandler_UnresolvedTenantFailsClosed proves the dynamic variant refuses
// before it even looks up a provider.
func TestDynamicCallbackHandler_UnresolvedTenantFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)

	store := NewMemoryStore()
	store.AddProvider("", p)

	stateCookie, state := runDynamicBegin(t, store, p.Name(), WithRedirectURL(testRedirect))

	linker := &countingLinker{
		stubLinker: stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}},
	}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runDynamicCallback(t, store, p.Name(), linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithTenantResolver(func(*http.Request) string { return "" }))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, linker.calls)
}

// TestCallbackHandler_SingleTenantWithoutResolverStillWorks pins that single-tenant
// deployments — which never configure a resolver — keep using the "" partition.
func TestCallbackHandler_SingleTenantWithoutResolverStillWorks(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)

	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &countingLinker{
		stubLinker: stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}},
	}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, 1, linker.calls)
	assert.Equal(t, "", linker.tenant)
}

// countingLinker records how many times the identity link ran and under which tenant.
type countingLinker struct {
	stubLinker
	calls  int
	tenant string
}

func (l *countingLinker) LinkOrCreateIdentity(ctx context.Context, tenantID, provider, providerID, email string, emailVerified bool) (*identity.User, error) {
	l.calls++
	l.tenant = tenantID
	return l.stubLinker.LinkOrCreateIdentity(ctx, tenantID, provider, providerID, email, emailVerified)
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}
