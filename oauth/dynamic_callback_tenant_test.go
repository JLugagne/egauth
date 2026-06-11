package oauth

// Regression test for TASK-092: DynamicCallbackHandler must resolve the tenant exactly
// once and thread the pre-resolved value through the security gate and the identity link,
// so that an impure resolver (one that returns different values on successive calls within
// the same request) cannot route the identity write to the wrong tenant partition.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tenantCapturingLinker records the tenantID that was passed to LinkOrCreateIdentity.
type tenantCapturingLinker struct {
	stubLinker
	gotTenant string
}

func (l *tenantCapturingLinker) LinkOrCreateIdentity(ctx context.Context, tenantID, provider, providerID, email string, emailVerified bool) (*identity.User, error) {
	l.gotTenant = tenantID
	return l.stubLinker.LinkOrCreateIdentity(ctx, tenantID, provider, providerID, email, emailVerified)
}

// TestDynamicCallbackHandler_ImpureResolverUsesPreResolvedTenant verifies that even when
// the tenant resolver is impure (returns a different value on successive calls within the
// same request), the handler resolves the tenant exactly once at the top and threads that
// single value through the cookieTenant gate and LinkOrCreateIdentity.
//
// Attack scenario: the callback resolver returns "tenant-a" on its first call (provider
// lookup) and "tenant-b" on subsequent calls (gate check and identity link). Before the
// fix, the delegated CallbackHandler rebuilt its own handlerConfig from opts and invoked
// cfg.tenant(r) independently on each use; on the third call the resolver returns
// "tenant-b", so the identity gets linked into tenant-b's partition even though tenant-a's
// provider minted the token. The fix pre-resolves the tenant once and injects it as a
// constant resolver, ensuring all three uses see the same value.
func TestDynamicCallbackHandler_ImpureResolverUsesPreResolvedTenant(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)

	// Two separate tenant partitions, both holding the same provider for simplicity.
	store := NewMemoryStore()
	store.AddProvider("tenant-a", p)
	store.AddProvider("tenant-b", p)

	// The begin flow always uses a pure resolver for tenant-a.
	stateCookie, state := runDynamicBegin(t, store, p.Name(),
		WithRedirectURL(testRedirect),
		WithTenantResolver(func(*http.Request) string { return "tenant-a" }))

	// The callback resolver is impure: it returns "tenant-a" on its first call (provider
	// lookup) but "tenant-b" on every subsequent call (gate check, identity link).
	// With the fix, only the first call's result ("tenant-a") is ever used.
	var callCount atomic.Int32
	callbackResolver := func(*http.Request) string {
		n := callCount.Add(1)
		if n == 1 {
			return "tenant-a"
		}
		return "tenant-b"
	}

	linker := &tenantCapturingLinker{
		stubLinker: stubLinker{user: &identity.User{ID: uuid.New(), Email: "u@example.com"}},
	}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runDynamicCallback(t, store, p.Name(), linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithTenantResolver(callbackResolver))

	require.Equal(t, http.StatusNoContent, rec.Code,
		"callback must succeed: the gate check must use the pre-resolved tenant-a, not tenant-b")

	// The identity must be linked into "tenant-a" (the tenant from the first resolution),
	// not "tenant-b" (what subsequent calls to the impure resolver would return).
	assert.Equal(t, "tenant-a", linker.gotTenant,
		"LinkOrCreateIdentity must receive the pre-resolved tenant, not a later re-resolution")
}

// runDynamicBegin drives DynamicBeginHandler and returns the state cookie + state param.
func runDynamicBegin(t *testing.T, store ProviderStore, providerName string, opts ...HandlerOption) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	DynamicBeginHandler(store, providerName, opts...)(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	require.Equal(t, http.StatusFound, rec.Code)

	res := rec.Result()
	var stateCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == DefaultStateCookieName {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie, "DynamicBeginHandler must set the state cookie")

	loc, err := url.Parse(res.Header.Get("Location"))
	require.NoError(t, err)
	return stateCookie, loc.Query().Get("state")
}

// runDynamicCallback drives DynamicCallbackHandler.
func runDynamicCallback(t *testing.T, store ProviderStore, providerName string, linker IdentityLinker, issuer tokens.Issuer[struct{}], stateCookie *http.Cookie, query string, opts ...HandlerOption) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?"+query, nil)
	if stateCookie != nil {
		req.AddCookie(stateCookie)
	}
	DynamicCallbackHandler[struct{}](store, providerName, linker, issuer, claimsOf, opts...)(rec, req)
	return rec
}
