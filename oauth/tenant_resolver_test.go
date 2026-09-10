package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A configured tenant resolver that cannot map the request must fail closed instead of falling
// back to the single-tenant ("") partition, in every OAuth handler shape (static and dynamic,
// begin and callback). With no resolver configured, "" remains valid.
func TestTenantResolverEmptyFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`

	t.Run("BeginHandler", func(t *testing.T) {
		p, _ := stubProviderServer(t, &body)
		h := BeginHandler(p, withTestStateKey([]HandlerOption{
			WithRedirectURL(testRedirect),
			WithTenantResolver(func(*http.Request) string { return "" }),
		})...)

		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "unresolved_tenant")
	})

	t.Run("CallbackHandler", func(t *testing.T) {
		p, _ := stubProviderServer(t, &body)
		linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
		issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{}}
		h := CallbackHandler[struct{}](p, linker, issuer, claimsOf, withTestStateKey([]HandlerOption{
			WithRedirectURL(testRedirect),
			WithTenantResolver(func(*http.Request) string { return "" }),
		})...)

		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/auth/test/callback?code=x&state=y", nil))

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "unresolved_tenant")
	})

	t.Run("DynamicBeginHandler", func(t *testing.T) {
		p, _ := stubProviderServer(t, &body)
		store := NewMemoryStore()
		store.AddProvider("tenant-a", p)
		h := DynamicBeginHandler(store, p.Name(), withTestStateKey([]HandlerOption{
			WithRedirectURL(testRedirect),
			WithTenantResolver(func(*http.Request) string { return "" }),
		})...)

		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "unresolved_tenant")
	})

	t.Run("DynamicCallbackHandler", func(t *testing.T) {
		p, _ := stubProviderServer(t, &body)
		store := NewMemoryStore()
		store.AddProvider("tenant-a", p)
		linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
		issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{}}
		h := DynamicCallbackHandler[struct{}](store, p.Name(), linker, issuer, claimsOf, withTestStateKey([]HandlerOption{
			WithRedirectURL(testRedirect),
			WithTenantResolver(func(*http.Request) string { return "" }),
		})...)

		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/auth/test/callback?code=x&state=y", nil))

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "unresolved_tenant")
	})
}

func TestBeginHandler_NoTenantResolverUsesSingleTenantPartition(t *testing.T) {
	body := `{"sub":"prov-1"}`
	p, _ := stubProviderServer(t, &body)

	rec := httptest.NewRecorder()
	BeginHandler(p, withTestStateKey([]HandlerOption{WithRedirectURL(testRedirect)})...)(rec,
		httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))

	require.Equal(t, http.StatusFound, rec.Code)
}
