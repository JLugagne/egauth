package oauth

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDynamicBeginHandler_ImpureResolverUsesPreResolvedTenant verifies that even when
// the tenant resolver is impure (returns a different value on successive calls within the
// same request), the handler resolves the tenant exactly once at the top and threads that
// single value through the cookieTenant gate, so the state cookie gets packed with the
// same tenant used to look up the provider.
func TestDynamicBeginHandler_ImpureResolverUsesPreResolvedTenant(t *testing.T) {
	body := `{"sub":"prov-1"}` // unused for begin, but needed for stubProviderServer
	p, _ := stubProviderServer(t, &body)

	// Two separate tenant partitions, both holding the same provider for simplicity.
	store := NewMemoryStore()
	store.AddProvider("tenant-a", p)
	store.AddProvider("tenant-b", p)

	// The begin resolver is impure: it returns "tenant-a" on its first call (provider
	// lookup) but "tenant-b" on subsequent calls (packing the state cookie).
	// With the fix, only the first call's result ("tenant-a") is used to pack the cookie.
	var callCount atomic.Int32
	beginResolver := func(*http.Request) string {
		n := callCount.Add(1)
		if n == 1 {
			return "tenant-a"
		}
		return "tenant-b"
	}

	stateCookie, _ := runDynamicBegin(t, store, p.Name(),
		WithRedirectURL(testRedirect),
		WithTenantResolver(beginResolver))

	// The state cookie must be minted for "tenant-a" (the provider lookup tenant).
	// Before the fix, the cookie would incorrectly bind to "tenant-b", causing
	// the callback to fail tenant_mismatch later when using a pure resolver.
	_, _, _, _, cookieTenant, ok := unpackState(stateCookie.Value)
	require.True(t, ok, "state cookie must unpack successfully")

	assert.Equal(t, "tenant-a", cookieTenant,
		"state cookie must be minted for the pre-resolved tenant-a, not tenant-b")
}
