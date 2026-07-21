package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestDynamicBeginHandler_ConcurrentDistinctTenantsNoAliasing is a regression test for the
// slice-aliasing bug in DynamicBeginHandler/DynamicCallbackHandler: `append(opts, fixedTenantOpt)`
// mutated the closure-captured variadic slice's shared backing array. When the caller passed an
// opts slice with spare capacity, concurrent requests for different tenants raced on — and
// clobbered — the same backing slot, so one request could pack another tenant's resolver into its
// state cookie. Run under -race the shared write is flagged deterministically; the functional
// assertion additionally catches a cross-tenant cookie.
func TestDynamicBeginHandler_ConcurrentDistinctTenantsNoAliasing(t *testing.T) {
	body := `{"sub":"prov-1"}`
	p, _ := stubProviderServer(t, &body)

	store := NewMemoryStore()
	store.AddProvider("tenant-a", p)
	store.AddProvider("tenant-b", p)

	// Spare capacity (len 2, cap 8) is the trigger: append reuses the backing array instead of
	// allocating a fresh one, so every request writes the same slot.
	base := make([]HandlerOption, 0, 8)
	base = append(base, WithRedirectURL(testRedirect))
	base = append(base, WithTenantResolver(func(r *http.Request) string { return r.Header.Get("X-Tenant") }))

	h := DynamicBeginHandler(store, p.Name(), base...)

	const n = 64
	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		tenant := "tenant-a"
		if i%2 == 1 {
			tenant = "tenant-b"
		}
		wg.Add(1)
		go func(tenant string) {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
			req.Header.Set("X-Tenant", tenant)
			h(rec, req)

			var sc *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == DefaultStateCookieName {
					sc = c
				}
			}
			if sc == nil {
				errs <- fmt.Errorf("tenant %s: no state cookie", tenant)
				return
			}
			_, _, _, _, cookieTenant, ok := unpackState(sc.Value)
			if !ok {
				errs <- fmt.Errorf("tenant %s: state cookie did not unpack", tenant)
				return
			}
			if cookieTenant != tenant {
				errs <- fmt.Errorf("cross-tenant leak: request for %s got a state cookie bound to %s", tenant, cookieTenant)
			}
		}(tenant)
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
