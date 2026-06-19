// Package internal_test holds the cross-package, end-to-end integration tests for egauth.
//
// This file proves the M7 forced-password-change handler wiring over a REAL HTTP journey
// (TASK-066, integration contract IC-1). Unlike the per-handler unit tests in
// identity/must_change_*_test.go (which use service mocks) and the gate test in
// tokens/gate_integration_test.go (which mints tokens by hand), this test wires the
// genuine components together:
//
//   - a real identity.Service over the in-memory store (registration, auth, change),
//   - a real jwt.Service used as BOTH the token issuer and the access-token verifier,
//   - the tokens middleware (RequireAuth + WithPasswordChangeGate, ContextMiddleware),
//
// behind an httptest.Server with a cookie jar, so a temporary (admin-provisioned) credential
// is driven through the whole forced-change flow exactly as a browser would experience it.
//
// Note: egauth does NOT do age-based rotation (NIST SP 800-63B discourages fixed-interval
// expiry), so the must-change requirement here is driven purely by the admin-provisioned flag.
package internal_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokensmemory "github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// journeyPolicy is a permissive password policy: the forced-change behaviour, not password
// strength, is the subject of this test.
type journeyPolicy struct{}

func (journeyPolicy) Verify(_ context.Context, _ string) error { return nil }

// journeyResetURL is where the password-change gate soft-redirects a flagged request.
const journeyResetURL = "/account/change-password"

// journeyServer bundles everything a test needs to drive the HTTP journey.
type journeyServer struct {
	srv    *httptest.Server
	svc    identity.Service
	store  *identitymemory.Store
	tenant string
}

// newJourneyServer wires the real identity service, a real jwt issuer/verifier and the
// tokens middleware into an httptest.Server. The mux exposes:
//
//   - POST /login        — identity.LoginHandler (consults the forced-change policy)
//   - GET  /app          — RequireAuth + WithPasswordChangeGate (the gated app route)
//   - POST /change       — identity.ChangePasswordWithReissueHandler (ungated escape hatch)
//
// Cookies are insecure, non-__Host- named so they round-trip over httptest's plain HTTP.
func newJourneyServer(t *testing.T, now func() time.Time) *journeyServer {
	t.Helper()

	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc: func(_ context.Context, p string) (string, error) { return "hashed-" + p, nil },
		CompareFunc: func(_ context.Context, hash, pw string) error {
			if hash != "hashed-"+pw {
				return identity.ErrInvalidCredentials
			}
			return nil
		},
	}
	svc := identity.NewService(store, hasher, journeyPolicy{}, identity.WithClock(now))

	// One jwt.Service is both the issuer (used by the handlers) and the verifier (used by
	// the middleware) — a genuine sign->verify round-trip of the must_change_password claim.
	jwtSvc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokensmemory.NewStore[struct{}](),
		SecretKey:  "journey-secret-key-aaaaaaaaaaaaaaaa", // 32+ bytes
		Issuer:     "egauth-journey",
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
		Clock:      now,
		// The provider deliberately does NOT set MustChangePassword: it models a normal app that
		// does not re-query the credential's must-change state on every refresh. The flag must
		// instead be carried forward by Rotate from the stored refresh family.
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, userID uuid.UUID, tenant string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}, nil
		}),
	})

	// Insecure, non-__Host- cookies so the test client jar will store and resend them over
	// plain HTTP. The same configuration is shared by the handlers and the middleware.
	cookies := tokens.Cookies{
		AccessName:  "access_token",
		RefreshName: "refresh_token",
		Path:        "/",
		RefreshPath: "/",
		SameSite:    http.SameSiteLaxMode,
		Insecure:    true,
	}
	require.NoError(t, cookies.Validate())

	claimsOf := func(u *identity.User) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: u.ID, TenantID: u.TenantID}
	}

	handlerOpts := []identity.HandlerOption{
		identity.WithCookies(cookies),
		identity.WithInsecureCookies(),
	}

	mux := http.NewServeMux()

	// Login: a flagged credential gets a full renewable pair carrying the must-change flag.
	mux.Handle("/login", identity.LoginHandler[struct{}](svc, jwtSvc, claimsOf, handlerOpts...))

	// Gated app route: RequireAuth verifies the access cookie, then the gate soft-redirects
	// (303) to the reset page when the verified claims carry must_change_password.
	mux.Handle("/app", tokens.RequireAuth[struct{}](
		jwtSvc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("app-reached"))
		},
		tokens.WithCookieAuth[struct{}](cookies),
		tokens.WithoutHeaderAuth[struct{}](),
		tokens.WithPasswordChangeGate[struct{}](journeyResetURL),
	))

	// Ungated change-password route (the escape hatch): ContextMiddleware verifies the
	// access cookie WITHOUT the gate and stashes the actor on the context; the change
	// handler reads it via WithUserResolver and, on success, re-issues a clean full pair.
	userResolver := identity.WithUserResolver(func(r *http.Request) (*identity.User, bool) {
		uid, tenant, ok := tokens.UserResolverFromContext(r)
		if !ok {
			return nil, false
		}
		u, err := store.FindUserByID(r.Context(), tenant, uid)
		if err != nil || u == nil {
			return nil, false
		}
		return u, true
	})
	changeHandler := identity.ChangePasswordWithReissueHandler[struct{}](
		svc, jwtSvc, claimsOf,
		append([]identity.HandlerOption{userResolver}, handlerOpts...)...,
	)
	mux.Handle("/change", tokens.ContextMiddleware[struct{}](
		jwtSvc,
		changeHandler,
		tokens.WithCookieAuth[struct{}](cookies),
		tokens.WithoutHeaderAuth[struct{}](),
	))

	// Refresh route: rotates the refresh cookie to a fresh pair. Used to prove that a flagged
	// session's renewed token still carries must_change_password (carried by the family, not the
	// provider) — a user cannot escape the gate by waiting for the access token to expire.
	mux.Handle("/refresh", tokens.RefreshHandler[struct{}](jwtSvc, tokens.WithCookies(cookies)))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	srv.Client().Jar = jar
	// Do not auto-follow redirects: the journey must observe the 303 from the gate.
	srv.Client().CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &journeyServer{srv: srv, svc: svc, store: store, tenant: ""}
}

// postForm sends an application/x-www-form-urlencoded POST through the jar-backed client,
// setting an Origin header that matches the server host so the handlers' CSRF origin check
// passes (as a real same-origin browser POST would).
func (j *journeyServer) postForm(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, j.srv.URL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", j.srv.URL)
	resp, err := j.srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// get sends a GET through the jar-backed client.
func (j *journeyServer) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, j.srv.URL+path, nil)
	require.NoError(t, err)
	resp, err := j.srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// jarCookie returns the named cookie currently held in the client jar for the server, or
// nil if absent. This is how the journey asserts an access cookie was set but NO refresh
// cookie. Used to assert a flagged login still receives a refresh cookie (renewable) and that the
// gate persists across a /refresh.
func (j *journeyServer) jarCookie(t *testing.T, name string) *http.Cookie {
	t.Helper()
	u, err := url.Parse(j.srv.URL)
	require.NoError(t, err)
	for _, c := range j.srv.Client().Jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestPasswordForcedChangeJourney_IC1_AdminProvisioned proves integration contract IC-1 over a
// full HTTP journey: the must-change requirement is driven purely by the admin-provisioned flag,
// the flagged session is RENEWABLE, and a refresh keeps the gate engaged.
//
//	AdminCreateUser(temp) -> login (renewable flagged pair) -> /app 303 to reset
//	  -> refresh -> /app STILL 303 (flag carried forward) -> change password -> clean pair -> /app 200.
func TestPasswordForcedChangeJourney_IC1_AdminProvisioned(t *testing.T) {
	ctx := context.Background()
	j := newJourneyServer(t, time.Now)

	const email = "admin-made@example.com"
	const tempPassword = "TempPass1!"
	_, err := j.svc.AdminCreateUser(ctx, j.tenant, email, tempPassword)
	require.NoError(t, err)

	// 1. The user logs in with the temporary password. Login SUCCEEDS (soft gate) and the flagged
	//    credential yields a full, renewable pair (access AND refresh) carrying must_change_password.
	resp := j.postForm(t, "/login", url.Values{"email": {email}, "password": {tempPassword}})
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "flagged login must still succeed")
	require.NotNil(t, j.jarCookie(t, "access_token"), "flagged login must set an access cookie")
	require.NotNil(t, j.jarCookie(t, "refresh_token"), "a flagged login is renewable: it must receive a refresh cookie")

	// 2. The protected app route soft-redirects (303) to the reset page: the gate fired.
	resp = j.get(t, "/app")
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, "the gate must 303 a flagged request")
	assert.Contains(t, resp.Header.Get("Location"), journeyResetURL)

	// 2b. Refresh the session (simulating the access token expiring). The renewed token MUST still
	//     carry the flag — the refresh family preserves it even though the ClaimsProvider does not
	//     re-set it — so the gate keeps firing. A user cannot escape the reset by waiting + refreshing.
	resp = j.postForm(t, "/refresh", url.Values{})
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "refresh must succeed for a flagged session")
	require.NotNil(t, j.jarCookie(t, "refresh_token"), "refresh must re-issue a refresh cookie")
	resp = j.get(t, "/app")
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, "the refreshed token must STILL be gated (flag carried forward)")
	assert.Contains(t, resp.Header.Get("Location"), journeyResetURL)

	// 3. The user changes their password via the re-issuing change handler (current = temp).
	resp = j.postForm(t, "/change", url.Values{"current_password": {tempPassword}, "new_password": {"ChosenPass1!"}})
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "the password change must succeed")
	require.NotNil(t, j.jarCookie(t, "access_token"), "the change must re-issue an access cookie")
	require.NotNil(t, j.jarCookie(t, "refresh_token"), "the change must re-issue a full pair (refresh cookie present)")

	// 4. The same protected route is now reachable: the fresh token is unflagged.
	resp = j.get(t, "/app")
	require.Equal(t, http.StatusOK, resp.StatusCode, "after the change the gated route must be reachable")
	assert.Equal(t, "app-reached", readBody(t, resp))

	// Sanity: the store-side flag is cleared too.
	required, err := j.svc.PasswordChangeRequired(ctx, j.tenant, mustUserID(t, j, email))
	require.NoError(t, err)
	assert.False(t, required, "after the change the credential must no longer be due")
}

// readBody drains and returns the response body as a trimmed string.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 0, 64)
	tmp := make([]byte, 512)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return strings.TrimSpace(string(buf))
}

// mustUserID resolves a user's ID by email from the store, failing the test if absent.
func mustUserID(t *testing.T, j *journeyServer, email string) uuid.UUID {
	t.Helper()
	u, err := j.store.FindUserByEmail(context.Background(), j.tenant, email)
	require.NoError(t, err)
	require.NotNil(t, u)
	return u.ID
}
