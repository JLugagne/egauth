// Package internal_test holds the cross-package, end-to-end integration tests for egauth.
//
// This file proves the M7 password-rotation handler wiring over a REAL HTTP journey
// (TASK-066, integration contract IC-1 and IC-2). Unlike the per-handler unit tests in
// identity/must_change_*_test.go (which use service mocks) and the gate test in
// tokens/gate_integration_test.go (which mints tokens by hand), these tests wire the
// genuine components together:
//
//   - a real identity.Service over the in-memory store (registration, auth, change),
//   - a real jwt.Service used as BOTH the token issuer and the access-token verifier,
//   - the tokens middleware (RequireAuth + WithPasswordChangeGate, ContextMiddleware),
//
// behind an httptest.Server with a cookie jar, so a flagged credential is driven through
// the whole forced-change flow exactly as a browser would experience it.
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

// journeyClock is a controllable clock so a single service instance can age a credential
// past its rotation max-age without rebuilding anything.
type journeyClock struct{ t time.Time }

func (c *journeyClock) now() time.Time      { return c.t }
func (c *journeyClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// journeyPolicy is a permissive password policy: the rotation behaviour, not password
// strength, is the subject of these tests.
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
//   - POST /login        — identity.LoginHandler (consults the rotation policy)
//   - GET  /app          — RequireAuth + WithPasswordChangeGate (the gated app route)
//   - POST /change       — identity.ChangePasswordWithReissueHandler (ungated escape hatch)
//
// Cookies are insecure, non-__Host- named so they round-trip over httptest's plain HTTP.
func newJourneyServer(t *testing.T, clock *journeyClock, opts ...identity.ServiceOption) *journeyServer {
	t.Helper()

	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc:    func(_ context.Context, p string) (string, error) { return "hashed-" + p, nil },
		CompareFunc: func(_ context.Context, hash, pw string) error {
			if hash != "hashed-"+pw {
				return identity.ErrInvalidCredentials
			}
			return nil
		},
	}
	base := []identity.ServiceOption{identity.WithClock(clock.now)}
	svc := identity.NewService(store, hasher, journeyPolicy{}, append(base, opts...)...)

	// One jwt.Service is both the issuer (used by the handlers) and the verifier (used by
	// the middleware) — a genuine sign->verify round-trip of the must_change_password claim.
	jwtSvc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokensmemory.NewStore[struct{}](),
		SecretKey:  "journey-secret-key-aaaaaaaaaaaaaaaa", // 32+ bytes
		Issuer:     "egauth-journey",
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
		Clock:      clock.now,
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

	// Login: a flagged credential gets an access-only short-TTL token (no refresh cookie).
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
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// get sends a GET through the jar-backed client.
func (j *journeyServer) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, j.srv.URL+path, nil)
	require.NoError(t, err)
	resp, err := j.srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// jarCookie returns the named cookie currently held in the client jar for the server, or
// nil if absent. This is how the journey asserts an access cookie was set but NO refresh
// cookie (the access-only flagged login) or that a full pair was issued after the change.
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

// TestPasswordRotationJourney_IC1_AdminProvisioned proves integration contract IC-1 over a
// full HTTP journey with no age-based rotation configured: the must-change requirement is
// driven purely by the admin-provisioned flag.
//
//	AdminCreateUser(temp) -> login (access-only flagged, NO refresh) -> /app 303 to reset
//	  -> change password -> full pair issued -> /app 200.
func TestPasswordRotationJourney_IC1_AdminProvisioned(t *testing.T) {
	ctx := context.Background()
	// The flagged access-only token's expiry is stamped from the real wall clock (see
	// issueMustChangeAndSetCookie), so the verifier clock must track real time too; using a
	// far-off fixed clock would make the short-TTL token look already-expired at verify time.
	clock := &journeyClock{t: time.Now()}
	j := newJourneyServer(t, clock) // rotation OFF: only the admin flag forces the change

	const email = "admin-made@example.com"
	const tempPassword = "TempPass1!"
	_, err := j.svc.AdminCreateUser(ctx, j.tenant, email, tempPassword)
	require.NoError(t, err)

	// 1. The user logs in with the temporary password. Login SUCCEEDS (soft gate) but the
	//    flagged credential yields an access-only token: access cookie set, no refresh.
	resp := j.postForm(t, "/login", url.Values{"email": {email}, "password": {tempPassword}})
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "flagged login must still succeed")
	require.NotNil(t, j.jarCookie(t, "access_token"), "flagged login must set an access cookie")
	require.Nil(t, j.jarCookie(t, "refresh_token"), "a must-change login must NOT receive a refresh cookie")

	// 2. The protected app route soft-redirects (303) to the reset page: the gate fired.
	resp = j.get(t, "/app")
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, "the gate must 303 a flagged request")
	assert.Contains(t, resp.Header.Get("Location"), journeyResetURL)

	// 3. The user changes their password via the re-issuing change handler (current = temp).
	resp = j.postForm(t, "/change", url.Values{"current_password": {tempPassword}, "new_password": {"ChosenPass1!"}})
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "the password change must succeed")
	require.NotNil(t, j.jarCookie(t, "access_token"), "the change must re-issue an access cookie")
	require.NotNil(t, j.jarCookie(t, "refresh_token"), "the change must re-issue a full pair (refresh cookie present)")

	// 4. The same protected route is now reachable: the fresh token is unflagged.
	resp = j.get(t, "/app")
	require.Equal(t, http.StatusOK, resp.StatusCode, "after the change the gated route must be reachable")
	body := readBody(t, resp)
	assert.Equal(t, "app-reached", body)

	// Sanity: the store-side flag is cleared too.
	required, err := j.svc.PasswordChangeRequired(ctx, j.tenant, mustUserID(t, j, email))
	require.NoError(t, err)
	assert.False(t, required, "after the change the credential must no longer be due")
}

// TestPasswordRotationJourney_IC2_AgeBasedRotation proves integration contract IC-2 over a
// full HTTP journey: with WithPasswordRotation enabled and a password aged past max-age, a
// FRESH login is flagged (access-only, no refresh) and the gate fires; after the change the
// NEXT login yields a clean full pair and the gated route is reachable.
func TestPasswordRotationJourney_IC2_AgeBasedRotation(t *testing.T) {
	ctx := context.Background()
	const maxAge = 90 * 24 * time.Hour
	clock := &journeyClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	j := newJourneyServer(t, clock, identity.WithPasswordRotation(maxAge))

	const email = "aged@example.com"
	const original = "OriginalPass1!"
	user, err := j.svc.Register(ctx, j.tenant, email, original)
	require.NoError(t, err)

	// Register leaves PasswordChangedAt zero (legacy, never due). Stamp a concrete timestamp
	// by changing the password once, then age the credential past max-age.
	require.NoError(t, j.svc.ChangePassword(ctx, j.tenant, user.ID, original, "StampPass1!"))
	clock.advance(maxAge + time.Hour)

	required, err := j.svc.PasswordChangeRequired(ctx, j.tenant, user.ID)
	require.NoError(t, err)
	require.True(t, required, "an aged credential must be due before login")

	// 1. A fresh login is flagged: access-only token, no refresh cookie.
	resp := j.postForm(t, "/login", url.Values{"email": {email}, "password": {"StampPass1!"}})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.NotNil(t, j.jarCookie(t, "access_token"), "aged login must set an access cookie")
	require.Nil(t, j.jarCookie(t, "refresh_token"), "an aged-rotation login must NOT receive a refresh cookie")

	// 2. The gate fires on the app route.
	resp = j.get(t, "/app")
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), journeyResetURL)

	// 3. The user changes the password; this re-stamps PasswordChangedAt at the current clock.
	resp = j.postForm(t, "/change", url.Values{"current_password": {"StampPass1!"}, "new_password": {"FreshPass1!"}})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	required, err = j.svc.PasswordChangeRequired(ctx, j.tenant, user.ID)
	require.NoError(t, err)
	require.False(t, required, "after the change the credential must no longer be due")

	// 4. Clear the jar and perform the NEXT login from scratch: it must be CLEAN — a full
	//    pair (access + refresh) and the gated route reachable.
	clearJar(t, j)
	resp = j.postForm(t, "/login", url.Values{"email": {email}, "password": {"FreshPass1!"}})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.NotNil(t, j.jarCookie(t, "access_token"), "the next login must set an access cookie")
	require.NotNil(t, j.jarCookie(t, "refresh_token"), "the next login must be a clean full pair (refresh present)")

	resp = j.get(t, "/app")
	require.Equal(t, http.StatusOK, resp.StatusCode, "after the change the next login reaches the gated route")
	assert.Equal(t, "app-reached", readBody(t, resp))
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

// clearJar replaces the client cookie jar with a fresh empty one, simulating a brand-new
// login session (no carried-over cookies).
func clearJar(t *testing.T, j *journeyServer) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	j.srv.Client().Jar = jar
}

// mustUserID resolves a user's ID by email from the store, failing the test if absent.
func mustUserID(t *testing.T, j *journeyServer, email string) uuid.UUID {
	t.Helper()
	u, err := j.store.FindUserByEmail(context.Background(), j.tenant, email)
	require.NoError(t, err)
	require.NotNil(t, u)
	return u.ID
}
