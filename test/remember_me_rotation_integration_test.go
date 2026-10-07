package internal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

type rememberClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *rememberClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *rememberClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type rememberServer struct {
	srv     *httptest.Server
	clock   *rememberClock
	cookies tokens.Cookies
}

func newRememberServer(t *testing.T) *rememberServer {
	t.Helper()

	clock := &rememberClock{now: time.Now()}
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
	svc := identity.NewService(store, hasher, journeyPolicy{}, identity.WithClock(clock.Now))

	jwtSvc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokensmemory.NewStore[struct{}](),
		SecretKey:  "remember-secret-key-aaaaaaaaaaaaaaa",
		Issuer:     "egauth-remember",
		AccessTTL:  time.Minute,
		RefreshTTL: 30 * 24 * time.Hour,
		Clock:      clock.Now,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, userID uuid.UUID, tenant string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}, nil
		}),
	})

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

	mux := http.NewServeMux()
	mux.Handle("/login", identity.LoginHandler[struct{}](svc, jwtSvc, claimsOf, identity.WithCookies(cookies), identity.WithInsecureCookies()))
	mux.Handle("/refresh", tokens.RefreshHandler[struct{}](jwtSvc, tokens.WithCookies(cookies)))
	mux.Handle("/app", tokens.RequireAuth[struct{}](
		jwtSvc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusOK)
		},
		tokens.WithCookieAuth[struct{}](cookies),
		tokens.WithoutHeaderAuth[struct{}](),
		tokens.WithAutoRefresh[struct{}](jwtSvc, cookies),
	))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_, err := svc.Register(context.Background(), "", "remember@example.com", "Password1!")
	require.NoError(t, err)

	return &rememberServer{srv: srv, clock: clock, cookies: cookies}
}

func (s *rememberServer) do(t *testing.T, method, path string, form url.Values, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(context.Background(), method, s.srv.URL+path, body)
	require.NoError(t, err)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Origin", s.srv.URL)
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func responseCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

func (s *rememberServer) login(t *testing.T, remember bool) (access, refresh *http.Cookie) {
	t.Helper()
	form := url.Values{"email": {"remember@example.com"}, "password": {"Password1!"}}
	if remember {
		form.Set("remember_me", "true")
	}
	resp := s.do(t, http.MethodPost, "/login", form)
	require.Less(t, resp.StatusCode, 400, "login must succeed")
	access = responseCookie(resp, s.cookies.AccessName)
	refresh = responseCookie(resp, s.cookies.RefreshName)
	require.NotNil(t, access)
	require.NotNil(t, refresh)
	return access, refresh
}

func TestRememberMe_SurvivesRefreshHandlerRotation(t *testing.T) {
	s := newRememberServer(t)
	_, refresh := s.login(t, true)
	require.Positive(t, refresh.MaxAge, "remember_me login must write a persistent refresh cookie")

	for i := range 3 {
		resp := s.do(t, http.MethodPost, "/refresh", nil, refresh)
		require.Less(t, resp.StatusCode, 400, "refresh %d must succeed", i)
		refresh = responseCookie(resp, s.cookies.RefreshName)
		require.NotNil(t, refresh)
		assert.Positive(t, refresh.MaxAge, "rotation %d must keep the refresh cookie persistent", i)
	}
}

func TestRememberMe_SurvivesAutoRefreshRotation(t *testing.T) {
	s := newRememberServer(t)
	access, refresh := s.login(t, true)
	require.Positive(t, refresh.MaxAge)

	s.clock.Advance(2 * time.Minute)
	resp := s.do(t, http.MethodGet, "/app", nil, access, refresh)
	require.Equal(t, http.StatusOK, resp.StatusCode, "auto-refresh must transparently rotate the expired access token")
	rotated := responseCookie(resp, s.cookies.RefreshName)
	require.NotNil(t, rotated, "auto-refresh must rotate the refresh cookie")
	assert.Positive(t, rotated.MaxAge, "auto-refresh must keep the refresh cookie persistent")
}

func TestRememberMe_AbsentStaysSessionCookieAcrossRotation(t *testing.T) {
	s := newRememberServer(t)
	access, refresh := s.login(t, false)
	require.Zero(t, refresh.MaxAge, "login without remember_me must write a session refresh cookie")

	resp := s.do(t, http.MethodPost, "/refresh", nil, refresh)
	require.Less(t, resp.StatusCode, 400)
	rotated := responseCookie(resp, s.cookies.RefreshName)
	require.NotNil(t, rotated)
	assert.Zero(t, rotated.MaxAge, "rotation must not upgrade a session refresh cookie to persistent")

	s.clock.Advance(2 * time.Minute)
	resp = s.do(t, http.MethodGet, "/app", nil, access, rotated)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	auto := responseCookie(resp, s.cookies.RefreshName)
	require.NotNil(t, auto)
	assert.Zero(t, auto.MaxAge, "auto-refresh must not upgrade a session refresh cookie to persistent")
}
