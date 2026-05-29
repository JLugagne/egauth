package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/libauth"
	"github.com/JLugagne/libauth/tokens"
	"github.com/JLugagne/libauth/tokens/jwt"
	"github.com/JLugagne/libauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// autoRefreshFixture builds a verifier/rotator service plus a minter that issues already
// expired access tokens (sharing the same secret and store), and the cookie config.
type autoRefreshFixture struct {
	svc           *jwt.Service[struct{}]
	expiredMinter *jwt.Service[struct{}]
	cookies       tokens.Cookies
}

func newAutoRefreshFixture(t *testing.T) autoRefreshFixture {
	t.Helper()
	store := memory.NewStore[struct{}]()
	cfg := jwt.Config[struct{}]{
		Store:      store,
		SecretKey:  "mw-secret",
		Issuer:     "libauth-test",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
		}),
	}
	expiredCfg := cfg
	expiredCfg.AccessTTL = -time.Minute
	return autoRefreshFixture{
		svc:           jwt.New[struct{}](cfg),
		expiredMinter: jwt.New[struct{}](expiredCfg),
		cookies:       tokens.DefaultCookies(),
	}
}

func (f autoRefreshFixture) request(accessVal, refreshVal string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if accessVal != "" {
		req.AddCookie(&http.Cookie{Name: f.cookies.AccessName, Value: accessVal})
	}
	if refreshVal != "" {
		req.AddCookie(&http.Cookie{Name: f.cookies.RefreshName, Value: refreshVal})
	}
	return req
}

func TestRequireAuth_ValidAccessCookie(t *testing.T) {
	f := newAutoRefreshFixture(t)
	uid := uuid.New()
	pair, err := f.svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uid})
	require.NoError(t, err)

	var gotActor libauth.Actor
	called := false
	h := tokens.RequireAuth[struct{}](f.svc, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, _ struct{}) {
		gotActor = actor
		called = true
		w.WriteHeader(http.StatusOK)
	}, tokens.WithCookieAuth[struct{}](f.cookies))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, f.request(pair.AccessToken, ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, called)
	assert.Equal(t, uid, gotActor.UserID)
}

func TestRequireAuth_ExpiredAccessAutoRefreshes(t *testing.T) {
	f := newAutoRefreshFixture(t)
	uid := uuid.New()
	// Expired access token, but a valid refresh token persisted in the shared store.
	pair, err := f.expiredMinter.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uid})
	require.NoError(t, err)

	called := false
	var gotActor libauth.Actor
	h := tokens.RequireAuth[struct{}](f.svc, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, _ struct{}) {
		called = true
		gotActor = actor
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAutoRefresh[struct{}](f.svc, f.cookies))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, f.request(pair.AccessToken, pair.RefreshToken))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, called, "handler must run after transparent refresh")
	assert.Equal(t, uid, gotActor.UserID)

	// Both cookies must have been rewritten with fresh values.
	newAccess := findCookie(t, rec, f.cookies.AccessName)
	newRefresh := findCookie(t, rec, f.cookies.RefreshName)
	require.NotNil(t, newAccess)
	require.NotNil(t, newRefresh)
	assert.NotEqual(t, pair.AccessToken, newAccess.Value)
	assert.NotEqual(t, pair.RefreshToken, newRefresh.Value)
}

func TestRequireAuth_MissingAccessAutoRefreshes(t *testing.T) {
	f := newAutoRefreshFixture(t)
	uid := uuid.New()
	pair, err := f.svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uid})
	require.NoError(t, err)

	called := false
	h := tokens.RequireAuth[struct{}](f.svc, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, _ struct{}) {
		called = true
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAutoRefresh[struct{}](f.svc, f.cookies))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, f.request("", pair.RefreshToken)) // refresh cookie only

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, called)
}

func TestRequireAuth_InvalidAccessNotEligibleForRefresh(t *testing.T) {
	f := newAutoRefreshFixture(t)
	pair, err := f.svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	called := false
	h := tokens.RequireAuth[struct{}](f.svc, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, _ struct{}) {
		called = true
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAutoRefresh[struct{}](f.svc, f.cookies))

	rec := httptest.NewRecorder()
	// A forged/garbage access token must be rejected outright, not auto-refreshed.
	h.ServeHTTP(rec, f.request("not.a.valid.jwt", pair.RefreshToken))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called)
}

func TestRequireAuth_RotationFailureClearsCookies(t *testing.T) {
	ctx := context.Background()
	f := newAutoRefreshFixture(t)
	pair, err := f.svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	// Consume the refresh token once so presenting it again is a replay.
	_, err = f.svc.Rotate(ctx, pair.RefreshToken)
	require.NoError(t, err)

	called := false
	h := tokens.RequireAuth[struct{}](f.svc, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, _ struct{}) {
		called = true
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAutoRefresh[struct{}](f.svc, f.cookies))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, f.request("", pair.RefreshToken)) // replay the consumed refresh token

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called)
	access := findCookie(t, rec, f.cookies.AccessName)
	refresh := findCookie(t, rec, f.cookies.RefreshName)
	require.NotNil(t, access)
	require.NotNil(t, refresh)
	assert.Less(t, access.MaxAge, 0, "cookies must be cleared on rotation failure")
	assert.Less(t, refresh.MaxAge, 0)
}

func TestRequireAuth_AutoRefreshDefaultsToSessionCookie(t *testing.T) {
	f := newAutoRefreshFixture(t)
	pair, err := f.svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	h := tokens.RequireAuth[struct{}](f.svc, func(w http.ResponseWriter, r *http.Request, _ libauth.Actor, _ struct{}) {
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAutoRefresh[struct{}](f.svc, f.cookies))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, f.request("", pair.RefreshToken))

	require.Equal(t, http.StatusOK, rec.Code)
	refresh := findCookie(t, rec, f.cookies.RefreshName)
	require.NotNil(t, refresh)
	assert.Equal(t, 0, refresh.MaxAge, "auto-refresh must default to a session cookie (no silent persistence upgrade)")
}

func TestRequireAuth_PersistentAutoRefreshOption(t *testing.T) {
	f := newAutoRefreshFixture(t)
	pair, err := f.svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	h := tokens.RequireAuth[struct{}](f.svc, func(w http.ResponseWriter, r *http.Request, _ libauth.Actor, _ struct{}) {
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAutoRefresh[struct{}](f.svc, f.cookies), tokens.WithPersistentAutoRefresh[struct{}]())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, f.request("", pair.RefreshToken))

	require.Equal(t, http.StatusOK, rec.Code)
	refresh := findCookie(t, rec, f.cookies.RefreshName)
	require.NotNil(t, refresh)
	assert.Greater(t, refresh.MaxAge, 0, "WithPersistentAutoRefresh must produce a persistent cookie")
}

func TestRequireAuth_ExpiredWithoutAutoRefreshRejected(t *testing.T) {
	f := newAutoRefreshFixture(t)
	pair, err := f.expiredMinter.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	called := false
	// Cookie auth but NO auto-refresh: an expired access token is simply rejected.
	h := tokens.RequireAuth[struct{}](f.svc, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, _ struct{}) {
		called = true
		w.WriteHeader(http.StatusOK)
	}, tokens.WithCookieAuth[struct{}](f.cookies))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, f.request(pair.AccessToken, pair.RefreshToken))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called)
}
