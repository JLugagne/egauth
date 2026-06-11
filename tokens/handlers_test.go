package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRotator(t *testing.T) (*jwt.Service[struct{}], *memory.Store[struct{}]) {
	t.Helper()
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      store,
		SecretKey:  "handlers-secret-aaaaaaaaaaaaaaa!", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
		}),
	})
	return svc, store
}

func postWithRefresh(value string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	if value != "" {
		req.AddCookie(&http.Cookie{Name: tokens.DefaultRefreshCookieName, Value: value})
	}
	return req
}

func TestRefreshHandler_CSRFBlocksCrossOrigin(t *testing.T) {
	called := false
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[struct{}], error) {
			called = true
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	h := tokens.RefreshHandler[struct{}](rot, tokens.WithTrustedOrigins("app.example.com"))

	req := postWithRefresh("some-refresh")
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
	assert.False(t, called, "rotator must not run for a cross-site request")
}

func TestRefreshHandler_CSRFAllowsSameOrigin(t *testing.T) {
	svc, _ := newRotator(t)
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](svc, tokens.WithTrustedOrigins("app.example.com"))
	req := postWithRefresh(pair.RefreshToken)
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://app.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestLogoutHandler_CSRFBlocksCrossOrigin(t *testing.T) {
	store := memory.NewStore[struct{}]()
	h := tokens.LogoutHandler(store, tokens.WithTrustedOrigins("app.example.com"))

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	req.AddCookie(&http.Cookie{Name: tokens.DefaultRefreshCookieName, Value: "x"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
}

func TestRefreshHandler_Success(t *testing.T) {
	svc, _ := newRotator(t)
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](svc)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh(pair.RefreshToken))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	access := findCookie(t, rec, tokens.DefaultAccessCookieName)
	refresh := findCookie(t, rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, access)
	require.NotNil(t, refresh)
	assert.NotEmpty(t, access.Value)
	assert.NotEqual(t, pair.RefreshToken, refresh.Value, "refresh cookie must rotate")
	assert.Equal(t, 0, refresh.MaxAge, "rotated refresh cookie is a session cookie by default (no silent persistence upgrade)")
}

func TestRefreshHandler_SuccessRedirect(t *testing.T) {
	svc, _ := newRotator(t)
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](svc, tokens.WithSuccessRedirect("/dashboard"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh(pair.RefreshToken))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/dashboard", rec.Header().Get("Location"))
}

func TestRefreshHandler_PersistentRefreshOption(t *testing.T) {
	svc, _ := newRotator(t)
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](svc, tokens.WithPersistentRefresh())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh(pair.RefreshToken))

	refresh := findCookie(t, rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, refresh)
	assert.Greater(t, refresh.MaxAge, 0, "WithPersistentRefresh must produce a persistent cookie")
}

func TestRefreshHandler_MissingCookie(t *testing.T) {
	// RotateFunc is nil and must never be called on the missing-cookie path.
	h := tokens.RefreshHandler[struct{}](&issuertest.MockRotator[struct{}]{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh(""))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "missing_refresh_token")
}

func TestRefreshHandler_ReuseClearsCookies(t *testing.T) {
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[struct{}], error) {
			return nil, tokens.ErrRefreshTokenReused
		},
	}
	h := tokens.RefreshHandler[struct{}](rot)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh("stolen-token"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "token_reuse_detected")
	access := findCookie(t, rec, tokens.DefaultAccessCookieName)
	refresh := findCookie(t, rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, access)
	require.NotNil(t, refresh)
	assert.Less(t, access.MaxAge, 0, "access cookie must be cleared on failure")
	assert.Less(t, refresh.MaxAge, 0, "refresh cookie must be cleared on failure")
}

func TestRefreshHandler_FailureRedirect(t *testing.T) {
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[struct{}], error) {
			return nil, tokens.ErrRefreshTokenReused
		},
	}
	h := tokens.RefreshHandler[struct{}](rot, tokens.WithFailureRedirect("/login"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh("stolen-token"))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), "/login?"))
	assert.Contains(t, rec.Header().Get("Location"), "error=token_reuse_detected")
}

func TestRefreshHandler_MethodNotAllowed(t *testing.T) {
	h := tokens.RefreshHandler[struct{}](&issuertest.MockRotator[struct{}]{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/refresh", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestLogoutHandler_RevokesFamilyAndClears(t *testing.T) {
	ctx := context.Background()
	svc, store := newRotator(t)
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	// store (*memory.Store) satisfies tokens.FamilyRevoker.
	h := tokens.LogoutHandler(store)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh(pair.RefreshToken))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	access := findCookie(t, rec, tokens.DefaultAccessCookieName)
	refresh := findCookie(t, rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, access)
	require.NotNil(t, refresh)
	assert.Less(t, access.MaxAge, 0)
	assert.Less(t, refresh.MaxAge, 0)

	// The family must have been revoked: the token is gone.
	_, err = store.FindRefreshToken(ctx, "", tokens.HashToken(pair.RefreshToken))
	require.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
}

func TestLogoutHandler_IdempotentWithoutCookie(t *testing.T) {
	_, store := newRotator(t)
	h := tokens.LogoutHandler(store)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh(""))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	refresh := findCookie(t, rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, refresh)
	assert.Less(t, refresh.MaxAge, 0, "logout must clear cookies even without a token")
}

func TestLogoutHandler_MethodNotAllowed(t *testing.T) {
	_, store := newRotator(t)
	h := tokens.LogoutHandler(store)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
