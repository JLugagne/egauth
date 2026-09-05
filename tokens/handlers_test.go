package tokens_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	// The CSRF same-origin check is on by default, so model a real same-origin browser
	// POST: httptest.NewRequest sets Host to "example.com", so the Origin must match.
	req.Header.Set("Origin", "http://"+req.Host)
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
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
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
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
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
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](svc, tokens.WithSuccessRedirect("/dashboard"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh(pair.RefreshToken))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/dashboard", rec.Header().Get("Location"))
}

func TestRefreshHandler_PersistentRefreshOption(t *testing.T) {
	svc, _ := newRotator(t)
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
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
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
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

// mockRevoker is a minimal tokens.FamilyRevoker that delegates to function fields.
type mockRevoker struct {
	findFunc   func(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error)
	revokeFunc func(ctx context.Context, tenantID string, familyID uuid.UUID) error
}

func (m *mockRevoker) FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
	return m.findFunc(ctx, tenantID, tokenHash)
}

func (m *mockRevoker) RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error {
	return m.revokeFunc(ctx, tenantID, familyID)
}

// TestLogoutHandler_FindStoreErrorIndicatesFailure verifies that when FindRefreshToken
// returns any error other than ErrRefreshTokenNotFound, the handler clears cookies but
// reports failure (not 204 success).
func TestLogoutHandler_FindStoreErrorIndicatesFailure(t *testing.T) {
	storeErr := errors.New("db: connection refused")
	rev := &mockRevoker{
		findFunc: func(_ context.Context, _ string, _ string) (*tokens.RefreshToken, error) {
			return nil, storeErr
		},
		revokeFunc: func(_ context.Context, _ string, _ uuid.UUID) error {
			return nil // should not be reached
		},
	}
	h := tokens.LogoutHandler(rev)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh("valid-looking-token"))

	// Cookies must always be cleared.
	refresh := findCookie(t, rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, refresh)
	assert.Less(t, refresh.MaxAge, 0, "refresh cookie must be cleared even on failure")

	// Must NOT report success.
	assert.NotEqual(t, http.StatusNoContent, rec.Code, "must not report 204 success when FindRefreshToken fails with a store error")
	assert.GreaterOrEqual(t, rec.Code, 400, "expected a 4xx/5xx status code")
}

// TestLogoutHandler_RevokeFamilyErrorIndicatesFailure verifies that when RevokeFamily
// returns an error, the handler clears cookies but reports failure (not 204 success).
func TestLogoutHandler_RevokeFamilyErrorIndicatesFailure(t *testing.T) {
	storeErr := errors.New("db: connection refused")
	familyID := uuid.Must(uuid.NewV7())
	rev := &mockRevoker{
		findFunc: func(_ context.Context, _ string, _ string) (*tokens.RefreshToken, error) {
			return &tokens.RefreshToken{FamilyID: familyID}, nil
		},
		revokeFunc: func(_ context.Context, _ string, _ uuid.UUID) error {
			return storeErr
		},
	}
	h := tokens.LogoutHandler(rev)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh("valid-looking-token"))

	// Cookies must always be cleared.
	refresh := findCookie(t, rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, refresh)
	assert.Less(t, refresh.MaxAge, 0, "refresh cookie must be cleared even on failure")

	// Must NOT report success.
	assert.NotEqual(t, http.StatusNoContent, rec.Code, "must not report 204 success when RevokeFamily fails")
	assert.GreaterOrEqual(t, rec.Code, 400, "expected a 4xx/5xx status code")
}

// TestLogoutHandler_RevokeFamilyErrorWithFailureRedirect verifies that when RevokeFamily
// returns an error and a failure redirect is configured, the handler redirects to the
// failure URL with error=logout_incomplete.
func TestLogoutHandler_RevokeFamilyErrorWithFailureRedirect(t *testing.T) {
	storeErr := errors.New("db: connection refused")
	familyID := uuid.Must(uuid.NewV7())
	rev := &mockRevoker{
		findFunc: func(_ context.Context, _ string, _ string) (*tokens.RefreshToken, error) {
			return &tokens.RefreshToken{FamilyID: familyID}, nil
		},
		revokeFunc: func(_ context.Context, _ string, _ uuid.UUID) error {
			return storeErr
		},
	}
	h := tokens.LogoutHandler(rev, tokens.WithFailureRedirect("/logout-failed"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh("valid-looking-token"))

	// Cookies must always be cleared.
	refresh := findCookie(t, rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, refresh)
	assert.Less(t, refresh.MaxAge, 0, "refresh cookie must be cleared even on failure")

	// Must redirect to failure URL with error=logout_incomplete.
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	assert.True(t, strings.HasPrefix(location, "/logout-failed?"), "redirect must go to failure URL, got: %s", location)
	assert.Contains(t, location, "error=logout_incomplete")
}

// TestLogoutHandler_NotFoundIsIdempotentSuccess verifies that when FindRefreshToken
// returns ErrRefreshTokenNotFound specifically, logout is treated as idempotent success.
func TestLogoutHandler_NotFoundIsIdempotentSuccess(t *testing.T) {
	rev := &mockRevoker{
		findFunc: func(_ context.Context, _ string, _ string) (*tokens.RefreshToken, error) {
			return nil, tokens.ErrRefreshTokenNotFound
		},
		revokeFunc: func(_ context.Context, _ string, _ uuid.UUID) error {
			return nil // must not be called
		},
	}
	h := tokens.LogoutHandler(rev)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh("already-gone-token"))

	assert.Equal(t, http.StatusNoContent, rec.Code, "ErrRefreshTokenNotFound is idempotent success")
}

// TestRefreshHandler_CSRFBlocksCrossOriginByDefault proves that, with no
// WithTrustedOrigins configured, a cross-origin POST must be rejected. This is the
// secure-by-default behavior required by TASK-025: the origin check is on by default
// and only same-origin (or explicitly trusted) requests are accepted.
func TestRefreshHandler_CSRFBlocksCrossOriginByDefault(t *testing.T) {
	called := false
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[struct{}], error) {
			called = true
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	h := tokens.RefreshHandler[struct{}](rot)

	req := postWithRefresh("some-refresh")
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
	assert.False(t, called, "rotator must not run for a cross-site request with default config")
}

// TestRefreshHandler_CSRFBlocksCrossScheme verifies that an HTTP origin targeting an HTTPS
// endpoint is rejected, preventing cross-scheme CSRF.
func TestRefreshHandler_CSRFBlocksCrossScheme(t *testing.T) {
	called := false
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[struct{}], error) {
			called = true
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	h := tokens.RefreshHandler[struct{}](rot)

	req := postWithRefresh("some-refresh")
	req.URL, _ = url.Parse("https://app.example.com/refresh")
	req.Host = "app.example.com"
	req.Header.Set("Origin", "http://app.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
	assert.False(t, called, "rotator must not run for a cross-scheme request")
}

// TestRefreshHandler_CSRFAllowsSameOriginByDefault proves the secure default does not
// produce a false positive: a same-origin POST with no WithTrustedOrigins still succeeds.
func TestRefreshHandler_CSRFAllowsSameOriginByDefault(t *testing.T) {
	svc, _ := newRotator(t)
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](svc)
	req := postWithRefresh(pair.RefreshToken)
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://app.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// TestRefreshHandler_WithInsecureNoOriginCheck proves the loud opt-out re-enables the old
// behavior: with WithInsecureNoOriginCheck the origin check is disabled and a cross-origin
// POST is accepted (and reaches the rotator).
func TestRefreshHandler_WithInsecureNoOriginCheck(t *testing.T) {
	svc, _ := newRotator(t)
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](svc, tokens.WithInsecureNoOriginCheck())
	req := postWithRefresh(pair.RefreshToken)
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// TestLogoutHandler_CSRFBlocksCrossOriginByDefault mirrors the refresh case for logout.
func TestLogoutHandler_CSRFBlocksCrossOriginByDefault(t *testing.T) {
	store := memory.NewStore[struct{}]()
	h := tokens.LogoutHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	req.AddCookie(&http.Cookie{Name: tokens.DefaultRefreshCookieName, Value: "x"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
}

func TestRefreshHandler_PassesClientContext(t *testing.T) {
	var capturedCC tokens.ClientContext
	var capturedOK bool
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[struct{}], error) {
			capturedCC, capturedOK = tokens.ClientContextFromContext(ctx)
			return &tokens.TokenPair[struct{}]{}, nil
		},
	}
	h := tokens.RefreshHandler[struct{}](rot)
	req := postWithRefresh("some-token")
	req.RemoteAddr = "192.0.2.10:4567"
	req.Header.Set("User-Agent", "TestBrowser/2.0")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.True(t, capturedOK)
	assert.Equal(t, "192.0.2.10", capturedCC.IP)
	assert.Equal(t, "TestBrowser/2.0", capturedCC.UserAgent)
}

