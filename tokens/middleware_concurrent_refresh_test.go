package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRotate_WithinGraceReplayReturnsConcurrent confirms that a replay of a freshly
// consumed refresh token, within the reuse grace window, is reported as the distinct
// ErrRefreshConcurrent sentinel (which still wraps ErrRefreshTokenReused for compatibility)
// rather than as an indistinguishable theft/reuse error. This lets cookie-clearing callers
// preserve the winning request's freshly minted cookies instead of logging the user out.
func TestRotate_WithinGraceReplayReturnsConcurrent(t *testing.T) {
	ctx := context.Background()
	f := newAutoRefreshFixture(t)
	pair, err := f.svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	// First rotation wins and consumes the token.
	_, err = f.svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	// Replay the same token immediately (well within the default 10s grace window):
	// this is benign concurrency, NOT theft.
	_, err = f.svc.Rotate(ctx, "", pair.RefreshToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, tokens.ErrRefreshConcurrent, "within-grace replay must surface ErrRefreshConcurrent")
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenReused, "ErrRefreshConcurrent must wrap ErrRefreshTokenReused for compatibility")
}

// TestRequireAuth_ConcurrentRefreshPreservesCookies is the core regression: two parallel
// requests carrying the same refresh cookie both enter auto-refresh. The winner mints new
// cookies; the loser must NOT clear the refresh cookie (which would wipe the winner's
// freshly issued cookie and log the user out), defeating the documented anti-lockout grace.
func TestRequireAuth_ConcurrentRefreshPreservesCookies(t *testing.T) {
	ctx := context.Background()
	f := newAutoRefreshFixture(t)
	pair, err := f.svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	// Simulate the winning request having already rotated the token.
	_, err = f.svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	called := false
	h := tokens.RequireAuth[struct{}](f.svc, func(w http.ResponseWriter, r *http.Request, _ egauth.Actor, _ struct{}) {
		called = true
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAutoRefresh[struct{}](f.svc, f.cookies))

	rec := httptest.NewRecorder()
	// The losing request replays the same (now consumed, within grace) refresh token.
	h.ServeHTTP(rec, f.request("", pair.RefreshToken))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called)

	// The refresh cookie must NOT be cleared: the winner already replaced it with a valid
	// new cookie, and clearing it here would wipe that and log the user out.
	refresh := findCookie(t, rec, f.cookies.RefreshName)
	if refresh != nil {
		assert.GreaterOrEqual(t, refresh.MaxAge, 0,
			"loser of a concurrent refresh must NOT clear the refresh cookie (anti-lockout grace)")
	}
}

// TestRefreshHandler_ConcurrentRefreshPreservesCookies covers the dedicated refresh
// endpoint: a within-grace concurrent replay must not clear the refresh cookie either.
func TestRefreshHandler_ConcurrentRefreshPreservesCookies(t *testing.T) {
	ctx := context.Background()
	f := newAutoRefreshFixture(t)
	pair, err := f.svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	_, err = f.svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](f.svc, tokens.WithCookies(f.cookies))

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	// httptest.NewRequest sets Host to example.com; send a same-origin Origin so the request
	// passes the secure-by-default CSRF check (TASK-025) and reaches the concurrent-refresh path
	// this test actually exercises.
	req.Header.Set("Origin", "http://"+req.Host)
	req.AddCookie(&http.Cookie{Name: f.cookies.RefreshName, Value: pair.RefreshToken})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	refresh := findCookie(t, rec, f.cookies.RefreshName)
	if refresh != nil {
		assert.GreaterOrEqual(t, refresh.MaxAge, 0,
			"RefreshHandler must NOT clear the refresh cookie on a within-grace concurrent replay")
	}
}
