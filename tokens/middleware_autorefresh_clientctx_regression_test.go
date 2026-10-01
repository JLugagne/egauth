package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression coverage for F-TOKWEB-001: the auto-refresh path behind RequireAuth and
// ContextMiddleware must populate the client context (IP + User-Agent) before calling
// Rotate, exactly like RefreshHandler. Without it, jwt.Rotate compares the presenting
// client against an empty rotation client, short-circuits isClientTheft to false, and a
// different client replaying a consumed refresh token within the reuse grace window is
// misclassified as benign concurrency — the family is never revoked.

// theftEventSink captures security events so the regression tests can assert the reuse
// detection was emitted on the middleware path.
type theftEventSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *theftEventSink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *theftEventSink) has(t event.Type, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.Type == t && e.Reason == reason {
			return true
		}
	}
	return false
}

func theftFixture(t *testing.T) (*jwt.Service[struct{}], *memory.Store[struct{}], tokens.Cookies, *theftEventSink) {
	t.Helper()
	store := memory.NewStore[struct{}]()
	sink := &theftEventSink{}
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      store,
		SecretKey:  "theft-secret-aaaaaaaaaaaaaaaaaaa!", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		EventSink:  sink,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
		}),
	})
	return svc, store, tokens.DefaultCookies(), sink
}

func TestRequireAuth_AutoRefreshPassesClientContextToRotate(t *testing.T) {
	cookies := tokens.DefaultCookies()
	var captured tokens.ClientContext
	var capturedOK bool
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, _ string, _ string) (*tokens.TokenPair[struct{}], error) {
			captured, capturedOK = tokens.ClientContextFromContext(ctx)
			return &tokens.TokenPair[struct{}]{}, nil
		},
	}
	h := tokens.RequireAuth[struct{}](nil, func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAutoRefresh[struct{}](rot, cookies))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("User-Agent", "thief-agent/1.0")
	req.AddCookie(&http.Cookie{Name: cookies.RefreshName, Value: "stolen-refresh-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, capturedOK, "Rotate must receive a client context on the RequireAuth auto-refresh path")
	assert.Equal(t, "203.0.113.9", captured.IP)
	assert.Equal(t, "thief-agent/1.0", captured.UserAgent)
}

func TestContextMiddleware_AutoRefreshPassesClientContextToRotate(t *testing.T) {
	cookies := tokens.DefaultCookies()
	var captured tokens.ClientContext
	var capturedOK bool
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, _ string, _ string) (*tokens.TokenPair[struct{}], error) {
			captured, capturedOK = tokens.ClientContextFromContext(ctx)
			return &tokens.TokenPair[struct{}]{}, nil
		},
	}
	h := tokens.ContextMiddleware[struct{}](nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), tokens.WithAutoRefresh[struct{}](rot, cookies))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("User-Agent", "thief-agent/1.0")
	req.AddCookie(&http.Cookie{Name: cookies.RefreshName, Value: "stolen-refresh-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, capturedOK, "Rotate must receive a client context on the ContextMiddleware auto-refresh path")
	assert.Equal(t, "203.0.113.9", captured.IP)
	assert.Equal(t, "thief-agent/1.0", captured.UserAgent)
}

func TestRequireAuth_AutoRefreshDifferentClientReplayRevokesFamily(t *testing.T) {
	svc, store, cookies, sink := theftFixture(t)
	ctx := context.Background()
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	handler := tokens.RequireAuth[struct{}](svc, func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAutoRefresh[struct{}](svc, cookies))

	present := func(ip, ua string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Host = "app.example.com"
		req.RemoteAddr = ip
		req.Header.Set("User-Agent", ua)
		req.AddCookie(&http.Cookie{Name: cookies.RefreshName, Value: pair.RefreshToken})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// 1. The thief rotates the stolen refresh token first through the middleware.
	thief := present("203.0.113.9:4444", "thief-agent/1.0")
	require.Equal(t, http.StatusOK, thief.Code, "the stolen token must rotate on the first use")
	rotated := findCookie(t, thief, cookies.RefreshName)
	require.NotNil(t, rotated, "a fresh refresh cookie must be issued to the thief")
	require.NotEqual(t, pair.RefreshToken, rotated.Value)

	// 2. The legitimate user replays the same (now consumed) token from a different
	//    client within the grace window: Rotate must classify this as theft.
	_ = present("198.51.100.5:5555", "victim-browser/2.0")

	_, err = store.FindRefreshToken(ctx, "", tokens.HashToken(rotated.Value))
	require.ErrorIs(t, err, tokens.ErrTokenFamilyRevoked,
		"a different client replaying a consumed refresh token within the grace window must revoke the family")
	assert.True(t, sink.has(event.RefreshReuseDetected, "grace_theft"),
		"the middleware auto-refresh path must emit the grace-theft reuse event")
}

func TestContextMiddleware_AutoRefreshDifferentClientReplayRevokesFamily(t *testing.T) {
	svc, store, cookies, sink := theftFixture(t)
	ctx := context.Background()
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	handler := tokens.ContextMiddleware[struct{}](svc, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), tokens.WithAutoRefresh[struct{}](svc, cookies))

	present := func(ip, ua string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Host = "app.example.com"
		req.RemoteAddr = ip
		req.Header.Set("User-Agent", ua)
		req.AddCookie(&http.Cookie{Name: cookies.RefreshName, Value: pair.RefreshToken})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	thief := present("203.0.113.9:4444", "thief-agent/1.0")
	require.Equal(t, http.StatusOK, thief.Code)
	rotated := findCookie(t, thief, cookies.RefreshName)
	require.NotNil(t, rotated)

	_ = present("198.51.100.5:5555", "victim-browser/2.0")

	_, err = store.FindRefreshToken(ctx, "", tokens.HashToken(rotated.Value))
	require.ErrorIs(t, err, tokens.ErrTokenFamilyRevoked,
		"a different client replaying a consumed refresh token within the grace window must revoke the family")
	assert.True(t, sink.has(event.RefreshReuseDetected, "grace_theft"),
		"the middleware auto-refresh path must emit the grace-theft reuse event")
}
