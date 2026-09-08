package oauth

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for WEB-02 (audit 2026-09-08): the redirect_uri fallback must never take its scheme
// from the spoofable X-Forwarded-Proto header, and the Host-derived fallback itself must be
// treated as dev-only and surface a security event when it is used in a production-like
// request (non-TLS, non-loopback Host).

func TestRequestScheme_IgnoresForwardedProto(t *testing.T) {
	protos := []string{"https", "HTTPS", "  https  ", "http", "javascript:alert(1)", ""}

	for _, proto := range protos {
		t.Run("plain request with proto "+proto, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Forwarded-Proto", proto)
			assert.Equal(t, "http", requestScheme(req),
				"X-Forwarded-Proto must never choose the scheme on a plaintext request")
		})
	}

	t.Run("TLS connection is https regardless of header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("X-Forwarded-Proto", "https")
		assert.Equal(t, "https", requestScheme(req))
	})
}

func TestBeginHandler_ForwardedProtoDoesNotUpgradeScheme(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	handler := BeginHandler(p, WithStateSigningKey(testStateKey))

	req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
	req.Host = "evil.example"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	redirectURI := loc.Query().Get("redirect_uri")
	assert.True(t, strings.HasPrefix(redirectURI, "http://evil.example/"),
		"a spoofed X-Forwarded-Proto must not upgrade the Host-derived redirect_uri scheme, got %q", redirectURI)
	assert.False(t, strings.HasPrefix(redirectURI, "https://"),
		"redirect_uri must not be https without r.TLS, got %q", redirectURI)
}

func TestBeginHandler_TLSConnectionProducesHTTPSRedirect(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	handler := BeginHandler(p, WithStateSigningKey(testStateKey))

	req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
	req.Host = "app.example.com"
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	redirectURI := loc.Query().Get("redirect_uri")
	assert.Equal(t, "https://app.example.com/oauth/begin", redirectURI)
}

func TestBeginHandler_RedirectFallbackEmitsMisuseEvent(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	sink := &captureSink{}
	handler := BeginHandler(p, WithStateSigningKey(testStateKey), WithEventSink(sink))

	req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	warns := sink.ofType(event.RedirectFallbackMisuse)
	require.Len(t, warns, 1, "the Host-derived redirect_uri fallback in a production-like request must emit a misuse event")
	assert.Equal(t, "evil.example", warns[0].Attrs["host"])
	assert.Equal(t, "host_derived_redirect_uri", warns[0].Reason)

	// The warning is rate-limited to once per handler instance.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req)
	assert.Len(t, sink.ofType(event.RedirectFallbackMisuse), 1)
}

func TestBeginHandler_RedirectFallbackLoopbackEmitsNothing(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	for _, host := range []string{"localhost", "localhost:8080", "127.0.0.1", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			sink := &captureSink{}
			handler := BeginHandler(p, WithStateSigningKey(testStateKey), WithEventSink(sink))

			req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusFound, rec.Code)
			assert.Empty(t, sink.ofType(event.RedirectFallbackMisuse))
		})
	}
}

func TestBeginHandler_RedirectFallbackTLSEmitsNothing(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	sink := &captureSink{}
	handler := BeginHandler(p, WithStateSigningKey(testStateKey), WithEventSink(sink))

	req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
	req.Host = "app.example.com"
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Empty(t, sink.ofType(event.RedirectFallbackMisuse))
}

func TestBeginHandler_ExplicitRedirectURLEmitsNothing(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	sink := &captureSink{}
	handler := BeginHandler(p, WithRedirectURL("https://app.example.com/cb"),
		WithStateSigningKey(testStateKey), WithEventSink(sink))

	req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
	req.Host = "app.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Empty(t, sink.ofType(event.RedirectFallbackMisuse))
}

func TestBeginHandler_AllowedHostsEmitsNothing(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	sink := &captureSink{}
	handler := BeginHandler(p, WithAllowedHosts("app.example.com"),
		WithStateSigningKey(testStateKey), WithEventSink(sink))

	req := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
	req.Host = "app.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Empty(t, sink.ofType(event.RedirectFallbackMisuse))
}

func TestBeginHandler_ExplicitRedirectURLWinsOverRequest(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid"}, nil)

	handler := BeginHandler(p, WithRedirectURL("https://app.example.com/auth/test/callback"),
		WithStateSigningKey(testStateKey))

	req := httptest.NewRequest(http.MethodGet, "/auth/test/login", nil)
	req.Host = "evil.example"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://app.example.com/auth/test/callback", loc.Query().Get("redirect_uri"))
}

// captureSink records every emitted event for assertions (mirrors the tokens package helper).
type captureSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *captureSink) EmitEvent(_ context.Context, e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) ofType(t event.Type) []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []event.Event
	for _, e := range c.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}
