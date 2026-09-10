package webapp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/ratelimit"
	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loginRequest builds a POST /auth/login request from a fixed client IP, so every call shares
// one rate-limit bucket.
func loginRequest(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = "203.0.113.7:49152"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func validLoginForm() url.Values {
	return url.Values{"email": {"alice@example.com"}, "password": {"Correct horse battery staple 1!"}}
}

// TestRateLimit_DefaultThrottlesAuthenticationEndpoints proves the preset throttles a client IP
// once the configured burst is exhausted, answering 429 with a Retry-After header.
func TestRateLimit_DefaultThrottlesAuthenticationEndpoints(t *testing.T) {
	cfg := baseConfig()
	cfg.InsecureNoOriginCheck = true
	cfg.RateLimitBurst = 2
	cfg.RateLimitRefill = time.Hour
	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)

	for i := range 2 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loginRequest(validLoginForm()))
		assert.NotEqual(t, http.StatusTooManyRequests, rec.Code, "request %d within the burst must not be throttled", i)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginRequest(validLoginForm()))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"), "429 must advertise when to retry")
}

// TestRateLimit_InsecureNoRateLimitDisables proves the explicit opt-out leaves the endpoints
// unthrottled even beyond the default burst.
func TestRateLimit_InsecureNoRateLimitDisables(t *testing.T) {
	cfg := baseConfig()
	cfg.InsecureNoOriginCheck = true
	cfg.InsecureNoRateLimit = true
	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)

	for i := range webapp.DefaultRateLimitBurst + 5 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loginRequest(validLoginForm()))
		assert.NotEqual(t, http.StatusTooManyRequests, rec.Code, "request %d must not be throttled when InsecureNoRateLimit is set", i)
	}
}

// TestRateLimit_CustomLimiterKeyedByClientIP proves Config.RateLimiter replaces the default
// TokenBucket and receives a key derived from the client IP (never a proxy header).
func TestRateLimit_CustomLimiterKeyedByClientIP(t *testing.T) {
	limiter := &recordingLimiter{allow: true}
	cfg := baseConfig()
	cfg.InsecureNoOriginCheck = true
	cfg.RateLimiter = limiter
	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginRequest(validLoginForm()))
	assert.NotEqual(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, []string{"203.0.113.7"}, limiter.seenKeys())
}

// TestRateLimit_ConflictingConfigRejected proves the preset fails closed when both a custom
// limiter and the insecure opt-out are supplied.
func TestRateLimit_ConflictingConfigRejected(t *testing.T) {
	cfg := baseConfig()
	cfg.InsecureNoOriginCheck = true
	cfg.RateLimiter = ratelimit.NewTokenBucket(1, time.Minute)
	cfg.InsecureNoRateLimit = true

	_, err := webapp.NewWebApp(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot specify both RateLimiter and InsecureNoRateLimit")
}

type recordingLimiter struct {
	mu    sync.Mutex
	allow bool
	keys  []string
}

func (l *recordingLimiter) Allow(_ context.Context, key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, key)
	return l.allow, 0
}

func (l *recordingLimiter) seenKeys() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.keys...)
}
