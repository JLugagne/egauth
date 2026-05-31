// Package ratelimit provides a small, pluggable request-throttling seam for the egauth
// HTTP handlers and a dependency-free in-memory token-bucket reference implementation.
//
// Authentication endpoints (login, password-reset / magic-link / verification requests, and
// OTP/TOTP verification) MUST be throttled to resist brute force, credential stuffing and
// email-bombing (OWASP ASVS, NIST SP 800-63B). egauth keeps the policy pluggable: supply a
// Limiter and wrap any http.Handler with Middleware, keyed per client IP and/or per account.
//
// The reference TokenBucket is process-local. For a multi-instance deployment back the
// Limiter with a shared store (e.g. Redis) implementing the same interface.
package ratelimit

import (
	"context"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Limiter decides whether an action identified by key may proceed now. When it may not, the
// returned duration is how long the caller should wait before retrying (zero if unknown).
// Implementations must be safe for concurrent use.
type Limiter interface {
	Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration)
}

// KeyFunc derives the rate-limit bucket key from a request. Requests sharing a key share a
// budget. The default (ClientIP) keys per source address.
type KeyFunc func(*http.Request) string

// ClientIP extracts the client IP from the request's RemoteAddr. It does NOT trust
// X-Forwarded-For/Forwarded headers (those are spoofable unless terminated by a trusted
// proxy); supply a custom KeyFunc that reads them only when you run behind such a proxy.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Middleware throttles the wrapped handler with limiter, keyed by key (defaults to ClientIP).
// On rejection it responds 429 Too Many Requests with a Retry-After header (seconds) when the
// limiter reports a wait, and does not call the next handler.
func Middleware(limiter Limiter, key KeyFunc) func(http.Handler) http.Handler {
	if key == nil {
		key = ClientIP
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, retryAfter := limiter.Allow(r.Context(), key(r))
			if !allowed {
				if retryAfter > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
				}
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Wrap is the http.HandlerFunc-friendly form of Middleware for a single endpoint.
func Wrap(limiter Limiter, key KeyFunc, next http.HandlerFunc) http.HandlerFunc {
	h := Middleware(limiter, key)(next)
	return h.ServeHTTP
}
