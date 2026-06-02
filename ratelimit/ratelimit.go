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
//
// # Throttling the unauthenticated Request* endpoints
//
// The identity Request* handlers (RequestPasswordResetHandler, RequestMagicLinkHandler) are
// unauthenticated and take an attacker-chosen email, and RequestPhoneVerificationHandler takes
// an attacker-chosen phone number into a paid SMS sender. Left unthrottled they enable
// mail-bombing a victim's inbox, magic-link/reset spam, and — most costly — SMS toll-fraud
// (an attacker pumping verification texts to premium-rate or attacker-controlled numbers to
// burn your SMS budget). egauth does NOT throttle them for you: the handlers are returned as
// plain http.HandlerFunc so you compose the policy that fits your deployment. Wire it
// explicitly with Wrap/Middleware. See the package examples for runnable recipes.
//
// Defence in depth — apply more than one layer:
//
//   - Per client IP, on every Request* endpoint, with ClientIP (or your own proxy-aware
//     KeyFunc). This is the cheap blanket cap; see Example (PasswordReset).
//   - Per account / per destination, so a single victim email or one phone number cannot be
//     targeted from many IPs (and one user cannot fan out to many numbers). This needs a
//     KeyFunc that reads the request form, so it is application-specific; see
//     Example (PerDestinationNumber).
//   - Cap outstanding tokens per (user, kind) at the Service layer and enforce a provider-side
//     spend cap / number allowlist on your SMS sender — rate limiting alone does not bound a
//     determined toll-fraud spend.
//
// SMS toll-fraud warning: phone verification spends real money per message. Always rate-limit
// RequestPhoneVerificationHandler per destination number (not only per IP/account), cap your
// SMS provider's spend, and prefer an allowlist of dialing regions you actually serve.
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
