package ratelimit_test

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth/ratelimit"
)

// Example_rateLimitedRouter is the turnkey recipe: a single http.ServeMux that mounts every
// unauthenticated identity Request* endpoint AND the mfa TOTP/recovery verify endpoints, each
// wrapped with ratelimit.Middleware so the secure composition is the path of least resistance.
//
// egauth does NOT throttle these endpoints for you — per-IP / per-destination rate limiting
// remains the consumer's responsibility. This example shows how to wire it once at the router.
//
// The handlers here are http.HandlerFunc stand-ins standing in for the real constructors
// (named in the comments) so the example stays focused on the rate-limit composition and needs
// no Service/Mailer/SMSSender wiring. The middleware-wrapping pattern is identical for the real
// handlers, which are themselves plain http.HandlerFunc.
func Example_rateLimitedRouter() {
	// Limiters. Pick generous bursts and slow refills; tune per deployment. In production you
	// MUST schedule TokenBucket.Cleanup (see the TokenBucket docs / janitor package) so a flood
	// of unique keys cannot grow the bucket map without bound.
	perIP := ratelimit.NewTokenBucket(10, time.Minute)       // blanket per-source cap
	perVerify := ratelimit.NewTokenBucket(5, 30*time.Second) // tighter cap on code-guessing
	perNumber := ratelimit.NewTokenBucket(2, 10*time.Minute) // paid-SMS toll-fraud cap

	// Per-IP key (default) for the email-driven Request* endpoints.
	ipKey := ratelimit.ClientIP

	// Per-destination-number key for phone verification: a single number must not be pumped
	// with paid texts from many IPs. Reads the "phone" form field (the handler's default).
	numberKey := func(r *http.Request) string {
		if n := strings.TrimSpace(r.FormValue("phone")); n != "" {
			return "phone:" + n
		}
		return "ip:" + ratelimit.ClientIP(r)
	}

	// stand-in stands in for a real egauth handler (all of which are plain http.HandlerFunc).
	standIn := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }

	mux := http.NewServeMux()

	// --- Unauthenticated identity Request* endpoints (email-driven), throttled per IP. ---
	// In real code each handler is identity.<Name>(svc, mailer, opts...).
	ipThrottle := ratelimit.Middleware(perIP, ipKey)
	mux.Handle("/auth/password-reset", ipThrottle(http.HandlerFunc(standIn)))          // identity.RequestPasswordResetHandler
	mux.Handle("/auth/magic-link", ipThrottle(http.HandlerFunc(standIn)))              // identity.RequestMagicLinkHandler
	mux.Handle("/auth/password-reset/recovery", ipThrottle(http.HandlerFunc(standIn))) // identity.RequestPasswordResetViaRecoveryHandler

	// Phone verification spends real money per text: throttle per DESTINATION number, not only
	// per IP. Pair with a provider-side spend cap and a dialing-region allowlist.
	mux.Handle("/auth/phone-verification", ratelimit.Middleware(perNumber, numberKey)(http.HandlerFunc(standIn))) // identity.RequestPhoneVerificationHandler

	// --- MFA second-factor verify endpoints, throttled per IP with a tighter limiter. ---
	// In real code each handler is mfa.<Name>(svc, opts...).
	verifyThrottle := ratelimit.Middleware(perVerify, ipKey)
	mux.Handle("/mfa/verify", verifyThrottle(http.HandlerFunc(standIn)))          // mfa.VerifyHandler (TOTP)
	mux.Handle("/mfa/verify-recovery", verifyThrottle(http.HandlerFunc(standIn))) // mfa.VerifyRecoveryHandler

	_ = mux
	fmt.Println("Request* and MFA verify endpoints mounted with ratelimit.Middleware")
	// Output: Request* and MFA verify endpoints mounted with ratelimit.Middleware
}
