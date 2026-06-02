package ratelimit_test

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth/ratelimit"
)

// resetService and resetMailer are nil stand-ins; these examples demonstrate the
// rate-limit composition, not how to build the identity Service/Mailer.

// ExampleWrap_passwordReset shows the cheap blanket layer: throttle the unauthenticated
// password-reset endpoint per client IP. The same recipe applies verbatim to
// identity.RequestMagicLinkHandler.
func ExampleWrap_passwordReset() {
	// In real code this is identity.RequestPasswordResetHandler(svc, mailer, opts...).
	resetHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// Allow a burst of 5 reset requests per IP, then one more per minute.
	limiter := ratelimit.NewTokenBucket(5, time.Minute)
	throttled := ratelimit.Wrap(limiter, ratelimit.ClientIP, resetHandler)

	mux := http.NewServeMux()
	mux.Handle("/auth/password-reset", throttled)
	_ = mux
	fmt.Println("password-reset throttled per client IP")
	// Output: password-reset throttled per client IP
}

// ExampleKeyFunc shows the per-account layer: key the limiter on the target email
// (read from the form) so a single victim address cannot be mail-bombed from many IPs.
// Because it reads the request body, the KeyFunc is application-specific. Compose it with
// the per-IP layer for defence in depth.
func ExampleKeyFunc() {
	// Key on the submitted email; fall back to IP when absent so an empty form still
	// shares a bucket rather than getting a free pass.
	perEmail := func(r *http.Request) string {
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		if email == "" {
			return "ip:" + ratelimit.ClientIP(r)
		}
		return "email:" + email
	}

	// A victim address may receive at most 3 reset/magic-link mails per 15 minutes,
	// regardless of how many IPs request them.
	limiter := ratelimit.NewTokenBucket(3, 5*time.Minute)
	key := ratelimit.KeyFunc(perEmail)

	resetHandler := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	throttled := ratelimit.Wrap(limiter, key, resetHandler)
	_ = throttled
	fmt.Println("password-reset throttled per target email")
	// Output: password-reset throttled per target email
}

// ExampleWrap_perDestinationNumber shows the SMS toll-fraud mitigation: rate-limit phone
// verification per DESTINATION number, not only per IP/account. A determined caller must
// not be able to pump paid texts to many premium-rate or attacker-controlled numbers.
// Pair this with a provider-side spend cap and a dialing-region allowlist.
func ExampleWrap_perDestinationNumber() {
	perNumber := func(r *http.Request) string {
		// Default form field for RequestPhoneVerificationHandler is "phone".
		number := strings.TrimSpace(r.FormValue("phone"))
		if number == "" {
			return "ip:" + ratelimit.ClientIP(r)
		}
		return "phone:" + number
	}

	// At most 1 SMS per number per 10 minutes, burst 2.
	limiter := ratelimit.NewTokenBucket(2, 10*time.Minute)

	// In real code this is identity.RequestPhoneVerificationHandler(svc, sender, opts...).
	phoneHandler := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	throttled := ratelimit.Wrap(limiter, perNumber, phoneHandler)
	_ = throttled
	fmt.Println("phone-verification throttled per destination number")
	// Output: phone-verification throttled per destination number
}

// ExampleMiddleware_layered composes two independent limiters — a per-IP blanket cap and a
// per-account cap — around one endpoint. Apply the cheap, broad limit on the outside and the
// targeted one on the inside; a request must satisfy both.
func ExampleMiddleware_layered() {
	perIP := ratelimit.Middleware(ratelimit.NewTokenBucket(20, time.Minute), ratelimit.ClientIP)
	perEmail := ratelimit.Middleware(
		ratelimit.NewTokenBucket(3, 5*time.Minute),
		func(r *http.Request) string { return "email:" + strings.ToLower(r.FormValue("email")) },
	)

	resetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// perIP (outer) → perEmail (inner) → handler.
	handler := perIP(perEmail(resetHandler))
	_ = handler
	fmt.Println("password-reset throttled per IP and per email")
	// Output: password-reset throttled per IP and per email
}
