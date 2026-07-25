package otp

import (
	"context"
	"net/http"
	"time"

	"github.com/JLugagne/egauth/internal/httputil"

	"github.com/google/uuid"
)

// DefaultMaxBodyBytes bounds the request body of the OTP handlers before form parsing.
const DefaultMaxBodyBytes int64 = 4 << 10 // 4 KiB

// DefaultDeliveryConcurrency is the default cap on the number of in-flight off-response-path
// deliveries (mail/SMS) a single IssueHandler instance will run concurrently. It bounds the
// unauthenticated goroutine fan-out the handler can be driven to spawn: without a cap, a flood
// of requests for valid/guessable subjects could spawn unbounded concurrent goroutines and
// amplify into unbounded outbound mail/SMS (toll fraud). Override with WithMaxConcurrentDeliveries.
const DefaultDeliveryConcurrency = 100

// DefaultDeliveryTimeout is the default per-delivery timeout applied to the off-response-path
// delivery context, so a slow or hung Mailer/SMSSender cannot pin a delivery slot indefinitely.
// Override with WithDeliveryTimeout.
const DefaultDeliveryTimeout = 30 * time.Second

// handlerConfig holds the configurable behavior of the OTP HTTP handlers.
type handlerConfig struct {
	subjectResolver func(*http.Request) (uuid.UUID, bool)
	purpose         string
	purposeResolver func(*http.Request) string
	codeField       string
	tenantResolver  func(*http.Request) (string, bool)
	trustedOrigins  map[string]bool
	// insecureNoOriginCheck disables the strict same-origin CSRF check (see WithInsecureNoOriginCheck). By default the check is ON even with an empty trustedOrigins allowlist.
	insecureNoOriginCheck bool
	maxBodyBytes          int64
	successURL            string
	failureURL            string
	onVerified            func(w http.ResponseWriter, r *http.Request, subjectID uuid.UUID)
	deliveryConcurrency   int
	deliveryTimeout       time.Duration
	// deliverySem is a buffered-channel semaphore bounding concurrent off-response-path
	// deliveries. It is created ONCE in newHandlerConfig (so it is shared across every request
	// served by a given handler instance — a per-request channel would make the cap meaningless)
	// with capacity deliveryConcurrency; a non-positive cap leaves it nil, disabling the bound.
	deliverySem chan struct{}
}

// HandlerOption configures the OTP HTTP handlers (IssueHandler, VerifyHandler).
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{
		codeField:           "code",
		purpose:             "login",
		maxBodyBytes:        DefaultMaxBodyBytes,
		deliveryConcurrency: DefaultDeliveryConcurrency,
		deliveryTimeout:     DefaultDeliveryTimeout,
	}
	for _, opt := range opts {
		opt(&c)
	}
	// Create the delivery semaphore ONCE here, after options are applied, so the cap is shared
	// across every request served by the handler instance built from this config. A non-positive
	// cap leaves it nil, disabling the bound (deliveries then fan out unbounded again).
	if c.deliveryConcurrency > 0 {
		c.deliverySem = make(chan struct{}, c.deliveryConcurrency)
	}
	return c
}

// WithSubjectResolver supplies the subject (e.g. user ID) an OTP challenge belongs to. The
// application maps the request (an authenticated session, or a submitted email) to a subject
// ID, returning ok=false when it cannot — handlers then respond uniformly so they leak no
// account-existence signal. It is required; without it the handlers respond 401.
func WithSubjectResolver(f func(*http.Request) (uuid.UUID, bool)) HandlerOption {
	return func(h *handlerConfig) { h.subjectResolver = f }
}

// WithPurpose sets the fixed challenge purpose (default "login").
func WithPurpose(purpose string) HandlerOption {
	return func(h *handlerConfig) { h.purpose = purpose }
}

// WithPurposeResolver derives the purpose from the request (overrides WithPurpose when set).
func WithPurposeResolver(f func(*http.Request) string) HandlerOption {
	return func(h *handlerConfig) { h.purposeResolver = f }
}

// WithCodeField overrides the form field carrying the code in VerifyHandler (default "code").
func WithCodeField(name string) HandlerOption {
	return func(h *handlerConfig) { h.codeField = name }
}

// WithTenantResolver derives the tenant from the request to scope store operations. The tenant is
// resolved ONCE per request and that single value scopes both the mint and the verification.
//
// A configured resolver MUST return a non-empty tenant ID for any request it can map. Returning
// "" means "the tenant could not be resolved" (an unmapped Host, a missing path segment, an
// absent claim) and the handler then REFUSES the request (401) instead of minting or verifying a
// challenge in the single-tenant ("") partition. Map the request explicitly (an allowlist of known
// hosts or a canonical host->tenant table), never the raw Host header. The "" partition is used
// only when no resolver is configured at all (single-tenant mode).
func WithTenantResolver(f func(*http.Request) string) HandlerOption {
	return func(h *handlerConfig) {
		if f == nil {
			h.tenantResolver = nil
			return
		}
		h.tenantResolver = func(r *http.Request) (string, bool) {
			tenant := f(r)
			return tenant, tenant != ""
		}
	}
}

// WithTrustedOrigins adds extra hosts to the CSRF same-origin allowlist for the OTP handlers.
//
// The origin check is ON by default (see originAllowed / WithInsecureNoOriginCheck): even with no
// trusted origins configured, a POST whose Origin (or Referer fallback) host is not the request's
// own Host is rejected with 403. This option WIDENS that allowlist to permit additional hosts.
// Supply hosts WITHOUT scheme, e.g. "app.example.com". To turn the check off entirely, use
// WithInsecureNoOriginCheck. See the identity/tokens handlers for the same behavior.
func WithTrustedOrigins(origins ...string) HandlerOption {
	return func(h *handlerConfig) {
		h.trustedOrigins = make(map[string]bool, len(origins))
		for _, o := range origins {
			h.trustedOrigins[o] = true
		}
	}
}

// WithMaxBodyBytes overrides the request-body cap (default DefaultMaxBodyBytes). Non-positive
// disables it.
func WithMaxBodyBytes(n int64) HandlerOption {
	return func(h *handlerConfig) { h.maxBodyBytes = n }
}

// WithSuccessRedirect replies with a 303 redirect to url on success instead of 204.
func WithSuccessRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.successURL = url }
}

// WithFailureRedirect replies with a 303 redirect to url (carrying ?error=<code>) on failure.
func WithFailureRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.failureURL = url }
}

// WithOnVerified runs after a successful verification (e.g. to issue a session/token pair). It
// owns the response when set; otherwise the handler replies 204 / the success redirect.
func WithOnVerified(f func(w http.ResponseWriter, r *http.Request, subjectID uuid.UUID)) HandlerOption {
	return func(h *handlerConfig) { h.onVerified = f }
}

// WithMaxConcurrentDeliveries caps the number of in-flight off-response-path deliveries
// (mail/SMS) a handler instance runs concurrently (default DefaultDeliveryConcurrency).
// IssueHandler dispatches delivery on a detached goroutine; this bound stops an unauthenticated
// flood from spawning unbounded goroutines or amplifying into unbounded outbound mail/SMS
// (toll fraud). When the cap is reached, further deliveries are DROPPED (not queued) rather
// than blocking the caller. A non-positive value disables the bound (deliveries fan out
// unbounded again) — do so only if an upstream layer already bounds the fan-out.
func WithMaxConcurrentDeliveries(n int) HandlerOption {
	return func(h *handlerConfig) { h.deliveryConcurrency = n }
}

// WithDeliveryTimeout sets the per-delivery timeout applied to the detached delivery context
// (default DefaultDeliveryTimeout), so a slow or hung Mailer/SMSSender cannot pin a delivery
// slot indefinitely. The timeout bounds delivery independently of the request lifetime: the
// context is detached (context.WithoutCancel) so the request finishing does not cancel delivery,
// but the timeout still abandons a delivery that runs too long. A non-positive value disables
// the timeout.
func WithDeliveryTimeout(d time.Duration) HandlerOption {
	return func(h *handlerConfig) { h.deliveryTimeout = d }
}

// IssueHandler builds an HTTP handler that mints an OTP for the resolved subject and hands the
// Challenge (including the plaintext code) to deliver for out-of-band delivery (email/SMS).
// It ALWAYS responds uniformly (204 / success redirect) — whether or not a subject was
// resolved or delivery succeeded — so it leaks no account-existence signal. Both the mint
// (svc.Issue) and delivery run off the response path: the request goroutine does no
// subject-dependent store work, so an existing subject cannot be distinguished from an unknown
// one by response latency (no timing oracle).
//
// Issuing and delivery are BOUNDED together: the handler instance holds a shared semaphore (see
// WithMaxConcurrentDeliveries) that caps concurrent in-flight goroutines and a per-delivery
// timeout (see WithDeliveryTimeout) that prevents a hung backend from pinning a slot
// indefinitely. Under a semaphore-full flood a mint may be dropped rather than queued — intended
// backpressure for an often-unauthenticated endpoint.
func IssueHandler(svc Service, deliver func(ctx context.Context, ch *Challenge) error, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !cfg.originAllowed(r) {
			cfg.fail(w, r, http.StatusForbidden, "cross_site_blocked")
			return
		}
		tenant, ok := cfg.requireTenant(w, r, "unauthorized")
		if !ok {
			return
		}
		if cfg.subjectResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		if subjectID, ok := cfg.subjectResolver(r); ok {
			purpose := cfg.purposeOf(r)
			cfg.dispatchDelivery(r, func(ctx context.Context) error {
				ch, err := svc.Issue(ctx, tenant, subjectID, purpose)
				if err != nil {
					return err
				}
				if deliver != nil {
					return deliver(ctx, ch)
				}
				return nil
			})
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// VerifyHandler builds an HTTP handler that verifies a presented OTP for the resolved subject.
// Every failure — wrong code, no/expired challenge, or too many attempts — is collapsed into a
// single 401 "invalid_code" response, so a client cannot tell a wrong guess from a missing
// challenge from a burned one (challenge enumeration). On success it runs WithOnVerified (if
// set) or replies 204 / the success redirect.
func VerifyHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !cfg.originAllowed(r) {
			cfg.fail(w, r, http.StatusForbidden, "cross_site_blocked")
			return
		}
		tenant, ok := cfg.requireTenant(w, r, "invalid_code")
		if !ok {
			return
		}
		if cfg.subjectResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		subjectID, ok := cfg.subjectResolver(r)
		code := r.PostForm.Get(cfg.codeField)
		// Uniform rejection for an unresolved subject or any verify failure.
		if !ok {
			cfg.fail(w, r, http.StatusUnauthorized, "invalid_code")
			return
		}
		if err := svc.Verify(r.Context(), tenant, subjectID, cfg.purposeOf(r), code); err != nil {
			cfg.fail(w, r, http.StatusUnauthorized, "invalid_code")
			return
		}

		if cfg.onVerified != nil {
			cfg.onVerified(w, r, subjectID)
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// dispatchDelivery hands a freshly minted OTP challenge to the deliver callback off the
// response path (a detached context, so the request finishing does not cancel delivery, and so
// the callback's latency is not a timing side channel). Delivery failures are swallowed so the
// response stays enumeration-safe.
//
// The fan-out is BOUNDED. IssueHandler is often unauthenticated, so an attacker can flood it
// for valid/guessable subjects; an unbounded goroutine-per-call would spawn unbounded concurrent
// goroutines and amplify into unbounded outbound mail/SMS (toll fraud). A buffered channel
// semaphore (cfg.deliverySem, created ONCE per handler instance and shared across all of its
// concurrent requests) caps in-flight deliveries at cfg.deliveryConcurrency. A slot is acquired
// NON-BLOCKING: when the semaphore is full the delivery is DROPPED (never queued, never blocks
// the caller). The slot is released when the delivery goroutine finishes.
//
// Each delivery also runs under a per-delivery timeout (cfg.deliveryTimeout) derived from the
// DETACHED context, so a slow or hung backend cannot pin a slot indefinitely while still keeping
// delivery durable across the request finishing.
func (cfg handlerConfig) dispatchDelivery(r *http.Request, send func(ctx context.Context) error) {
	base := context.WithoutCancel(r.Context())

	if cfg.deliverySem != nil {
		select {
		case cfg.deliverySem <- struct{}{}:
			// Slot acquired; released by the goroutine below.
		default:
			// Semaphore full: drop the delivery rather than block the caller goroutine.
			return
		}
	}

	go func() {
		if cfg.deliverySem != nil {
			defer func() { <-cfg.deliverySem }()
		}
		ctx := base
		if cfg.deliveryTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(base, cfg.deliveryTimeout)
			defer cancel()
		}
		_ = send(ctx)
	}()
}

func (cfg handlerConfig) purposeOf(r *http.Request) string {
	if cfg.purposeResolver != nil {
		return cfg.purposeResolver(r)
	}
	return cfg.purpose
}

func (cfg handlerConfig) resolveTenant(r *http.Request) (string, bool) {
	if cfg.tenantResolver == nil {
		return "", true
	}
	return cfg.tenantResolver(r)
}

func (cfg handlerConfig) requireTenant(w http.ResponseWriter, r *http.Request, code string) (string, bool) {
	tenant, ok := cfg.resolveTenant(r)
	if !ok {
		cfg.fail(w, r, http.StatusUnauthorized, code)
		return "", false
	}
	return tenant, true
}

func (cfg handlerConfig) parseLimitedForm(w http.ResponseWriter, r *http.Request) bool {
	return httputil.ParseLimitedForm(w, r, cfg.maxBodyBytes, cfg.fail)
}

// originAllowed reports whether the request passes the CSRF same-origin check. The check is ON
// by default — even with an empty trustedOrigins allowlist — to match the tokens/identity handlers
// and make "CSRF-by-default" mean the same thing across handler families. A request is allowed only
// when its Origin (or Referer fallback) host equals the request's own Host or an allowlisted host;
// a POST carrying neither header is treated as untrusted. WithInsecureNoOriginCheck restores the
// pre-v1 accept-all behavior.
func (cfg handlerConfig) originAllowed(r *http.Request) bool {
	if cfg.insecureNoOriginCheck {
		return true
	}
	host := httputil.RequestOriginHost(r)
	if host == "" {
		return false
	}
	return host == r.Host || cfg.trustedOrigins[host]
}

func (cfg handlerConfig) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	httputil.Fail(w, r, cfg.failureURL, status, code)
}

// WithInsecureNoOriginCheck disables the CSRF same-origin check on the OTP handlers.
//
// By default these handlers reject any state-changing POST whose Origin (or Referer fallback)
// host is neither the request's own Host nor an explicitly trusted origin (see WithTrustedOrigins).
// This option turns that protection OFF, restoring the pre-v1 behavior where every origin is
// accepted. It is named "Insecure" deliberately: only reach for it when CSRF is handled by a
// separate layer or in trusted test setups. Prefer WithTrustedOrigins to extend, rather than
// remove, the allowlist.
func WithInsecureNoOriginCheck() HandlerOption {
	return func(h *handlerConfig) { h.insecureNoOriginCheck = true }
}
