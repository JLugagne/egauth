package identity

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
)

// ClaimsBuilder maps an authenticated user to the claims embedded in their issued tokens.
// The application supplies it so egauth stays agnostic about the custom claim type C.
// Implementations should leave Claims.ExpiresAt zero so the issuer's configured access TTL
// applies.
type ClaimsBuilder[C any] func(*User) tokens.Claims[C]

// DefaultMaxBodyBytes is the default cap applied to the request body of the form handlers.
// It bounds attacker-controlled input (notably the password field, which feeds the expensive
// argon2 KDF) to prevent a pre-authentication CPU/memory amplification DoS. It is comfortably
// larger than a legitimate email+password+token form. Override with WithMaxBodyBytes.
const DefaultMaxBodyBytes int64 = 4 << 10 // 4 KiB

// DefaultDeliveryConcurrency is the default cap on the number of in-flight off-response-path
// deliveries (mail/SMS) a single handler instance will run concurrently. It bounds the
// unauthenticated goroutine fan-out the Request* handlers can be driven to spawn: without a cap,
// a flood of requests for valid/guessable accounts could spawn unbounded concurrent goroutines and
// amplify into unbounded outbound mail/SMS (toll fraud). Override with WithDeliveryConcurrency.
const DefaultDeliveryConcurrency = 64

// DefaultDeliveryTimeout is the default per-delivery timeout applied to the off-response-path
// delivery context, so a slow or hung Mailer/SMSSender cannot pin a delivery slot indefinitely.
// Override with WithDeliveryTimeout.
const DefaultDeliveryTimeout = 30 * time.Second

// DefaultInterimTokenTTL is the lifetime of the short-lived INTERIM access token issued by an
// MFA-gated LoginHandler to an enrolled user after a correct password but before the second
// factor is verified. It must be just long enough for the user to complete the TOTP/recovery
// step, never long enough to be a usable session. Override with WithInterimTokenTTL.
const DefaultInterimTokenTTL = 5 * time.Minute

// handlerConfig holds the configurable behavior of the identity HTTP handlers.
type handlerConfig struct {
	provider             string
	cookies              tokens.Cookies
	tenantResolver       func(*http.Request) string
	successURL           string
	failureURL           string
	emailField           string
	passwordField        string
	rememberField        string
	tokenField           string
	currentPasswordField string
	newPasswordField     string
	newEmailField        string
	phoneField           string
	recoveryEmailField   string
	userResolver         func(*http.Request) (*User, bool)
	trustedOrigins       map[string]bool
	maxBodyBytes         int64
	events               event.Sink
	deliveryConcurrency  int
	deliveryTimeout      time.Duration
	// deliverySem is a buffered-channel semaphore bounding concurrent off-response-path
	// deliveries. It is created ONCE in newHandlerConfig (so it is shared across every request
	// served by a given handler instance — a per-request channel would make the cap meaningless)
	// with capacity deliveryConcurrency; a non-positive cap leaves it nil, disabling the bound.
	deliverySem chan struct{}
	// mfaGate, when non-nil, turns LoginHandler into an MFA-gated handler: after a correct
	// password it checks whether the user has a confirmed second factor and, if so, issues a
	// short-lived INTERIM access token (AMR=[pwd], no refresh cookie) instead of the full pair,
	// forcing a step-up (see mfa.StepUpHandler) before a refreshable session is granted.
	mfaGate MFAEnrollmentChecker
	// interimTTL is the lifetime of that interim access token. Zero means DefaultInterimTokenTTL.
	interimTTL time.Duration
}

// HandlerOption configures the identity HTTP handlers (LoginHandler, RegisterHandler).
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{
		provider:             "password",
		cookies:              tokens.DefaultCookies(),
		emailField:           "email",
		passwordField:        "password",
		rememberField:        "remember_me",
		tokenField:           "token",
		currentPasswordField: "current_password",
		newPasswordField:     "new_password",
		newEmailField:        "new_email",
		phoneField:           "phone",
		recoveryEmailField:   "recovery_email",
		maxBodyBytes:         DefaultMaxBodyBytes,
		deliveryConcurrency:  DefaultDeliveryConcurrency,
		deliveryTimeout:      DefaultDeliveryTimeout,
		interimTTL:           DefaultInterimTokenTTL,
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

// WithProvider sets the identity provider used by the credential (form) login path
// (default "password"). Only "password" carries a verifiable secret on this path:
// Service.Authenticate compares the submitted password against the stored hash. Any other
// provider (e.g. "google"/"github") has no password to compare, so the credential path now
// rejects it with ErrInvalidCredentials rather than authenticating on identifier alone —
// setting it here does NOT turn the login form into a passwordless bypass. External
// identities must be established through their own OAuth/OIDC flow, not this handler.
func WithProvider(provider string) HandlerOption {
	return func(h *handlerConfig) { h.provider = provider }
}

// WithCookies replaces the cookie configuration wholesale.
func WithCookies(c tokens.Cookies) HandlerOption {
	return func(h *handlerConfig) { h.cookies = c }
}

// WithCookieDomain scopes the auth cookies to a domain.
func WithCookieDomain(domain string) HandlerOption {
	return func(h *handlerConfig) { h.cookies.Domain = domain }
}

// WithSameSite overrides the SameSite attribute of the auth cookies.
func WithSameSite(mode http.SameSite) HandlerOption {
	return func(h *handlerConfig) { h.cookies.SameSite = mode }
}

// WithCookiePath sets the path for both the access and refresh cookies.
func WithCookiePath(path string) HandlerOption {
	return func(h *handlerConfig) {
		h.cookies.Path = path
		h.cookies.RefreshPath = path
	}
}

// WithRefreshCookiePath scopes only the refresh cookie (e.g. to a dedicated refresh route).
func WithRefreshCookiePath(path string) HandlerOption {
	return func(h *handlerConfig) { h.cookies.RefreshPath = path }
}

// WithInsecureCookies disables the Secure attribute. Use only for local HTTP development.
func WithInsecureCookies() HandlerOption {
	return func(h *handlerConfig) { h.cookies.Insecure = true }
}

// WithSuccessRedirect makes the handler reply with a 303 redirect to url on success
// (instead of 204 No Content).
func WithSuccessRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.successURL = url }
}

// WithFailureRedirect makes the handler reply with a 303 redirect to url (with an
// ?error=<code> query parameter) on failure, instead of an HTTP error status.
func WithFailureRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.failureURL = url }
}

// WithFormFields overrides the form field names read from the POST body.
func WithFormFields(email, password, remember string) HandlerOption {
	return func(h *handlerConfig) {
		h.emailField = email
		h.passwordField = password
		h.rememberField = remember
	}
}

// WithTenantResolver derives the tenant from the request to scope identity and token store
// operations in multi-tenant deployments.
func WithTenantResolver(f func(*http.Request) string) HandlerOption {
	return func(h *handlerConfig) { h.tenantResolver = f }
}

// WithTokenField overrides the form field carrying the verification token in the
// password-reset and email-verification confirmation handlers (default "token").
func WithTokenField(name string) HandlerOption {
	return func(h *handlerConfig) { h.tokenField = name }
}

// WithUserResolver supplies the authenticated user to RequestEmailVerificationHandler,
// typically by reading whatever the application's auth middleware stashed on the request
// context. When it is unset (or returns ok=false) the handler responds 401.
func WithUserResolver(f func(*http.Request) (*User, bool)) HandlerOption {
	return func(h *handlerConfig) { h.userResolver = f }
}

// WithHandlerEventSink registers a security-event sink (see the event package) for the handlers.
// Its main use is making swallowed Mailer delivery failures observable: the Request* handlers
// reply uniformly for enumeration safety and dispatch delivery off the response path, so a Mailer
// outage is otherwise invisible — with a sink configured it surfaces as a DeliveryFailed event.
// (The identity Service has its own WithEventSink for service-level lifecycle events.)
func WithHandlerEventSink(sink event.Sink) HandlerOption {
	return func(h *handlerConfig) { h.events = sink }
}

// WithTrustedOrigins enables CSRF origin checking on the form handlers (login/register).
//
// Login and registration are state-changing endpoints driven purely by the request body,
// so SameSite=Lax cookies alone do not prevent login-CSRF / session fixation (the attack
// needs no pre-existing cookie). When trusted origins are configured, a request whose
// Origin — or, failing that, Referer — host is neither the request's own Host nor one of
// the supplied hosts is rejected with 403. Supply hosts WITHOUT scheme, e.g.
// "app.example.com". When left unset the check is disabled and CSRF protection becomes the
// consumer's responsibility (see SECURITY.md).
func WithTrustedOrigins(origins ...string) HandlerOption {
	return func(h *handlerConfig) {
		h.trustedOrigins = make(map[string]bool, len(origins))
		for _, o := range origins {
			h.trustedOrigins[o] = true
		}
	}
}

// WithPasswordChangeFields overrides the form field names read by ChangePasswordHandler
// (defaults "current_password" and "new_password").
func WithPasswordChangeFields(current, newField string) HandlerOption {
	return func(h *handlerConfig) {
		h.currentPasswordField = current
		h.newPasswordField = newField
	}
}

// WithEmailChangeField overrides the form field carrying the requested new address in
// RequestEmailChangeHandler (default "new_email").
func WithEmailChangeField(name string) HandlerOption {
	return func(h *handlerConfig) { h.newEmailField = name }
}

// WithPhoneField overrides the form field carrying the requested phone number in
// RequestPhoneVerificationHandler (default "phone").
func WithPhoneField(name string) HandlerOption {
	return func(h *handlerConfig) { h.phoneField = name }
}

// WithRecoveryEmailField overrides the form field carrying the candidate recovery address in
// RequestRecoveryEmailHandler (default "recovery_email").
func WithRecoveryEmailField(name string) HandlerOption {
	return func(h *handlerConfig) { h.recoveryEmailField = name }
}

// WithMaxBodyBytes overrides the request-body size cap applied before form parsing
// (default DefaultMaxBodyBytes). A non-positive value disables the cap; do so only if an
// upstream layer already bounds the body, since an unbounded password feeds the expensive
// argon2 KDF (a pre-auth DoS vector).
func WithMaxBodyBytes(n int64) HandlerOption {
	return func(h *handlerConfig) { h.maxBodyBytes = n }
}

// WithDeliveryConcurrency caps the number of in-flight off-response-path deliveries (mail/SMS)
// a handler instance runs concurrently (default DefaultDeliveryConcurrency). The Request*
// handlers dispatch delivery on a detached goroutine; this bound stops an unauthenticated flood
// from spawning unbounded goroutines or amplifying into unbounded outbound mail/SMS. When the
// cap is reached further deliveries are DROPPED (not queued) and surface as a DeliveryFailed
// event rather than blocking the request. A non-positive value disables the bound (deliveries
// fan out unbounded again) — do so only if an upstream layer already bounds the fan-out.
func WithDeliveryConcurrency(n int) HandlerOption {
	return func(h *handlerConfig) { h.deliveryConcurrency = n }
}

// WithDeliveryTimeout sets the per-delivery timeout applied to the detached delivery context
// (default DefaultDeliveryTimeout), so a slow or hung Mailer/SMSSender cannot pin a delivery slot
// indefinitely. The timeout bounds delivery independently of the request lifetime: the context is
// detached (context.WithoutCancel) so the request finishing does not cancel delivery, but the
// timeout still abandons a delivery that runs too long. A non-positive value disables the timeout.
func WithDeliveryTimeout(d time.Duration) HandlerOption {
	return func(h *handlerConfig) { h.deliveryTimeout = d }
}

// parseLimitedForm bounds the request body to cfg.maxBodyBytes before parsing the form. It
// protects the argon2 hashing path from unbounded attacker-controlled input. On failure it
// writes the error response (413 when the body is too large, 400 when malformed) and returns
// false.
func (cfg handlerConfig) parseLimitedForm(w http.ResponseWriter, r *http.Request) bool {
	if cfg.maxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes)
	}
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			cfg.fail(w, r, http.StatusRequestEntityTooLarge, "request_too_large")
		} else {
			cfg.fail(w, r, http.StatusBadRequest, "invalid_request")
		}
		return false
	}
	return true
}

// LoginHandler builds an HTTP handler that authenticates form credentials and, on success,
// issues an access+refresh token pair, writes them as secure cookies and redirects.
//
// The request is expected as application/x-www-form-urlencoded with email, password and an
// optional remember_me field; remember_me makes the refresh cookie persistent.
func LoginHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		email := strings.TrimSpace(r.PostForm.Get(cfg.emailField))
		password := r.PostForm.Get(cfg.passwordField)
		remember := parseFormBool(r.PostForm.Get(cfg.rememberField))

		user, err := svc.Authenticate(r.Context(), cfg.tenant(r), cfg.provider, email, password)
		if err != nil {
			status, code := mapAuthError(err)
			cfg.fail(w, r, status, code)
			return
		}

		// MFA gate: when configured, an enrolled user does NOT get a full refreshable session on
		// the password alone. They receive a short-lived interim access token (AMR=[pwd], no
		// refresh cookie) and must complete the second factor (see mfa.StepUpHandler) to obtain
		// the full pair. Users without an enrolled factor fall through to the full pair below.
		if cfg.mfaGate != nil {
			enrolled, err := cfg.mfaGate.IsEnrolled(r.Context(), cfg.tenant(r), user.ID)
			if err != nil {
				cfg.fail(w, r, http.StatusInternalServerError, "mfa_check_failed")
				return
			}
			if enrolled {
				if err := issueInterimAndSetCookie(w, r, cfg, issuer, claimsOf, user); err != nil {
					cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
					return
				}
				redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
				return
			}
		}

		if err := issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, remember); err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// RegisterHandler builds an HTTP handler that registers a new user from form credentials
// and, on success, auto-logs them in by issuing a token pair and writing the auth cookies.
func RegisterHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		email := strings.TrimSpace(r.PostForm.Get(cfg.emailField))
		password := r.PostForm.Get(cfg.passwordField)
		remember := parseFormBool(r.PostForm.Get(cfg.rememberField))

		user, err := svc.Register(r.Context(), cfg.tenant(r), email, password)
		if err != nil {
			status, code := mapRegisterError(err)
			cfg.fail(w, r, status, code)
			return
		}

		if err := issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, remember); err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// issuePairAndSetCookies builds the user's claims, issues a token pair and writes both auth
// cookies. The refresh cookie is persistent when remember is true.
func issuePairAndSetCookies[C any](w http.ResponseWriter, r *http.Request, cfg handlerConfig, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], user *User, remember bool) error {
	claims := claimsOf(user)
	pair, err := issuer.IssueTokenPair(r.Context(), claims)
	if err != nil {
		return err
	}
	cfg.cookies.SetAccess(w, pair.AccessToken)
	cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, remember)
	return nil
}

func (cfg handlerConfig) tenant(r *http.Request) string {
	if cfg.tenantResolver == nil {
		return ""
	}
	return cfg.tenantResolver(r)
}

// dispatchDelivery hands a freshly minted credential to the Mailer/SMSSender off the response
// path (a detached context, so the request finishing does not cancel delivery, and so the
// Mailer's latency — which only occurs for existing accounts — is not a timing side channel). A
// delivery failure is otherwise swallowed to keep the enumeration-safe response uniform; emitting
// a DeliveryFailed event makes that otherwise-invisible outage observable to a configured sink.
//
// The fan-out is BOUNDED. The Request* handlers are mostly unauthenticated, so an attacker can
// flood them for valid/guessable accounts; an unbounded goroutine-per-call would spawn unbounded
// concurrent goroutines and amplify into unbounded outbound mail/SMS (toll fraud). A buffered
// channel semaphore (cfg.deliverySem, created ONCE per handler instance and shared across all of
// its concurrent requests) caps the in-flight deliveries at cfg.deliveryConcurrency. A slot is
// acquired NON-BLOCKING: when the semaphore is full the delivery is DROPPED (never queued, never
// blocks the caller) and surfaces as a DeliveryFailed event, so an over-cap drop is observable
// exactly like a Mailer outage. The slot is released when the delivery goroutine finishes.
//
// Each delivery also runs under a per-delivery timeout (cfg.deliveryTimeout) derived from the
// DETACHED context, so a slow or hung backend cannot pin a slot indefinitely while still keeping
// delivery durable across the request finishing.
func (cfg handlerConfig) dispatchDelivery(r *http.Request, userID string, send func(ctx context.Context) error) {
	base := context.WithoutCancel(r.Context())
	tenant := cfg.tenant(r)

	if cfg.deliverySem != nil {
		select {
		case cfg.deliverySem <- struct{}{}:
			// Slot acquired; released by the goroutine below.
		default:
			// Semaphore full: drop the delivery rather than block the (often unauthenticated)
			// caller goroutine, and surface the drop as a DeliveryFailed event so it is observable.
			event.Emit(base, cfg.events, event.Event{
				Type: event.DeliveryFailed, TenantID: tenant, UserID: userID,
				Reason: "delivery_concurrency_exceeded", Err: ErrDeliveryDropped,
			})
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
		if err := send(ctx); err != nil {
			event.Emit(ctx, cfg.events, event.Event{
				Type: event.DeliveryFailed, TenantID: tenant, UserID: userID, Err: err,
			})
		}
	}()
}

// originAllowed reports whether the request passes the CSRF origin check. When no trusted
// origins are configured the check is disabled (CSRF protection is then the consumer's
// responsibility, per SECURITY.md). A configured check rejects any request whose Origin
// (or Referer fallback) host is neither the request's own Host nor an allowlisted host;
// a browser-driven POST that carries neither header is treated as untrusted.
func (cfg handlerConfig) originAllowed(r *http.Request) bool {
	if len(cfg.trustedOrigins) == 0 {
		return true
	}
	host := requestOriginHost(r)
	if host == "" {
		return false
	}
	return host == r.Host || cfg.trustedOrigins[host]
}

func requestOriginHost(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		if u, err := url.Parse(o); err == nil {
			return u.Host
		}
		return ""
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			return u.Host
		}
	}
	return ""
}

func (cfg handlerConfig) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	if cfg.failureURL != "" {
		http.Redirect(w, r, withErrorParam(cfg.failureURL, code), http.StatusSeeOther)
		return
	}
	http.Error(w, code, status)
}

// mapAuthError maps authentication errors to an HTTP status and a stable error code.
// Note: per the PRD, ErrAccountLocked is intentionally surfaced (429) even though it
// reveals that the account exists; lockout is meant to be observable.
// ErrAccountDisabled is folded into the same 429 "account_locked" response to avoid
// leaking whether an existing account is suspended versus locked (enumeration defence).
func mapAuthError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrAccountLocked):
		return http.StatusTooManyRequests, "account_locked"
	case errors.Is(err, ErrAccountDisabled):
		// Fold disabled into the same response as locked so that callers cannot
		// distinguish a suspended (disabled) account from a locked one: both yield
		// 429 "account_locked". This prevents account-state enumeration while still
		// avoiding the misleading 500 "login_failed" that the default branch would
		// otherwise return.
		return http.StatusTooManyRequests, "account_locked"
	case errors.Is(err, ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid_credentials"
	default:
		return http.StatusInternalServerError, "login_failed"
	}
}

// RequestPasswordResetHandler builds an HTTP handler that starts the password-reset flow.
// It reads the account email from the form, mints a reset token and hands it to the Mailer
// for delivery. To prevent account enumeration it ALWAYS responds the same way — success —
// whether or not the email maps to an account, and it ignores Mailer delivery errors so the
// response is uniform (the Mailer should handle its own logging/retries).
//
// This and the other unauthenticated Request* handlers (RequestMagicLinkHandler,
// RequestPhoneVerificationHandler, RequestPasswordResetViaRecoveryHandler) are NOT throttled
// by egauth — per-IP / per-destination rate limiting remains YOUR responsibility. Wrap them
// with [github.com/JLugagne/egauth/ratelimit.Middleware] (the recommended way to throttle
// these endpoints); see the ratelimit package examples for a turnkey rate-limited router.
func RequestPasswordResetHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		email := strings.TrimSpace(r.PostForm.Get(cfg.emailField))
		// Swallow the service error: the client-visible response must be identical whether or
		// not the email maps to an account, so a backend error must NOT be surfaced as a
		// distinct status — a 500 reachable only for existing accounts would itself be an
		// enumeration oracle. Errors are the consumer's to observe via their own Mailer/store.
		token, user, _ := svc.RequestPasswordReset(r.Context(), cfg.tenant(r), email)
		if token != "" && user != nil && mailer.PasswordReset != nil {
			cfg.dispatchDelivery(r, user.ID.String(), func(ctx context.Context) error {
				return mailer.PasswordReset(ctx, PasswordResetMail{User: user, Token: token})
			})
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// ResetPasswordHandler builds an HTTP handler that completes the password-reset flow: it
// reads the token and the new password from the form, validates the password against the
// policy, consumes the (single-use) token and sets the new password.
func ResetPasswordHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		password := r.PostForm.Get(cfg.passwordField)
		if err := svc.ResetPassword(r.Context(), cfg.tenant(r), token, password); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// RequestEmailVerificationHandler builds an HTTP handler that (re)sends an email-verification
// token for the currently authenticated user. The user is obtained via WithUserResolver; if
// no resolver is configured or it reports no user, the handler responds 401.
func RequestEmailVerificationHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.userResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		user, ok := cfg.userResolver(r)
		if !ok || user == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}

		token, err := svc.RequestEmailVerification(r.Context(), cfg.tenant(r), user.ID)
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "verification_request_failed")
			return
		}
		// token is empty when the account is not a live, same-tenant user (swallowed at the
		// service for enumeration safety); only dispatch delivery when a token was minted.
		if token != "" && mailer.EmailVerification != nil {
			cfg.dispatchDelivery(r, user.ID.String(), func(ctx context.Context) error {
				return mailer.EmailVerification(ctx, EmailVerificationMail{User: user, Token: token})
			})
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// VerifyEmailHandler builds an HTTP handler that completes the email-verification flow: it
// reads the token from the form, consumes it (single-use) and marks the email verified. It is
// POST-only on purpose — a GET-triggered side effect would be consumed by link prefetchers
// and email scanners, so the verification link should land on a page that POSTs the token.
func VerifyEmailHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		if _, err := svc.VerifyEmail(r.Context(), cfg.tenant(r), token); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// RequestMagicLinkHandler builds an HTTP handler that starts the passwordless magic-link login
// flow: it reads the account email from the form, mints a login token and hands it to the
// Mailer. Like the password-reset request it ALWAYS responds uniformly (whether or not the
// email maps to an account) and dispatches delivery off the response path, so it leaks no
// account-existence signal.
func RequestMagicLinkHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		email := strings.TrimSpace(r.PostForm.Get(cfg.emailField))
		token, user, _ := svc.RequestMagicLink(r.Context(), cfg.tenant(r), email)
		if token != "" && user != nil && mailer.MagicLink != nil {
			cfg.dispatchDelivery(r, user.ID.String(), func(ctx context.Context) error {
				return mailer.MagicLink(ctx, MagicLinkMail{User: user, Token: token})
			})
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// MagicLinkLoginHandler builds an HTTP handler that completes passwordless login: it consumes
// the magic-link token (single-use) from the form and, on success, issues an access+refresh
// token pair and writes the auth cookies — exactly like LoginHandler, but authenticated by the
// emailed token instead of a password. The optional remember_me field makes the refresh cookie
// persistent.
func MagicLinkLoginHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		remember := parseFormBool(r.PostForm.Get(cfg.rememberField))

		user, err := svc.LoginWithMagicLink(r.Context(), cfg.tenant(r), token)
		if err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}

		if err := issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, remember); err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// ChangePasswordHandler builds an authenticated HTTP handler that lets a signed-in user
// change their own password. The current user is obtained via WithUserResolver (typically
// reading whatever the application's auth middleware stashed on the request); if no resolver
// is configured or it reports no user, the handler responds 401. It reads the current and new
// passwords from the form (fields configurable via WithPasswordChangeFields), then calls
// Service.ChangePassword.
//
// On success the consumer SHOULD revoke the user's other sessions / refresh-token families
// (cross-module, so not done here). A wrong current password maps to 401; a new password that
// fails the policy maps to 400.
func ChangePasswordHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
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
		if cfg.userResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		user, ok := cfg.userResolver(r)
		if !ok || user == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		current := r.PostForm.Get(cfg.currentPasswordField)
		newPassword := r.PostForm.Get(cfg.newPasswordField)

		if err := svc.ChangePassword(r.Context(), cfg.tenant(r), user.ID, current, newPassword); err != nil {
			switch {
			case errors.Is(err, ErrInvalidCredentials):
				cfg.fail(w, r, http.StatusUnauthorized, "invalid_credentials")
			case isPasswordPolicyError(err):
				cfg.fail(w, r, http.StatusBadRequest, "password_rejected")
			default:
				cfg.fail(w, r, http.StatusInternalServerError, "internal_error")
			}
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// RequestEmailChangeHandler builds an authenticated HTTP handler that starts the change-email
// flow for the signed-in user. The current user is obtained via WithUserResolver (typically
// reading whatever the application's auth middleware stashed on the request); if no resolver
// is configured or it reports no user, the handler responds 401. It reads the requested new
// address from the form (field configurable via WithEmailChangeField, default "new_email"),
// mints a confirmation token via Service.RequestEmailChange and hands it to the Mailer for
// delivery to the NEW address — delivery is dispatched off the response path. A malformed
// address maps to 400; an address already taken by another account maps to 409.
func RequestEmailChangeHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc {
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
		if cfg.userResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		user, ok := cfg.userResolver(r)
		if !ok || user == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		newEmail := strings.TrimSpace(r.PostForm.Get(cfg.newEmailField))
		token, err := svc.RequestEmailChange(r.Context(), cfg.tenant(r), user.ID, newEmail)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidEmail):
				cfg.fail(w, r, http.StatusBadRequest, "invalid_email")
			case errors.Is(err, ErrEmailAlreadyExists):
				cfg.fail(w, r, http.StatusConflict, "email_taken")
			case errors.Is(err, ErrUserNotFound):
				// The session resolved to an account that is no longer live; treat as unauthorized.
				cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			default:
				cfg.fail(w, r, http.StatusInternalServerError, "internal_error")
			}
			return
		}
		if token != "" && mailer.EmailChange != nil {
			// Deliver to the canonical form of the new address — the same normalization the
			// service applied before binding it to the token.
			deliverTo := newEmail
			if n, nerr := normalizeEmail(newEmail); nerr == nil {
				deliverTo = n
			}
			cfg.dispatchDelivery(r, user.ID.String(), func(ctx context.Context) error {
				return mailer.EmailChange(ctx, EmailChangeMail{User: user, NewEmail: deliverTo, Token: token})
			})
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// ConfirmEmailChangeHandler builds an HTTP handler that completes the change-email flow: it
// reads the token from the form, consumes it (single-use) and atomically switches the account's
// email to the confirmed new address. It is authenticated by the single-use token (delivered to
// the new address), so it needs no resolved session — like VerifyEmailHandler / ResetPassword
// Handler. It is POST-only so a link prefetcher cannot trigger the swap.
func ConfirmEmailChangeHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		if _, err := svc.ConfirmEmailChange(r.Context(), cfg.tenant(r), token); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// DeleteAccountHandler builds an authenticated HTTP handler that lets a signed-in user delete
// their own account. The current user is obtained via WithUserResolver (typically reading
// whatever the application's auth middleware stashed on the request); if no resolver is
// configured or it reports no user, the handler responds 401. On success it clears the auth
// cookies (the account is gone) and responds 204 (or redirects). Deletion is sensitive and
// irreversible: you SHOULD gate it behind a re-authentication / step-up check (fresh proof of
// presence) in front of this handler in addition to the session, and configure WithTrustedOrigins
// so the CSRF origin check is active. For a first-class enforceable step-up, gate the route with
// tokens.WithRequiredAMR(tokens.AMRMFA) and produce MFA-bearing tokens via identity.WithMFAGate +
// mfa.StepUpHandler.
func DeleteAccountHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
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
		if cfg.userResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		user, ok := cfg.userResolver(r)
		if !ok || user == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}

		if err := svc.DeleteAccount(r.Context(), cfg.tenant(r), user.ID); err != nil {
			switch {
			case errors.Is(err, ErrUserNotFound):
				cfg.fail(w, r, http.StatusNotFound, "not_found")
			default:
				cfg.fail(w, r, http.StatusInternalServerError, "internal_error")
			}
			return
		}
		// The account no longer exists; clear this session's auth cookies client-side. Revoking
		// the server-side session/refresh artifacts is handled by the Service's AccountErasers.
		cfg.cookies.Clear(w)
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// mapVerificationError maps password-reset / email-verification / change-email errors to an
// HTTP status and a stable error code.
func mapVerificationError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrVerificationTokenExpired):
		return http.StatusGone, "token_expired"
	case errors.Is(err, ErrVerificationTokenNotFound):
		return http.StatusBadRequest, "invalid_token"
	case errors.Is(err, ErrIdentityNotFound):
		// e.g. a password reset for an account with no password identity (OAuth-only).
		return http.StatusBadRequest, "invalid_token"
	case errors.Is(err, ErrUserNotFound):
		// The token was valid but its account has since been deactivated/deleted.
		return http.StatusBadRequest, "invalid_token"
	case errors.Is(err, ErrEmailAlreadyExists):
		// Change-email: the target address was claimed by another account in the interim.
		return http.StatusConflict, "email_taken"
	case errors.Is(err, ErrPhoneAlreadyExists):
		// Phone-verification: the target number was claimed by another account in the interim.
		return http.StatusConflict, "phone_taken"
	case errors.Is(err, ErrInvalidEmail):
		// Change-email: the token's stored address failed re-validation (defensive).
		return http.StatusBadRequest, "invalid_email"
	case errors.Is(err, ErrInvalidPhone):
		// Phone-verification: the token's stored number failed re-validation (defensive).
		return http.StatusBadRequest, "invalid_phone"
	case isPasswordPolicyError(err):
		return http.StatusBadRequest, "password_rejected"
	default:
		// Unknown/transient backend errors must surface as 5xx — never tell a user that a
		// genuinely valid token or a strong password was "rejected" because the DB hiccuped.
		return http.StatusInternalServerError, "internal_error"
	}
}

// isPasswordPolicyError reports whether err is one of the password-policy rejections raised
// by the default passwords.Policy, so it maps to a 400 rather than a 500. A custom policy
// returning its own error types will fall through to 500; wrap such errors in one of these
// sentinels (or a 400-mapped sentinel of your own) if 400 is desired.
func isPasswordPolicyError(err error) bool {
	return errors.Is(err, passwords.ErrPasswordTooShort) ||
		errors.Is(err, passwords.ErrPasswordTooLong) ||
		errors.Is(err, passwords.ErrPasswordMissingUppercase) ||
		errors.Is(err, passwords.ErrPasswordMissingLowercase) ||
		errors.Is(err, passwords.ErrPasswordMissingNumber) ||
		errors.Is(err, passwords.ErrPasswordMissingSpecial) ||
		errors.Is(err, passwords.ErrPasswordBreached)
}

func mapRegisterError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrEmailAlreadyExists):
		return http.StatusConflict, "email_taken"
	default:
		// Password-policy violations and other validation failures.
		return http.StatusBadRequest, "registration_failed"
	}
}

// parseFormBool interprets common truthy form values, including the HTML checkbox "on".
func parseFormBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "yes":
		return true
	default:
		return false
	}
}

func redirectOrStatus(w http.ResponseWriter, r *http.Request, url string, okStatus int) {
	if url != "" {
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}
	w.WriteHeader(okStatus)
}

func withErrorParam(rawURL, code string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("error", code)
	u.RawQuery = q.Encode()
	return u.String()
}

// RequestPhoneVerificationHandler builds an authenticated HTTP handler that starts the
// phone-verification flow for the signed-in user. The current user is obtained via
// WithUserResolver (typically reading whatever the application's auth middleware stashed on the
// request); if no resolver is configured or it reports no user, the handler responds 401. It reads
// the requested phone number from the form (field configurable via WithPhoneField, default
// "phone"), mints a verification token via Service.RequestPhoneVerification and hands it to the
// SMSSender for delivery to that number — delivery is dispatched off the response path. A malformed
// number maps to 400; a number already taken by another account maps to 409. Phone is a
// lower-assurance contact channel and is NOT an MFA factor (NIST SP 800-63B excludes SMS).
func RequestPhoneVerificationHandler(svc Service, sender SMSSender, opts ...HandlerOption) http.HandlerFunc {
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
		if cfg.userResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		user, ok := cfg.userResolver(r)
		if !ok || user == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		phone := strings.TrimSpace(r.PostForm.Get(cfg.phoneField))
		token, err := svc.RequestPhoneVerification(r.Context(), cfg.tenant(r), user.ID, phone)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidPhone):
				cfg.fail(w, r, http.StatusBadRequest, "invalid_phone")
			case errors.Is(err, ErrPhoneAlreadyExists):
				cfg.fail(w, r, http.StatusConflict, "phone_taken")
			case errors.Is(err, ErrUserNotFound):
				// The session resolved to an account that is no longer live; treat as unauthorized.
				cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			default:
				cfg.fail(w, r, http.StatusInternalServerError, "internal_error")
			}
			return
		}
		if token != "" && sender.PhoneVerification != nil {
			// Deliver to the canonical form of the number — the same normalization the service
			// applied before binding it to the token.
			deliverTo := phone
			if n, nerr := normalizePhone(phone); nerr == nil {
				deliverTo = n
			}
			cfg.dispatchDelivery(r, user.ID.String(), func(ctx context.Context) error {
				return sender.PhoneVerification(ctx, PhoneVerificationSMS{User: user, Phone: deliverTo, Token: token})
			})
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// ConfirmPhoneVerificationHandler builds an HTTP handler that completes the phone-verification
// flow: it reads the token from the form, consumes it (single-use) and atomically sets the
// account's phone to the confirmed number, marking it verified. It is authenticated by the
// single-use token (delivered by SMS to the number), so it needs no resolved session — like
// VerifyEmailHandler / ConfirmEmailChangeHandler. It is POST-only so a link prefetcher cannot
// trigger the change.
func ConfirmPhoneVerificationHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		if _, err := svc.ConfirmPhoneVerification(r.Context(), cfg.tenant(r), token); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// RequestRecoveryEmailHandler builds an authenticated HTTP handler that starts enrollment of an
// independent recovery email for the signed-in user. The current user is obtained via
// WithUserResolver; without a resolved user it responds 401. It reads the candidate address from
// the form (field configurable via WithRecoveryEmailField, default "recovery_email"), mints a token
// via Service.RequestRecoveryEmail and hands it to the Mailer for delivery to THAT address (off the
// response path). A malformed address maps to 400; using the primary email as the recovery address
// maps to 409.
func RequestRecoveryEmailHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc {
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
		if cfg.userResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		user, ok := cfg.userResolver(r)
		if !ok || user == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		recoveryEmail := strings.TrimSpace(r.PostForm.Get(cfg.recoveryEmailField))
		token, err := svc.RequestRecoveryEmail(r.Context(), cfg.tenant(r), user.ID, recoveryEmail)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidEmail):
				cfg.fail(w, r, http.StatusBadRequest, "invalid_email")
			case errors.Is(err, ErrRecoveryEmailIsPrimary):
				cfg.fail(w, r, http.StatusConflict, "recovery_email_is_primary")
			case errors.Is(err, ErrUserNotFound):
				cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			default:
				cfg.fail(w, r, http.StatusInternalServerError, "internal_error")
			}
			return
		}
		if token != "" && mailer.RecoveryEmailVerification != nil {
			deliverTo := recoveryEmail
			if n, nerr := normalizeEmail(recoveryEmail); nerr == nil {
				deliverTo = n
			}
			cfg.dispatchDelivery(r, user.ID.String(), func(ctx context.Context) error {
				return mailer.RecoveryEmailVerification(ctx, RecoveryEmailMail{User: user, RecoveryEmail: deliverTo, Token: token})
			})
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// ConfirmRecoveryEmailHandler builds an HTTP handler that completes recovery-email enrollment: it
// reads the token from the form, consumes it (single-use) and sets the account's recovery email,
// marking it verified. It is authenticated by the single-use token (delivered to the recovery
// address), so it needs no resolved session. It is POST-only so a link prefetcher cannot trigger it.
func ConfirmRecoveryEmailHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		if _, err := svc.ConfirmRecoveryEmail(r.Context(), cfg.tenant(r), token); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// RequestPasswordResetViaRecoveryHandler builds an HTTP handler that starts a password reset
// directed at the account's VERIFIED INDEPENDENT recovery channel (recovery email and/or phone)
// rather than the primary inbox — so a compromised primary mailbox cannot drive the reset. It is
// enumeration-uniform: it always responds the same (204 or the success redirect) whether or not the
// account exists or has a recovery channel, dispatching delivery off the response path. mailer
// delivers to the recovery email and sms delivers to the phone; either may be nil to disable that
// channel. It reads the account's primary email from the form (the usual email field).
func RequestPasswordResetViaRecoveryHandler(svc Service, mailer Mailer, sms SMSSender, opts ...HandlerOption) http.HandlerFunc {
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
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		email := strings.TrimSpace(r.PostForm.Get(cfg.emailField))
		// Swallow the service error: the client-visible response must be identical whether or
		// not the email maps to an account, so a backend error must NOT be surfaced as a
		// distinct status — a 500 reachable only for existing accounts would itself be an
		// enumeration oracle. Errors are observable via the store/event instrumentation.
		token, user, channels, _ := svc.RequestPasswordResetViaRecovery(r.Context(), cfg.tenant(r), email)
		// Uniform response regardless of account existence or recovery-channel availability; deliver
		// off the response path to the verified channels only (token/user are empty otherwise).
		if token != "" && user != nil {
			if channels.RecoveryEmail && mailer.PasswordReset != nil && user.RecoveryEmail != nil {
				recoveryEmail := *user.RecoveryEmail
				cfg.dispatchDelivery(r, user.ID.String(), func(ctx context.Context) error {
					return mailer.PasswordReset(ctx, PasswordResetMail{User: &User{
						ID: user.ID, TenantID: user.TenantID, Email: recoveryEmail,
					}, Token: token})
				})
			}
			if channels.Phone && sms.PhoneVerification != nil && user.Phone != nil {
				phone := *user.Phone
				cfg.dispatchDelivery(r, user.ID.String(), func(ctx context.Context) error {
					return sms.PhoneVerification(ctx, PhoneVerificationSMS{User: user, Phone: phone, Token: token})
				})
			}
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// MFAEnrollmentChecker reports whether a user has a confirmed second factor enrolled. It is
// the minimal slice of mfa.Service that the MFA login gate needs; mfa.Service satisfies it
// directly. It is consumed by WithMFAGate so the identity package does not import the mfa
// package (which would create an import cycle: mfa already depends on tokens, not identity).
type MFAEnrollmentChecker interface {
	IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)
}

// WithMFAGate turns LoginHandler into an MFA-gated handler. After a correct password it asks
// the checker whether the user has a confirmed second factor enrolled. An enrolled user is NOT
// granted the full access+refresh pair; instead they receive a short-lived INTERIM access token
// stamped AMR=[tokens.AMRPassword] (never the MFA marker) and NO refresh cookie, so the pre-MFA
// state is not an indefinitely renewable session. The application then drives the second factor
// (e.g. mfa.StepUpHandler) which re-issues the full pair with AMR including tokens.AMRMFA. Users
// without an enrolled factor are unaffected and still receive the full pair.
//
// This is the producing half of the AMR/step-up model whose enforcing half is
// tokens.WithRequiredAMR. mfa.Service satisfies MFAEnrollmentChecker directly.
func WithMFAGate(checker MFAEnrollmentChecker) HandlerOption {
	return func(h *handlerConfig) { h.mfaGate = checker }
}

// WithInterimTokenTTL overrides the lifetime of the INTERIM access token issued by an
// MFA-gated LoginHandler (default DefaultInterimTokenTTL). A non-positive value falls back to
// the default rather than minting a non-expiring token.
func WithInterimTokenTTL(d time.Duration) HandlerOption {
	return func(h *handlerConfig) {
		if d > 0 {
			h.interimTTL = d
		}
	}
}

// issueInterimAndSetCookie issues the short-lived INTERIM access token for an MFA-enrolled user
// who has passed the password step but not yet the second factor, and writes ONLY the access
// cookie. The interim token carries AMR=[tokens.AMRPassword] (so tokens.WithRequiredAMR with the
// MFA marker rejects it) and an explicit short expiry; no refresh cookie is written, so the
// pre-step-up state is not a renewable session. The application completes the flow with
// mfa.StepUpHandler, which re-issues the full pair with the MFA factor in AMR.
func issueInterimAndSetCookie[C any](w http.ResponseWriter, r *http.Request, cfg handlerConfig, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], user *User) error {
	claims := claimsOf(user)
	// Stamp the password factor only and force a short explicit access-token expiry, overriding
	// whatever AMR/ExpiresAt the consumer's builder produced for this pre-MFA token.
	claims.AMR = []string{tokens.AMRPassword}
	ttl := cfg.interimTTL
	if ttl <= 0 {
		ttl = DefaultInterimTokenTTL
	}
	claims.ExpiresAt = time.Now().Add(ttl)
	pair, err := issuer.IssueTokenPair(r.Context(), claims)
	if err != nil {
		return err
	}
	// Deliberately set ONLY the access cookie: the refresh token (minted by the issuer) is not
	// surfaced to the client, so the interim state cannot be renewed via /refresh.
	cfg.cookies.SetAccess(w, pair.AccessToken)
	return nil
}
