package identity

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/httputil"
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
	tenantResolver       func(*http.Request) (string, bool)
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
	// insecureNoOriginCheck disables the strict same-origin CSRF check (see WithInsecureNoOriginCheck). By default the check is ON even with an empty trustedOrigins allowlist.
	insecureNoOriginCheck bool
	maxBodyBytes          int64
	events                event.Sink
	deliveryConcurrency   int
	deliveryTimeout       time.Duration
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
	// mfaRequiredURL is where an MFA-gated login redirects (303) when the user must still complete
	// a second factor. Empty makes that response a 200 JSON {"mfa_required":true} instead, so the
	// pre-step-up outcome is never indistinguishable from a full login (see WithMFARequiredRedirect).
	mfaRequiredURL string
	// assuranceResolver reports the assurance of the credential behind the request. It backs the
	// step-up enforcement of ChangePasswordWithReissueHandler and DeleteAccountHandler and defaults
	// to tokens.AssuranceResolverFromContext (see WithAssuranceResolver). It fails CLOSED: a
	// request whose assurance cannot be resolved is refused.
	assuranceResolver tokens.AssuranceResolver
	// noStepUpCheck disables that enforcement entirely (see WithInsecureNoStepUpCheck).
	noStepUpCheck bool
}

// MFARequiredHeader is set (to "1") on the response of an MFA-gated login whose user must still
// complete a second factor, on every response shape — the 303 of WithMFARequiredRedirect and the
// default 200 JSON alike. It is the machine-readable marker a client can read without access to the
// HttpOnly auth cookies, so an MFA-gated login is never indistinguishable from a full one.
const MFARequiredHeader = "X-Egauth-MFA-Required"

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
		assuranceResolver:    tokens.AssuranceResolverFromContext,
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
	c.cookies.MustValidate()
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
//
// A Domain is incompatible with the __Host- prefix the default names carry, so a cookie name still
// carrying it is DEMOTED (to __Secure- while the cookie stays Secure with Path="/", otherwise to
// the bare name): setting a Domain is an explicit opt-out of host-lock semantics. Note that this
// forfeits the subdomain cookie-tossing protection __Host- provides.
func WithCookieDomain(domain string) HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithDomain(domain) }
}

// WithSameSite overrides the SameSite attribute of the auth cookies.
func WithSameSite(mode http.SameSite) HandlerOption {
	return func(h *handlerConfig) { h.cookies.SameSite = mode }
}

// WithCookiePath sets the path for both the access and refresh cookies.
//
// A path other than "/" is incompatible with the __Host- prefix the default names carry, so a
// cookie name still carrying it is DEMOTED (see WithCookieDomain).
func WithCookiePath(path string) HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithPath(path) }
}

// WithRefreshCookiePath scopes only the refresh cookie (e.g. to a dedicated refresh route).
//
// A path other than "/" is incompatible with the __Host- prefix the default refresh name carries,
// so that name is DEMOTED (see WithCookieDomain).
func WithRefreshCookiePath(path string) HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithRefreshPath(path) }
}

// WithInsecureCookies disables the Secure attribute. Use only for local HTTP development.
//
// Browsers reject a __Host- or __Secure- named cookie that is not Secure, so the cookie names are
// DEMOTED to their bare form ("access_token" / "refresh_token").
func WithInsecureCookies() HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithInsecure() }
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
// operations in multi-tenant deployments. The tenant is resolved ONCE per request and that
// single value scopes every store operation the handler performs, so an impure resolver cannot
// route parts of one request into different partitions.
//
// A configured resolver MUST return a non-empty tenant ID for any request it can map. Returning
// "" means "the tenant could not be resolved" (an unmapped Host, a missing path segment, an
// absent claim) and the handler then REFUSES the request with 401 "tenant_unresolved" instead of
// falling back to the single-tenant ("") partition — where a bootstrap/operator account may
// live. Map the request explicitly (an allowlist of known hosts or a canonical host->tenant
// table), never the raw Host header. The "" partition is used only when no resolver is
// configured at all (single-tenant mode). This mirrors sessions.WithTenantResolver and
// tokens.WithAuthTenantResolver.
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

// WithTrustedOrigins adds extra hosts to the CSRF same-origin allowlist for the form handlers
// (login/register and the authenticated mutations).
//
// The origin check is ON by default (see originAllowed / WithInsecureNoOriginCheck): even with
// no trusted origins configured, a request whose Origin — or, failing that, Referer — host is
// not the request's own Host is rejected with 403. This option WIDENS that allowlist to permit
// additional hosts (e.g. a separate front-end origin on another subdomain). Supply hosts WITHOUT
// scheme, e.g. "app.example.com". To turn the check off entirely, use WithInsecureNoOriginCheck.
//
// Login and registration are state-changing endpoints driven purely by the request body, so
// SameSite=Lax cookies alone do not prevent login-CSRF / session fixation (the attack needs no
// pre-existing cookie) — which is why the default is now strict rather than the consumer's
// responsibility (see SECURITY.md).
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

// WithMFARequiredRedirect makes an MFA-gated login reply with a 303 redirect to url when the user
// must still complete a second factor, instead of the default 200 JSON {"mfa_required":true}. It is
// the pre-step-up counterpart of WithSuccessRedirect: a browser-driven deployment SHOULD configure
// both, pointing this one at the page that collects the second factor. The response also carries the
// MFARequiredHeader either way, and the successURL of a full login is untouched.
func WithMFARequiredRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.mfaRequiredURL = url }
}

// WithAssuranceResolver supplies the assurance of the credential behind the request to the handlers
// that enforce step-up: ChangePasswordWithReissueHandler (which must never upgrade a pre-step-up
// interim credential into a full renewable pair) and DeleteAccountHandler (irreversible).
//
// It DEFAULTS to tokens.AssuranceResolverFromContext, so mounting those handlers behind
// tokens.ContextMiddleware needs no extra wiring. Supply your own only when the access token is
// verified by a middleware of your own; then map its verified tokens.Claims with
// Claims.SatisfiesStepUp / Claims.Interim.
//
// It fails CLOSED: when the resolver is nil or reports ok=false, those handlers refuse the request
// with 403 "step_up_required" rather than guessing that the credential is a full session. Use
// WithInsecureNoStepUpCheck to opt out deliberately.
func WithAssuranceResolver(f tokens.AssuranceResolver) HandlerOption {
	return func(h *handlerConfig) { h.assuranceResolver = f }
}

// WithInsecureNoStepUpCheck disables the step-up enforcement of ChangePasswordWithReissueHandler
// and DeleteAccountHandler.
//
// By default those handlers refuse any request whose credential is a pre-step-up interim one, or
// whose assurance cannot be resolved at all (fail closed), because re-issuing a full pair to — or
// irreversibly deleting an account from — a credential that has not completed the account's second
// factor defeats MFA entirely. This option turns that protection OFF. It is named "Insecure"
// deliberately: only reach for it when no login path in the deployment can mint an interim
// credential (no identity.WithMFAGate, no oauth.WithMFAGate) or in trusted test setups. Prefer
// WithAssuranceResolver to supply the missing signal rather than removing the check.
func WithInsecureNoStepUpCheck() HandlerOption {
	return func(h *handlerConfig) { h.noStepUpCheck = true }
}

// mfaRequired writes the pre-step-up response of an MFA-gated login: the machine-readable
// MFARequiredHeader plus either the configured 303 redirect (WithMFARequiredRedirect) or a 200 JSON
// {"mfa_required":true}. It is deliberately NOT the 204/successURL of a full login: the consumer
// must be able to tell the two apart to drive the second factor (mfa.StepUpHandler).
func (cfg handlerConfig) mfaRequired(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(MFARequiredHeader, "1")
	if cfg.mfaRequiredURL != "" {
		http.Redirect(w, r, cfg.mfaRequiredURL, http.StatusSeeOther)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"mfa_required": true})
}

// resolveAssurance reports the assurance of the credential behind the request, failing closed when
// no resolver is configured.
func (cfg handlerConfig) resolveAssurance(r *http.Request) (tokens.Assurance, bool) {
	if cfg.assuranceResolver == nil {
		return tokens.Assurance{}, false
	}
	return cfg.assuranceResolver(r)
}

// requireNotInterim refuses a request carried by a PRE-STEP-UP interim credential (and any request
// whose assurance cannot be resolved) with 403 "step_up_required". It is what stops an interim
// credential from being upgraded into a full renewable pair. It reports whether the caller may
// proceed.
func (cfg handlerConfig) requireNotInterim(w http.ResponseWriter, r *http.Request) bool {
	if cfg.noStepUpCheck {
		return true
	}
	assurance, ok := cfg.resolveAssurance(r)
	if !ok || assurance.Interim {
		cfg.fail(w, r, http.StatusForbidden, "step_up_required")
		return false
	}
	return true
}

// requireStepUp is the bar for an irreversible action: the credential must not be a pre-step-up
// interim one and, when an MFA gate is configured and the user has a confirmed second factor, the
// credential must actually carry a step-up factor. It reports whether the caller may proceed.
func (cfg handlerConfig) requireStepUp(w http.ResponseWriter, r *http.Request, tenant string, userID uuid.UUID) bool {
	if cfg.noStepUpCheck {
		return true
	}
	assurance, ok := cfg.resolveAssurance(r)
	if !ok || assurance.Interim {
		cfg.fail(w, r, http.StatusForbidden, "step_up_required")
		return false
	}
	if assurance.StepUp || cfg.mfaGate == nil {
		return true
	}
	enrolled, err := cfg.mfaGate.IsEnrolled(r.Context(), tenant, userID)
	if err != nil {
		cfg.fail(w, r, http.StatusInternalServerError, "mfa_check_failed")
		return false
	}
	if enrolled {
		cfg.fail(w, r, http.StatusForbidden, "step_up_required")
		return false
	}
	return true
}

// parseLimitedForm bounds the request body to cfg.maxBodyBytes before parsing the form. It
// protects the argon2 hashing path from unbounded attacker-controlled input. On failure it
// writes the error response (413 when the body is too large, 400 when malformed) and returns
// false.
func (cfg handlerConfig) parseLimitedForm(w http.ResponseWriter, r *http.Request) bool {
	return httputil.ParseLimitedForm(w, r, cfg.maxBodyBytes, cfg.fail)
}

// LoginHandler builds an HTTP handler that authenticates form credentials and, on success,
// issues an access+refresh token pair, writes them as secure cookies and redirects.
//
// The request is expected as application/x-www-form-urlencoded with email, password and an
// optional remember_me field; remember_me makes the refresh cookie persistent.
//
// With WithMFAGate configured, a user who has a confirmed second factor instead receives the
// short-lived INTERIM credential and the distinct pre-step-up response described there (the
// MFARequiredHeader plus a 200 JSON {"mfa_required":true}, or the 303 of WithMFARequiredRedirect) —
// never the 204/successURL of a full login.
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		email := strings.TrimSpace(r.PostForm.Get(cfg.emailField))
		password := r.PostForm.Get(cfg.passwordField)
		remember := parseFormBool(r.PostForm.Get(cfg.rememberField))

		user, err := svc.Authenticate(r.Context(), tenant, cfg.provider, email, password, requestContext(r))
		if err != nil {
			status, code := mapAuthError(err)
			cfg.fail(w, r, status, code)
			return
		}

		// Forced-change gate: consult whether the credential is flagged (admin-provisioned /
		// temporary password). This is a soft gate — login still succeeds and the session is fully
		// renewable — but the issued pair carries Claims.MustChangePassword so the middleware
		// soft-redirects to the reset page. Fail closed on a policy error rather than silently
		// issuing an unflagged pair, which would let a flagged user slip past the gate.
		mustChange, err := svc.PasswordChangeRequired(r.Context(), tenant, user.ID)
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "password_rotation_check_failed")
			return
		}

		// MFA gate: when configured, an enrolled user does NOT get a full refreshable session on
		// the password alone. They receive a short-lived interim credential (Claims.Interim,
		// AMR=[pwd], no refresh cookie) and must complete the second factor (see mfa.StepUpHandler)
		// to obtain the full pair. Users without an enrolled factor fall through below. When the user
		// is also must-change, the flag is carried onto the interim token so step-up preserves it.
		if cfg.mfaGate != nil {
			enrolled, err := cfg.mfaGate.IsEnrolled(r.Context(), tenant, user.ID)
			if err != nil {
				cfg.fail(w, r, http.StatusInternalServerError, "mfa_check_failed")
				return
			}
			if enrolled {
				interim := claimsOf(user)
				// Stamp the password factor only, overriding whatever AMR the consumer's builder
				// produced for this pre-MFA credential.
				interim.AMR = []string{tokens.AMRPassword}
				if err := issueInterimAndSetCookie(w, r, cfg, issuer, interim, mustChange); err != nil {
					cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
					return
				}
				cfg.mfaRequired(w, r)
				return
			}
		}

		// Not MFA-gated: issue the full, renewable pair. When mustChange is true the pair carries
		// Claims.MustChangePassword and the refresh family persists it (Rotate replays it on every
		// silent refresh), so WithPasswordChangeGate keeps soft-redirecting to the reset page while
		// the session stays valid. Login is never a lockout.
		if err := issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, remember, mustChange); err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		email := strings.TrimSpace(r.PostForm.Get(cfg.emailField))
		password := r.PostForm.Get(cfg.passwordField)
		remember := parseFormBool(r.PostForm.Get(cfg.rememberField))

		user, err := svc.Register(r.Context(), tenant, email, password)
		if err != nil {
			status, code := mapRegisterError(err)
			cfg.fail(w, r, status, code)
			return
		}

		if err := issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, remember, false); err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// issuePairAndSetCookies builds the user's claims, issues a token pair and writes both auth
// cookies. The refresh cookie is persistent when remember is true.
//
// When mustChange is true the credential is flagged for a forced password change: the pair still
// authenticates and is fully renewable (login is never a lockout), but its access token carries
// Claims.MustChangePassword and the refresh family persists the flag, so Rotate replays it onto
// every silent refresh. WithPasswordChangeGate therefore keeps soft-redirecting to the reset page
// until the password is actually changed — the user cannot escape by waiting for the access token
// to expire.
func issuePairAndSetCookies[C any](w http.ResponseWriter, r *http.Request, cfg handlerConfig, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], user *User, remember bool, mustChange bool) error {
	claims := claimsOf(user)
	claims.MustChangePassword = mustChange
	pair, err := issuer.IssueTokenPair(r.Context(), claims)
	if err != nil {
		return err
	}
	cfg.cookies.SetAccess(w, pair.AccessToken)
	cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, remember)
	return nil
}

func (cfg handlerConfig) resolveTenant(r *http.Request) (string, bool) {
	if cfg.tenantResolver == nil {
		return "", true
	}
	return cfg.tenantResolver(r)
}

func (cfg handlerConfig) requireTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenant, ok := cfg.resolveTenant(r)
	if !ok {
		cfg.fail(w, r, http.StatusUnauthorized, "tenant_unresolved")
		return "", false
	}
	return tenant, true
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
func (cfg handlerConfig) dispatchDelivery(r *http.Request, tenant, userID string, send func(ctx context.Context) error) {
	base := context.WithoutCancel(r.Context())

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

// originAllowed reports whether the request passes the CSRF same-origin check. The check is
// ON by default — even with an empty trustedOrigins allowlist — to match the tokens handlers
// and make "CSRF-by-default" mean the same thing across handler families. A request is allowed
// only when its Origin (or Referer fallback) host equals the request's own Host or an explicitly
// allowlisted host; a browser-driven POST that carries neither header is treated as untrusted.
// WithInsecureNoOriginCheck restores the pre-v1 accept-all behavior. The strict allow/deny
// policy is enforced here — NOT httputil.OriginAllowed, whose empty-allowlist default is permissive.
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
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
		token, user, _ := svc.RequestPasswordReset(r.Context(), tenant, email)
		if token != "" && user != nil && mailer.PasswordReset != nil {
			cfg.dispatchDelivery(r, tenant, user.ID.String(), func(ctx context.Context) error {
				return mailer.PasswordReset(ctx, PasswordResetMail{User: user, Token: token})
			})
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		password := r.PostForm.Get(cfg.passwordField)
		if err := svc.ResetPassword(r.Context(), tenant, token, password); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		if !cfg.originAllowed(r) {
			cfg.fail(w, r, http.StatusForbidden, "cross_site_blocked")
			return
		}
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
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

		token, err := svc.RequestEmailVerification(r.Context(), tenant, user.ID)
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "verification_request_failed")
			return
		}
		// token is empty when the account is not a live, same-tenant user (swallowed at the
		// service for enumeration safety); only dispatch delivery when a token was minted.
		if token != "" && mailer.EmailVerification != nil {
			cfg.dispatchDelivery(r, tenant, user.ID.String(), func(ctx context.Context) error {
				return mailer.EmailVerification(ctx, EmailVerificationMail{User: user, Token: token})
			})
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		if !cfg.originAllowed(r) {
			cfg.fail(w, r, http.StatusForbidden, "cross_site_blocked")
			return
		}
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		if _, err := svc.VerifyEmail(r.Context(), tenant, token); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		email := strings.TrimSpace(r.PostForm.Get(cfg.emailField))
		token, user, _ := svc.RequestMagicLink(r.Context(), tenant, email)
		if token != "" && user != nil && mailer.MagicLink != nil {
			cfg.dispatchDelivery(r, tenant, user.ID.String(), func(ctx context.Context) error {
				return mailer.MagicLink(ctx, MagicLinkMail{User: user, Token: token})
			})
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// MagicLinkLoginHandler builds an HTTP handler that completes passwordless login: it consumes
// the magic-link token (single-use) from the form and, on success, issues an access+refresh
// token pair and writes the auth cookies — exactly like LoginHandler, but authenticated by the
// emailed token instead of a password. The optional remember_me field makes the refresh cookie
// persistent.
//
// A magic link is a FIRST factor, so WithMFAGate applies here exactly as it does to LoginHandler: an
// MFA-enrolled user receives the short-lived INTERIM credential and the pre-step-up response instead
// of a renewable session, so a compromised mailbox cannot bypass the account's second factor.
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		remember := parseFormBool(r.PostForm.Get(cfg.rememberField))

		user, err := svc.LoginWithMagicLink(r.Context(), tenant, token, requestContext(r))
		if err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}

		// Forced-change gate: a magic-link login is still subject to the must-change flag. When the
		// credential is flagged the renewable pair carries Claims.MustChangePassword (persisted across
		// refresh), so the middleware soft-redirects to the reset page. Fail closed on a policy error.
		mustChange, err := svc.PasswordChangeRequired(r.Context(), tenant, user.ID)
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "password_rotation_check_failed")
			return
		}

		// MFA gate: a magic link is a FIRST factor like a password, so an enrolled user must not be
		// handed a full renewable session by mailbox possession alone. The gate applies here exactly
		// as in LoginHandler — the AMR is left as the consumer's builder produced it (minus any
		// step-up marker, stripped by AsInterim) since no password was verified on this path.
		if cfg.mfaGate != nil {
			enrolled, gateErr := cfg.mfaGate.IsEnrolled(r.Context(), tenant, user.ID)
			if gateErr != nil {
				cfg.fail(w, r, http.StatusInternalServerError, "mfa_check_failed")
				return
			}
			if enrolled {
				if err := issueInterimAndSetCookie(w, r, cfg, issuer, claimsOf(user), mustChange); err != nil {
					cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
					return
				}
				cfg.mfaRequired(w, r)
				return
			}
		}

		if err := issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, remember, mustChange); err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
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

		if err := svc.ChangePassword(r.Context(), tenant, user.ID, current, newPassword); err != nil {
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
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// ChangePasswordWithReissueHandler is the generic, re-issuing sibling of ChangePasswordHandler.
// It accepts the same service, options and form fields, but additionally takes a token issuer and
// a claims builder. On a successful password change it forges a FRESH FULL ACCESS+REFRESH token
// pair (MustChangePassword is absent, since the builder does not set it and UpdateIdentityPassword
// cleared the flag in the store) and writes BOTH cookies, so the caller is immediately
// re-authenticated — no extra round-trip login required after clearing the must-change gate.
//
// Use this variant when ChangePasswordHandler is wired behind the WithPasswordChangeGate
// middleware and you want the user to land back in the application immediately after the change.
// Use the plain ChangePasswordHandler when you prefer the caller to re-authenticate via the
// normal login flow (it returns 204/redirect and writes no new cookies).
//
// The new pair is issued AFTER svc.ChangePassword returns, so it is never caught by the
// AccountErasers that revoke prior refresh-token families. remember is always false for the
// re-issued refresh cookie: a password change is not a "remember me" affirmation.
//
// Because it MINTS a full renewable session, this handler refuses any request carried by a
// pre-step-up interim credential — or whose assurance cannot be resolved at all — with 403
// "step_up_required" (see WithAssuranceResolver, which defaults to
// tokens.AssuranceResolverFromContext; WithInsecureNoStepUpCheck opts out). Otherwise a password
// holder who has not completed the account's second factor could upgrade their interim credential
// into a full session and bypass MFA entirely.
func ChangePasswordWithReissueHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
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
		// A pre-step-up interim credential must NOT be upgradable: re-issuing a full renewable pair
		// here would let anyone who knows the password (and so holds an interim credential) escape
		// the account's second factor entirely. Refuse before touching the password.
		if !cfg.requireNotInterim(w, r) {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		current := r.PostForm.Get(cfg.currentPasswordField)
		newPassword := r.PostForm.Get(cfg.newPasswordField)

		if err := svc.ChangePassword(r.Context(), tenant, user.ID, current, newPassword); err != nil {
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

		// ChangePassword succeeded: the must-change flag is cleared in the store and prior
		// refresh-token families have been revoked by the AccountErasers. Issue a fresh full pair
		// now (mustChange=false) so the user is immediately re-authenticated, with a clean refresh
		// family that no longer replays the gate, without an extra login round-trip.
		if err := issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, false, false); err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
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
		token, err := svc.RequestEmailChange(r.Context(), tenant, user.ID, newEmail)
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
			cfg.dispatchDelivery(r, tenant, user.ID.String(), func(ctx context.Context) error {
				return mailer.EmailChange(ctx, EmailChangeMail{User: user, NewEmail: deliverTo, Token: token})
			})
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		if _, err := svc.ConfirmEmailChange(r.Context(), tenant, token); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// DeleteAccountHandler builds an authenticated HTTP handler that lets a signed-in user delete
// their own account. The current user is obtained via WithUserResolver (typically reading
// whatever the application's auth middleware stashed on the request); if no resolver is
// configured or it reports no user, the handler responds 401. On success it clears the auth
// cookies (the account is gone) and responds 204 (or redirects).
//
// Deletion is irreversible, so the handler ENFORCES a step-up bar itself rather than trusting the
// route to be gated: a request carried by a pre-step-up interim credential — or one whose assurance
// cannot be resolved at all — is refused with 403 "step_up_required" (see WithAssuranceResolver,
// which defaults to tokens.AssuranceResolverFromContext, so mounting this handler behind
// tokens.ContextMiddleware is all the wiring it needs; WithInsecureNoStepUpCheck opts out). Pass
// WithMFAGate as well and an MFA-enrolled user must additionally present a credential carrying a
// step-up factor (tokens.AMRMFA/AMROTP/AMRWebAuthn).
//
// Also configure WithTrustedOrigins so the CSRF origin check covers your front-end, and gate the
// route with tokens.WithRequiredAMR(tokens.AMRMFA) — optionally alongside tokens.WithMaxAuthAge for
// a freshness ("sudo mode") window — to make the requirement explicit at the routing layer too.
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
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
		// Deletion is irreversible, so the handler enforces the step-up bar itself rather than
		// trusting the route to be gated: a pre-step-up interim credential is refused outright, and
		// when an MFA gate is configured a user with a confirmed second factor must present a
		// credential that actually carries it.
		if !cfg.requireStepUp(w, r, tenant, user.ID) {
			return
		}

		if err := svc.DeleteAccount(r.Context(), tenant, user.ID); err != nil {
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
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
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
		token, err := svc.RequestPhoneVerification(r.Context(), tenant, user.ID, phone)
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
			cfg.dispatchDelivery(r, tenant, user.ID.String(), func(ctx context.Context) error {
				return sender.PhoneVerification(ctx, PhoneVerificationSMS{User: user, Phone: deliverTo, Token: token})
			})
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		if _, err := svc.ConfirmPhoneVerification(r.Context(), tenant, token); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
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
		token, err := svc.RequestRecoveryEmail(r.Context(), tenant, user.ID, recoveryEmail)
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
			cfg.dispatchDelivery(r, tenant, user.ID.String(), func(ctx context.Context) error {
				return mailer.RecoveryEmailVerification(ctx, RecoveryEmailMail{User: user, RecoveryEmail: deliverTo, Token: token})
			})
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		token := r.PostForm.Get(cfg.tokenField)
		if _, err := svc.ConfirmRecoveryEmail(r.Context(), tenant, token); err != nil {
			status, code := mapVerificationError(err)
			cfg.fail(w, r, status, code)
			return
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
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
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
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
		token, user, channels, _ := svc.RequestPasswordResetViaRecovery(r.Context(), tenant, email)
		// Uniform response regardless of account existence or recovery-channel availability; deliver
		// off the response path to the verified channels only (token/user are empty otherwise).
		if token != "" && user != nil {
			if channels.RecoveryEmail && mailer.PasswordReset != nil && user.RecoveryEmail != nil {
				recoveryEmail := *user.RecoveryEmail
				cfg.dispatchDelivery(r, tenant, user.ID.String(), func(ctx context.Context) error {
					return mailer.PasswordReset(ctx, PasswordResetMail{User: &User{
						ID: user.ID, TenantID: user.TenantID, Email: recoveryEmail,
					}, Token: token})
				})
			}
			if channels.Phone && sms.PhoneVerification != nil && user.Phone != nil {
				phone := *user.Phone
				cfg.dispatchDelivery(r, tenant, user.ID.String(), func(ctx context.Context) error {
					return sms.PhoneVerification(ctx, PhoneVerificationSMS{User: user, Phone: phone, Token: token})
				})
			}
		}
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// MFAEnrollmentChecker reports whether a user has a confirmed second factor enrolled. It is
// the minimal slice of mfa.Service that the MFA login gate needs; mfa.Service satisfies it
// directly. It is consumed by WithMFAGate so the identity package does not import the mfa
// package (which would create an import cycle: mfa already depends on tokens, not identity).
type MFAEnrollmentChecker interface {
	IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)
}

// WithMFAGate turns LoginHandler AND MagicLinkLoginHandler into MFA-gated handlers. After a
// successful FIRST factor (a correct password, or a consumed magic-link token) it asks the checker
// whether the user has a confirmed second factor enrolled. An enrolled user is NOT granted the full
// access+refresh pair; instead they receive a short-lived INTERIM credential stamped
// tokens.Claims.Interim with no step-up factor in its AMR and NO refresh cookie, and the response
// carries the MFARequiredHeader (see WithMFARequiredRedirect). The application then drives the second
// factor (e.g. mfa.StepUpHandler) which re-issues the full pair with AMR including tokens.AMRMFA.
// Users without an enrolled factor are unaffected and still receive the full pair.
//
// The interim credential is not a session: tokens.RequireAuth and tokens.ContextMiddleware refuse it
// with 403 "step_up_required" on every route that does not opt in with tokens.WithInterimAllowed —
// mount that option on the step-up route ONLY. It is also refused outright by the factor-mutating and
// destructive handlers (mfa.DisableHandler, mfa.RegenerateRecoveryCodesHandler,
// ChangePasswordWithReissueHandler, DeleteAccountHandler).
//
// Passing it to DeleteAccountHandler additionally requires an MFA-enrolled user to present a
// credential carrying a step-up factor before their account can be deleted.
//
// This is the producing half of the AMR/step-up model whose enforcing half is
// tokens.WithRequiredAMR. mfa.Service satisfies MFAEnrollmentChecker directly. The oauth callback has
// its own oauth.WithMFAGate.
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

// issueInterimAndSetCookie issues the short-lived INTERIM credential for an MFA-enrolled user who
// has cleared the first factor but not the second, and writes ONLY the access cookie.
//
// The credential is stamped Claims.Interim (so tokens.RequireAuth / ContextMiddleware refuse it on
// every route that does not opt in with tokens.WithInterimAllowed, and the factor-mutating and
// destructive handlers refuse it outright), carries no step-up factor in its AMR (so
// tokens.WithRequiredAMR(tokens.AMRMFA) rejects it) and expires after cfg.interimTTL. No refresh
// cookie is written and — when the issuer implements tokens.AccessTokenIssuer — no refresh-token
// family is persisted at all, so the pre-step-up state is not a renewable session. The application
// completes the flow with mfa.StepUpHandler, which re-issues the full pair with the MFA factor.
func issueInterimAndSetCookie[C any](w http.ResponseWriter, r *http.Request, cfg handlerConfig, issuer tokens.Issuer[C], claims tokens.Claims[C], mustChange bool) error {
	// When the credential is ALSO flagged for rotation, carry the advisory flag on the interim
	// token so the step-up re-issuance (mfa.StepUpHandler) can preserve it: an MFA-enrolled
	// must-change user must not escape the gate by completing the second factor.
	claims.MustChangePassword = mustChange
	ttl := cfg.interimTTL
	if ttl <= 0 {
		ttl = DefaultInterimTokenTTL
	}
	claims = claims.AsInterim(ttl)

	// Prefer the access-token-only path: minting a full pair here would persist a refresh-token row
	// for a refresh token that is deliberately never surfaced to the client.
	token := ""
	if accessIssuer, ok := issuer.(tokens.AccessTokenIssuer[C]); ok {
		issued, _, err := accessIssuer.IssueAccessToken(r.Context(), claims)
		if err != nil {
			return err
		}
		token = issued
	} else {
		pair, err := issuer.IssueTokenPair(r.Context(), claims)
		if err != nil {
			return err
		}
		// The refresh token minted by the issuer is deliberately dropped, never surfaced to the
		// client, so the interim state cannot be renewed via /refresh.
		token = pair.AccessToken
	}
	// Set ONLY the access cookie, and CLEAR any refresh cookie a previous full session left in the
	// browser: this login attempt supersedes it, and the interim state must leave no renewable
	// credential behind.
	cfg.cookies.SetAccess(w, token)
	cfg.cookies.ClearRefresh(w)
	return nil
}

// WithInsecureNoOriginCheck disables the CSRF same-origin check on the identity form handlers
// (login, register, and the authenticated mutations: change-password, change-email,
// delete-account, recovery, phone/email verification).
//
// By default these handlers reject any state-changing POST whose Origin (or Referer fallback)
// host is neither the request's own Host nor an explicitly trusted origin (see WithTrustedOrigins),
// because login/register are driven purely by the request body and SameSite=Lax alone does not
// prevent login-CSRF / session fixation.
//
// This option turns that protection OFF, restoring the pre-v1 behavior where every origin is
// accepted. It is named "Insecure" deliberately: only reach for it when CSRF is handled by a
// separate layer (e.g. a synchronizer-token middleware) or in trusted test setups. Prefer
// WithTrustedOrigins to extend, rather than remove, the allowlist.
func WithInsecureNoOriginCheck() HandlerOption {
	return func(h *handlerConfig) { h.insecureNoOriginCheck = true }
}

// requestContext builds the optional event.RequestContext that LoginHandler threads into
// Service.Authenticate so the client IP and User-Agent land in the login.* event Attrs.
//
// The IP is taken from r.RemoteAddr (host part only) — the address of the immediate peer. egauth
// deliberately does NOT trust X-Forwarded-For / Forwarded here: those headers are spoofable unless
// a trusted reverse proxy terminates them, and egauth cannot know the deployment's proxy topology.
// A deployment that terminates such a header at a trusted hop, or that wants a different IP source,
// can call Service.Authenticate directly with its own event.RequestContext. This mirrors the
// untrusted-RemoteAddr stance of ratelimit.ClientIP.
func requestContext(r *http.Request) event.RequestContext {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	return event.RequestContext{IP: ip, UserAgent: r.UserAgent()}
}
