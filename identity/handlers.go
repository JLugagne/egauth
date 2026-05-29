package identity

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/JLugagne/libauth/passwords"
	"github.com/JLugagne/libauth/tokens"
)

// ClaimsBuilder maps an authenticated user to the claims embedded in their issued tokens.
// The application supplies it so libauth stays agnostic about the custom claim type C.
// Implementations should leave Claims.ExpiresAt zero so the issuer's configured access TTL
// applies.
type ClaimsBuilder[C any] func(*User) tokens.Claims[C]

// DefaultMaxBodyBytes is the default cap applied to the request body of the form handlers.
// It bounds attacker-controlled input (notably the password field, which feeds the expensive
// argon2 KDF) to prevent a pre-authentication CPU/memory amplification DoS. It is comfortably
// larger than a legitimate email+password+token form. Override with WithMaxBodyBytes.
const DefaultMaxBodyBytes int64 = 4 << 10 // 4 KiB

// handlerConfig holds the configurable behavior of the identity HTTP handlers.
type handlerConfig struct {
	provider       string
	cookies        tokens.Cookies
	tenantResolver func(*http.Request) string
	successURL     string
	failureURL     string
	emailField     string
	passwordField  string
	rememberField  string
	tokenField           string
	currentPasswordField string
	newPasswordField     string
	userResolver         func(*http.Request) (*User, bool)
	trustedOrigins       map[string]bool
	maxBodyBytes         int64
}

// HandlerOption configures the identity HTTP handlers (LoginHandler, RegisterHandler).
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{
		provider:      "password",
		cookies:       tokens.DefaultCookies(),
		emailField:    "email",
		passwordField: "password",
		rememberField:        "remember_me",
		tokenField:           "token",
		currentPasswordField: "current_password",
		newPasswordField:     "new_password",
		maxBodyBytes:         DefaultMaxBodyBytes,
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// WithProvider sets the identity provider used for authentication (default "password").
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

// WithMaxBodyBytes overrides the request-body size cap applied before form parsing
// (default DefaultMaxBodyBytes). A non-positive value disables the cap; do so only if an
// upstream layer already bounds the body, since an unbounded password feeds the expensive
// argon2 KDF (a pre-auth DoS vector).
func WithMaxBodyBytes(n int64) HandlerOption {
	return func(h *handlerConfig) { h.maxBodyBytes = n }
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

		user, err := svc.Authenticate(r.Context(), cfg.provider, email, password, cfg.authOpts(r)...)
		if err != nil {
			status, code := mapAuthError(err)
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

		user, err := svc.Register(r.Context(), email, password, cfg.authOpts(r)...)
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

func (cfg handlerConfig) authOpts(r *http.Request) []Option {
	if cfg.tenantResolver == nil {
		return nil
	}
	return []Option{WithTenant(cfg.tenantResolver(r))}
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
func mapAuthError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrAccountLocked):
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
		token, user, _ := svc.RequestPasswordReset(r.Context(), email, cfg.authOpts(r)...)
		if token != "" && user != nil && mailer != nil {
			// Dispatch delivery off the response path (detached context) so the Mailer's
			// latency, which only occurs for existing accounts, is not a timing side channel.
			ctx := context.WithoutCancel(r.Context())
			go func() { _ = mailer.SendPasswordReset(ctx, user, token) }()
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
		if err := svc.ResetPassword(r.Context(), token, password, cfg.authOpts(r)...); err != nil {
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

		token, err := svc.RequestEmailVerification(r.Context(), user.ID, cfg.authOpts(r)...)
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "verification_request_failed")
			return
		}
		if mailer != nil {
			_ = mailer.SendEmailVerification(r.Context(), user, token)
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
		if _, err := svc.VerifyEmail(r.Context(), token, cfg.authOpts(r)...); err != nil {
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
		token, user, _ := svc.RequestMagicLink(r.Context(), email, cfg.authOpts(r)...)
		if token != "" && user != nil && mailer != nil {
			ctx := context.WithoutCancel(r.Context())
			go func() { _ = mailer.SendMagicLink(ctx, user, token) }()
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

		user, err := svc.LoginWithMagicLink(r.Context(), token, cfg.authOpts(r)...)
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

		if err := svc.ChangePassword(r.Context(), user.ID, current, newPassword, cfg.authOpts(r)...); err != nil {
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

// mapVerificationError maps password-reset / email-verification errors to an HTTP status and
// a stable error code.
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
	case errors.Is(err, ErrTenantRequired):
		return http.StatusBadRequest, "tenant_required"
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
