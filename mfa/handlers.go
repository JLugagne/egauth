package mfa

import (
	"context"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/internal/httputil"

	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
)

// DefaultMaxBodyBytes bounds the request body of the MFA handlers before form parsing (4 KiB),
// matching the same cap applied by the otp package.
const DefaultMaxBodyBytes int64 = 4 << 10 // 4 KiB

// UserResolver extracts the authenticated user (and its tenant) from the request — typically
// from whatever the application's auth middleware stored on the request context. All MFA
// handlers require it; when it reports ok=false the handler responds 401.
type UserResolver func(r *http.Request) (userID uuid.UUID, tenant string, ok bool)

type handlerConfig struct {
	resolve      UserResolver
	accountField string
	codeField    string
	successURL   string
	failureURL   string
	// cookies controls how StepUpHandler writes the re-issued access+refresh pair. The other
	// handlers do not mint tokens and ignore it. It defaults to tokens.DefaultCookies().
	cookies tokens.Cookies
	// trustedOrigins, when non-empty, enables CSRF Origin/Referer enforcement (see WithTrustedOrigins).
	trustedOrigins map[string]bool
	// insecureNoOriginCheck disables the strict same-origin CSRF check (see WithInsecureNoOriginCheck). By default the check is ON even with an empty trustedOrigins allowlist.
	insecureNoOriginCheck bool
	// maxBodyBytes caps the request body before form parsing (default DefaultMaxBodyBytes). Non-positive disables the cap.
	maxBodyBytes int64
	// mustChangeResolve, when set and reporting true, marks the stepped-up user as must-change: StepUpHandler stamps Claims.MustChangePassword=true and issues ACCESS-ONLY (no refresh cookie), so a verified interim token carrying the flag cannot escape the rotation gate after a second factor. Nil (default) keeps the full-pair behavior.
	mustChangeResolve func(r *http.Request) bool
}

// HandlerOption configures the MFA HTTP handlers.
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{
		accountField: "account",
		codeField:    "code",
		cookies:      tokens.DefaultCookies(),
		maxBodyBytes: DefaultMaxBodyBytes,
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// WithUserResolver supplies the authenticated user to the handlers (required).
func WithUserResolver(r UserResolver) HandlerOption {
	return func(h *handlerConfig) { h.resolve = r }
}

// WithAccountField sets the form field carrying the account label shown in the authenticator
// app during enrollment (default "account"); when empty the user ID is used.
func WithAccountField(name string) HandlerOption {
	return func(h *handlerConfig) { h.accountField = name }
}

// WithCodeField sets the form field carrying the TOTP / recovery code (default "code").
func WithCodeField(name string) HandlerOption {
	return func(h *handlerConfig) { h.codeField = name }
}

// WithSuccessRedirect makes the action handlers (verify, disable) reply with a 303 redirect on
// success instead of 204. Data handlers (enroll, confirm, regenerate) always return JSON.
func WithSuccessRedirect(rawURL string) HandlerOption {
	return func(h *handlerConfig) { h.successURL = rawURL }
}

// WithFailureRedirect makes handlers reply with a 303 redirect (carrying ?error=<code>) on
// failure instead of an HTTP error status.
func WithFailureRedirect(rawURL string) HandlerOption {
	return func(h *handlerConfig) { h.failureURL = rawURL }
}

// WithCookies configures how StepUpHandler writes the re-issued access+refresh pair. It must
// match the cookie configuration of the identity LoginHandler that issued the interim token so
// the step-up cookies overwrite the interim ones. Defaults to tokens.DefaultCookies().
func WithCookies(c tokens.Cookies) HandlerOption {
	return func(h *handlerConfig) { h.cookies = c }
}

// WithTrustedOrigins adds extra hosts to the CSRF same-origin allowlist for all state-changing
// MFA handlers.
//
// The origin check is ON by default (see originAllowed / WithInsecureNoOriginCheck): even with no
// trusted origins configured, a POST whose Origin (or Referer fallback) host is not the request's
// own Host is rejected with 403 "cross_site_blocked". This option WIDENS that allowlist to permit
// additional hosts. Supply hosts WITHOUT scheme, e.g. "app.example.com". Use it whenever the MFA
// endpoints are reachable from a browser session on another origin (e.g. cross-subdomain or
// embedded apps). To turn the check off entirely, use WithInsecureNoOriginCheck.
func WithTrustedOrigins(origins ...string) HandlerOption {
	return func(h *handlerConfig) {
		h.trustedOrigins = make(map[string]bool, len(origins))
		for _, o := range origins {
			h.trustedOrigins[o] = true
		}
	}
}

// WithMaxBodyBytes overrides the request-body cap applied in guarded() before form parsing
// (default DefaultMaxBodyBytes = 4 KiB). A non-positive value disables the cap.
func WithMaxBodyBytes(n int64) HandlerOption {
	return func(h *handlerConfig) { h.maxBodyBytes = n }
}

// WithMustChangeResolver surfaces the verified interim token's password-rotation flag to
// StepUpHandler. When fn reports true, the re-issued step-up token is stamped
// Claims.MustChangePassword=true and is issued ACCESS-ONLY (the access cookie is written but
// the refresh cookie is NOT), mirroring the flagged login path so a must-change user who is
// also MFA-enrolled cannot drop the flag by completing a second factor and then silently
// refreshing. Wire it with tokens.MustChangeResolverFromContext when StepUpHandler is mounted
// behind tokens.ContextMiddleware. Nil (the default) keeps the unconditional full-pair behavior.
func WithMustChangeResolver(fn func(r *http.Request) bool) HandlerOption {
	return func(h *handlerConfig) { h.mustChangeResolve = fn }
}

// EnrollHandler starts TOTP enrollment and returns the shared secret and otpauth URI as JSON
// for the client to render (e.g. as a QR code). The factor is not active until confirmed.
func EnrollHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		account := r.PostForm.Get(cfg.accountField)
		if account == "" {
			account = uid.String()
		}
		enrollment, err := svc.EnrollTOTP(r.Context(), tenant, uid, account)
		if err != nil {
			cfg.failErr(w, r, err)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"secret": enrollment.Secret, "uri": enrollment.URI})
	})
}

// ConfirmHandler verifies an enrollment code, activates the factor, and returns the freshly
// minted single-use recovery codes as JSON (shown once).
func ConfirmHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		codes, err := svc.ConfirmTOTP(r.Context(), tenant, uid, r.PostForm.Get(cfg.codeField))
		if err != nil {
			cfg.failErr(w, r, err)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string][]string{"recovery_codes": codes})
	})
}

// VerifyHandler checks a login second-factor TOTP code and replies 204 (or a 303 redirect).
//
// The Service caps per-user code attempts (ErrTooManyAttempts), but egauth does NOT apply a
// per-IP / per-destination request rate limit to this or VerifyRecoveryHandler — that remains
// YOUR responsibility. Wrap these verify endpoints with
// [github.com/JLugagne/egauth/ratelimit.Middleware] (the recommended way to throttle them);
// see the ratelimit package examples for a turnkey rate-limited router.
func VerifyHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		if err := svc.VerifyTOTP(r.Context(), tenant, uid, r.PostForm.Get(cfg.codeField)); err != nil {
			cfg.failErr(w, r, err)
			return
		}
		cfg.ok(w, r)
	})
}

// VerifyRecoveryHandler consumes a single-use recovery code and replies 204 (or a 303 redirect).
func VerifyRecoveryHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		if err := svc.VerifyRecoveryCode(r.Context(), tenant, uid, r.PostForm.Get(cfg.codeField)); err != nil {
			cfg.failErr(w, r, err)
			return
		}
		cfg.ok(w, r)
	})
}

// RegenerateRecoveryCodesHandler issues a fresh set of recovery codes (invalidating the old)
// and returns them as JSON.
func RegenerateRecoveryCodesHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		codes, err := svc.RegenerateRecoveryCodes(r.Context(), tenant, uid)
		if err != nil {
			cfg.failErr(w, r, err)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string][]string{"recovery_codes": codes})
	})
}

// DisableHandler removes the user's TOTP factor and recovery codes, replying 204 (or 303).
func DisableHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		if err := svc.DisableTOTP(r.Context(), tenant, uid); err != nil {
			cfg.failErr(w, r, err)
			return
		}
		cfg.ok(w, r)
	})
}

// guarded wraps the common preamble: POST-only, origin check (when WithTrustedOrigins is set),
// user resolution and tenant derivation, body-size cap (DefaultMaxBodyBytes, overridable via
// WithMaxBodyBytes), then invokes fn with the resolved user ID and tenant string.
func (cfg handlerConfig) guarded(fn func(http.ResponseWriter, *http.Request, uuid.UUID, string)) http.HandlerFunc {
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
		if cfg.resolve == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		uid, tenant, ok := cfg.resolve(r)
		if !ok {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}
		fn(w, r, uid, tenant)
	}
}

// parseLimitedForm wraps r.Body with http.MaxBytesReader (when maxBodyBytes > 0), parses the
// form, and writes the appropriate error response on failure. It returns true on success.
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

func (cfg handlerConfig) ok(w http.ResponseWriter, r *http.Request) {
	if cfg.successURL != "" {
		http.Redirect(w, r, cfg.successURL, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg handlerConfig) failErr(w http.ResponseWriter, r *http.Request, err error) {
	status, code := mapMFAError(err)
	cfg.fail(w, r, status, code)
}

func (cfg handlerConfig) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	httputil.Fail(w, r, cfg.failureURL, status, code)
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

func mapMFAError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrTooManyAttempts):
		return http.StatusTooManyRequests, "too_many_attempts"
	case errors.Is(err, ErrInvalidCode), errors.Is(err, ErrRecoveryCodeNotFound):
		return http.StatusUnauthorized, "invalid_code"
	case errors.Is(err, ErrAlreadyEnrolled):
		return http.StatusConflict, "already_enrolled"
	case errors.Is(err, ErrNotEnrolled):
		return http.StatusBadRequest, "not_enrolled"
	case errors.Is(err, ErrNotConfirmed):
		return http.StatusBadRequest, "not_confirmed"
	default:
		return http.StatusInternalServerError, "mfa_error"
	}
}

// StepUpClaimsBuilder maps the stepped-up user (resolved from the interim session) to the claims
// embedded in the full token pair StepUpHandler re-issues. The handler overwrites the returned
// AMR with [pwd, otp, mfa]; the builder supplies the rest (subject, tenant, scopes, custom).
// Implementations should leave Claims.ExpiresAt zero so the issuer's configured access TTL
// applies to the full session.
type StepUpClaimsBuilder[C any] func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[C]

// StepUpHandler is the completion half of the AMR/step-up model whose pre-step-up half is
// identity.WithMFAGate. It is mounted behind the interim session (the access cookie set by an
// MFA-gated LoginHandler) supplied via WithUserResolver. On a correct TOTP code it verifies the
// second factor, then re-issues the FULL access+refresh pair with AMR=[tokens.AMRPassword,
// tokens.AMROTP, tokens.AMRMFA] and writes both cookies, overwriting the interim access cookie.
// A route gated with tokens.WithRequiredAMR(tokens.AMRMFA) accepts the new token but never the
// interim one. On an incorrect/expired code it fails (like VerifyHandler) and mints nothing, so
// the interim session is never upgraded.
//
// Rate-limiting note matches VerifyHandler: wrap this endpoint with ratelimit.Middleware.
func StepUpHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf StepUpClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		if err := svc.VerifyTOTP(r.Context(), tenant, uid, r.PostForm.Get(cfg.codeField)); err != nil {
			cfg.failErr(w, r, err)
			return
		}
		claims := claimsOf(r.Context(), uid, tenant)
		// The factor set is now password + a verified TOTP, so the token reaches the MFA
		// assurance level. AMR is set here (not by the builder) so it is authoritative.
		claims.AMR = []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}
		// Carry the rotation gate forward. If the verified interim token was flagged
		// must-change, the stepped-up token MUST stay flagged and access-only, exactly like the
		// flagged login path — otherwise an MFA-enrolled must-change user could complete a second
		// factor, obtain a full renewable pair, and silently refresh the flag away.
		mustChange := cfg.mustChangeResolve != nil && cfg.mustChangeResolve(r)
		if mustChange {
			claims.MustChangePassword = true
		}
		pair, err := issuer.IssueTokenPair(r.Context(), claims)
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		cfg.cookies.SetAccess(w, pair.AccessToken)
		if !mustChange {
			// Full renewable session: the interim access-only state is upgraded to a pair.
			cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, false)
		}
		cfg.ok(w, r)
	})
}

// WithInsecureNoOriginCheck disables the CSRF same-origin check on all state-changing MFA
// handlers.
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
