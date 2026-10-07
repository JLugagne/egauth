package mfa

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/JLugagne/egauth/issuance"
	"github.com/JLugagne/egauth/origin"

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
	// tenantResolver, when set, overrides the tenant returned by the user resolver and fails
	// closed with 401 when it cannot resolve a non-empty tenant (see WithTenantResolver). When
	// nil (the default) the tenant comes from WithUserResolver, which may be "" in a
	// single-tenant deployment.
	tenantResolver func(*http.Request) string
	// cookies controls how StepUpHandler writes the re-issued access+refresh pair. The other
	// handlers do not mint tokens and ignore it. It defaults to tokens.DefaultCookies().
	cookies tokens.Cookies
	// trustedOrigins widens the strict same-origin CSRF allowlist (see WithTrustedOrigins); the
	// check itself is ON by default even when this is empty (see insecureNoOriginCheck).
	trustedOrigins map[string]bool
	// insecureNoOriginCheck disables the strict same-origin CSRF check (see WithInsecureNoOriginCheck). By default the check is ON even with an empty trustedOrigins allowlist.
	insecureNoOriginCheck bool
	// maxBodyBytes caps the request body before form parsing (default DefaultMaxBodyBytes). Non-positive disables the cap.
	maxBodyBytes int64
	// mustChangeResolve, when set, overrides the default must-change propagation: reporting true stamps Claims.MustChangePassword=true on the re-issued full pair, reporting false leaves the pair unflagged (a live re-check of identity.PasswordChangeRequired, e.g. after the password was changed in the meantime). When nil (the default) the flag of the verified interim token's claims is propagated, so a flagged interim yields a flagged pair and the forced-change gate survives step-up. That default reads the interim claims from tokens.ClaimsFromContext, which is populated only when StepUpHandler is mounted behind tokens.ContextMiddleware; a custom WithUserResolver that does not inject them must pair itself with WithMustChangeResolver, otherwise the interim flag is not recoverable here.
	mustChangeResolve func(r *http.Request) bool
	stepUpRequired    bool
	amrResolve        func(r *http.Request) []string
	// sessionResolver, when set, is the authoritative account-state resolver the step-up
	// issuance pipeline consults before re-issuing the full pair. When nil the StepUpHandler fails
	// closed (500 misconfigured) unless insecureEchoSessionState is set. See
	// WithSessionStateResolver and WithInsecureEchoSessionState.
	sessionResolver issuance.Resolver
	// assurance, when set, is the credential-enrollment assurance gate (see WithCredentialAssurance). EnrollHandler/ConfirmHandler call it before doing any work and refuse with 403 assurance_required when it returns an error. When nil AND insecureNoAssuranceCheck is false the handlers FAIL CLOSED: enrolling a second factor must never silently accept an interim (pre-MFA) session.
	assurance func(*http.Request) error
	// insecureNoAssuranceCheck disables the fail-closed assurance requirement (see WithInsecureNoAssuranceCheck): enrollment then accepts any authenticated session, including an interim (pre-MFA) one.
	insecureNoAssuranceCheck bool
	// insecureEchoSessionState restores the legacy StepUpHandler default (see WithInsecureEchoSessionState): with no authoritative session-state resolver, the issuance pipeline echoes the interim token's own subject/tenant. Off by default so the handler fails closed instead.
	insecureEchoSessionState bool
}

// HandlerOption configures the MFA HTTP handlers.
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{
		accountField:   "account",
		codeField:      "code",
		cookies:        tokens.DefaultCookies(),
		maxBodyBytes:   DefaultMaxBodyBytes,
		stepUpRequired: true,
	}
	for _, opt := range opts {
		opt(&c)
	}
	c.cookies.MustValidate()
	return c
}

// WithUserResolver supplies the authenticated user to the handlers (required).
func WithUserResolver(r UserResolver) HandlerOption {
	return func(h *handlerConfig) { h.resolve = r }
}

// WithTenantResolver derives the tenant from the request, overriding the tenant returned by
// WithUserResolver. A configured resolver MUST return a non-empty tenant for any request it can
// map; returning "" is treated as a resolution failure and the handler rejects the request with
// 401 instead of falling back to the single-tenant ("") partition. When no tenant resolver is
// configured the tenant from WithUserResolver is used unchanged — which may legitimately be ""
// in a single-tenant deployment.
func WithTenantResolver(f func(*http.Request) string) HandlerOption {
	return func(h *handlerConfig) { h.tenantResolver = f }
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
// additional hosts. Entries may be full origins ("https://app.example.com") or bare hosts
// ("app.example.com"); both are normalized to the bare host before matching, so the documented
// full-origin form works when handlers are wired directly. Use it whenever the MFA endpoints are
// reachable from a browser session on another origin (e.g. cross-subdomain or embedded apps). To
// turn the check off entirely, use WithInsecureNoOriginCheck.
func WithTrustedOrigins(origins ...string) HandlerOption {
	return func(h *handlerConfig) {
		h.trustedOrigins = origin.TrustedSet(origins...)
	}
}

// WithMaxBodyBytes overrides the request-body cap applied in guarded() before form parsing
// (default DefaultMaxBodyBytes = 4 KiB). A non-positive value disables the cap.
func WithMaxBodyBytes(n int64) HandlerOption {
	return func(h *handlerConfig) { h.maxBodyBytes = n }
}

// WithMustChangeResolver surfaces the verified interim token's forced-change flag to
// StepUpHandler. When fn reports true, the re-issued step-up full pair is stamped
// Claims.MustChangePassword=true. The pair is fully renewable, but the refresh family persists the
// flag and Rotate replays it onto every silent refresh, so a must-change user who is also
// MFA-enrolled cannot drop the flag by completing a second factor and then refreshing. Wire it with
// tokens.MustChangeResolverFromContext when StepUpHandler is mounted behind
// tokens.ContextMiddleware. When nil (the default), the flag is read from the interim claims the
// middleware injects; wire this resolver whenever the handler runs WITHOUT that middleware (e.g.
// with a custom WithUserResolver), because the interim claims — and therefore the flag — are then
// unavailable to the handler.
func WithMustChangeResolver(fn func(r *http.Request) bool) HandlerOption {
	return func(h *handlerConfig) { h.mustChangeResolve = fn }
}

// WithSessionStateResolver supplies the authoritative account-state resolver the step-up
// issuance pipeline consults before re-issuing the full pair. Wire it whenever the application
// keeps account lifecycle state outside the interim token (the usual case): the interim token
// may outlive the account's disabled/deleted check by its TTL, so step-up must re-check the
// live account before minting a renewable pair. The resolver's must-change answer is OR-ed with
// the interim/must-change-resolver signal, so it can add the flag but never clear it.
//
// StepUpHandler FAILS CLOSED without it: when neither this option nor
// WithInsecureEchoSessionState is supplied, every step-up request is refused with 500
// misconfigured. The legacy echo behavior is available only through the explicit insecure
// opt-out.
func WithSessionStateResolver(r issuance.Resolver) HandlerOption {
	return func(h *handlerConfig) { h.sessionResolver = r }
}

// WithoutStepUp disables step-up / AMR verification on the handlers that change the factor's
// secrets (DisableHandler, RegenerateRecoveryCodesHandler).
//
// Prefer WithStepUpRequired(false) when you want that visible at the call site; the two are
// equivalent. Turning the check off lets any authenticated session — including the short-lived
// interim access token issued before a second factor is presented — replace the account's
// second-factor secrets, so only do it when an outer layer enforces the same assurance.
func WithoutStepUp() HandlerOption {
	return func(h *handlerConfig) { h.stepUpRequired = false }
}

// WithStepUpRequired explicitly configures whether the handlers that change the factor's secrets
// (DisableHandler, RegenerateRecoveryCodesHandler) require step-up elevation. Step-up is ON by
// default: those handlers accept only a session whose AMR contains tokens.AMRMFA.
//
// Enrollment (EnrollHandler / ConfirmHandler) is deliberately NOT gated: it is the path by which a
// user who has not yet enrolled establishes the factor, so requiring an MFA-elevated session there
// would make first-time enrollment impossible. VerifyHandler / VerifyRecoveryHandler present the
// second factor and so complete the elevation rather than requiring it.
func WithStepUpRequired(required bool) HandlerOption {
	return func(h *handlerConfig) { h.stepUpRequired = required }
}

// WithAMRResolver configures a custom function to extract AMR factors from the request.
func WithAMRResolver(fn func(r *http.Request) []string) HandlerOption {
	return func(h *handlerConfig) { h.amrResolve = fn }
}

// EnrollHandler starts TOTP enrollment and returns the shared secret and otpauth URI as JSON
// for the client to render (e.g. as a QR code). The factor is not active until confirmed.
func EnrollHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		// Enrolling a second factor is a credential-management action: refuse a session that
		// has not met the configured assurance gate (fail closed by default).
		if !cfg.assuranceCheck(w, r) {
			return
		}
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
		// Confirming a factor is a credential-management action: refuse a session that has not
		// met the configured assurance gate (fail closed by default).
		if !cfg.assuranceCheck(w, r) {
			return
		}
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
//
// By default it enforces step-up elevation (requiring tokens.AMRMFA in the session's AMR), like
// DisableHandler. Recovery codes are a second factor in their own right — one of them completes
// step-up — so a session that has not presented a factor must not be able to replace them.
// Without the gate, the short-lived interim access token issued between the password and the
// second factor could rotate the codes and then spend one to obtain a fully elevated session,
// which both bypasses the second factor and locks the legitimate user out of it. Opt out with
// WithStepUpRequired(false) only when an outer layer enforces the same assurance.
func RegenerateRecoveryCodesHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		if cfg.stepUpRequired && !cfg.isSteppedUp(r) {
			cfg.fail(w, r, http.StatusForbidden, "step_up_required")
			return
		}
		codes, err := svc.RegenerateRecoveryCodes(r.Context(), tenant, uid)
		if err != nil {
			cfg.failErr(w, r, err)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string][]string{"recovery_codes": codes})
	})
}

// DisableHandler removes the user's TOTP factor and recovery codes, replying 204 (or 303).
// By default it enforces step-up elevation (requiring tokens.AMRMFA in the session's AMR).
func DisableHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		if cfg.stepUpRequired && !cfg.isSteppedUp(r) {
			cfg.fail(w, r, http.StatusForbidden, "step_up_required")
			return
		}
		if err := svc.DisableTOTP(r.Context(), tenant, uid); err != nil {
			cfg.failErr(w, r, err)
			return
		}
		cfg.ok(w, r)
	})
}

func (cfg handlerConfig) isSteppedUp(r *http.Request) bool {
	var amrs []string
	if cfg.amrResolve != nil {
		amrs = cfg.amrResolve(r)
	} else if ctxAMRs, ok := tokens.AMRFromContext(r.Context()); ok {
		amrs = ctxAMRs
	} else {
		return false
	}
	for _, a := range amrs {
		if a == tokens.AMRMFA {
			return true
		}
	}
	return false
}

// steppedUpAMR computes the authoritative AMR for the full pair re-issued by StepUpHandler: the
// interim session's primary factor(s) (resolved via WithAMRResolver, then the context AMR, then
// the context claims — the same precedence isSteppedUp uses), the verified second factor (otp,
// the family both TOTP and recovery codes belong to) and the MFA marker. Duplicates collapse (a
// magic-link interim already carries otp, so the result is [otp, mfa], never a fabricated pwd).
// When no interim AMR is resolvable the historical password-primary default applies, keeping the
// pre-existing [pwd, otp, mfa] contract for the password-gated wiring.
func steppedUpAMR[C any](cfg handlerConfig, r *http.Request) []string {
	var interim []string
	if cfg.amrResolve != nil {
		interim = cfg.amrResolve(r)
	} else if ctxAMRs, ok := tokens.AMRFromContext(r.Context()); ok {
		interim = ctxAMRs
	} else if claims, ok := tokens.ClaimsFromContext[C](r.Context()); ok {
		interim = claims.AMR
	}
	amr := make([]string, 0, len(interim)+2)
	seen := make(map[string]bool, len(interim)+2)
	appendUnique := func(values ...string) {
		for _, v := range values {
			if !seen[v] {
				seen[v] = true
				amr = append(amr, v)
			}
		}
	}
	for _, a := range interim {
		if a != tokens.AMRMFA {
			appendUnique(a)
		}
	}
	if len(amr) == 0 {
		appendUnique(tokens.AMRPassword)
	}
	appendUnique(tokens.AMROTP, tokens.AMRMFA)
	return amr
}

// guarded wraps the common preamble: POST-only, origin check (on by default), user resolution,
// tenant derivation (from WithUserResolver, or from WithTenantResolver when configured — in which
// case an empty tenant fails closed with 401), body-size cap (DefaultMaxBodyBytes, overridable via
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
		if cfg.tenantResolver != nil {
			tenant = cfg.tenantResolver(r)
			if tenant == "" {
				cfg.fail(w, r, http.StatusUnauthorized, "unresolved_tenant")
				return
			}
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
	httputil.MarkNoStore(w)
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
// when its Origin (or Referer fallback) host equals the request's own Host or an allowlisted host
// (enforced by httputil.OriginAllowed, which also enforces cross-scheme protection);
// a POST carrying neither header is treated as untrusted. WithInsecureNoOriginCheck restores the
// pre-v1 accept-all behavior.
func (cfg handlerConfig) originAllowed(r *http.Request) bool {
	if cfg.insecureNoOriginCheck {
		return true
	}
	return httputil.OriginAllowed(r, cfg.trustedOrigins)
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
// AMR with the authoritative step-up factor set (the interim session's primary factor + otp +
// mfa); the builder supplies the rest (subject, tenant, scopes, custom).
// Implementations should leave Claims.ExpiresAt zero so the issuer's configured access TTL
// applies to the full session.
type StepUpClaimsBuilder[C any] func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[C]

// StepUpHandler is the completion half of the AMR/step-up model whose pre-step-up half is
// identity.WithMFAGate. It is mounted behind the interim session (the access cookie set by an
// MFA-gated LoginHandler or MagicLinkLoginHandler) supplied via WithUserResolver. On a correct
// TOTP code or backup recovery code it verifies the second factor, then re-issues the FULL
// access+refresh pair whose AMR preserves the interim session's primary factor and adds
// tokens.AMROTP + tokens.AMRMFA (password interim: [pwd, otp, mfa]; magic-link interim:
// [otp, mfa] — never a factor the ceremony did not verify), and writes both cookies, overwriting
// the interim access cookie. A route gated with tokens.WithRequiredAMR(tokens.AMRMFA) accepts the
// new token but never the interim one. On an incorrect/expired code it fails (like VerifyHandler)
// and mints nothing, so the interim session is never upgraded.
//
// It FAILS CLOSED without an authoritative session-state resolver: when neither
// WithSessionStateResolver nor WithInsecureEchoSessionState is supplied, every request is
// refused with 500 misconfigured, because minting the renewable pair from the interim token's
// own subject would let an account disabled between the two factors obtain a fresh session.
// The legacy echo behavior is available only through the explicit insecure opt-out.
//
// Rate-limiting note matches VerifyHandler: wrap this endpoint with ratelimit.Middleware.
func StepUpHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf StepUpClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	resolver := cfg.sessionResolver
	// Fail closed: minting the final renewable pair from the interim token's own subject is a
	// lifecycle bypass — an account disabled between the password factor and the second factor
	// would obtain a fresh session — so with no authoritative resolver (and no explicit
	// opt-out) every request is refused. See WithInsecureEchoSessionState for the legacy echo
	// behavior.
	misconfigured := resolver == nil && !cfg.insecureEchoSessionState
	if resolver == nil {
		// No lifecycle store is available to the MFA package; the interim ceremony has already
		// proven the second factor, so the state source reports the resolved identity only. Wire
		// WithSessionStateResolver to add the authoritative account-state re-check.
		resolver = issuance.ResolverFunc(func(_ context.Context, tenantID string, userID uuid.UUID) (issuance.State, error) {
			return issuance.State{UserID: userID, TenantID: tenantID}, nil
		})
	}
	pipe, pipeErr := issuance.New(issuer, issuance.WithResolver(resolver))
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		if misconfigured {
			cfg.fail(w, r, http.StatusInternalServerError, "misconfigured")
			return
		}
		if pipeErr != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		recCode := r.PostForm.Get("recovery_code")
		code := r.PostForm.Get(cfg.codeField)

		var err error
		if recCode != "" {
			err = svc.VerifyRecoveryCode(r.Context(), tenant, uid, recCode)
		} else if isRecoveryCodeFormat(code) {
			err = svc.VerifyRecoveryCode(r.Context(), tenant, uid, code)
		} else {
			err = svc.VerifyTOTP(r.Context(), tenant, uid, code)
			if errors.Is(err, ErrInvalidCode) && (strings.Contains(code, "-") || len(code) > 8) {
				if rerr := svc.VerifyRecoveryCode(r.Context(), tenant, uid, code); rerr == nil {
					err = nil
				}
			}
		}
		if err != nil {
			cfg.failErr(w, r, err)
			return
		}
		// The factor set is now the interim session's verified primary factor + a verified TOTP or
		// recovery code, so the token reaches the MFA assurance level. AMR is set here (not by the
		// builder) so it is authoritative. The primary factor is PRESERVED from the interim session
		// instead of being hardcoded to pwd: a password-gated login presents [pwd], a magic-link
		// gated login presents [otp] — the stepped-up token must never claim a factor the ceremony
		// did not verify (SEC-MFA-01). With no interim AMR resolvable, the historical password
		// default applies.
		amr := steppedUpAMR[C](cfg, r)
		// Carry the forced-change gate forward: the stepped-up full pair keeps the verified interim
		// token's must-change flag. The session is fully renewable — the refresh family persists the
		// flag and Rotate replays it onto every silent refresh — so an MFA-enrolled must-change user
		// cannot escape WithPasswordChangeGate by completing a second factor and then refreshing. The
		// flag clears only on a fresh login after the password is changed (or when an admin revokes
		// the family). By default the flag is read from the interim claims in r.Context() (the entry
		// tokens.ContextMiddleware injects), so default wiring is safe. WithMustChangeResolver
		// overrides the interim flag per request — reporting true flags the pair, reporting false
		// defers to the authoritative state (a live re-check of identity.PasswordChangeRequired,
		// e.g. after the user changed their password in the meantime). The issuance pipeline ORs
		// this signal with the configured authoritative resolver, so a stale interim flag can never
		// be silently cleared while the account is still flagged.
		mustChange := false
		if cfg.mustChangeResolve != nil {
			mustChange = cfg.mustChangeResolve(r)
		} else if interim, ok := tokens.ClaimsFromContext[C](r.Context()); ok {
			mustChange = interim.MustChangePassword
		}
		remember := false
		if interim, ok := tokens.ClaimsFromContext[C](r.Context()); ok && interim != nil {
			remember = interim.RememberMe
		}
		// Re-issue the full pair through the unified issuance pipeline: it enforces the tenant
		// binding, OR-s the authoritative must-change state and emits the uniform audit event.
		res, err := pipe.Issue(r.Context(), issuance.Request[C]{
			TenantID:           tenant,
			UserID:             uid,
			Claims:             claimsOf(r.Context(), uid, tenant),
			Method:             "mfa_step_up",
			AMR:                amr,
			MustChangePassword: mustChange,
			MFAVerified:        true,
			RememberMe:         remember,
		})
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		// Upgrade the interim access-only state to a full renewable pair, writing both cookies.
		cfg.cookies.SetAccess(w, res.Pair.AccessToken)
		cfg.cookies.SetRefresh(w, res.Pair.RefreshToken, res.Pair.RefreshTokenExpiresAt, res.Pair.Claims.RememberMe)
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

// WithCredentialAssurance gates the credential-enrollment handlers (EnrollHandler and
// ConfirmHandler) on fn, which must return nil for a session allowed to enroll a factor and
// an error otherwise. The intended gate is tokens.DenyInterim, which refuses an interim
// (pre-second-factor) session: without it, an attacker holding only the password can enroll
// their own TOTP factor on the interim session and then complete step-up with it.
//
// The handlers FAIL CLOSED by default: when neither this option nor
// WithInsecureNoAssuranceCheck is supplied, Enroll/Confirm refuse with 403
// assurance_required. That makes the secure composition the default rather than a wiring the
// application must remember.
func WithCredentialAssurance(fn func(*http.Request) error) HandlerOption {
	return func(h *handlerConfig) { h.assurance = fn }
}

// WithInsecureNoAssuranceCheck removes the fail-closed credential-enrollment protection: the
// enrollment handlers no longer require an assurance gate, so ANY authenticated session —
// including an interim (pre-MFA) session minted after only the password factor — can enroll a
// second factor. Use it only when the application has no second factor to protect (an interim
// session is then indistinguishable from a full one) or enforces the assurance requirement in
// an outer layer. Prefer WithCredentialAssurance(tokens.DenyInterim).
func WithInsecureNoAssuranceCheck() HandlerOption {
	return func(h *handlerConfig) { h.insecureNoAssuranceCheck = true }
}

// assuranceCheck enforces the credential-enrollment assurance gate. It reports true when the
// request may proceed. By default (no gate configured and no explicit opt-out) it fails closed
// with 403 assurance_required, because an enrollment route must never silently accept an
// interim (pre-MFA) session.
func (cfg handlerConfig) assuranceCheck(w http.ResponseWriter, r *http.Request) bool {
	if cfg.insecureNoAssuranceCheck {
		return true
	}
	if cfg.assurance == nil {
		cfg.fail(w, r, http.StatusForbidden, "assurance_required")
		return false
	}
	if err := cfg.assurance(r); err != nil {
		cfg.fail(w, r, http.StatusForbidden, "assurance_required")
		return false
	}
	return true
}

// WithInsecureEchoSessionState restores the legacy StepUpHandler default: with no
// WithSessionStateResolver the issuance pipeline re-uses the interim token's own subject and
// tenant without consulting authoritative account state. That disables the live
// disabled/deleted re-check every other login path enforces by construction, so an account
// suspended between the password factor and the second factor can still complete step-up and
// receive a full renewable pair. Use it only when account lifecycle is enforced outside the
// library, or in tests of the legacy behavior; prefer WithSessionStateResolver.
func WithInsecureEchoSessionState() HandlerOption {
	return func(h *handlerConfig) { h.insecureEchoSessionState = true }
}
