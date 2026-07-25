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
	// trustedOrigins widens the strict same-origin CSRF allowlist (see WithTrustedOrigins); the
	// check itself is ON by default even when this is empty (see insecureNoOriginCheck).
	trustedOrigins map[string]bool
	// insecureNoOriginCheck disables the strict same-origin CSRF check (see WithInsecureNoOriginCheck). By default the check is ON even with an empty trustedOrigins allowlist.
	insecureNoOriginCheck bool
	// maxBodyBytes caps the request body before form parsing (default DefaultMaxBodyBytes). Non-positive disables the cap.
	maxBodyBytes int64
	// mustChangeResolve, when set and reporting true, marks the stepped-up user as must-change: StepUpHandler stamps Claims.MustChangePassword=true on the re-issued full pair. The pair is renewable, but the refresh family persists the flag (Rotate replays it on every refresh), so a verified interim token carrying the flag cannot escape the forced-change gate after a second factor. Nil (default) leaves the flag unset.
	mustChangeResolve func(r *http.Request) bool
	// assuranceResolver reports the assurance of the credential behind the request. It backs the
	// step-up enforcement of the factor-mutating handlers (DisableHandler,
	// RegenerateRecoveryCodesHandler) and defaults to tokens.AssuranceResolverFromContext (see
	// WithAssuranceResolver). It fails CLOSED: an unresolvable assurance is refused.
	assuranceResolver tokens.AssuranceResolver
	// noStepUpCheck disables that enforcement entirely (see WithInsecureNoStepUpCheck).
	noStepUpCheck bool
	// priorAMR reports the factors the credential carrying the step-up request already proved (see WithPriorAMR). The step-up handlers carry those forward and add only the factor they verified themselves, so the re-issued AMR never asserts a factor that was not presented. Nil (default) means nothing is carried forward.
	priorAMR func(r *http.Request) []string
}

// HandlerOption configures the MFA HTTP handlers.
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{
		accountField:      "account",
		codeField:         "code",
		cookies:           tokens.DefaultCookies(),
		maxBodyBytes:      DefaultMaxBodyBytes,
		assuranceResolver: tokens.AssuranceResolverFromContext,
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
// additional hosts. Each entry may be a bare host, e.g. "app.example.com" (matched against the
// request origin's host only), or a scheme-qualified origin, e.g. "https://app.example.com"
// (matched against scheme AND host — the stricter form). Use it whenever the MFA endpoints are
// reachable from a browser session on another origin (e.g. cross-subdomain or embedded apps). To
// turn the check off entirely, use WithInsecureNoOriginCheck.
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

// WithMustChangeResolver surfaces the verified interim token's forced-change flag to
// StepUpHandler. When fn reports true, the re-issued step-up full pair is stamped
// Claims.MustChangePassword=true. The pair is fully renewable, but the refresh family persists the
// flag and Rotate replays it onto every silent refresh, so a must-change user who is also
// MFA-enrolled cannot drop the flag by completing a second factor and then refreshing. Wire it with
// tokens.MustChangeResolverFromContext when StepUpHandler is mounted behind
// tokens.ContextMiddleware. Nil (the default) leaves the flag unset.
func WithMustChangeResolver(fn func(r *http.Request) bool) HandlerOption {
	return func(h *handlerConfig) { h.mustChangeResolve = fn }
}

// WithPriorAMR supplies the authentication methods the credential carrying the step-up request
// ALREADY proved — typically the interim credential's own Claims.AMR — so the step-up handlers can
// carry them forward.
//
// The step-up handlers assert only the factor they verified themselves (AMROTP for StepUpHandler,
// AMRRecoveryCode for StepUpRecoveryHandler) plus the AMRMFA marker. Without this option nothing
// else is claimed: the first factor may have been a password, a magic link or a federated IdP, and
// egauth will not assert a password that was never presented. Wire it with
// tokens.PriorAMRResolverFromContext when the handler is mounted behind tokens.ContextMiddleware:
//
//	mux.Handle("/mfa/step-up", tokens.ContextMiddleware(verifier,
//	    mfa.StepUpHandler(svc, issuer, claimsOf,
//	        mfa.WithUserResolver(tokens.UserResolverFromContext),
//	        mfa.WithPriorAMR(tokens.PriorAMRResolverFromContext[C]))))
//
// Values are carried forward in order and de-duplicated.
func WithPriorAMR(fn func(r *http.Request) []string) HandlerOption {
	return func(h *handlerConfig) { h.priorAMR = fn }
}

// stepUpAMR builds the AMR of the re-issued pair: the factors the prior credential proved (when
// WithPriorAMR is wired), then the factor this ceremony verified, then the AMRMFA marker — with
// duplicates removed and order preserved.
func (cfg handlerConfig) stepUpAMR(r *http.Request, verified string) []string {
	var prior []string
	if cfg.priorAMR != nil {
		prior = cfg.priorAMR(r)
	}
	amr := make([]string, 0, len(prior)+2)
	seen := make(map[string]bool, len(prior)+2)
	for _, v := range append(append([]string{}, prior...), verified, tokens.AMRMFA) {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		amr = append(amr, v)
	}
	return amr
}

// WithAssuranceResolver supplies the assurance of the credential behind the request to the
// factor-mutating handlers (DisableHandler, RegenerateRecoveryCodesHandler), which refuse anything
// that does not prove a second factor.
//
// It DEFAULTS to tokens.AssuranceResolverFromContext, so mounting those handlers behind
// tokens.ContextMiddleware — the same wiring WithUserResolver already needs — is enough. Supply your
// own only when the access token is verified by a middleware of your own; then map its verified
// tokens.Claims with Claims.SatisfiesStepUp / Claims.Interim.
//
// It fails CLOSED: a nil resolver, or one reporting ok=false, refuses the request with 403
// "step_up_required". Use WithInsecureNoStepUpCheck to opt out deliberately.
func WithAssuranceResolver(f tokens.AssuranceResolver) HandlerOption {
	return func(h *handlerConfig) { h.assuranceResolver = f }
}

// WithInsecureNoStepUpCheck disables the step-up enforcement of the factor-mutating handlers
// (DisableHandler, RegenerateRecoveryCodesHandler).
//
// By default those handlers refuse a request whose credential does not prove a second factor, so a
// stolen password-only or pre-MFA interim session cannot strip the victim's MFA or invalidate their
// recovery codes. This option turns that protection OFF, restoring the pre-v1 behavior where the
// ambient session was enough. It is named "Insecure" deliberately: only reach for it when an
// equivalent step-up gate is enforced in front of the route (e.g.
// tokens.RequireAuth(..., tokens.WithRequiredAMR(tokens.AMRMFA))) or in trusted test setups. Prefer
// WithAssuranceResolver to supply the missing signal rather than removing the check.
func WithInsecureNoStepUpCheck() HandlerOption {
	return func(h *handlerConfig) { h.noStepUpCheck = true }
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
//
// It is FACTOR-MUTATING (it destroys every existing recovery code), so like DisableHandler it
// requires a credential that carries a step-up factor and refuses anything less with 403
// "step_up_required". See DisableHandler for the wiring and the opt-out.
func RegenerateRecoveryCodesHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guardedStepUp(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		codes, err := svc.RegenerateRecoveryCodes(r.Context(), tenant, uid)
		if err != nil {
			cfg.failErr(w, r, err)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string][]string{"recovery_codes": codes})
	})
}

// DisableHandler removes the user's TOTP factor and recovery codes, replying 204 (or 303).
//
// Stripping the second factor is the single most destructive MFA operation, so the handler ENFORCES
// step-up itself rather than trusting the route to be gated: the request must be carried by a
// credential that proves a second factor (tokens.Claims.SatisfiesStepUp — its AMR carries
// tokens.AMRMFA, AMROTP or AMRWebAuthn and it is not a pre-step-up interim credential). Anything
// less — a password-only session, a pre-MFA interim credential, or a request whose assurance cannot
// be resolved at all — is refused with 403 "step_up_required".
//
// The assurance comes from WithAssuranceResolver, which defaults to
// tokens.AssuranceResolverFromContext: mounting this handler behind tokens.ContextMiddleware (the
// same wiring WithUserResolver already needs) is all it takes. Deployments that produce their own
// tokens must stamp Claims.AMR after verifying the second factor (mfa.StepUpHandler does it for
// you). WithInsecureNoStepUpCheck opts out.
func DisableHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guardedStepUp(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
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

// guardedStepUp is guarded() plus the step-up bar the factor-mutating handlers enforce: the
// credential behind the request must prove a second factor. The check runs after guarded()'s
// preamble and immediately before the action, so no factor is ever mutated by a request that does
// not clear it.
func (cfg handlerConfig) guardedStepUp(fn func(http.ResponseWriter, *http.Request, uuid.UUID, string)) http.HandlerFunc {
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		if !cfg.stepUpSatisfied(w, r) {
			return
		}
		fn(w, r, uid, tenant)
	})
}

// stepUpSatisfied reports whether the request may perform a factor-mutating action, writing the 403
// "step_up_required" response when it may not. It fails CLOSED: a missing resolver, an
// unresolvable assurance, an interim credential and an AMR without a step-up factor are all refused.
func (cfg handlerConfig) stepUpSatisfied(w http.ResponseWriter, r *http.Request) bool {
	if cfg.noStepUpCheck {
		return true
	}
	if cfg.assuranceResolver == nil {
		cfg.fail(w, r, http.StatusForbidden, "step_up_required")
		return false
	}
	assurance, ok := cfg.assuranceResolver(r)
	if !ok || !assurance.StepUp {
		cfg.fail(w, r, http.StatusForbidden, "step_up_required")
		return false
	}
	return true
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
	return httputil.OriginMatchesTrusted(r, cfg.trustedOrigins)
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
// embedded in the full token pair StepUpHandler and StepUpRecoveryHandler re-issue. The handler
// overwrites the returned AMR with the factors actually presented (see WithPriorAMR); the builder
// supplies the rest (subject, tenant, scopes, custom).
// Implementations should leave Claims.ExpiresAt zero so the issuer's configured access TTL
// applies to the full session.
type StepUpClaimsBuilder[C any] func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[C]

// StepUpHandler is the completion half of the AMR/step-up model whose pre-step-up half is
// identity.WithMFAGate. It is mounted behind the interim session (the access cookie set by an
// MFA-gated LoginHandler) supplied via WithUserResolver. On a correct TOTP code it verifies the
// second factor, then re-issues the FULL access+refresh pair with AMR=[tokens.AMROTP,
// tokens.AMRMFA] — plus whatever the interim credential already proved, when WithPriorAMR is wired —
// and writes both cookies, overwriting the interim access cookie.
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
		issueStepUpPair(w, r, cfg, issuer, claimsOf, uid, tenant, tokens.AMROTP)
	})
}

// StepUpRecoveryHandler is the recovery-code twin of StepUpHandler, and the shipped way back in for
// a user who has LOST their authenticator: it redeems a single-use recovery code and, on success,
// re-issues the FULL access+refresh pair (AMR carrying tokens.AMRRecoveryCode and tokens.AMRMFA,
// Interim cleared) exactly as StepUpHandler does for a TOTP code. Without it, recovery codes could
// be verified (VerifyRecoveryHandler) but never converted into a session, so the enrolled user with
// a dead phone had no self-service path at all.
//
// The code is consumed by Service.VerifyRecoveryCode, so it is single-use and shares the TOTP
// failed-attempt budget (ErrTooManyAttempts -> 429): a recovery code cannot be brute-forced any more
// than a TOTP can. As with StepUpHandler and VerifyHandler, egauth does NOT apply a per-IP request
// rate limit — wrap this endpoint with [github.com/JLugagne/egauth/ratelimit.Middleware].
//
// Mount it beside the step-up route, behind the same interim session:
//
//	mux.Handle("/mfa/step-up/recovery", tokens.ContextMiddleware(verifier,
//	    mfa.StepUpRecoveryHandler(svc, issuer, claimsOf,
//	        mfa.WithUserResolver(tokens.UserResolverFromContext)),
//	    tokens.WithInterimAllowed[C]()))
func StepUpRecoveryHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf StepUpClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return cfg.guarded(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		if err := svc.VerifyRecoveryCode(r.Context(), tenant, uid, r.PostForm.Get(cfg.codeField)); err != nil {
			cfg.failErr(w, r, err)
			return
		}
		issueStepUpPair(w, r, cfg, issuer, claimsOf, uid, tenant, tokens.AMRRecoveryCode)
	})
}

// issueStepUpPair mints and writes the full pair both step-up handlers re-issue once their factor
// verified. verified is the AMR value of the factor THIS ceremony proved.
func issueStepUpPair[C any](w http.ResponseWriter, r *http.Request, cfg handlerConfig, issuer tokens.Issuer[C], claimsOf StepUpClaimsBuilder[C], uid uuid.UUID, tenant, verified string) {
	claims := claimsOf(r.Context(), uid, tenant)
	// AMR is set here (not by the builder) so it is authoritative, and records ONLY what was
	// actually presented: the factor this ceremony verified, the MFA marker it earns, and whatever
	// the prior credential already proved (WithPriorAMR). The pre-step-up marker is cleared for the
	// same reason: the second factor was just verified, so the pair this handler mints is a full
	// session everywhere.
	claims.AMR = cfg.stepUpAMR(r, verified)
	claims.Interim = false
	// Carry the forced-change gate forward: if the verified interim token was flagged
	// must-change, the stepped-up full pair stays flagged. The session is fully renewable — the
	// refresh family persists the flag and Rotate replays it onto every silent refresh — so an
	// MFA-enrolled must-change user cannot escape WithPasswordChangeGate by completing a second
	// factor and then refreshing. The flag clears only on a fresh login after the password is
	// changed (or when an admin revokes the family).
	if cfg.mustChangeResolve != nil && cfg.mustChangeResolve(r) {
		claims.MustChangePassword = true
	}
	pair, err := issuer.IssueTokenPair(r.Context(), claims)
	if err != nil {
		cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
		return
	}
	// Upgrade the interim access-only state to a full renewable pair, writing both cookies.
	cfg.cookies.SetAccess(w, pair.AccessToken)
	cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, false)
	cfg.ok(w, r)
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
