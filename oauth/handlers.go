package oauth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/JLugagne/egauth/tokens"
)

// Default state-cookie configuration.
const (
	DefaultStateCookieName = "oauth_state"
	DefaultStateTTL        = 10 * time.Minute
)

// IdentityLinker resolves the local user behind an external identity. identity.Service
// satisfies it; the callback handler depends only on this narrow method so it stays
// decoupled from the rest of the identity service.
type IdentityLinker interface {
	LinkOrCreateIdentity(ctx context.Context, tenantID string, provider, providerID, email string, emailVerified bool) (*identity.User, error)
}

// handlerConfig holds the configurable behavior of the OAuth handlers.
type handlerConfig struct {
	cookies         tokens.Cookies
	stateCookieName string
	stateTTL        time.Duration
	redirectURL     string
	usePKCE         bool
	tenantResolver  func(*http.Request) (string, bool)
	successURL      string
	failureURL      string
	persistRefresh  bool

	allowUnverifiedEmail bool

	// mfaGate, when non-nil, turns CallbackHandler into an MFA-gated handler: a federated login by
	// a user with a confirmed second factor yields the short-lived INTERIM credential instead of a
	// full renewable pair (see WithMFAGate).
	mfaGate identity.MFAEnrollmentChecker
	// interimTTL is the lifetime of that interim credential. Zero means
	// identity.DefaultInterimTokenTTL.
	interimTTL time.Duration
	// mfaRequiredURL is where a gated callback redirects (303) when the second factor is still
	// required. Empty makes that response a 200 JSON {"mfa_required":true} instead.
	mfaRequiredURL string
}

// HandlerOption configures the OAuth handlers (BeginHandler, CallbackHandler).
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{
		cookies:         tokens.DefaultCookies(),
		stateCookieName: DefaultStateCookieName,
		stateTTL:        DefaultStateTTL,
		usePKCE:         true,
	}
	for _, opt := range opts {
		opt(&c)
	}
	c.cookies.MustValidate()
	return c
}

// WithCookies replaces the auth-cookie configuration wholesale.
func WithCookies(c tokens.Cookies) HandlerOption { return func(h *handlerConfig) { h.cookies = c } }

// WithCookieDomain scopes the auth and state cookies to a domain.
//
// A Domain is incompatible with the __Host- prefix the default auth-cookie names carry, so a name
// still carrying it is DEMOTED (to __Secure- while the cookie stays Secure with Path="/", otherwise
// to the bare name): setting a Domain is an explicit opt-out of host-lock semantics. Note that this
// forfeits the subdomain cookie-tossing protection __Host- provides.
func WithCookieDomain(domain string) HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithDomain(domain) }
}

// WithSameSite overrides the SameSite attribute of the auth cookies set on success. (The
// short-lived state cookie is always SameSite=Lax so it survives the provider redirect.)
func WithSameSite(mode http.SameSite) HandlerOption {
	return func(h *handlerConfig) { h.cookies.SameSite = mode }
}

// WithInsecureCookies disables the Secure attribute on all cookies. Local HTTP dev only.
//
// Browsers reject a __Host- or __Secure- named cookie that is not Secure, so the auth-cookie names
// are DEMOTED to their bare form ("access_token" / "refresh_token").
func WithInsecureCookies() HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithInsecure() }
}

// WithRedirectURL sets the OAuth redirect_uri. It MUST equal the callback URL registered with
// the provider and be identical for BeginHandler and CallbackHandler. When unset it is
// derived from the request (scheme://host/path), which is reliable only for the callback;
// configure it explicitly in production.
func WithRedirectURL(rawURL string) HandlerOption {
	return func(h *handlerConfig) { h.redirectURL = rawURL }
}

// WithStateCookieName overrides the CSRF state cookie name (default "oauth_state").
func WithStateCookieName(name string) HandlerOption {
	return func(h *handlerConfig) { h.stateCookieName = name }
}

// WithStateTTL overrides how long the state cookie (and thus the in-flight flow) is valid.
func WithStateTTL(d time.Duration) HandlerOption {
	return func(h *handlerConfig) { h.stateTTL = d }
}

// WithoutPKCE disables the PKCE S256 challenge. PKCE is on by default (OAuth 2.1 best
// practice); disable only for a provider that rejects it.
func WithoutPKCE() HandlerOption {
	return func(h *handlerConfig) { h.usePKCE = false }
}

// WithSuccessRedirect makes the callback reply with a 303 redirect to url on success instead
// of 204 No Content.
func WithSuccessRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.successURL = url }
}

// WithFailureRedirect makes the handlers reply with a 303 redirect to url (carrying an
// ?error=<code> query parameter) on failure instead of an HTTP error status.
func WithFailureRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.failureURL = url }
}

// WithPersistentRefresh issues the refresh cookie as a persistent ("remember me") cookie.
// By default the OAuth flow sets a session refresh cookie.
func WithPersistentRefresh() HandlerOption {
	return func(h *handlerConfig) { h.persistRefresh = true }
}

// WithTenantResolver derives the tenant from the request to scope identity store operations and
// to bind the in-flight flow to a tenant. The tenant is resolved ONCE per request and that single
// value is used for the state-cookie binding and the identity link, so an impure resolver cannot
// route parts of one flow into different partitions. The resolver SHOULD still be a pure,
// deterministic function of the request: DynamicBeginHandler and DynamicCallbackHandler pin the
// single resolved value for the provider lookup, the CSRF gate and the identity link, and a
// resolver that consults mutable external state only makes that pinned value arbitrary.
//
// A configured resolver MUST return a non-empty tenant ID for any request it can map. Returning
// "" means "the tenant could not be resolved" (an unmapped Host, a missing path segment, an
// absent claim) and the handler then REFUSES the request with 403 "tenant_unresolved" instead of
// linking or provisioning the identity in the single-tenant ("") partition — where a
// bootstrap/operator account may live. Map the request explicitly (an allowlist of known hosts or
// a canonical host->tenant table), never the raw Host header. The "" partition is used only when
// no resolver is configured at all (single-tenant mode).
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

func withPinnedTenant(tenant string) HandlerOption {
	return func(h *handlerConfig) {
		h.tenantResolver = func(*http.Request) (string, bool) { return tenant, true }
	}
}

// WithAllowUnverifiedEmail permits JIT-provisioning an account from a provider email the
// provider reports as UNVERIFIED. It is OFF by default so the secure behavior is the zero
// value: a callback whose provider email is not verified is rejected, preventing an attacker
// from squatting an account under an email they have not proven they own. Enable this only
// for a provider that cannot supply a verified flag and whose emails you otherwise trust.
func WithAllowUnverifiedEmail() HandlerOption {
	return func(h *handlerConfig) { h.allowUnverifiedEmail = true }
}

// WithMFAGate turns CallbackHandler into an MFA-gated handler, the federated counterpart of
// identity.WithMFAGate. After the provider identity is linked it asks the checker whether the local
// user has a confirmed second factor; an enrolled user is NOT granted the full access+refresh pair
// but a short-lived INTERIM credential (tokens.Claims.Interim, no step-up factor in its AMR, no
// refresh cookie), and the response carries identity.MFARequiredHeader plus either a 200 JSON
// {"mfa_required":true} or the 303 of WithMFARequiredRedirect. The application then drives the second
// factor (mfa.StepUpHandler), which re-issues the full pair.
//
// Without it, an IdP-account compromise yields a full, indefinitely renewable local session even for
// a user who has enrolled a second factor. mfa.Service satisfies identity.MFAEnrollmentChecker
// directly. An enrollment-check error fails CLOSED (500, no cookies).
func WithMFAGate(checker identity.MFAEnrollmentChecker) HandlerOption {
	return func(h *handlerConfig) { h.mfaGate = checker }
}

// WithInterimTokenTTL overrides the lifetime of the INTERIM credential issued by an MFA-gated
// callback (default identity.DefaultInterimTokenTTL). A non-positive value falls back to the default
// rather than minting a non-expiring credential.
func WithInterimTokenTTL(d time.Duration) HandlerOption {
	return func(h *handlerConfig) {
		if d > 0 {
			h.interimTTL = d
		}
	}
}

// WithMFARequiredRedirect makes an MFA-gated callback reply with a 303 redirect to url when the
// second factor is still required, instead of the default 200 JSON {"mfa_required":true}. Point it at
// the page that collects the second factor; the successURL of a full login is untouched.
func WithMFARequiredRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.mfaRequiredURL = url }
}

// BeginHandler builds an HTTP handler that starts the OAuth flow: it mints a CSRF state and a
// PKCE verifier, stores them in a short-lived secure cookie and redirects the browser to the
// provider's authorization endpoint.
func BeginHandler(p *Provider, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		state, err := newState()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var verifier, challenge string
		if cfg.usePKCE {
			if verifier, challenge, err = newPKCE(); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		// For an OIDC-enabled provider, mint a nonce, bind it through the state cookie and send
		// it on the authorization request so the returned id_token can be tied to this attempt.
		var nonce string
		var authOpts []AuthCodeOption
		if p.oidcEnabled() {
			if nonce, err = newNonce(); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			authOpts = append(authOpts, WithAuthNonce(nonce))
		}
		cfg.setStateCookie(w, packState(state, verifier, nonce, p.Name(), tenant))
		http.Redirect(w, r, p.AuthCodeURL(state, cfg.resolveRedirectURL(r), challenge, authOpts...), http.StatusFound)
	}
}

// CallbackHandler builds an HTTP handler for the provider redirect. It validates the state
// cookie (CSRF), exchanges the code (with PKCE), fetches the user info, links or
// JIT-provisions the local account, then issues an access+refresh token pair and writes the
// auth cookies. The state cookie is always cleared, and on any failure no auth cookie is set.
//
// With WithMFAGate configured, a user who has a confirmed second factor instead receives the
// short-lived INTERIM credential and the distinct pre-step-up response described there — never a
// full renewable session on the federated assertion alone.
func CallbackHandler[C any](p *Provider, linker IdentityLinker, issuer tokens.Issuer[C], claimsOf identity.ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := cfg.readStateCookie(r)
		cfg.clearStateCookie(w) // single-use, regardless of outcome
		if !ok {
			cfg.fail(w, r, http.StatusForbidden, "invalid_state")
			return
		}
		cookieState, verifier, nonce, cookieProvider, cookieTenant, ok := unpackState(raw)
		if !ok {
			cfg.fail(w, r, http.StatusForbidden, "invalid_state")
			return
		}

		q := r.URL.Query()
		if q.Get("error") != "" {
			// The user denied consent or the provider reported an error.
			cfg.fail(w, r, http.StatusUnauthorized, "access_denied")
			return
		}
		if !stateMatches(q.Get("state"), cookieState) {
			cfg.fail(w, r, http.StatusForbidden, "state_mismatch")
			return
		}
		// Bind the in-flight attempt to the provider and tenant that started it, so a state
		// cookie minted for provider/tenant A cannot be replayed against the callback of
		// provider/tenant B (SEC-12: provider confusion / cross-tenant state reuse).
		if !stateMatches(cookieProvider, p.Name()) {
			cfg.fail(w, r, http.StatusForbidden, "provider_mismatch")
			return
		}
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		if !stateMatches(cookieTenant, tenant) {
			cfg.fail(w, r, http.StatusForbidden, "tenant_mismatch")
			return
		}
		code := q.Get("code")
		if code == "" {
			cfg.fail(w, r, http.StatusBadRequest, "missing_code")
			return
		}

		var exchOpts []ExchangeOption
		if p.oidcEnabled() {
			exchOpts = append(exchOpts, WithExpectedNonce(nonce))
		}
		info, err := p.Exchange(r.Context(), code, cfg.resolveRedirectURL(r), verifier, exchOpts...)
		if err != nil {
			cfg.fail(w, r, http.StatusBadGateway, "exchange_failed")
			return
		}
		if info.Email == "" {
			cfg.fail(w, r, http.StatusBadRequest, "email_missing")
			return
		}
		if info.ProviderID == "" {
			// Defense-in-depth: fetchers already reject an empty subject, but guard here
			// too so a future custom fetcher cannot accidentally open a ProviderID=""
			// identity-collision window (see TASK-062).
			cfg.fail(w, r, http.StatusBadGateway, "provider_id_missing")
			return
		}
		if !info.EmailVerified && !cfg.allowUnverifiedEmail {
			// Refuse to provision/log in from an email the provider has not verified — it
			// could be an arbitrary address the OAuth principal merely typed in (account
			// squatting / pre-registration). Opt in via WithAllowUnverifiedEmail if needed.
			cfg.fail(w, r, http.StatusBadRequest, "email_unverified")
			return
		}

		user, err := linker.LinkOrCreateIdentity(r.Context(), tenant, p.Name(), info.ProviderID, info.Email, info.EmailVerified)
		if err != nil {
			status, code := mapLinkError(err)
			cfg.fail(w, r, status, code)
			return
		}

		// MFA gate: a federated identity is a FIRST factor, so an enrolled user must not receive a
		// full renewable session on the IdP assertion alone. Fail closed on a check error.
		if cfg.mfaGate != nil {
			enrolled, gateErr := cfg.mfaGate.IsEnrolled(r.Context(), tenant, user.ID)
			if gateErr != nil {
				cfg.fail(w, r, http.StatusInternalServerError, "mfa_check_failed")
				return
			}
			if enrolled {
				if err := issueInterim(w, r, cfg, issuer, claimsOf(user)); err != nil {
					cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
					return
				}
				cfg.mfaRequired(w, r)
				return
			}
		}

		pair, err := issuer.IssueTokenPair(r.Context(), claimsOf(user))
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		cfg.cookies.SetAccess(w, pair.AccessToken)
		cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, cfg.persistRefresh)
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// issueInterim mints the short-lived PRE-STEP-UP credential for an MFA-enrolled federated login and
// writes ONLY the access cookie. It mirrors the identity package's interim issuance: the claims are
// stamped tokens.Claims.Interim with every step-up AMR marker stripped and a short expiry, and the
// access-token-only issuance path is preferred so no refresh-token family is persisted for a
// credential that must never be renewable.
func issueInterim[C any](w http.ResponseWriter, r *http.Request, cfg handlerConfig, issuer tokens.Issuer[C], claims tokens.Claims[C]) error {
	ttl := cfg.interimTTL
	if ttl <= 0 {
		ttl = identity.DefaultInterimTokenTTL
	}
	claims = claims.AsInterim(ttl)
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
		token = pair.AccessToken
	}
	// Set ONLY the access cookie, and CLEAR any refresh cookie an earlier full session left behind:
	// the interim state must leave no renewable credential in the browser.
	cfg.cookies.SetAccess(w, token)
	cfg.cookies.ClearRefresh(w)
	return nil
}

// mfaRequired writes the pre-step-up response of an MFA-gated callback: the machine-readable
// identity.MFARequiredHeader plus either the configured 303 redirect (WithMFARequiredRedirect) or a
// 200 JSON {"mfa_required":true}. It is deliberately NOT the 204/successURL of a full login.
func (cfg handlerConfig) mfaRequired(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(identity.MFARequiredHeader, "1")
	if cfg.mfaRequiredURL != "" {
		http.Redirect(w, r, cfg.mfaRequiredURL, http.StatusSeeOther)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"mfa_required": true})
}

// setStateCookie writes the short-lived CSRF/PKCE cookie. It is always HttpOnly and
// SameSite=Lax (Lax is required so the cookie is sent on the top-level GET redirect back from
// the provider; Strict would drop it and break the flow).
func (cfg handlerConfig) setStateCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.stateCookieName,
		Value:    value,
		Domain:   cfg.cookies.Domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   !cfg.cookies.Insecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(cfg.stateTTL.Seconds()),
	})
}

func (cfg handlerConfig) readStateCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(cfg.stateCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func (cfg handlerConfig) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.stateCookieName,
		Value:    "",
		Domain:   cfg.cookies.Domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   !cfg.cookies.Insecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// resolveRedirectURL returns the configured redirect_uri or, as a fallback, derives one from
// the request. The fallback is correct for the callback handler (the request URL is the
// callback URL) but not for BeginHandler — configure WithRedirectURL in production.
func (cfg handlerConfig) resolveRedirectURL(r *http.Request) string {
	if cfg.redirectURL != "" {
		return cfg.redirectURL
	}
	return requestScheme(r) + "://" + r.Host + r.URL.Path
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
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
		cfg.fail(w, r, http.StatusForbidden, "tenant_unresolved")
		return "", false
	}
	return tenant, true
}

func mapLinkError(err error) (int, string) {
	switch {
	case errors.Is(err, identity.ErrEmailAlreadyExists):
		// An account with this email already exists via another identity. The app should
		// drive explicit linking from an authenticated session rather than auto-merging.
		return http.StatusConflict, "account_exists"
	case errors.Is(err, identity.ErrAccountDisabled):
		// The already-linked account has been administratively suspended. Refuse the social
		// login with a clean 403 instead of issuing a fresh session, matching the password
		// and token-gated login paths.
		return http.StatusForbidden, "account_disabled"
	default:
		return http.StatusInternalServerError, "link_failed"
	}
}

func (cfg handlerConfig) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	httputil.Fail(w, r, cfg.failureURL, status, code)
}

// DynamicBeginHandler is like BeginHandler but resolves the Provider dynamically using a
// ProviderStore. This is useful for multi-tenant applications where each tenant brings
// their own OIDC/OAuth configuration.
func DynamicBeginHandler(store ProviderStore, providerName string, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		p, err := store.GetProvider(r.Context(), tenant, providerName)
		if err != nil {
			cfg.fail(w, r, http.StatusNotFound, "provider_not_found")
			return
		}
		// Thread the pre-resolved tenant into the delegated handler as a constant resolver
		// so that the state cookie binding operates on the same value that was used to look
		// up the provider above.
		fixedTenantOpt := withPinnedTenant(tenant)
		// Copy opts into a fresh slice before appending. opts is the closure-captured variadic
		// shared across every request; appending into its spare capacity would race concurrent
		// requests on the same backing array and could leak one tenant's resolver into another's.
		reqOpts := append(append([]HandlerOption(nil), opts...), fixedTenantOpt)
		BeginHandler(p, reqOpts...)(w, r)
	}
}

// DynamicCallbackHandler is like CallbackHandler but resolves the Provider dynamically.
// The tenant is resolved exactly once at the start of each request; that single value is
// threaded through the CSRF/tenant gate check and the identity link so all operations are
// consistent even if the supplied resolver is not perfectly pure (see WithTenantResolver).
func DynamicCallbackHandler[C any](store ProviderStore, providerName string, linker IdentityLinker, issuer tokens.Issuer[C], claimsOf identity.ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := cfg.requireTenant(w, r)
		if !ok {
			return
		}
		p, err := store.GetProvider(r.Context(), tenant, providerName)
		if err != nil {
			cfg.fail(w, r, http.StatusNotFound, "provider_not_found")
			return
		}
		// Thread the pre-resolved tenant into the delegated handler as a constant resolver
		// so that the cookieTenant binding check and LinkOrCreateIdentity operate on the
		// same value that was used to look up the provider above. Without this, an impure
		// resolver could return a different tenant on later calls inside CallbackHandler,
		// causing the identity to be linked into a different partition than the one whose
		// provider minted the token (TASK-092 / 2026-06 audit INFO).
		fixedTenantOpt := withPinnedTenant(tenant)
		// Copy opts into a fresh slice before appending (see DynamicBeginHandler): the captured
		// variadic is shared across requests, so appending into its spare capacity would race
		// concurrent callbacks and could cross tenants at the link/provision step.
		reqOpts := append(append([]HandlerOption(nil), opts...), fixedTenantOpt)
		CallbackHandler(p, linker, issuer, claimsOf, reqOpts...)(w, r)
	}
}
