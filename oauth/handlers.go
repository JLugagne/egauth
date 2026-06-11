package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/JLugagne/egauth/identity"
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
	tenantResolver  func(*http.Request) string
	successURL      string
	failureURL      string
	persistRefresh  bool

	allowUnverifiedEmail bool
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
	return c
}

// WithCookies replaces the auth-cookie configuration wholesale.
func WithCookies(c tokens.Cookies) HandlerOption { return func(h *handlerConfig) { h.cookies = c } }

// WithCookieDomain scopes the auth and state cookies to a domain.
func WithCookieDomain(domain string) HandlerOption {
	return func(h *handlerConfig) { h.cookies.Domain = domain }
}

// WithSameSite overrides the SameSite attribute of the auth cookies set on success. (The
// short-lived state cookie is always SameSite=Lax so it survives the provider redirect.)
func WithSameSite(mode http.SameSite) HandlerOption {
	return func(h *handlerConfig) { h.cookies.SameSite = mode }
}

// WithInsecureCookies disables the Secure attribute on all cookies. Local HTTP dev only.
func WithInsecureCookies() HandlerOption {
	return func(h *handlerConfig) { h.cookies.Insecure = true }
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

// WithTenantResolver derives the tenant from the request to scope identity store operations
// in multi-tenant deployments.
func WithTenantResolver(f func(*http.Request) string) HandlerOption {
	return func(h *handlerConfig) { h.tenantResolver = f }
}

// WithAllowUnverifiedEmail permits JIT-provisioning an account from a provider email the
// provider reports as UNVERIFIED. It is OFF by default so the secure behavior is the zero
// value: a callback whose provider email is not verified is rejected, preventing an attacker
// from squatting an account under an email they have not proven they own. Enable this only
// for a provider that cannot supply a verified flag and whose emails you otherwise trust.
func WithAllowUnverifiedEmail() HandlerOption {
	return func(h *handlerConfig) { h.allowUnverifiedEmail = true }
}

// BeginHandler builds an HTTP handler that starts the OAuth flow: it mints a CSRF state and a
// PKCE verifier, stores them in a short-lived secure cookie and redirects the browser to the
// provider's authorization endpoint.
func BeginHandler(p *Provider, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
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
		cfg.setStateCookie(w, packState(state, verifier, nonce, p.Name(), cfg.tenant(r)))
		http.Redirect(w, r, p.AuthCodeURL(state, cfg.resolveRedirectURL(r), challenge, authOpts...), http.StatusFound)
	}
}

// CallbackHandler builds an HTTP handler for the provider redirect. It validates the state
// cookie (CSRF), exchanges the code (with PKCE), fetches the user info, links or
// JIT-provisions the local account, then issues an access+refresh token pair and writes the
// auth cookies. The state cookie is always cleared, and on any failure no auth cookie is set.
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
		if !stateMatches(cookieTenant, cfg.tenant(r)) {
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

		user, err := linker.LinkOrCreateIdentity(r.Context(), cfg.tenant(r), p.Name(), info.ProviderID, info.Email, info.EmailVerified)
		if err != nil {
			status, code := mapLinkError(err)
			cfg.fail(w, r, status, code)
			return
		}

		pair, err := issuer.IssueTokenPair(r.Context(), claimsOf(user))
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		cfg.cookies.SetAccess(w, pair.AccessToken)
		cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, cfg.persistRefresh)
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
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

// tenant returns the tenant derived from the request's resolver, or "" when no resolver is
// configured (the single-tenant default partition).
func (cfg handlerConfig) tenant(r *http.Request) string {
	if cfg.tenantResolver == nil {
		return ""
	}
	return cfg.tenantResolver(r)
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
	if cfg.failureURL != "" {
		http.Redirect(w, r, withErrorParam(cfg.failureURL, code), http.StatusSeeOther)
		return
	}
	http.Error(w, code, status)
}

func redirectOrStatus(w http.ResponseWriter, r *http.Request, rawURL string, okStatus int) {
	if rawURL != "" {
		http.Redirect(w, r, rawURL, http.StatusSeeOther)
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

// DynamicBeginHandler is like BeginHandler but resolves the Provider dynamically using a
// ProviderStore. This is useful for multi-tenant applications where each tenant brings
// their own OIDC/OAuth configuration.
func DynamicBeginHandler(store ProviderStore, providerName string, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		tenant := cfg.tenant(r)
		p, err := store.GetProvider(r.Context(), tenant, providerName)
		if err != nil {
			cfg.fail(w, r, http.StatusNotFound, "provider_not_found")
			return
		}
		// Delegate to the static handler
		BeginHandler(p, opts...)(w, r)
	}
}

// DynamicCallbackHandler is like CallbackHandler but resolves the Provider dynamically.
func DynamicCallbackHandler[C any](store ProviderStore, providerName string, linker IdentityLinker, issuer tokens.Issuer[C], claimsOf identity.ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		tenant := cfg.tenant(r)
		p, err := store.GetProvider(r.Context(), tenant, providerName)
		if err != nil {
			cfg.fail(w, r, http.StatusNotFound, "provider_not_found")
			return
		}
		// Delegate to the static handler
		CallbackHandler(p, linker, issuer, claimsOf, opts...)(w, r)
	}
}
