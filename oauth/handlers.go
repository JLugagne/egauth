package oauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/JLugagne/egauth/issuance"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
)

// Default state-cookie configuration. The state cookie carries the CSRF state, the PKCE
// verifier and the OIDC nonce, so it is host-locked by default via the __Host- prefix
// (STATE-01): the browser then refuses to send it to or receive it from a sibling subdomain.
const (
	DefaultStateCookieName = "__Host-oauth_state"
	DefaultStateTTL        = 10 * time.Minute

	// MinStateSigningKeyLength is the minimum length (in bytes) accepted for the state-cookie
	// HMAC key. The cookie is authenticated with HMAC-SHA-256, so a key shorter than the
	// 32-byte hash output is recoverable offline from a single captured state cookie;
	// WithStateSigningKey rejects anything shorter. Use a persistent random key of at least
	// this length.
	MinStateSigningKeyLength = 32

	// hostPrefix is the browser-enforced cookie name prefix that requires Secure, no
	// Domain and Path=/ (mirrors the __Host- auth cookies in tokens).
	hostPrefix = "__Host-"
)

// IdentityLinker resolves the local user behind an external identity. identity.Service
// satisfies it; the callback handler depends only on these methods so it stays decoupled from
// the rest of the identity service. PasswordChangeRequired supplies the authoritative
// forced-password-change state of the linked credential: the callback passes it to the unified
// flow engine (WithAuthFlow) or, on the native path, to the issuance pipeline, which OR-s it
// with the account's live state so the flag survives even when a component has no
// password-policy checker of its own. Implementations must answer from authoritative identity
// state (identity.Service.PasswordChangeRequired does).
//
// The callback's native issuance pipeline additionally needs authoritative account state. When
// the linker also implements issuance.Resolver (identity.Service does) it is used directly;
// otherwise configure WithSessionStateResolver, or the native path fails closed.
type IdentityLinker interface {
	LinkOrCreateIdentity(ctx context.Context, tenantID string, provider, providerID, email string, emailVerified bool) (*identity.User, error)
	PasswordChangeRequired(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)
}

// handlerConfig holds the configurable behavior of the OAuth handlers.
type handlerConfig struct {
	cookies         tokens.Cookies
	stateCookieName string
	stateTTL        time.Duration
	// events receives security events (see WithEventSink); nil disables emission.
	events          event.Sink
	stateSigningKey []byte
	redirectURL     string
	allowedHosts    []string
	usePKCE         bool
	tenantResolver  func(*http.Request) string
	successURL      string
	failureURL      string
	persistRefresh  bool
	// authFlow, when non-nil, delegates the post-callback pipeline (account state, MFA policy,
	// issuance) of CallbackHandler to a unified flow engine (see AuthFlow / WithAuthFlow).
	authFlow AuthFlow
	// sessionResolver overrides the authoritative account-state resolver the native issuance
	// pipeline consults when no flow engine is configured. See WithSessionStateResolver.
	sessionResolver      issuance.Resolver
	allowUnverifiedEmail bool
	// redirectFallbackWarned rate-limits the WEB-02 fallback misuse event to once per handler.
	redirectFallbackWarned *sync.Once
	// configErr records a startup validation failure (see validate); the handlers fail
	// closed with 500 on it.
	configErr error
}

// HandlerOption configures the OAuth handlers (BeginHandler, CallbackHandler).
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{
		cookies:                tokens.DefaultCookies(),
		stateCookieName:        DefaultStateCookieName,
		stateTTL:               DefaultStateTTL,
		redirectFallbackWarned: &sync.Once{},
		usePKCE:                true,
	}
	for _, opt := range opts {
		opt(&c)
	}
	// STATE-01: validate the configuration eagerly and record the outcome; the handlers
	// fail closed with 500 at request time when it is invalid, and the same check is
	// exposed by ValidateHandlerConfig for a server startup check.
	c.configErr = c.validate()
	return c
}

// WithCookies replaces the auth-cookie configuration wholesale.
func WithCookies(c tokens.Cookies) HandlerOption { return func(h *handlerConfig) { h.cookies = c } }

// WithCookieDomain scopes the auth and state cookies to a domain. Incompatible with the
// default __Host- state cookie name; pair it with WithStateCookieName to opt out of the
// __Host- host-locking (and accept the login-CSRF residual of a tossable state cookie).
func WithCookieDomain(domain string) HandlerOption {
	return func(h *handlerConfig) { h.cookies.Domain = domain }
}

// WithSameSite overrides the SameSite attribute of the auth cookies set on success. (The
// short-lived state cookie is always SameSite=Lax so it survives the provider redirect.)
func WithSameSite(mode http.SameSite) HandlerOption {
	return func(h *handlerConfig) { h.cookies.SameSite = mode }
}

// WithInsecureCookies disables the Secure attribute on all cookies. Local HTTP dev only.
// Incompatible with the default __Host- state cookie name: rename the state cookie via
// WithStateCookieName when serving plaintext HTTP.
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

// WithAllowedHosts configures the hostnames permitted when dynamically deriving the
// redirect_uri from the incoming request. If the request's Host does not match any
// allowed host, the redirect URI derivation fails and the handler rejects the request.
func WithAllowedHosts(hosts ...string) HandlerOption {
	return func(h *handlerConfig) { h.allowedHosts = append(h.allowedHosts, hosts...) }
}

// WithStateCookieName overrides the CSRF state cookie name (default "__Host-oauth_state",
// host-locked per STATE-01). Only override it for cross-subdomain deployments that must share
// the in-flight state cookie across subdomains (with WithCookieDomain): those explicitly opt
// out of host-locking and accept the login-CSRF residual of a tossable state cookie.
func WithStateCookieName(name string) HandlerOption {
	return func(h *handlerConfig) { h.stateCookieName = name }
}

// WithStateTTL overrides how long the state cookie (and thus the in-flight flow) is valid.
func WithStateTTL(d time.Duration) HandlerOption {
	return func(h *handlerConfig) { h.stateTTL = d }
}

// WithStateSigningKey configures the HMAC secret key used to sign and authenticate the
// short-lived state cookie (SEC-OAU-03). The key is REQUIRED (STATE-01) and must be at least
// MinStateSigningKeyLength (32) bytes: the handlers fail closed with 500 when it is missing
// or too short, because an unsigned state cookie can be forged by any attacker able to plant
// a cookie (sibling-subdomain tossing, plaintext HTTP), and a shorter HMAC key is
// brute-forceable offline from a single captured cookie. Use a persistent random key of at
// least 32 bytes; rotating it invalidates in-flight flows.
func WithStateSigningKey(key []byte) HandlerOption {
	return func(h *handlerConfig) {
		h.stateSigningKey = append([]byte(nil), key...)
	}
}

// WithEventSink registers a security-event sink for the OAuth handlers. A nil sink (the
// default) makes every emission a no-op, and emission never changes the handlers'
// client-visible behavior (see the event package contract).
//
// The WEB-02 misuse guard uses it: when neither WithRedirectURL nor WithAllowedHosts is
// configured, the handlers derive redirect_uri from the request Host — a fallback intended
// for local development only. When such a request looks production-like (a non-loopback
// Host over a non-TLS connection), they emit a single WARN-level event.RedirectFallbackMisuse
// per handler instance. To silence it legitimately, configure WithRedirectURL or
// WithAllowedHosts, serve over TLS, or develop against a loopback host.
func WithEventSink(sink event.Sink) HandlerOption {
	return func(h *handlerConfig) { h.events = sink }
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

// WithSessionStateResolver overrides the authoritative account-state resolver the callback's
// native issuance pipeline consults. When unset, the pipeline uses the IdentityLinker itself if
// it implements issuance.Resolver (identity.Service does); a linker that exposes neither makes
// the callback fail closed with 500 on the native path rather than minting an unchecked session.
// The option is not consulted when WithAuthFlow is configured, because the flow engine owns
// issuance on that path.
func WithSessionStateResolver(r issuance.Resolver) HandlerOption {
	return func(h *handlerConfig) { h.sessionResolver = r }
}

// WithTenantResolver derives the tenant from the request to scope identity store operations
// in multi-tenant deployments. A configured resolver MUST return a non-empty tenant for any
// request it can map; returning "" is treated as a resolution failure and the handler rejects
// the request with 401 instead of falling back to the single-tenant ("") partition. When no
// resolver is configured at all, the empty string (single-tenant partition) is used.
//
// The resolver MUST also be a pure, deterministic function of the request: given the same
// *http.Request it must always return the same string. DynamicBeginHandler and
// DynamicCallbackHandler resolve the tenant exactly once per request and thread that single
// value through all subsequent operations (provider lookup, CSRF gate, identity link), so a
// resolver that consults mutable external state and returns different values on successive calls
// would violate that guarantee and could cause the token-exchange, security gate, and identity
// partition to operate on different tenants within the same request.
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
		if cfg.configErr != nil {
			http.Error(w, "oauth handler misconfigured", http.StatusInternalServerError)
			return
		}
		tenant, ok := cfg.resolveTenant(w, r)
		if !ok {
			return
		}
		redirectURI := cfg.resolveRedirectURL(r)
		if redirectURI == "" {
			http.Error(w, "invalid or untrusted host", http.StatusBadRequest)
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
		cfg.setStateCookie(w, packState(state, verifier, nonce, p.Name(), tenant, cfg.stateSigningKey))
		http.Redirect(w, r, p.AuthCodeURL(state, redirectURI, challenge, authOpts...), http.StatusFound)
	}
}

// CallbackHandler builds an HTTP handler for the provider redirect. It validates the state
// cookie (CSRF), exchanges the code (with PKCE), fetches the user info, links or
// JIT-provisions the local account, then mints an access+refresh token pair through the
// unified issuance pipeline and writes the auth cookies. The state cookie is always cleared,
// and on any failure no auth cookie is set.
//
// The pipeline re-loads the linked account's authoritative state and OR-s the linked
// credential's forced-password-change state (resolved from the linker) onto the pair, so a
// flagged account cannot escape tokens.WithPasswordChangeGate by signing in through the
// provider. A lookup or issuance failure aborts the callback without issuing any session.
//
// When WithAuthFlow is configured, issuance is delegated to the unified flow engine instead
// (SEC-GLO-02): an MFA-enrolled user receives only the engine's flow-token cookie and must
// complete the second factor before any access/refresh cookie is written.
func CallbackHandler[C any](p *Provider, linker IdentityLinker, issuer tokens.Issuer[C], claimsOf identity.ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	pipe, pipeErr := newCallbackPipeline(cfg, linker, issuer)
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.configErr != nil {
			http.Error(w, "oauth handler misconfigured", http.StatusInternalServerError)
			return
		}
		tenant, ok := cfg.resolveTenant(w, r)
		if !ok {
			return
		}
		redirectURI := cfg.resolveRedirectURL(r)
		if redirectURI == "" {
			cfg.fail(w, r, http.StatusBadRequest, "untrusted_host")
			return
		}

		q := r.URL.Query()
		// RFC 9207 Section 2.2: Authorization Server Issuer Identification.
		// If the authorization response contains the "iss" parameter, validate that it matches
		// the expected issuer to prevent IdP mix-up attacks (SEC-OAU-08).
		if iss := q.Get("iss"); iss != "" {
			if !p.ValidateIssuer(iss) {
				cfg.clearStateCookie(w)
				cfg.fail(w, r, http.StatusForbidden, "issuer_mismatch")
				return
			}
		}

		raw, ok := cfg.readStateCookie(r)
		cfg.clearStateCookie(w) // single-use, regardless of outcome
		if !ok {
			cfg.fail(w, r, http.StatusForbidden, "invalid_state")
			return
		}
		cookieState, verifier, nonce, cookieProvider, cookieTenant, ok := unpackState(raw, cfg.stateSigningKey)
		if !ok {
			cfg.fail(w, r, http.StatusForbidden, "invalid_state")
			return
		}

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
		info, err := p.Exchange(r.Context(), code, redirectURI, verifier, exchOpts...)
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

		// Forced-change gate: an admin-provisioned credential (temporary password) is flagged
		// so the session it authenticates must carry Claims.MustChangePassword and the
		// password-change middleware can divert it to the reset flow. Resolve the
		// authoritative state from the linker and share it between the two issuance paths
		// below. Fail closed on a policy error rather than minting an unflagged session from a
		// transient store failure.
		mustChange, err := linker.PasswordChangeRequired(r.Context(), tenant, user.ID)
		if err != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "password_rotation_check_failed")
			return
		}

		// Unified flow engine (issue #71 / SEC-GLO-02): when configured, the engine owns the
		// post-callback pipeline — account lifecycle re-validation, MFA policy enforcement and
		// issuance. An MFA-enrolled user does NOT get a full pair here: the engine writes only
		// its flow-token cookie and the ceremony completes through the engine's step-up
		// endpoint. The linked credential's forced-change flag resolved above is passed into
		// the flow so the engine stamps it onto whatever it issues. Fail closed: a rejected
		// flow NEVER falls through to the direct issuance below.
		if cfg.authFlow != nil {
			if err := cfg.authFlow.ProcessPrimaryAuth(r.Context(), w, r, user, "oauth:"+p.Name(), []string{"oauth"}, cfg.persistRefresh, mustChange); err != nil {
				status, code := mapLinkError(err)
				cfg.fail(w, r, status, code)
				return
			}
			httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
			return
		}

		// Native path: mint through the unified issuance pipeline, which re-loads the linked
		// account's authoritative state (rejecting a since-disabled/deleted account) and stamps
		// the forced-change flag resolved above onto the pair (the caller signal is OR-ed with
		// the authoritative state, never able to clear it).
		if pipeErr != nil {
			cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			return
		}
		res, err := pipe.Issue(r.Context(), issuance.Request[C]{
			TenantID:           tenant,
			UserID:             user.ID,
			Claims:             claimsOf(user),
			Method:             "oauth:" + p.Name(),
			AMR:                []string{"oauth"},
			MustChangePassword: mustChange,
		})
		if err != nil {
			status, code := mapIssuanceError(err)
			cfg.fail(w, r, status, code)
			return
		}
		cfg.cookies.SetAccess(w, res.Pair.AccessToken)
		cfg.cookies.SetRefresh(w, res.Pair.RefreshToken, res.Pair.RefreshTokenExpiresAt, cfg.persistRefresh)
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// newCallbackPipeline builds the native issuance pipeline used by CallbackHandler. It is only
// needed when no flow engine is configured: with WithAuthFlow, the engine owns issuance. The
// authoritative resolver is either explicitly configured (WithSessionStateResolver) or the
// linker itself when it implements issuance.Resolver; otherwise construction records an error
// and the handler fails closed with 500 on the native path instead of minting a session whose
// account state was never re-checked.
func newCallbackPipeline[C any](cfg handlerConfig, linker IdentityLinker, issuer tokens.Issuer[C]) (*issuance.Pipeline[C], error) {
	if cfg.authFlow != nil {
		return nil, nil
	}
	resolver := cfg.sessionResolver
	if resolver == nil {
		if r, ok := linker.(issuance.Resolver); ok {
			resolver = r
		}
	}
	if resolver == nil {
		return nil, errors.New("oauth: CallbackHandler requires authoritative session state (an issuance.Resolver or identity.SessionStateReader); configure WithSessionStateResolver")
	}
	return issuance.New(issuer,
		issuance.WithResolver(resolver),
		issuance.WithEventSink(cfg.events),
	)
}

// mapIssuanceError maps a rejected issuance to the callback's client-visible failure. A
// disabled account is the post-authentication re-load refusing a credential that was suspended
// between linking and issuance; the other lifecycle outcomes are collapsed into the same
// failure the linker would have produced.
func mapIssuanceError(err error) (int, string) {
	switch {
	case errors.Is(err, issuance.ErrAccountDisabled):
		return http.StatusForbidden, "account_disabled"
	case errors.Is(err, issuance.ErrAccountDeleted):
		return http.StatusUnauthorized, "account_disabled"
	default:
		return http.StatusInternalServerError, "token_issuance_failed"
	}
}

// setStateCookie writes the short-lived CSRF/PKCE cookie. It is always HttpOnly and
// SameSite=Lax (Lax is required so the cookie is sent on the top-level GET redirect back from
// the provider; Strict would drop it and break the flow).
func (cfg handlerConfig) setStateCookie(w http.ResponseWriter, value string) {
	httputil.MarkNoStore(w)
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
	httputil.MarkNoStore(w)
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
// the request. The fallback validates that r.Host is syntactically valid and, if allowedHosts
// are configured, that r.Host matches one of them.
func (cfg handlerConfig) resolveRedirectURL(r *http.Request) string {
	if cfg.redirectURL != "" {
		return cfg.redirectURL
	}
	if !isValidHost(r.Host) {
		return ""
	}
	if len(cfg.allowedHosts) > 0 {
		reqHost := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			reqHost = h
		}
		reqHost = strings.Trim(reqHost, "[]")
		allowed := false
		for _, ah := range cfg.allowedHosts {
			target := ah
			if h, _, err := net.SplitHostPort(ah); err == nil {
				target = h
			}
			target = strings.Trim(target, "[]")
			if strings.EqualFold(reqHost, target) || strings.EqualFold(r.Host, ah) {
				allowed = true
				break
			}
		}
		if !allowed {
			return ""
		}
	}
	uri := requestScheme(r) + "://" + r.Host + r.URL.Path
	cfg.warnIfRedirectFallbackMisuse(r)
	return uri
}

func isValidHost(rawHost string) bool {
	if rawHost == "" {
		return false
	}
	for i := 0; i < len(rawHost); i++ {
		b := rawHost[i]
		if b <= ' ' || b == 0x7f || b == '/' || b == '\\' || b == '@' || b == '?' || b == '#' || b == '%' {
			return false
		}
	}
	host := rawHost
	if h, port, err := net.SplitHostPort(rawHost); err == nil {
		host = h
		if port == "" {
			return false
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return false
		}
	} else {
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	}
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if strings.ContainsAny(host, ":[]") {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for j := 0; j < len(label); j++ {
			ch := label[j]
			isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
			if !isAlphaNum && ch != '-' && ch != '_' {
				return false
			}
		}
	}
	return true
}

// requestScheme derives the scheme of the redirect_uri from the request itself: https only
// when the connection carries r.TLS, http otherwise. The spoofable X-Forwarded-Proto (and
// Forwarded) headers are deliberately never consulted (WEB-02): a client-controlled header
// must not choose the scheme sent to the provider. Deployments behind a TLS-terminating
// reverse proxy therefore get an http scheme here and must pin the redirect_uri with
// WithRedirectURL instead.
func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// resolveTenant derives the tenant for the request. When no resolver is configured
// (single-tenant deployment) it returns the empty default partition. When a resolver IS
// configured it MUST yield a non-empty tenant: an empty result means the request could not be
// mapped (an unknown host or issuer), and falling back to the "" partition would let it reach
// single-tenant state, so the handler fails closed with 401 "unresolved_tenant".
func (cfg handlerConfig) resolveTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if cfg.tenantResolver == nil {
		return "", true
	}
	tenant := cfg.tenantResolver(r)
	if tenant == "" {
		cfg.fail(w, r, http.StatusUnauthorized, "unresolved_tenant")
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
		tenant, ok := cfg.resolveTenant(w, r)
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
		fixedTenantOpt := WithTenantResolver(func(*http.Request) string { return tenant })
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
		tenant, ok := cfg.resolveTenant(w, r)
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
		fixedTenantOpt := WithTenantResolver(func(*http.Request) string { return tenant })
		// Copy opts into a fresh slice before appending (see DynamicBeginHandler): the captured
		// variadic is shared across requests, so appending into its spare capacity would race
		// concurrent callbacks and could cross tenants at the link/provision step.
		reqOpts := append(append([]HandlerOption(nil), opts...), fixedTenantOpt)
		CallbackHandler(p, linker, issuer, claimsOf, reqOpts...)(w, r)
	}
}

func (cfg handlerConfig) validate() error {
	var errs []error
	if len(cfg.stateSigningKey) == 0 {
		errs = append(errs, errors.New("oauth: WithStateSigningKey is required: the OAuth state cookie must be HMAC-signed, otherwise a cookie an attacker can plant (sibling-subdomain tossing, plaintext HTTP) drives the callback into a forged login (STATE-01)"))
	} else if len(cfg.stateSigningKey) < MinStateSigningKeyLength {
		errs = append(errs, fmt.Errorf("oauth: WithStateSigningKey key must be at least %d bytes, got %d: a shorter HMAC-SHA-256 key is brute-forceable offline from a single captured state cookie, re-enabling forged logins (STATE-01)", MinStateSigningKeyLength, len(cfg.stateSigningKey)))
	}
	if strings.HasPrefix(cfg.stateCookieName, hostPrefix) {
		if cfg.cookies.Domain != "" {
			errs = append(errs, fmt.Errorf("oauth: state cookie %q: __Host- prefix requires Domain to be empty, got %q", cfg.stateCookieName, cfg.cookies.Domain))
		}
		if cfg.cookies.Insecure {
			errs = append(errs, fmt.Errorf("oauth: state cookie %q: __Host- prefix requires Secure (Insecure must be false)", cfg.stateCookieName))
		}
	}
	return errors.Join(errs...)
}

func ValidateHandlerConfig(opts ...HandlerOption) error {
	return newHandlerConfig(opts).configErr
}

// warnIfRedirectFallbackMisuse emits a one-shot WARN event when the handler is falling back
// to a Host-derived redirect_uri (WEB-02) on a request that looks production-like: a
// non-loopback Host over a plaintext (non-TLS) connection. It deliberately warns rather than
// refusing: the fallback is a documented dev convenience, and refusing would break existing
// deployments that rely on it. The warning fires at most once per handler instance
// (redirectFallbackWarned), so it never spams per request. Only the bare fallback warns:
// with WithRedirectURL the URI is pinned, and with WithAllowedHosts the operator has declared
// the acceptable Hosts.
func (cfg handlerConfig) warnIfRedirectFallbackMisuse(r *http.Request) {
	if cfg.redirectURL != "" || len(cfg.allowedHosts) > 0 {
		return
	}
	if r.TLS != nil {
		return
	}
	if isLoopbackHost(r.Host) {
		return
	}
	once := cfg.redirectFallbackWarned
	if once == nil {
		// Defensive: a handler built without newHandlerConfig still must not panic; emit every
		// time rather than crash (the supported path always has a non-nil Once).
		once = &sync.Once{}
	}
	once.Do(func() {
		event.Emit(r.Context(), cfg.events, event.Event{
			Type:   event.RedirectFallbackMisuse,
			Reason: "host_derived_redirect_uri",
			Attrs:  map[string]any{"host": r.Host},
		})
	})
}

// isLoopbackHost reports whether host (an HTTP Host header value, optionally with a port) refers
// to the local machine — localhost or a loopback IP literal. These are the legitimate local-HTTP
// development targets for the redirect_uri fallback, so they must never trigger the misuse
// warning.
func isLoopbackHost(host string) bool {
	if host == "" {
		// No Host at all is not a host we can call "production"; stay quiet.
		return true
	}
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
