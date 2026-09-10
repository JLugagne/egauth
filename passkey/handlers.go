package passkey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth/internal/httputil"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Default ceremony-cookie configuration.
const (
	// DefaultSessionCookieName is the secure-by-default name of the HTTP-only ceremony
	// cookie that carries the HMAC-sealed WebAuthn SessionData (challenge + user-verification
	// level) between Begin and Finish. It carries the browser-enforced __Host- prefix, which
	// guarantees the cookie is host-locked: browsers refuse to store it unless it is Secure,
	// carries no Domain, and has Path=/. That structurally defeats sibling-subdomain
	// cookie-tossing — an attacker controlling evil.example.com could otherwise plant their
	// own legitimately-obtained ceremony cookie in a victim's browser and drive the victim's
	// registration/login against the attacker's challenge and account. Use
	// WithSessionCookieName to override it only when the deployment genuinely cannot meet
	// the __Host- requirements (plain-HTTP local development, a path-scoped mount);
	// overriding to a plain name forfeits the host-lock hardening.
	DefaultSessionCookieName = hostPrefix + "passkey_ceremony"
	DefaultSessionTTL        = 5 * time.Minute
)

// hostPrefix is the browser-enforced __Host- cookie-name prefix (see
// DefaultSessionCookieName and handlerConfig.validate).
const hostPrefix = "__Host-"

// DefaultMaxBodyBytes is the default cap applied to the request body of the Finish ceremony
// handlers. A WebAuthn attestation/assertion response is small; this bound prevents an
// authenticated caller from forcing unbounded buffering and base64 decoding (a low-severity
// memory-pressure DoS). Override with WithMaxBodyBytes.
const DefaultMaxBodyBytes int64 = 64 << 10

// UserResolver extracts the subject of a passkey ceremony from the request — typically the
// authenticated user (for registration) or the user identified by a prior username step (for
// login). name/displayName are only used during registration. ok=false yields a 401.
type UserResolver func(r *http.Request) (userID uuid.UUID, name, displayName, tenant string, ok bool)

// LoginSuccessFunc is invoked after a passkey login ceremony verifies, so the application can
// establish its own session (e.g. issue tokens and set cookies). If nil, the handler replies
// 204.
type LoginSuccessFunc func(w http.ResponseWriter, r *http.Request, userID uuid.UUID)

type handlerConfig struct {
	resolve            UserResolver
	onLoginSuccess     LoginSuccessFunc
	sessionCookie      string
	sessionTTL         time.Duration
	cookieDomain       string
	cookieSameSite     http.SameSite
	insecureCookies    bool
	cookieKey          []byte
	challenges         ChallengeStore
	discoverableTenant TenantExtractor
	maxBodyBytes       int64
	// trustedOrigins widens the strict same-origin CSRF allowlist (see WithTrustedOrigins); the
	// check remains on by default with an empty allowlist.
	trustedOrigins map[string]bool
	// insecureNoOriginCheck disables the strict same-origin CSRF check (see
	// WithInsecureNoOriginCheck). By default the check is ON even with an empty trustedOrigins
	// allowlist.
	insecureNoOriginCheck bool
	// configErr records a construction-time validation failure (see validate); the handlers fail closed with 500 on it.
	configErr error
	// cookieKeys, when set, resolves the ceremony-cookie HMAC key per tenant so a cookie sealed for one tenant cannot be opened under another (per-tenant cryptographic isolation). When nil the static cookieKey is used for every tenant (unchanged single-key behavior).
	cookieKeys CookieKeyResolver
}

// HandlerOption configures the passkey HTTP handlers.
type HandlerOption func(*handlerConfig)

// newHandlerConfig seeds the handler config from the Service's secure defaults (the
// construction-validated cookie key and the configured ChallengeStore) and then applies the
// per-handler options, which may override them. Seeding from the Service means a Service built
// via NewService — which fails fast without a cookie key — yields handlers that are secure by
// default without repeating WithCookieKey/WithChallengeStore at every call site.
func newHandlerConfig(svc *Service, opts []HandlerOption) handlerConfig {
	c := defaultHandlerConfig()
	c.cookieKey = svc.cookieKey
	c.challenges = svc.challenges
	for _, opt := range opts {
		opt(&c)
	}
	// Fail loudly: validate the configuration eagerly and record the outcome; the handlers
	// fail closed with 500 at request time when it is invalid, and the same check is
	// exposed by ValidateHandlerConfig for a server startup check.
	c.configErr = c.validate()
	return c
}

// WithUserResolver supplies the ceremony subject (required).
func WithUserResolver(r UserResolver) HandlerOption {
	return func(h *handlerConfig) { h.resolve = r }
}

// WithLoginSuccess registers a callback invoked after a successful login ceremony.
func WithLoginSuccess(f LoginSuccessFunc) HandlerOption {
	return func(h *handlerConfig) { h.onLoginSuccess = f }
}

// WithSessionCookieName overrides the ceremony cookie name. The secure default is
// DefaultSessionCookieName ("__Host-passkey_ceremony"), whose __Host- prefix makes browsers
// enforce the host-lock (Secure, no Domain, Path=/) that defeats sibling-subdomain
// cookie-tossing of the sealed ceremony state. Override it only when the deployment
// genuinely cannot satisfy the __Host- requirements — plaintext-HTTP local development, or
// a cross-subdomain shared cookie mount (pair with WithCookieDomain) — and accept that a
// sibling subdomain can then toss a ceremony cookie into a victim's browser.
func WithSessionCookieName(name string) HandlerOption {
	return func(h *handlerConfig) { h.sessionCookie = name }
}

// WithSessionTTL overrides how long an in-flight ceremony stays valid.
func WithSessionTTL(d time.Duration) HandlerOption {
	return func(h *handlerConfig) { h.sessionTTL = d }
}

// WithCookieDomain scopes the ceremony cookie to a domain. Incompatible with the default
// __Host- ceremony cookie name; pair it with WithSessionCookieName to opt out of the
// __Host- host-locking (and accept the credential-binding confusion a tossable ceremony
// cookie enables).
func WithCookieDomain(domain string) HandlerOption {
	return func(h *handlerConfig) { h.cookieDomain = domain }
}

// WithSameSite overrides the ceremony cookie SameSite attribute (default Lax).
func WithSameSite(mode http.SameSite) HandlerOption {
	return func(h *handlerConfig) { h.cookieSameSite = mode }
}

// WithInsecureCookies disables the Secure attribute on the ceremony cookie (local HTTP dev
// only). Incompatible with the default __Host- ceremony cookie name: browsers refuse to
// store a __Host- cookie that is not Secure, so pair it with WithSessionCookieName to opt
// out of the prefix when serving plaintext HTTP.
func WithInsecureCookies() HandlerOption {
	return func(h *handlerConfig) { h.insecureCookies = true }
}

// WithCookieKey overrides, for a single handler, the secret key used to HMAC-authenticate the
// ceremony cookie. The key is normally supplied once via Config.CookieKey (validated at
// NewService) and inherited by every handler, so this option is only needed to use a different
// key for a specific handler. The cookie carries the WebAuthn challenge and user-verification
// requirement, which the server treats as trusted state, so an unauthenticated cookie would let
// a client forge them (e.g. downgrade user verification). Use a stable, random secret
// (>= MinCookieKeyLength bytes) and pass the SAME key to the matching Begin and Finish handlers.
func WithCookieKey(key []byte) HandlerOption {
	return func(h *handlerConfig) { h.cookieKey = key }
}

// BeginRegistrationHandler returns the credential-creation options (for
// navigator.credentials.create) as JSON and stores the ceremony SessionData in a secure cookie.
func BeginRegistrationHandler(svc *Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(svc, opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.failClosedOnMisconfig(w) {
			return
		}
		uid, name, displayName, tenant, ok := cfg.subject(w, r)
		if !ok {
			return
		}
		creation, session, err := svc.BeginRegistration(r.Context(), tenant, uid, name, displayName)
		if err != nil {
			cfg.fail(w, err)
			return
		}
		if err := cfg.recordChallenge(r.Context(), tenant, session); err != nil {
			cfg.fail(w, err)
			return
		}
		if !cfg.storeSession(w, r, tenant, session) {
			return
		}
		httputil.WriteJSON(w, http.StatusOK, creation)
	}
}

// FinishRegistrationHandler verifies the attestation response (POST body) against the cookie's
// SessionData and persists the new credential.
func FinishRegistrationHandler(svc *Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(svc, opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.failClosedOnMisconfig(w) {
			return
		}
		uid, name, displayName, tenant, ok := cfg.subject(w, r)
		if !ok {
			return
		}
		session, ok := cfg.loadSession(w, r, tenant)
		if !ok {
			return
		}
		// Consume the challenge before verifying so a replayed registration Finish is rejected.
		if !cfg.consumeChallenge(w, r.Context(), tenant, session) {
			return
		}
		// Cap the ceremony body before the go-webauthn decoder reads it (DOS-01): the attestation
		// response is small, so an oversized body is an abuse attempt, not a legitimate request.
		if cfg.maxBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes)
		}
		if _, err := svc.FinishRegistration(r.Context(), tenant, uid, name, displayName, session, r); err != nil {
			cfg.fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// BeginLoginHandler returns the credential-request options (for navigator.credentials.get) as
// JSON and stores the ceremony SessionData in a secure cookie.
func BeginLoginHandler(svc *Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(svc, opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.failClosedOnMisconfig(w) {
			return
		}
		uid, _, _, tenant, ok := cfg.subject(w, r)
		if !ok {
			return
		}
		assertion, session, err := svc.BeginLogin(r.Context(), tenant, uid)
		if err != nil {
			cfg.fail(w, err)
			return
		}
		if err := cfg.recordChallenge(r.Context(), tenant, session); err != nil {
			cfg.fail(w, err)
			return
		}
		if !cfg.storeSession(w, r, tenant, session) {
			return
		}
		httputil.WriteJSON(w, http.StatusOK, assertion)
	}
}

// FinishLoginHandler verifies the assertion response (POST body) against the cookie's
// SessionData. On success it calls the configured LoginSuccess callback (or replies 204).
func FinishLoginHandler(svc *Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(svc, opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.failClosedOnMisconfig(w) {
			return
		}
		uid, _, _, tenant, ok := cfg.subject(w, r)
		if !ok {
			return
		}
		session, ok := cfg.loadSession(w, r, tenant)
		if !ok {
			return
		}
		// Consume the challenge before verifying: a replayed Finish (identical cookie + body)
		// fails here on the second attempt, even for a sign-count-0 authenticator whose clone
		// counter never advances.
		if !cfg.consumeChallenge(w, r.Context(), tenant, session) {
			return
		}
		// Cap the ceremony body before the go-webauthn decoder reads it (DOS-01): the assertion
		// response is small, so an oversized body is an abuse attempt, not a legitimate request.
		if cfg.maxBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes)
		}
		if _, err := svc.FinishLogin(r.Context(), tenant, uid, session, r); err != nil {
			cfg.fail(w, err)
			return
		}
		if cfg.onLoginSuccess != nil {
			cfg.onLoginSuccess(w, r, uid)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// subject runs the common preamble (POST-only, resolve the user) and returns it.
func (cfg handlerConfig) subject(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, string, string, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return uuid.Nil, "", "", "", false
	}
	return cfg.resolveSubject(w, r)
}

// resolveSubject applies the authenticated-subject half of the preamble (the configured user
// resolver) without the method check. Mutation handlers run the CSRF origin gate between the
// method check and this call.
func (cfg handlerConfig) resolveSubject(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, string, string, bool) {
	if cfg.resolve == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return uuid.Nil, "", "", "", false
	}
	uid, name, displayName, tenant, ok := cfg.resolve(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return uuid.Nil, "", "", "", false
	}
	return uid, name, displayName, tenant, true
}

// ceremonyState binds the ceremony session data to the initiating tenant ID, preventing
// cross-tenant ceremony replay and submission (SEC-PSK-04).
type ceremonyState struct {
	TenantID    string               `json:"tenantId"`
	SessionData webauthn.SessionData `json:"sessionData"`
}

func (cfg handlerConfig) storeSession(w http.ResponseWriter, r *http.Request, tenant string, session *webauthn.SessionData) bool {
	key, ok := cfg.cookieKeyFor(w, r.Context(), tenant)
	if !ok {
		// Fail closed: an unauthenticated ceremony cookie is forgeable (challenge / UV
		// downgrade). cookieKeyFor has already written the 500.
		return false
	}
	var sessionData webauthn.SessionData
	if session != nil {
		sessionData = *session
	}
	state := ceremonyState{
		TenantID:    tenant,
		SessionData: sessionData,
	}
	raw, err := json.Marshal(state)
	if err != nil {
		http.Error(w, "session_error", http.StatusInternalServerError)
		return false
	}
	httputil.MarkNoStore(w)
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.sessionCookie,
		Value:    cfg.seal(key, raw),
		Domain:   cfg.cookieDomain,
		Path:     "/",
		HttpOnly: true,
		Secure:   !cfg.insecureCookies,
		SameSite: cfg.cookieSameSite,
		MaxAge:   int(cfg.sessionTTL.Seconds()),
	})
	return true
}

func (cfg handlerConfig) loadSession(w http.ResponseWriter, r *http.Request, tenant string) (webauthn.SessionData, bool) {
	cfg.clearSession(w) // single-use, regardless of outcome
	var session webauthn.SessionData
	key, ok := cfg.cookieKeyFor(w, r.Context(), tenant)
	if !ok {
		return session, false
	}
	c, err := r.Cookie(cfg.sessionCookie)
	if err != nil || c.Value == "" {
		cfg.fail(w, ErrSessionInvalid)
		return session, false
	}
	raw, ok := cfg.open(key, c.Value)
	if !ok {
		cfg.fail(w, ErrSessionInvalid)
		return session, false
	}
	var state ceremonyState
	if err := json.Unmarshal(raw, &state); err != nil {
		cfg.fail(w, ErrSessionInvalid)
		return session, false
	}
	if state.TenantID != tenant {
		cfg.fail(w, ErrSessionInvalid)
		return session, false
	}
	return state.SessionData, true
}

// seal prepends an HMAC-SHA256 tag to the payload and base64url-encodes the result, so the
// cookie cannot be tampered with by the client.
func (cfg handlerConfig) seal(key, raw []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(append(mac.Sum(nil), raw...))
}

// open verifies the HMAC tag (constant time) and returns the payload, or ok=false on any
// mismatch / malformed value.
func (cfg handlerConfig) open(key []byte, value string) ([]byte, bool) {
	blob, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(blob) < sha256.Size {
		return nil, false
	}
	tag, raw := blob[:sha256.Size], blob[sha256.Size:]
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, false
	}
	return raw, true
}

func (cfg handlerConfig) clearSession(w http.ResponseWriter) {
	httputil.MarkNoStore(w)
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.sessionCookie,
		Value:    "",
		Domain:   cfg.cookieDomain,
		Path:     "/",
		HttpOnly: true,
		Secure:   !cfg.insecureCookies,
		SameSite: cfg.cookieSameSite,
		MaxAge:   -1,
	})
}

func (cfg handlerConfig) fail(w http.ResponseWriter, err error) {
	httputil.MarkNoStore(w)
	var protoErr *protocol.Error
	switch {
	case errors.Is(err, ErrSessionInvalid):
		http.Error(w, "session_invalid", http.StatusBadRequest)
	case errors.Is(err, ErrNoCredentials):
		http.Error(w, "no_credentials", http.StatusBadRequest)
	case errors.Is(err, ErrCredentialCloned):
		http.Error(w, "credential_cloned", http.StatusUnauthorized)
	case errors.Is(err, ErrCredentialNotFound):
		http.Error(w, "credential_not_found", http.StatusNotFound)
	case errors.Is(err, ErrCredentialExists):
		http.Error(w, "credential_exists", http.StatusConflict)
	case errors.Is(err, ErrAttestationRejected):
		http.Error(w, "attestation_rejected", http.StatusForbidden)
	case errors.Is(err, ErrAccountDisabled):
		// The account-lifecycle gate refused the login (Config.AccountGate): a suspended
		// account must not mint a session, surfaced distinctly so UX can explain it.
		http.Error(w, "account_disabled", http.StatusForbidden)
	case errors.Is(err, ErrAccountDeleted):
		http.Error(w, "account_deleted", http.StatusForbidden)
	case errors.As(err, &protoErr):
		// A WebAuthn protocol error is a bad/invalid attestation or assertion from the client.
		http.Error(w, "verification_failed", http.StatusBadRequest)
	default:
		// Anything else is a store/infrastructure failure: surface it as 5xx so it is not
		// mislabeled as a client verification failure (and operators keep the error signal).
		http.Error(w, "internal_error", http.StatusInternalServerError)
	}
}

// WithChallengeStore overrides, for a single handler, the ChallengeStore that provides
// server-side, single-use replay protection for the ceremony challenge (SEC-05). On Begin the
// issued challenge is recorded; on Finish it is atomically consumed before the assertion is
// verified, so a captured Finish request replayed within the cookie TTL is rejected (the second
// consume fails). The store is normally supplied once via Config.ChallengeStore (required at
// NewService unless Config.InsecureNoChallengeStore is set) and inherited by every handler, so
// this option is only needed to use a different store for a specific handler. Pass the same
// store to the matching Begin and Finish handlers.
func WithChallengeStore(cs ChallengeStore) HandlerOption {
	return func(h *handlerConfig) { h.challenges = cs }
}

// recordChallenge stores the ceremony challenge for single-use replay protection, if a
// ChallengeStore is configured. It is called on Begin, after the ceremony succeeds and before
// the session cookie is written. The TTL follows session.Expires; when that is zero it falls
// back to sessionTTL from now (matching the cookie MaxAge). A store error is propagated so the
// caller can fail closed rather than issue a challenge that can never be consumed.
func (cfg handlerConfig) recordChallenge(ctx context.Context, tenant string, session *webauthn.SessionData) error {
	if cfg.challenges == nil {
		return nil
	}
	expires := session.Expires
	if expires.IsZero() {
		expires = time.Now().Add(cfg.sessionTTL)
	}
	return cfg.challenges.Put(ctx, tenant, session.Challenge, expires)
}

// consumeChallenge atomically consumes the ceremony challenge for single-use replay
// protection, if a ChallengeStore is configured. It is called on Finish, right after
// loadSession succeeds and BEFORE the assertion is verified, so a replayed Finish (identical
// cookie + body) is reliably blocked: the second consume of the same challenge returns false.
// It returns true when the ceremony may proceed; on a missing/already-consumed challenge or a
// store error it writes the failure response and returns false.
func (cfg handlerConfig) consumeChallenge(w http.ResponseWriter, ctx context.Context, tenant string, session webauthn.SessionData) bool {
	if cfg.challenges == nil {
		return true
	}
	ok, err := cfg.challenges.Consume(ctx, tenant, session.Challenge)
	if err != nil {
		cfg.fail(w, err)
		return false
	}
	if !ok {
		// Unknown or already-used challenge: treat as an invalid ceremony session (a replay).
		cfg.fail(w, ErrSessionInvalid)
		return false
	}
	return true
}

// WithMaxBodyBytes overrides the request-body size cap applied to the Finish ceremony
// handlers before the WebAuthn response is decoded (default DefaultMaxBodyBytes). A
// non-positive value disables the cap; do so only if an upstream layer already bounds the
// body, since the go-webauthn decoder buffers and base64-decodes the body unbounded otherwise.
func WithMaxBodyBytes(n int64) HandlerOption {
	return func(h *handlerConfig) { h.maxBodyBytes = n }
}

// TenantExtractor derives the tenant identifier from the request for discoverable-login
// handlers, where no UserResolver is available (the user is not known until after the
// ceremony completes). Return an empty string for single-tenant deployments.
type TenantExtractor func(r *http.Request) string

// WithDiscoverableTenant supplies the tenant extractor used by BeginDiscoverableLoginHandler
// and FinishDiscoverableLoginHandler. In single-tenant deployments this option is unnecessary
// (the default extractor returns ""). In multi-tenant deployments derive the tenant from the
// request (e.g. host header, subdomain, or path prefix) and return it here; the same value is
// used to scope the challenge-store key so Begin and Finish must agree on the tenant.
func WithDiscoverableTenant(fn TenantExtractor) HandlerOption {
	return func(h *handlerConfig) { h.discoverableTenant = fn }
}

// BeginDiscoverableLoginHandler returns the credential-request options (for
// navigator.credentials.get) as JSON and stores the ceremony SessionData in a secure cookie.
// Unlike BeginLoginHandler no user needs to be identified in advance; the authenticator
// reveals the account via the credential's user handle at FinishDiscoverableLoginHandler.
// The challenge is recorded in the ChallengeStore (SEC-05) so the matching Finish handler
// can atomically consume it, blocking sign-count-0 replays that the clone-counter check alone
// would not catch.
func BeginDiscoverableLoginHandler(svc *Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(svc, opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.failClosedOnMisconfig(w) {
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tenant := ""
		if cfg.discoverableTenant != nil {
			tenant = cfg.discoverableTenant(r)
		}
		assertion, session, err := svc.BeginDiscoverableLogin()
		if err != nil {
			cfg.fail(w, err)
			return
		}
		if err := cfg.recordChallenge(r.Context(), tenant, session); err != nil {
			cfg.fail(w, err)
			return
		}
		if !cfg.storeSession(w, r, tenant, session) {
			return
		}
		httputil.WriteJSON(w, http.StatusOK, assertion)
	}
}

// FinishDiscoverableLoginHandler verifies the usernameless assertion response (POST body)
// against the cookie's SessionData. It atomically consumes the challenge before verification
// (SEC-05 replay defence) and applies the maxBodyBytes cap (DOS-01). On success it calls
// the configured LoginSuccess callback (or replies 204) with the resolved user ID.
func FinishDiscoverableLoginHandler(svc *Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(svc, opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.failClosedOnMisconfig(w) {
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tenant := ""
		if cfg.discoverableTenant != nil {
			tenant = cfg.discoverableTenant(r)
		}
		session, ok := cfg.loadSession(w, r, tenant)
		if !ok {
			return
		}
		// Consume the challenge before verifying: a replayed Finish (identical cookie + body)
		// fails here on the second attempt, even for a sign-count-0 authenticator whose clone
		// counter never advances.
		if !cfg.consumeChallenge(w, r.Context(), tenant, session) {
			return
		}
		// Cap the ceremony body before the go-webauthn decoder reads it (DOS-01): the assertion
		// response is small, so an oversized body is an abuse attempt, not a legitimate request.
		if cfg.maxBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes)
		}
		cred, uid, err := svc.FinishDiscoverableLogin(r.Context(), tenant, session, r)
		if err != nil {
			cfg.fail(w, err)
			return
		}
		_ = cred
		if cfg.onLoginSuccess != nil {
			cfg.onLoginSuccess(w, r, uid)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// WithTrustedOrigins adds extra hosts to the CSRF same-origin allowlist for
// RenameCredentialHandler.
//
// The origin check is ON by default (see originAllowed / WithInsecureNoOriginCheck): even with no
// trusted origins configured, a POST whose Origin — or, failing that, Referer — host is not the
// request's own Host is rejected with 403 cross_site_blocked. This option WIDENS that allowlist to
// permit additional hosts (e.g. a separate front-end origin on another subdomain). Supply hosts
// WITHOUT scheme, e.g. "app.example.com". To turn the check off entirely, use
// WithInsecureNoOriginCheck.
//
// Renewing a credential nickname is a state-changing endpoint authenticated purely by the
// consumer's session (ambient cookie), so SameSite=Lax alone does not prevent a forged same-site
// request; the strict check is therefore on by default, exactly as in the identity/tokens/mfa/otp
// handler families. The WebAuthn ceremony handlers are exempt: they are protected by the
// HMAC-sealed __Host- ceremony cookie and go-webauthn's own origin validation.
func WithTrustedOrigins(origins ...string) HandlerOption {
	return func(h *handlerConfig) {
		h.trustedOrigins = make(map[string]bool, len(origins))
		for _, o := range origins {
			h.trustedOrigins[o] = true
		}
	}
}

// WithInsecureNoOriginCheck disables the CSRF same-origin check on RenameCredentialHandler.
//
// By default the handler rejects any state-changing request whose Origin (or Referer fallback)
// host is neither the request's own Host nor an explicitly trusted origin (see
// WithTrustedOrigins), because the consumer's session cookie is ambient and SameSite=Lax alone
// does not prevent a forged same-site request.
//
// This option turns that protection OFF, restoring the pre-v1 behavior where every origin is
// accepted. It is named "Insecure" deliberately: only reach for it when CSRF is handled by a
// separate layer (e.g. a synchronizer-token middleware) or in trusted test setups. Prefer
// WithTrustedOrigins to extend, rather than remove, the allowlist.
func WithInsecureNoOriginCheck() HandlerOption {
	return func(h *handlerConfig) { h.insecureNoOriginCheck = true }
}

// originAllowed reports whether the request passes the CSRF same-origin check. The check is ON
// by default — even with an empty trustedOrigins allowlist — to match the tokens/identity
// handlers and make "CSRF-by-default" mean the same thing across handler families. A request is
// allowed only when its Origin (or Referer fallback) host equals the request's own Host or an
// allowlisted host (enforced by httputil.OriginAllowed, which also enforces cross-scheme
// protection); a request carrying neither header is treated as untrusted.
// WithInsecureNoOriginCheck restores the pre-v1 accept-all behavior.
func (cfg handlerConfig) originAllowed(r *http.Request) bool {
	if cfg.insecureNoOriginCheck {
		return true
	}
	return httputil.OriginAllowed(r, cfg.trustedOrigins)
}

// requireJSON enforces an application/json Content-Type on the JSON body and writes a 415 when it
// is absent or different. It is defense in depth on top of the origin gate: a CORS-simple
// cross-site form POST must not be able to smuggle a JSON payload through this endpoint.
func (cfg handlerConfig) requireJSON(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "unsupported_media_type", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

// RenameCredentialHandler sets a human-friendly nickname on one of the authenticated user's
// credentials. It is POST-only and requires the user resolver (the preamble), applies the strict
// CSRF same-origin origin gate by default (see WithTrustedOrigins / WithInsecureNoOriginCheck),
// requires a Content-Type of application/json (415 otherwise), caps the request body via
// http.MaxBytesReader, and decodes a JSON body of the shape:
//
//	{"credentialId": "<base64url, no padding>", "nickname": "..."}
//
// On success it replies 204 No Content; errors are routed through cfg.fail (ErrCredentialNotFound
// -> 404). It does not touch the ceremony cookie/challenge machinery — rename is not a WebAuthn
// ceremony.
func RenameCredentialHandler(svc *Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(svc, opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.failClosedOnMisconfig(w) {
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !cfg.originAllowed(r) {
			http.Error(w, "cross_site_blocked", http.StatusForbidden)
			return
		}
		uid, _, _, tenant, ok := cfg.resolveSubject(w, r)
		if !ok {
			return
		}
		if !cfg.requireJSON(w, r) {
			return
		}
		if cfg.maxBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes)
		}
		var body struct {
			CredentialID string `json:"credentialId"`
			Nickname     string `json:"nickname"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid_request", http.StatusBadRequest)
			return
		}
		credID, err := base64.RawURLEncoding.DecodeString(body.CredentialID)
		if err != nil {
			http.Error(w, "invalid_request", http.StatusBadRequest)
			return
		}
		if err := svc.RenameCredential(r.Context(), tenant, uid, credID, body.Nickname); err != nil {
			cfg.fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// WithTenantCookieKeys makes the ceremony-cookie HMAC key tenant-scoped: before sealing or
// opening the cookie, the handler resolves the key for the request's tenant through resolver. This
// extends the per-tenant cryptographic isolation already provided for JWT signing keys (see
// egauth/keystore) to the passkey ceremony cookie, so a ceremony cookie sealed under tenant A's key
// fails its HMAC check — and is rejected as an invalid session — when presented to tenant B.
//
// resolver receives the tenant id exactly as produced by WithUserResolver (registration/login) or
// WithDiscoverableTenant (discoverable login); the empty string is the single-tenant partition. It
// must return a stable, random secret of at least MinCookieKeyLength bytes for the tenant. Returning
// an error fails the request closed (500) rather than falling back to a shared key. Back the
// resolver with egauth/keystore (e.g. derive a per-tenant cookie key from the tenant's KeyStore
// material) so cookie keys rotate and revoke with the rest of the tenant's crypto.
//
// WithTenantCookieKeys takes precedence over the static Config.CookieKey / WithCookieKey for every
// tenant it is asked about; leave it unset to keep the single shared cookie key (unchanged behavior).
func WithTenantCookieKeys(resolver CookieKeyResolver) HandlerOption {
	return func(h *handlerConfig) { h.cookieKeys = resolver }
}

// cookieKeyFor resolves the ceremony-cookie HMAC key for the request's tenant. When a per-tenant
// resolver is configured (WithTenantCookieKeys) it is consulted; otherwise the static cookieKey
// (Config.CookieKey / WithCookieKey) is returned. A resolver error or a too-short / missing /
// all-zero / published-example key fails the request closed with 500 and ok=false, mirroring storeSession/loadSession's existing
// fail-closed behavior for an unconfigured key — never silently downgrading to a shared key.
func (cfg handlerConfig) cookieKeyFor(w http.ResponseWriter, ctx context.Context, tenant string) ([]byte, bool) {
	if cfg.cookieKeys == nil {
		if len(cfg.cookieKey) < MinCookieKeyLength || cookieKeyError(cfg.cookieKey) != nil {
			http.Error(w, "server_misconfigured", http.StatusInternalServerError)
			return nil, false
		}
		return cfg.cookieKey, true
	}
	key, err := cfg.cookieKeys(ctx, tenant)
	if err != nil || len(key) < MinCookieKeyLength || cookieKeyError(key) != nil {
		http.Error(w, "server_misconfigured", http.StatusInternalServerError)
		return nil, false
	}
	return key, true
}

// defaultHandlerConfig seeds the secure ceremony-cookie defaults shared by newHandlerConfig
// (which layers the Service's construction-validated cookie key and ChallengeStore on top)
// and ValidateHandlerConfig (which checks options without needing a Service).
func defaultHandlerConfig() handlerConfig {
	return handlerConfig{
		sessionCookie:  DefaultSessionCookieName,
		sessionTTL:     DefaultSessionTTL,
		cookieSameSite: http.SameSiteLaxMode,
		maxBodyBytes:   DefaultMaxBodyBytes,
	}
}

// validate rejects handler configurations where the ceremony cookie name and its attributes
// are incompatible. The __Host- prefix is browser-enforced: a cookie named __Host-* is
// silently discarded unless it is Secure and written with no Domain and Path=/ — the
// ceremony would then break with no visible cause (the cookie never reaches the browser),
// so the misconfiguration must fail loudly here, the handlers fail closed at request time,
// and ValidateHandlerConfig surfaces it for a server startup check. The ceremony cookie's
// path is hardcoded to Path=/ (storeSession/clearSession) with no option to change it, so
// only a shared Domain and the Secure attribute can conflict with the prefix today.
func (cfg handlerConfig) validate() error {
	if !strings.HasPrefix(cfg.sessionCookie, hostPrefix) {
		return nil
	}
	var errs []error
	if cfg.cookieDomain != "" {
		errs = append(errs, fmt.Errorf("passkey: ceremony cookie %q: __Host- prefix requires Domain to be empty, got %q", cfg.sessionCookie, cfg.cookieDomain))
	}
	if cfg.insecureCookies {
		errs = append(errs, fmt.Errorf("passkey: ceremony cookie %q: __Host- prefix requires Secure (insecure cookies must be disabled)", cfg.sessionCookie))
	}
	return errors.Join(errs...)
}

// ValidateHandlerConfig runs the handler-option validation without building a handler, so a
// server can fail fast at startup the same way the handlers fail closed at request time
// (mirrors oauth.ValidateHandlerConfig).
func ValidateHandlerConfig(opts ...HandlerOption) error {
	c := defaultHandlerConfig()
	for _, opt := range opts {
		opt(&c)
	}
	return c.validate()
}

// failClosedOnMisconfig writes a 500 and reports true when the handler configuration failed
// construction-time validation (see validate): a __Host- ceremony cookie with a Domain or
// without Secure never reaches the browser, so any response other than a loud 500 would
// break ceremonies invisibly.
func (cfg handlerConfig) failClosedOnMisconfig(w http.ResponseWriter) bool {
	if cfg.configErr == nil {
		return false
	}
	http.Error(w, "passkey handler misconfigured", http.StatusInternalServerError)
	return true
}
