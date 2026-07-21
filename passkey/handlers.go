package passkey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/JLugagne/egauth/internal/httputil"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Default ceremony-cookie configuration.
const (
	DefaultSessionCookieName = "passkey_ceremony"
	DefaultSessionTTL        = 5 * time.Minute
)

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
	c := handlerConfig{
		sessionCookie:  DefaultSessionCookieName,
		sessionTTL:     DefaultSessionTTL,
		cookieSameSite: http.SameSiteLaxMode,
		maxBodyBytes:   DefaultMaxBodyBytes,
		cookieKey:      svc.cookieKey,
		challenges:     svc.challenges,
	}
	for _, opt := range opts {
		opt(&c)
	}
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

// WithSessionCookieName overrides the ceremony cookie name.
func WithSessionCookieName(name string) HandlerOption {
	return func(h *handlerConfig) { h.sessionCookie = name }
}

// WithSessionTTL overrides how long an in-flight ceremony stays valid.
func WithSessionTTL(d time.Duration) HandlerOption {
	return func(h *handlerConfig) { h.sessionTTL = d }
}

// WithCookieDomain scopes the ceremony cookie to a domain.
func WithCookieDomain(domain string) HandlerOption {
	return func(h *handlerConfig) { h.cookieDomain = domain }
}

// WithSameSite overrides the ceremony cookie SameSite attribute (default Lax).
func WithSameSite(mode http.SameSite) HandlerOption {
	return func(h *handlerConfig) { h.cookieSameSite = mode }
}

// WithInsecureCookies disables the Secure attribute on the ceremony cookie (local HTTP dev).
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

func (cfg handlerConfig) storeSession(w http.ResponseWriter, r *http.Request, tenant string, session *webauthn.SessionData) bool {
	key, ok := cfg.cookieKeyFor(w, r.Context(), tenant)
	if !ok {
		// Fail closed: an unauthenticated ceremony cookie is forgeable (challenge / UV
		// downgrade). cookieKeyFor has already written the 500.
		return false
	}
	raw, err := json.Marshal(session)
	if err != nil {
		http.Error(w, "session_error", http.StatusInternalServerError)
		return false
	}
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
	if !ok || json.Unmarshal(raw, &session) != nil {
		cfg.fail(w, ErrSessionInvalid)
		return session, false
	}
	return session, true
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

// RenameCredentialHandler sets a human-friendly nickname on one of the authenticated user's
// credentials. It is POST-only and requires the user resolver (cfg.subject preamble), caps the
// request body via http.MaxBytesReader, and decodes a JSON body of the shape:
//
//	{"credentialId": "<base64url, no padding>", "nickname": "..."}
//
// On success it replies 204 No Content; errors are routed through cfg.fail (ErrCredentialNotFound
// -> 404). It does not touch the ceremony cookie/challenge machinery — rename is not a WebAuthn
// ceremony.
func RenameCredentialHandler(svc *Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(svc, opts)
	return func(w http.ResponseWriter, r *http.Request) {
		uid, _, _, tenant, ok := cfg.subject(w, r)
		if !ok {
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
// (Config.CookieKey / WithCookieKey) is returned. A resolver error or a too-short / missing key
// fails the request closed with 500 and ok=false, mirroring storeSession/loadSession's existing
// fail-closed behavior for an unconfigured key — never silently downgrading to a shared key.
func (cfg handlerConfig) cookieKeyFor(w http.ResponseWriter, ctx context.Context, tenant string) ([]byte, bool) {
	if cfg.cookieKeys == nil {
		if len(cfg.cookieKey) < MinCookieKeyLength {
			http.Error(w, "server_misconfigured", http.StatusInternalServerError)
			return nil, false
		}
		return cfg.cookieKey, true
	}
	key, err := cfg.cookieKeys(ctx, tenant)
	if err != nil || len(key) < MinCookieKeyLength {
		http.Error(w, "server_misconfigured", http.StatusInternalServerError)
		return nil, false
	}
	return key, true
}
