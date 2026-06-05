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
	resolve         UserResolver
	onLoginSuccess  LoginSuccessFunc
	sessionCookie   string
	sessionTTL      time.Duration
	cookieDomain    string
	cookieSameSite  http.SameSite
	insecureCookies bool
	cookieKey       []byte
	challenges      ChallengeStore
	maxBodyBytes    int64
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
		if !cfg.storeSession(w, session) {
			return
		}
		writeJSON(w, http.StatusOK, creation)
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
		session, ok := cfg.loadSession(w, r)
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
		if !cfg.storeSession(w, session) {
			return
		}
		writeJSON(w, http.StatusOK, assertion)
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
		session, ok := cfg.loadSession(w, r)
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

func (cfg handlerConfig) storeSession(w http.ResponseWriter, session *webauthn.SessionData) bool {
	if len(cfg.cookieKey) == 0 {
		// Fail closed: an unauthenticated ceremony cookie is forgeable (challenge / UV
		// downgrade). The consumer must configure WithCookieKey.
		http.Error(w, "server_misconfigured", http.StatusInternalServerError)
		return false
	}
	raw, err := json.Marshal(session)
	if err != nil {
		http.Error(w, "session_error", http.StatusInternalServerError)
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.sessionCookie,
		Value:    cfg.seal(raw),
		Domain:   cfg.cookieDomain,
		Path:     "/",
		HttpOnly: true,
		Secure:   !cfg.insecureCookies,
		SameSite: cfg.cookieSameSite,
		MaxAge:   int(cfg.sessionTTL.Seconds()),
	})
	return true
}

func (cfg handlerConfig) loadSession(w http.ResponseWriter, r *http.Request) (webauthn.SessionData, bool) {
	cfg.clearSession(w) // single-use, regardless of outcome
	var session webauthn.SessionData
	if len(cfg.cookieKey) == 0 {
		http.Error(w, "server_misconfigured", http.StatusInternalServerError)
		return session, false
	}
	c, err := r.Cookie(cfg.sessionCookie)
	if err != nil || c.Value == "" {
		cfg.fail(w, ErrSessionInvalid)
		return session, false
	}
	raw, ok := cfg.open(c.Value)
	if !ok || json.Unmarshal(raw, &session) != nil {
		cfg.fail(w, ErrSessionInvalid)
		return session, false
	}
	return session, true
}

// seal prepends an HMAC-SHA256 tag to the payload and base64url-encodes the result, so the
// cookie cannot be tampered with by the client.
func (cfg handlerConfig) seal(raw []byte) string {
	mac := hmac.New(sha256.New, cfg.cookieKey)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(append(mac.Sum(nil), raw...))
}

// open verifies the HMAC tag (constant time) and returns the payload, or ok=false on any
// mismatch / malformed value.
func (cfg handlerConfig) open(value string) ([]byte, bool) {
	blob, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(blob) < sha256.Size {
		return nil, false
	}
	tag, raw := blob[:sha256.Size], blob[sha256.Size:]
	mac := hmac.New(sha256.New, cfg.cookieKey)
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

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
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
