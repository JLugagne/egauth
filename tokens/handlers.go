package tokens

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// FamilyRevoker is the minimal store capability LogoutHandler needs to revoke a rotation
// family. tokens.Store[C] satisfies it for any C (neither method depends on C).
type FamilyRevoker interface {
	FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*RefreshToken, error)
	RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error
}

// handlerConfig holds the configurable behavior of the tokens HTTP handlers.
type handlerConfig struct {
	cookies        Cookies
	tenantResolver func(*http.Request) string
	successURL     string
	failureURL     string
	persistRefresh bool
	trustedOrigins map[string]bool
}

// HandlerOption configures the tokens HTTP handlers (RefreshHandler, LogoutHandler).
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{cookies: DefaultCookies()}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// WithCookies replaces the cookie configuration wholesale.
func WithCookies(c Cookies) HandlerOption { return func(h *handlerConfig) { h.cookies = c } }

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

// WithPersistentRefresh re-issues the rotated refresh cookie as a PERSISTENT cookie
// (Max-Age aligned to the refresh expiry). By default the rotated refresh cookie is a
// session cookie, since this endpoint cannot recover the original remember_me choice from
// the request and must not silently upgrade a session-only cookie to a persistent one.
func WithPersistentRefresh() HandlerOption {
	return func(h *handlerConfig) { h.persistRefresh = true }
}

// WithTenantResolver derives the tenant from the request to scope store operations in
// multi-tenant deployments.
func WithTenantResolver(f func(*http.Request) string) HandlerOption {
	return func(h *handlerConfig) { h.tenantResolver = f }
}

// WithTrustedOrigins enables a CSRF origin check on the cookie-driven token endpoints
// (RefreshHandler, LogoutHandler).
//
// These are state-changing POSTs authenticated purely by the refresh cookie, so SameSite=Lax
// alone does not fully prevent a forged cross-site refresh/logout. When trusted origins are
// configured, a request whose Origin — or, failing that, Referer — host is neither the
// request's own Host nor one of the supplied hosts is rejected with 403. Supply hosts WITHOUT
// scheme, e.g. "app.example.com". When left unset the check is disabled and CSRF protection is
// the consumer's responsibility (see SECURITY.md).
func WithTrustedOrigins(origins ...string) HandlerOption {
	return func(h *handlerConfig) {
		h.trustedOrigins = make(map[string]bool, len(origins))
		for _, o := range origins {
			h.trustedOrigins[o] = true
		}
	}
}

// RefreshHandler builds an HTTP handler that rotates the refresh token carried in the
// refresh cookie: it consumes the old token, issues a fresh access+refresh pair within the
// same family, and rewrites both cookies. A replayed token causes family revocation and a
// rejection. On failure the cookies are cleared, except for the benign concurrency case
// (ErrRefreshConcurrent: a parallel request won the rotation race within the reuse grace),
// where only the stale access cookie is cleared so the winner's fresh refresh cookie survives.
func RefreshHandler[C any](rotator Rotator[C], opts ...HandlerOption) http.HandlerFunc {
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

		refreshToken, ok := cfg.cookies.Refresh(r)
		if !ok {
			cfg.cookies.Clear(w)
			cfg.fail(w, r, http.StatusUnauthorized, "missing_refresh_token")
			return
		}

		pair, err := rotator.Rotate(r.Context(), cfg.tenant(r), refreshToken)
		if err != nil {
			// ErrRefreshConcurrent is benign concurrency: a parallel request won the rotation
			// race and already minted a fresh, valid refresh cookie for this client (the family
			// is NOT poisoned). Clearing the refresh cookie would wipe the winner's freshly
			// issued cookie and log the user out — the lockout the reuse grace prevents. Drop
			// only the stale access cookie and reject; the client retries with the live cookie.
			if errors.Is(err, ErrRefreshConcurrent) {
				cfg.cookies.ClearAccess(w)
				cfg.fail(w, r, http.StatusUnauthorized, refreshErrorCode(err))
				return
			}
			// Any other failure (after-grace reuse already revoked the family, expired, not
			// found): clear the client's now-useless cookies.
			cfg.cookies.Clear(w)
			cfg.fail(w, r, http.StatusUnauthorized, refreshErrorCode(err))
			return
		}

		cfg.cookies.SetAccess(w, pair.AccessToken)
		cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, cfg.persistRefresh)
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// LogoutHandler builds an HTTP handler that revokes the entire rotation family of the
// presented refresh token (global logout) and clears the auth cookies.
//
// Idempotency: if the token is absent or already gone (ErrRefreshTokenNotFound) the
// handler clears the cookies and returns success (204 / success redirect), so a
// client-side double-logout does not fail.
//
// Store errors are surfaced: if FindRefreshToken returns any error other than
// ErrRefreshTokenNotFound, or if RevokeFamily returns an error, the cookies are still
// cleared (the local session ends) but the handler responds with 500 (or with a
// failure redirect carrying error=logout_incomplete when WithFailureRedirect is set).
// This lets clients retry and lets monitoring catch un-revoked families.
func LogoutHandler(revoker FamilyRevoker, opts ...HandlerOption) http.HandlerFunc {
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

		if refreshToken, ok := cfg.cookies.Refresh(r); ok {
			tenantID := cfg.tenant(r)
			hash := HashToken(refreshToken)
			rt, err := revoker.FindRefreshToken(r.Context(), tenantID, hash)
			switch {
			case err == nil:
				// Token found: revoke the whole rotation family.
				if err := revoker.RevokeFamily(r.Context(), tenantID, rt.FamilyID); err != nil {
					cfg.cookies.Clear(w)
					cfg.fail(w, r, http.StatusInternalServerError, "logout_incomplete")
					return
				}
			case errors.Is(err, ErrRefreshTokenNotFound):
				// Token already gone: idempotent success — fall through.
			default:
				// Unexpected store error: clear cookies but report failure so the
				// client knows the server-side revocation did not happen.
				cfg.cookies.Clear(w)
				cfg.fail(w, r, http.StatusInternalServerError, "logout_incomplete")
				return
			}
		}

		cfg.cookies.Clear(w)
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// originAllowed reports whether the request passes the CSRF origin check. When no trusted
// origins are configured the check is disabled (the consumer's responsibility, per
// SECURITY.md). A configured check rejects any request whose Origin (or Referer fallback)
// host is neither the request's own Host nor an allowlisted host; a POST carrying neither
// header is treated as untrusted.
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

// tenant returns the tenant derived from the request's resolver, or "" when no resolver is
// configured (the single-tenant default partition).
func (cfg handlerConfig) tenant(r *http.Request) string {
	if cfg.tenantResolver == nil {
		return ""
	}
	return cfg.tenantResolver(r)
}

// fail emits a failure response: a 303 redirect to the configured failure URL (carrying an
// ?error=<code> param) when set, otherwise an HTTP error with the given status.
func (cfg handlerConfig) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	if cfg.failureURL != "" {
		http.Redirect(w, r, withErrorParam(cfg.failureURL, code), http.StatusSeeOther)
		return
	}
	http.Error(w, code, status)
}

func refreshErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrRefreshConcurrent):
		// Benign concurrency, not theft: a parallel request already rotated the token. Distinct
		// from token_reuse_detected so clients can retry with the winner's fresh cookie. Checked
		// before ErrRefreshTokenReused since ErrRefreshConcurrent wraps it.
		return "concurrent_refresh"
	case errors.Is(err, ErrRefreshTokenReused):
		return "token_reuse_detected"
	case errors.Is(err, ErrTokenExpired):
		return "refresh_expired"
	case errors.Is(err, ErrRefreshTokenNotFound):
		return "invalid_refresh_token"
	default:
		return "refresh_failed"
	}
}

// redirectOrStatus replies with a 303 redirect to url when non-empty, otherwise writes
// okStatus.
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
