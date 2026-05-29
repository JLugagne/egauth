package tokens

import (
	"net/http"
	"time"
)

// Default cookie names used by libauth handlers and middleware.
const (
	DefaultAccessCookieName  = "access_token"
	DefaultRefreshCookieName = "refresh_token"
)

// Cookies describes how authentication cookies are written and read. It is the single
// source of truth for cookie behavior, shared by the tokens handlers/middleware and the
// identity login handler.
//
// Per the PRD, every cookie emitted by libauth is HttpOnly, Secure and SameSite=Lax by
// default and scoped via Path. HttpOnly is always enforced (auth cookies are never read
// by client-side JavaScript in the server-rendered model), so it is not configurable.
type Cookies struct {
	// AccessName is the name of the short-lived access-token cookie.
	AccessName string
	// RefreshName is the name of the long-lived refresh-token cookie.
	RefreshName string
	// Domain optionally scopes the cookies to a domain (empty = host-only).
	Domain string
	// Path scopes the access-token cookie (default "/").
	Path string
	// RefreshPath scopes the refresh-token cookie (default "/"). When the auto-refresh
	// middleware is mounted on protected routes, this must remain "/" so the refresh
	// cookie is sent with every request; scope it down only for a dedicated refresh
	// endpoint model.
	RefreshPath string
	// SameSite controls the SameSite attribute (default http.SameSiteLaxMode).
	SameSite http.SameSite
	// Insecure disables the Secure attribute. The zero value keeps cookies Secure; set it
	// only for local HTTP development. It is modeled as an opt-out so that the Go bool
	// zero value (false) is the SECURE default — even for a partially-initialized Cookies
	// or one built without DefaultCookies.
	Insecure bool
}

// DefaultCookies returns a Cookies value populated with secure defaults.
func DefaultCookies() Cookies {
	return Cookies{
		AccessName:  DefaultAccessCookieName,
		RefreshName: DefaultRefreshCookieName,
		Path:        "/",
		RefreshPath: "/",
		SameSite:    http.SameSiteLaxMode,
		// Secure is on by default via the zero value of Insecure (false).
	}
}

// withDefaults returns a copy of c with any zero-valued fields filled from DefaultCookies,
// so that a partially-initialized Cookies (or its zero value) still behaves securely.
func (c Cookies) withDefaults() Cookies {
	d := DefaultCookies()
	if c.AccessName == "" {
		c.AccessName = d.AccessName
	}
	if c.RefreshName == "" {
		c.RefreshName = d.RefreshName
	}
	if c.Path == "" {
		c.Path = d.Path
	}
	if c.RefreshPath == "" {
		c.RefreshPath = d.RefreshPath
	}
	if c.SameSite == 0 {
		c.SameSite = d.SameSite
	}
	return c
}

// SetAccess writes the access-token cookie. It is always a session cookie (no Max-Age):
// the access token is short-lived and its expiry is carried inside the JWT, so the cookie
// only needs to survive until the browser is closed. Keeping it present (rather than
// expiring the cookie itself) lets the auto-refresh middleware observe the stale token and
// rotate transparently.
func (c Cookies) SetAccess(w http.ResponseWriter, accessToken string) {
	c = c.withDefaults()
	http.SetCookie(w, &http.Cookie{
		Name:     c.AccessName,
		Value:    accessToken,
		Domain:   c.Domain,
		Path:     c.Path,
		HttpOnly: true,
		Secure:   !c.Insecure,
		SameSite: c.SameSite,
	})
}

// SetRefresh writes the refresh-token cookie. When persistent is true (remember-me), the
// cookie is given a Max-Age aligned to expiresAt; otherwise it is a session cookie that the
// browser drops on close.
func (c Cookies) SetRefresh(w http.ResponseWriter, refreshToken string, expiresAt time.Time, persistent bool) {
	c = c.withDefaults()
	cookie := &http.Cookie{
		Name:     c.RefreshName,
		Value:    refreshToken,
		Domain:   c.Domain,
		Path:     c.RefreshPath,
		HttpOnly: true,
		Secure:   !c.Insecure,
		SameSite: c.SameSite,
	}
	if persistent {
		maxAge := int(time.Until(expiresAt).Seconds())
		if maxAge < 1 {
			maxAge = 1
		}
		cookie.MaxAge = maxAge
		cookie.Expires = expiresAt
	}
	http.SetCookie(w, cookie)
}

// ClearAccess expires the access-token cookie.
func (c Cookies) ClearAccess(w http.ResponseWriter) {
	c = c.withDefaults()
	http.SetCookie(w, &http.Cookie{
		Name:     c.AccessName,
		Value:    "",
		Domain:   c.Domain,
		Path:     c.Path,
		HttpOnly: true,
		Secure:   !c.Insecure,
		SameSite: c.SameSite,
		MaxAge:   -1,
	})
}

// ClearRefresh expires the refresh-token cookie.
func (c Cookies) ClearRefresh(w http.ResponseWriter) {
	c = c.withDefaults()
	http.SetCookie(w, &http.Cookie{
		Name:     c.RefreshName,
		Value:    "",
		Domain:   c.Domain,
		Path:     c.RefreshPath,
		HttpOnly: true,
		Secure:   !c.Insecure,
		SameSite: c.SameSite,
		MaxAge:   -1,
	})
}

// Clear expires both the access and refresh cookies (used on logout).
func (c Cookies) Clear(w http.ResponseWriter) {
	c.ClearAccess(w)
	c.ClearRefresh(w)
}

// Access reads the access-token cookie value, if present and non-empty.
func (c Cookies) Access(r *http.Request) (string, bool) {
	c = c.withDefaults()
	cookie, err := r.Cookie(c.AccessName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

// Refresh reads the refresh-token cookie value, if present and non-empty.
func (c Cookies) Refresh(r *http.Request) (string, bool) {
	c = c.withDefaults()
	cookie, err := r.Cookie(c.RefreshName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}
