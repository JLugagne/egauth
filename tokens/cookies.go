package tokens

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Default cookie names used by egauth handlers and middleware.
// Both names carry the __Host- prefix so browsers enforce host-lock semantics:
// the cookie must be Secure, must not have a Domain attribute, and must have Path=/.
// This defeats subdomain cookie-tossing / refresh-token fixation attacks where a
// sibling subdomain (evil.example.com) plants a same-named cookie with Domain=.example.com
// that the browser sends ahead of the legitimate cookie.
const (
	DefaultAccessCookieName  = "__Host-access_token"
	DefaultRefreshCookieName = "__Host-refresh_token"
)

// hostPrefix is the browser-enforced cookie name prefix that requires Secure, no Domain,
// and Path=/.
const hostPrefix = "__Host-"

// Cookies describes how authentication cookies are written and read. It is the single
// source of truth for cookie behavior, shared by the tokens handlers/middleware and the
// identity login handler.
//
// Per the PRD, every cookie emitted by egauth is HttpOnly, Secure and SameSite=Lax by
// default and scoped via Path. HttpOnly is always enforced (auth cookies are never read
// by client-side JavaScript in the server-rendered model), so it is not configurable.
type Cookies struct {
	// AccessName is the name of the short-lived access-token cookie.
	AccessName string
	// RefreshName is the name of the long-lived refresh-token cookie.
	RefreshName string
	// Domain optionally scopes the cookies to a domain (empty = host-only).
	// Must be empty when AccessName or RefreshName carries the __Host- prefix.
	Domain string
	// Path scopes the access-token cookie (default "/").
	// Must be "/" when AccessName carries the __Host- prefix.
	Path string
	// RefreshPath scopes the refresh-token cookie (default "/"). When the auto-refresh
	// middleware is mounted on protected routes, this must remain "/" so the refresh
	// cookie is sent with every request; scope it down only for a dedicated refresh
	// endpoint model.
	// Must be "/" when RefreshName carries the __Host- prefix.
	RefreshPath string
	// SameSite controls the SameSite attribute (default http.SameSiteLaxMode).
	SameSite http.SameSite
	// Insecure disables the Secure attribute. The zero value keeps cookies Secure; set it
	// only for local HTTP development. It is modeled as an opt-out so that the Go bool
	// zero value (false) is the SECURE default — even for a partially-initialized Cookies
	// or one built without DefaultCookies.
	// Must be false when AccessName or RefreshName carries the __Host- prefix.
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

// Validate checks that the Cookies configuration is self-consistent.
// It returns an error when a cookie name carries the __Host- prefix but the accompanying
// attributes violate the browser-enforced requirements: the cookie must be Secure
// (Insecure==false), must have no Domain, and must have Path="/".
//
// Validate is called automatically by withDefaults (and therefore by all Set*/Clear*/
// Access/Refresh methods). It is exported so callers can surface configuration mistakes
// early, e.g. in a server startup check.
func (c Cookies) Validate() error {
	var errs []error
	if strings.HasPrefix(c.AccessName, hostPrefix) {
		if c.Domain != "" {
			errs = append(errs, fmt.Errorf("cookie %q: __Host- prefix requires Domain to be empty, got %q", c.AccessName, c.Domain))
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		if path != "/" {
			errs = append(errs, fmt.Errorf("cookie %q: __Host- prefix requires Path=\"/\", got %q", c.AccessName, c.Path))
		}
		if c.Insecure {
			errs = append(errs, fmt.Errorf("cookie %q: __Host- prefix requires Secure (Insecure must be false)", c.AccessName))
		}
	}
	if strings.HasPrefix(c.RefreshName, hostPrefix) {
		if c.Domain != "" {
			errs = append(errs, fmt.Errorf("cookie %q: __Host- prefix requires Domain to be empty, got %q", c.RefreshName, c.Domain))
		}
		refreshPath := c.RefreshPath
		if refreshPath == "" {
			refreshPath = "/"
		}
		if refreshPath != "/" {
			errs = append(errs, fmt.Errorf("cookie %q: __Host- prefix requires Path=\"/\", got %q", c.RefreshName, c.RefreshPath))
		}
		if c.Insecure {
			errs = append(errs, fmt.Errorf("cookie %q: __Host- prefix requires Secure (Insecure must be false)", c.RefreshName))
		}
	}
	return errors.Join(errs...)
}

// withDefaults returns a copy of c with any zero-valued fields filled from DefaultCookies,
// so that a partially-initialized Cookies (or its zero value) still behaves securely.
// It panics if Validate detects a __Host- prefix constraint violation, because such a
// mismatch is a programmer error that must be caught at development time.
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
	if err := c.Validate(); err != nil {
		panic("tokens.Cookies: invalid __Host- cookie configuration: " + err.Error())
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
		maxAge := max(int(time.Until(expiresAt).Seconds()), 1)
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
