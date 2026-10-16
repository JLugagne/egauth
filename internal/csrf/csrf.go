// Package csrf is the only cross-site request gate (DESIGN §6.4, T-10, X-07) and the only reader of
// the Origin, Referer and Sec-Fetch-* headers. Its polarity is deny by default: a checked request
// passes only on positive same-origin evidence.
package csrf

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
)

const (
	headerOrigin        = "Origin"
	headerReferer       = "Referer"
	headerFetchSite     = "Sec-Fetch-Site"
	headerFetchMode     = "Sec-Fetch-Mode"
	headerAuthorization = "Authorization"
	tenantMarker        = "{tenant}"
	bearerScheme        = "bearer"
)

// Request header names the gate reads. They are exported so that the test harness, which must send
// them, never spells them as literals.
const (
	HeaderOrigin    = headerOrigin
	HeaderReferer   = headerReferer
	HeaderFetchSite = headerFetchSite
	HeaderFetchMode = headerFetchMode
)

// HeaderTransport mirrors routes.HeaderTransport; a guard test keeps them equal.
const HeaderTransport = "X-Egauth-Transport"

var (
	// ErrForbidden is returned by Check for every refused request, joined with the reason.
	ErrForbidden = errors.New("csrf: cross-site request refused")
	// ErrInvalidOrigin is returned by NewOrigins for a value that is not an exact origin.
	ErrInvalidOrigin = errors.New("csrf: invalid origin")
)

// Origins is the trusted-origin set: the public origin, possibly with a {tenant} first host label,
// and the exact extra origins. The zero Origins trusts nothing.
type Origins struct {
	public string
	extra  []string
}

// NewOrigins canonicalises public and extra (lowercase scheme and host, default port dropped).
// Only public may carry {tenant}, and only as its whole first host label. It returns
// ErrInvalidOrigin.
func NewOrigins(public string, extra []string) (Origins, error) {
	p, err := canonical(public, true)
	if err != nil {
		return Origins{}, err
	}
	o := Origins{public: p}
	for _, e := range extra {
		c, err := canonical(e, false)
		if err != nil {
			return Origins{}, err
		}
		o.extra = append(o.extra, c)
	}
	return o, nil
}

func canonical(raw string, templated bool) (string, error) {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return "", errors.Join(ErrInvalidOrigin, errors.New("no scheme"))
	}
	label := ""
	if strings.Contains(rest, tenantMarker) {
		if !templated || !strings.HasPrefix(rest, tenantMarker+".") || strings.Count(raw, tenantMarker) != 1 {
			return "", errors.Join(ErrInvalidOrigin, errors.New("misplaced {tenant}"))
		}
		label, rest = tenantMarker, "t"+strings.TrimPrefix(rest, tenantMarker)
	}
	u, err := url.Parse(scheme + "://" + rest)
	if err != nil {
		return "", errors.Join(ErrInvalidOrigin, err)
	}
	s := strings.ToLower(u.Scheme)
	if (s != "https" && s != "http") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" {
		return "", errors.Join(ErrInvalidOrigin, errors.New(raw))
	}
	host := asciiLower(u.Hostname())
	if strings.Contains(u.Hostname(), ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && (s != "https" || port != "443") && (s != "http" || port != "80") {
		host += ":" + port
	}
	if label != "" {
		host = label + strings.TrimPrefix(host, "t")
	}
	return s + "://" + host, nil
}

// IsZero reports whether o trusts no origin.
func (o Origins) IsZero() bool { return o.public == "" && len(o.extra) == 0 }

// For returns the exact origins trusted for a request of tenant t: the tenant-expanded public
// origin (omitted for the zero tenant when the public origin is a template) and the extra
// origins.
func (o Origins) For(t core.TenantID) []string {
	out := make([]string, 0, len(o.extra)+1)
	switch {
	case o.public == "":
	case strings.Contains(o.public, tenantMarker):
		if !t.IsZero() {
			out = append(out, strings.Replace(o.public, tenantMarker, asciiLower(t.String()), 1))
		}
	default:
		out = append(out, o.public)
	}
	return append(out, o.extra...)
}

// Policy is the per-request input of Check.
type Policy struct {
	// Origins are the exact trusted origins of this request (Origins.For).
	Origins []string
	// SetsCookies is EndpointMeta.SetsCookies: unsafe requests are checked even without cookies,
	// which closes login CSRF.
	SetsCookies bool
	// Authenticated applies the safe-method rule: the target serves a session principal (Protect,
	// Optional, or an authenticated auth endpoint).
	Authenticated bool
	// BearerTransport reports that the request resolves to Bearer transport, so the response sets no
	// cookie. The bearer exemption applies only then: a bearer-looking request that would still get
	// cookies is checked like any other.
	BearerTransport bool
}

// Check applies DESIGN §6.4 to r and returns nil or ErrForbidden.
//
// Safe methods (GET, HEAD, OPTIONS) are refused only when p.Authenticated, r carries a cookie,
// Sec-Fetch-Site is cross-site and Sec-Fetch-Mode is not navigate. Every other method is checked
// when r carries a cookie or p.SetsCookies; a request with no cookie that carries
// X-Egauth-Transport: bearer or an Authorization Bearer credential is exempt when
// p.BearerTransport. A checked request
// needs Sec-Fetch-Site same-origin or none when present, then an Origin (or, without Origin, a
// Referer origin) among p.Origins.
func Check(r *http.Request, p Policy) error {
	hasCookie := cookie.Present(r)
	if safe(r.Method) {
		if !p.Authenticated || !hasCookie {
			return nil
		}
		return safeFetch(r)
	}
	if !hasCookie && ((p.BearerTransport && bearerExempt(r)) || !p.SetsCookies) {
		return nil
	}
	if err := fetchSite(r); err != nil {
		return err
	}
	return originMatch(r, p.Origins)
}

func safe(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func deny(reason string) error {
	return errors.Join(ErrForbidden, errors.New(reason))
}

func single(r *http.Request, name string) (string, int) {
	vs := r.Header.Values(name)
	if len(vs) != 1 {
		return "", len(vs)
	}
	return strings.TrimSpace(vs[0]), 1
}

func safeFetch(r *http.Request) error {
	site, n := single(r, headerFetchSite)
	if n > 1 {
		return deny("duplicate Sec-Fetch-Site")
	}
	if !strings.EqualFold(site, "cross-site") {
		return nil
	}
	if mode, n := single(r, headerFetchMode); n == 1 && strings.EqualFold(mode, "navigate") {
		return nil
	}
	return deny("cross-site non-navigation request")
}

func fetchSite(r *http.Request) error {
	site, n := single(r, headerFetchSite)
	switch {
	case n == 0:
		return nil
	case n > 1:
		return deny("duplicate Sec-Fetch-Site")
	case strings.EqualFold(site, "same-origin"), strings.EqualFold(site, "none"):
		return nil
	}
	return deny("Sec-Fetch-Site " + site)
}

func originMatch(r *http.Request, trusted []string) error {
	origin, n := single(r, headerOrigin)
	switch {
	case n > 1:
		return deny("duplicate Origin")
	case n == 1:
		if origin == "null" || !contains(trusted, asciiLower(origin)) {
			return deny("untrusted Origin")
		}
		return nil
	}
	ref, n := single(r, headerReferer)
	if n != 1 {
		return deny("no Origin and no single Referer")
	}
	u, err := url.Parse(ref)
	if err != nil || u.User != nil || u.Host == "" || u.Opaque != "" {
		return deny("unparsable Referer")
	}
	if !contains(trusted, asciiLower(u.Scheme+"://"+u.Host)) {
		return deny("untrusted Referer")
	}
	return nil
}

func contains(trusted []string, origin string) bool {
	for _, t := range trusted {
		if t != "" && t == origin {
			return true
		}
	}
	return false
}

func bearerExempt(r *http.Request) bool {
	if v, n := single(r, HeaderTransport); n == 1 && strings.EqualFold(v, bearerScheme) {
		return true
	}
	return BearerAuthorization(r)
}

// BearerAuthorization reports whether r carries exactly one Authorization header holding a
// non-empty Bearer credential. It applies the bearer exemption of Check, so the
// preamble can resolve the transport of an endpoint that never issues a credential from it.
func BearerAuthorization(r *http.Request) bool {
	auth, n := single(r, headerAuthorization)
	if n != 1 {
		return false
	}
	scheme, token, ok := strings.Cut(auth, " ")
	return ok && strings.EqualFold(scheme, bearerScheme) && strings.TrimSpace(token) != ""
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
