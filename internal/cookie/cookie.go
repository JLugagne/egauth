// Package cookie is the only writer and reader of HTTP cookies. It defines the three closed
// cookie classes of DESIGN §6.5 (session, flow, bind); names and attributes are fixed here, so a
// writer and a reader can never disagree (D-01, D-05) and no caller can configure them (I-16).
package cookie

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/JLugagne/egauth/store/ceremony"
)

const (
	prefixHost      = "__Host-"
	prefixSecure    = "__Secure-"
	tenantMarker    = "{tenant}"
	maxValueLen     = 4096
	headerCookie    = "Cookie"
	headerSetCookie = "Set-Cookie"
)

var (
	// ErrInvalidPolicy is returned by NewPolicy for an origin or shared domain it cannot honour.
	ErrInvalidPolicy = errors.New("cookie: invalid cookie policy")
	// ErrInvalidCookie is returned by a writer given a name of another class, an invalid value or
	// lifetime, or an invalid ceremony kind.
	ErrInvalidCookie = errors.New("cookie: invalid cookie")
)

// Class is one of the three closed cookie classes. The zero Class is invalid.
type Class uint8

const (
	// ClassSession carries session credentials: SameSite=Lax, Max-Age only when remembered.
	ClassSession Class = iota + 1
	// ClassFlow carries the MFA flow handle: always __Host-, SameSite=Strict, Kind.TTL().
	ClassFlow
	// ClassBind carries the browser-binding secret of an unauthenticated ceremony: always __Host-,
	// SameSite=Lax because the OAuth callback is a cross-site top-level GET, Kind.TTL().
	ClassBind
)

// Name is one library cookie. The set is closed; the zero Name is invalid.
type Name uint8

const (
	AccessToken Name = iota + 1
	RefreshToken
	StatefulSession
	Flow
	Bind
)

// Names returns every declared cookie name.
func Names() []Name {
	return []Name{AccessToken, RefreshToken, StatefulSession, Flow, Bind}
}

// Class returns the class of n, or 0 for an undeclared name.
func (n Name) Class() Class {
	switch n {
	case AccessToken, RefreshToken, StatefulSession:
		return ClassSession
	case Flow:
		return ClassFlow
	case Bind:
		return ClassBind
	}
	return 0
}

func (n Name) base() string {
	switch n {
	case AccessToken:
		return "access_token"
	case RefreshToken:
		return "refresh_token"
	case StatefulSession:
		return "session"
	case Flow:
		return "egauth_flow"
	case Bind:
		return "egauth_bind"
	}
	return ""
}

// Options is the deployment input of NewPolicy.
type Options struct {
	// PublicOrigin is the configured public origin; a {tenant} host label is allowed.
	PublicOrigin string
	// SharedDomain is Insecure.SharedCookieDomain's domain, or "" for host-only session cookies.
	SharedDomain string
}

// Policy fixes the attributes of every library cookie for one deployment. The zero Policy is
// invalid; writers refuse it.
type Policy struct {
	valid  bool
	secure bool
	domain string
}

// NewPolicy derives the cookie policy from the public origin. Cookies are Secure and prefixed
// unless the origin is http on loopback, where browsers refuse prefixed cookies; any other http
// origin is refused. A shared domain demotes only session cookies to __Secure- with that Domain;
// it must be a parent of the origin host, requires https, and is refused with a {tenant} origin,
// whose tenant hosts must not share session cookies. It returns ErrInvalidPolicy.
func NewPolicy(o Options) (Policy, error) {
	u, err := url.Parse(strings.Replace(o.PublicOrigin, tenantMarker, "tenant", 1))
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return Policy{}, errors.Join(ErrInvalidPolicy, errors.New("public origin is not an origin"))
	}
	host := strings.ToLower(u.Hostname())
	p := Policy{valid: true}
	switch u.Scheme {
	case "https":
		p.secure = true
	case "http":
		if !loopback(host) {
			return Policy{}, errors.Join(ErrInvalidPolicy, errors.New("http origin off loopback"))
		}
	default:
		return Policy{}, errors.Join(ErrInvalidPolicy, errors.New("origin scheme"))
	}
	if o.SharedDomain == "" {
		return p, nil
	}
	if strings.Contains(o.PublicOrigin, tenantMarker) {
		return Policy{}, errors.Join(ErrInvalidPolicy, errors.New("tenant subdomain origins keep host-only session cookies"))
	}
	d := strings.ToLower(o.SharedDomain)
	if !p.secure || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || (host != d && !strings.HasSuffix(host, "."+d)) {
		return Policy{}, errors.Join(ErrInvalidPolicy, errors.New("shared domain must be an https parent of the origin host"))
	}
	p.domain = d
	return p, nil
}

func loopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && a.IsLoopback()
}

// CookieName returns the wire name of n under p, or "" for an undeclared name.
func (p Policy) CookieName(n Name) string {
	base := n.base()
	if base == "" || !p.secure {
		return base
	}
	if n.Class() == ClassSession && p.domain != "" {
		return prefixSecure + base
	}
	return prefixHost + base
}

func (p Policy) cookie(n Name, value string) *http.Cookie {
	c := &http.Cookie{
		Name:     p.CookieName(n),
		Value:    value,
		Path:     "/",
		Secure:   p.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if n.Class() == ClassSession {
		c.Domain = p.domain
	}
	if n.Class() == ClassFlow {
		c.SameSite = http.SameSiteStrictMode
	}
	return c
}

func (p Policy) check(n Name, c Class, value string) error {
	if !p.valid {
		return errors.Join(ErrInvalidCookie, errors.New("zero policy"))
	}
	if n.Class() != c {
		return errors.Join(ErrInvalidCookie, errors.New("name of another class"))
	}
	if !validValue(value) {
		return errors.Join(ErrInvalidCookie, errors.New("invalid value"))
	}
	return nil
}

// SetSession writes the session-class cookie n. With remember, Max-Age is maxAge rounded down to
// whole seconds and must be at least one second; without it the cookie is a browser-session
// cookie and maxAge is ignored. Callers rewrite it on every server expiry extension.
func (p Policy) SetSession(w http.ResponseWriter, n Name, value string, remember bool, maxAge time.Duration) error {
	if err := p.check(n, ClassSession, value); err != nil {
		return err
	}
	c := p.cookie(n, value)
	if remember {
		secs := int(maxAge / time.Second)
		if secs < 1 {
			return errors.Join(ErrInvalidCookie, errors.New("remembered cookie needs a positive lifetime"))
		}
		c.MaxAge = secs
	}
	http.SetCookie(w, c)
	return nil
}

// SetFlow writes the flow cookie carrying a handle of ceremony kind k, which must be valid; its
// Max-Age is k.TTL().
func (p Policy) SetFlow(w http.ResponseWriter, value string, k ceremony.Kind) error {
	if err := p.check(Flow, ClassFlow, value); err != nil {
		return err
	}
	return p.setTTL(w, p.cookie(Flow, value), k)
}

// SetBind writes the bind cookie for a ceremony of kind k begun by an unauthenticated client.
func (p Policy) SetBind(w http.ResponseWriter, b BindSecret, k ceremony.Kind) error {
	if err := p.check(Bind, ClassBind, b.value); err != nil {
		return err
	}
	return p.setTTL(w, p.cookie(Bind, b.value), k)
}

func (p Policy) setTTL(w http.ResponseWriter, c *http.Cookie, k ceremony.Kind) error {
	secs := int(k.TTL() / time.Second)
	if !k.Valid() || secs < 1 {
		return errors.Join(ErrInvalidCookie, errors.New("invalid ceremony kind"))
	}
	c.MaxAge = secs
	http.SetCookie(w, c)
	return nil
}

// Clear expires cookie n with the attributes it was written with. Undeclared names and the zero
// Policy are ignored.
func (p Policy) Clear(w http.ResponseWriter, n Name) {
	if !p.valid || n.Class() == 0 {
		return
	}
	c := p.cookie(n, "")
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// Read returns the value of cookie n. It reports false when the cookie is absent, empty, or
// present more than once: a duplicate means a cookie was tossed from a sibling host, and choosing
// one would let an attacker pick the session (fixation).
func (p Policy) Read(r *http.Request, n Name) (string, bool) {
	name := p.CookieName(n)
	if !p.valid || name == "" {
		return "", false
	}
	var found []string
	for _, c := range r.Cookies() {
		if c.Name == name {
			found = append(found, c.Value)
		}
	}
	if len(found) != 1 || found[0] == "" {
		return "", false
	}
	return found[0], true
}

// Present reports whether r carries any Cookie header, parsable or not, so that the CSRF gate
// treats every cookie-carrying request as cookie-authenticated.
func Present(r *http.Request) bool {
	for _, v := range r.Header.Values(headerCookie) {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// Discard drops every Set-Cookie queued on w and not yet sent, so that a refused response never
// carries a credential written earlier in the same request (a rotation by Resume, for instance).
func Discard(w http.ResponseWriter) {
	w.Header().Del(headerSetCookie)
}

func validValue(v string) bool {
	if v == "" || len(v) > maxValueLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' || c == '='
		if !ok {
			return false
		}
	}
	return true
}
