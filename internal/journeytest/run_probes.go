package journeytest

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JLugagne/egauth/internal/routes"
)

// Probe is one G22 probe: Name is unique and stable across configurations, so a variant's report can be
// compared with the golden one; Run returns what was observed and whether the denying
// expectation held.
type Probe struct {
	Category string
	Name     string
	Want     string
	// Control marks a positive control: it asserts that a legitimate request is served, so that a
	// denial probe is never vacuous. A control is not a security expectation.
	Control bool
	Run     func() (got string, held bool)
}

// Result is the outcome of one Probe.
type Result struct {
	Category string
	Name     string
	Want     string
	Got      string
	Held     bool
	Control  bool
}

// Report is the ordered outcome of a battery.
type Report []Result

// Collect runs every probe and reports the outcomes without failing a test.
func Collect(probes []Probe) Report {
	out := make(Report, 0, len(probes))
	for _, p := range probes {
		got, held := p.Run()
		out = append(out, Result{Category: p.Category, Name: p.Name, Want: p.Want, Got: got, Held: held, Control: p.Control})
	}
	return out
}

// Failed returns the results whose expectation did not hold.
func (r Report) Failed() Report {
	var out Report
	for _, x := range r {
		if !x.Held {
			out = append(out, x)
		}
	}
	return out
}

// ByName indexes the report by probe name.
func (r Report) ByName() map[string]Result {
	m := make(map[string]Result, len(r))
	for _, x := range r {
		m[x.Name] = x
	}
	return m
}

// Names returns the sorted probe names.
func (r Report) Names() []string {
	out := make([]string, 0, len(r))
	for _, x := range r {
		out = append(out, x.Name)
	}
	sort.Strings(out)
	return out
}

// Check fails t for every probe whose expectation did not hold.
func (r Report) Check(t testing.TB) {
	t.Helper()
	for _, x := range r.Failed() {
		t.Errorf("probe %s: want %s, got %s", x.Name, x.Want, x.Got)
	}
}

// Describe renders a probe outcome for failure messages.
func Describe(r *Resp) string {
	return fmt.Sprintf("%d %s", r.Status, strings.TrimSpace(string(r.Body)))
}

func status(r *Resp, want int, code string) (string, bool) {
	ok := r.Status == want && (code == "" || r.Code() == code)
	return Describe(r), ok
}

// Endpoint is one auth endpoint resolved against a base path.
type Endpoint struct {
	Registry string
	Path     string
	Method   string
	Meta     routes.EndpointMeta
}

// Label is the probe-name form of the endpoint.
func (e Endpoint) Label() string { return e.Method + " " + e.Path }

func concrete(path string) string {
	path = strings.ReplaceAll(path, "{provider}", ProviderName)
	return strings.ReplaceAll(path, "{name}", ExternalName)
}

// Endpoints returns every registered auth endpoint under base with its metadata; the metadata is
// the only source of the G22 expectations.
func Endpoints(base string) []Endpoint {
	var out []Endpoint
	for _, p := range routes.All() {
		m, ok := routes.MetaFor(p)
		if !ok {
			continue
		}
		out = append(out, Endpoint{Registry: p, Path: base + concrete(p), Method: routes.Method(p), Meta: m})
	}
	return out
}

const (
	evilOrigin  = ForeignOrigin
	junkCookie  = "__Host-access_token"
	crossOrigin = "cross_site_request"
)

// ForeignOrigin is an origin no deployment trusts by default, a host under the relying-party domain
// the tests use (tenant.example.com) so that it is also a valid ExtraOrigins entry for the G7b
// variant that does trust it.
const ForeignOrigin = "https://evil.tenant.example.com"

func withJunkCookie() []*http.Cookie {
	return []*http.Cookie{{Name: junkCookie, Value: "junk"}}
}

// Served reports whether the endpoint is mounted: deny-by-default answers 404 for a route that is
// not.
func Served(c *Client, e Endpoint) bool {
	r := c.Do(Req{Method: e.Method, Path: e.Path, NoJar: true, Remote: c.FreshRemote()})
	return r.Status != http.StatusNotFound
}

// FreshRemote returns a source address no earlier call returned, so that each request of a probe
// draws on its own rate-limit bucket.
func (c *Client) FreshRemote() string {
	n := remoteSeq.Add(1)
	return fmt.Sprintf("203.%d.%d.%d:5000", (n>>16)&0xff, (n>>8)&0xff, n&0xff)
}

var remoteSeq atomic.Uint32

func jsonBodyOfSize(size int64) []byte {
	const head, tail = `{"identifier":"`, `"}`
	b := make([]byte, 0, size)
	b = append(b, head...)
	for int64(len(b)) < size-int64(len(tail)) {
		b = append(b, 'a')
	}
	return append(b, tail...)
}

func burstRequest(e Endpoint, identifier string) Req {
	r := Req{Method: e.Method, Path: e.Path}
	if e.Meta.Mutation {
		r.JSON = map[string]any{"identifier": identifier}
	}
	return r
}

func hitsUntilLimited(c *Client, mk func(i int) Req, burst int) (limitedAt int, last *Resp) {
	for i := 0; i <= burst+1; i++ {
		last = c.Do(mk(i))
		if last.Status == http.StatusTooManyRequests {
			return i + 1, last
		}
	}
	return 0, last
}

// AuthProbes returns the credentialless G22 probes of every auth endpoint under base, derived from
// the endpoint metadata and the route kind only: CSRF, request limits, ceremony binding and
// deny-by-default. They need no account, so RunAgainst applies them to any server.
func AuthProbes(c *Client, base string) []Probe {
	var ps []Probe
	for _, e := range Endpoints(base) {
		if !Served(c, e) {
			continue
		}
		ps = append(ps, csrfProbes(c, e)...)
		ps = append(ps, limitProbes(c, e)...)
	}
	ps = append(ps, Probe{
		Category: "deny-by-default", Name: "deny-by-default/unknown-path", Want: "404",
		Run: func() (string, bool) {
			return status(c.Do(Req{Path: "/no-such-route", NoJar: true}), http.StatusNotFound, "")
		},
	})
	ps = append(ps, ceremonyBindProbes(c, base)...)
	return ps
}

func csrfProbes(c *Client, e Endpoint) []Probe {
	var ps []Probe
	add := func(name string, r Req, held func(*Resp) (string, bool)) {
		ps = append(ps, Probe{
			Category: "csrf", Name: "csrf/" + name + "/" + e.Label(), Want: "403 " + crossOrigin,
			Run: func() (string, bool) { r.Remote = c.FreshRemote(); return held(c.Do(r)) },
		})
	}
	forbidden := func(r *Resp) (string, bool) { return status(r, http.StatusForbidden, crossOrigin) }
	m := e.Meta
	if m.Mutation {
		base := func(h http.Header, noOrigin bool) Req {
			return Req{Method: e.Method, Path: e.Path, NoJar: true, Cookies: withJunkCookie(), Header: h, NoOrig: noOrigin}
		}
		add("cross-origin-with-cookie", base(Headers(Origin(evilOrigin)), false), forbidden)
		add("null-origin-with-cookie", base(Headers(Origin("null")), false), forbidden)
		add("no-origin-no-referer-with-cookie", base(nil, true), forbidden)
		add("same-site-fetch-with-cookie", base(Headers(FetchSite("same-site")), false), forbidden)
		add("cross-site-fetch-with-cookie", base(Headers(FetchSite("cross-site")), false), forbidden)
		add("cross-origin-referer-with-cookie", base(Headers(Referer(evilOrigin+"/x")), true), forbidden)
	}
	if !m.Mutation && m.Authenticated {
		add("cross-site-get-with-cookie", Req{
			Method: e.Method, Path: e.Path, NoJar: true, Cookies: withJunkCookie(),
			Header: Headers(FetchSite("cross-site"), FetchMode("cors")),
		}, forbidden)
	}
	if m.Mutation && m.SetsCookies {
		add("login-cross-origin-no-cookie", Req{Method: e.Method, Path: e.Path, NoJar: true, Header: Headers(Origin(evilOrigin))}, forbidden)
		add("login-null-origin-no-cookie", Req{Method: e.Method, Path: e.Path, NoJar: true, Header: Headers(Origin("null"))}, forbidden)
		add("login-no-origin-no-cookie", Req{Method: e.Method, Path: e.Path, NoJar: true, NoOrig: true}, forbidden)
	}
	return ps
}

func limitProbes(c *Client, e Endpoint) []Probe {
	var ps []Probe
	m := e.Meta
	if m.Mutation {
		sized := func(size int64) *Resp {
			return c.Do(Req{Method: e.Method, Path: e.Path, Raw: jsonBodyOfSize(size), Header: http.Header{"Content-Type": {"application/json"}}, NoJar: true, Remote: c.FreshRemote()})
		}
		ps = append(ps, Probe{
			Category: "limits", Name: "limits/body-cap-plus-one/" + e.Label(), Want: "413",
			Run: func() (string, bool) { return status(sized(m.BodyCap+1), http.StatusRequestEntityTooLarge, "") },
		}, Probe{
			Category: "limits", Name: "limits/body-cap-exact/" + e.Label(), Want: "anything but 413", Control: true,
			Run: func() (string, bool) {
				r := sized(m.BodyCap)
				return Describe(r), r.Status != http.StatusRequestEntityTooLarge
			},
		})
	}
	if cl := m.ClientLimit; cl != 0 {
		burst := cl.Budget().Burst
		ps = append(ps, Probe{
			Category: "limits", Name: "limits/client-burst-plus-one/" + e.Label(), Want: "429 on request " + strconv.Itoa(burst+1),
			Run: func() (string, bool) {
				remote := c.FreshRemote()
				at, last := hitsUntilLimited(c, func(i int) Req {
					r := burstRequest(e, fmt.Sprintf("client-burst-%d-%s@mail.test", i, remote))
					r.NoJar, r.Remote = true, remote
					return r
				}, burst)
				return fmt.Sprintf("429 on request %d (%s)", at, Describe(last)), at == burst+1
			},
		})
	}
	if il := m.IdentifierLimit; il != 0 && m.IdentifierKeyed {
		burst := il.Budget().Burst
		ps = append(ps, Probe{
			Category: "limits", Name: "limits/identifier-burst-plus-one/" + e.Label(), Want: "429 on request " + strconv.Itoa(burst+1),
			Run: func() (string, bool) {
				id := "identifier-burst-" + strconv.Itoa(int(remoteSeq.Add(1))) + "@mail.test"
				at, last := hitsUntilLimited(c, func(int) Req {
					r := burstRequest(e, id)
					r.NoJar, r.Remote = true, c.FreshRemote()
					return r
				}, burst)
				return fmt.Sprintf("429 on request %d (%s)", at, Describe(last)), at == burst+1
			},
		})
	}
	return ps
}

func ceremonyBindProbes(c *Client, base string) []Probe {
	var ps []Probe
	for _, e := range Endpoints(base) {
		if e.Registry != routes.OAuthCallback || !Served(c, e) {
			continue
		}
		begin := base + concrete(routes.OAuthBegin)
		callback := func(browser *Client, withJar bool) (string, *Resp) {
			resp := browser.Do(Req{Path: begin, Remote: c.FreshRemote()})
			if resp.Header.Get("Location") == "" && resp.Status == http.StatusOK {
				return "n/a: the Bearer transport binds the ceremony through the exchange, not a cookie: " + Describe(resp), nil
			}
			state := OAuthState(resp)
			if state == "" {
				return "begin gave no state: " + Describe(resp), nil
			}
			return "", browser.Do(Req{Method: e.Method, Path: e.Path + "?state=" + url.QueryEscape(state) + "&code=forged", NoJar: !withJar, Remote: c.FreshRemote()})
		}
		ps = append(ps, Probe{
			Category: "ceremony-binding", Name: "ceremony-binding/oauth-callback-without-bind", Want: "400 unbound_ceremony for a genuine state presented without the bind",
			Run: func() (string, bool) {
				broken, r := callback(c.Stranger(), false)
				if r == nil {
					return broken, strings.HasPrefix(broken, "n/a")
				}
				return status(r, http.StatusBadRequest, "unbound_ceremony")
			},
		}, Probe{
			Category: "ceremony-binding", Name: "ceremony-binding/oauth-callback-with-bind-passes-the-bind-check", Want: "anything but unbound_ceremony", Control: true,
			Run: func() (string, bool) {
				broken, r := callback(c.Stranger(), true)
				if r == nil {
					return broken, strings.HasPrefix(broken, "n/a")
				}
				return Describe(r), r.Code() != "unbound_ceremony"
			},
		})
	}
	return ps
}
