package journeytest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/JLugagne/egauth"
)

// Tokens of the Bearer transport, as the library hands them out in response headers.
const (
	HeaderAccessToken  = "X-Egauth-Access-Token"
	HeaderRefreshToken = "X-Egauth-Refresh-Token"
	HeaderSessionToken = "X-Egauth-Session-Token"
)

// Client is a browser-like caller of one handler: it keeps a cookie jar, sends the Origin a browser
// would for an unsafe request, and presents one source address. A Client is not safe for
// concurrent use.
type Client struct {
	T       testing.TB
	server  *memServer
	Host    string
	Origin  string
	Remote  string
	Bearer  string
	jar     map[string]*http.Cookie
	flow    string
	refresh string
}

// Req describes one request. Zero fields take the browser-like default.
type Req struct {
	Method  string
	Path    string
	Form    url.Values
	JSON    map[string]any
	Raw     []byte
	Header  http.Header
	Cookies []*http.Cookie
	NoJar   bool
	NoOrig  bool
	Host    string
	Remote  string
}

// Resp is a recorded response.
type Resp struct {
	Status  int
	Header  http.Header
	Body    []byte
	Cookies []*http.Cookie
}

// NewClient returns a Client of the world's handler, presenting its own source address.
func (w *World) NewClient() *Client {
	w.nextAddr++
	if w.mem == nil {
		w.mem = newMemServer(w.T, w.Handler)
	}
	return &Client{
		T: w.T, server: w.mem, Host: w.Host, Origin: w.Origin,
		Remote: fmt.Sprintf("198.51.%d.%d:4000", (w.nextAddr>>8)&0xff, w.nextAddr&0xff),
		jar:    map[string]*http.Cookie{},
	}
}

// NewBareClient returns a Client of h at origin with an empty jar, for a server that is not a World.
func NewBareClient(t testing.TB, h http.Handler, origin string) *Client {
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatalf("journeytest: origin %q: %v", origin, err)
	}
	return &Client{T: t, server: newMemServer(t, h), Host: u.Host, Origin: origin, Remote: "198.51.100.200:4000", jar: map[string]*http.Cookie{}}
}

// Stranger returns a Client of the same handler with an empty jar and its own source address, the
// browser of someone who never began the ceremony c began.
func (c *Client) Stranger() *Client {
	return &Client{T: c.T, server: c.server, Host: c.Host, Origin: c.Origin, Remote: c.FreshRemote(), jar: map[string]*http.Cookie{}}
}

// Do sends r and records the response and its cookies in the jar.
func (c *Client) Do(r Req) *Resp {
	c.T.Helper()
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	var ctype string
	switch {
	case r.Raw != nil:
		body = strings.NewReader(string(r.Raw))
	case r.JSON != nil:
		b, err := json.Marshal(r.JSON)
		if err != nil {
			c.T.Fatalf("journeytest: encoding request: %v", err)
		}
		body, ctype = strings.NewReader(string(b)), "application/json"
	case r.Form != nil:
		body, ctype = strings.NewReader(r.Form.Encode()), "application/x-www-form-urlencoded"
	}
	host := r.Host
	if host == "" {
		host = c.Host
	}
	remote := c.Remote
	if r.Remote != "" {
		remote = r.Remote
	}
	req, err := http.NewRequestWithContext(context.Background(), method, "http://"+remote+r.Path, body)
	if err != nil {
		c.T.Fatalf("journeytest: building the request: %v", err)
	}
	req.Host = host
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("Accept", "application/json")
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions && !r.NoOrig {
		req.Header.Set(Origin(c.Origin).Name, c.Origin)
	}
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	if !r.NoJar {
		for _, name := range c.jarNames() {
			req.AddCookie(c.jar[name])
		}
	}
	for _, k := range r.Cookies {
		req.AddCookie(k)
	}
	for k, vs := range r.Header {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	res, err := c.server.hc.Do(req)
	if err != nil {
		c.T.Fatalf("journeytest: %s %s: %v", method, r.Path, err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		c.T.Fatalf("journeytest: reading the response of %s %s: %v", method, r.Path, err)
	}
	out := &Resp{Status: res.StatusCode, Header: res.Header.Clone(), Body: raw, Cookies: res.Cookies()}
	if !r.NoJar {
		c.absorb(out.Cookies)
	}
	return out
}

func (c *Client) jarNames() []string {
	names := make([]string, 0, len(c.jar))
	for n := range c.jar {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (c *Client) absorb(cookies []*http.Cookie) {
	for _, k := range cookies {
		if k.MaxAge < 0 || k.Value == "" {
			delete(c.jar, k.Name)
			continue
		}
		c.jar[k.Name] = k
	}
}

// Cookie returns the jar cookie with name suffix, such as "access_token" or "egauth_bind".
func (c *Client) Cookie(suffix string) (*http.Cookie, bool) {
	for n, k := range c.jar {
		if strings.HasSuffix(n, suffix) {
			return k, true
		}
	}
	return nil, false
}

// HasSessionCookie reports whether the jar holds a session credential.
func (c *Client) HasSessionCookie() bool {
	for _, s := range []string{"access_token", "refresh_token", "-session"} {
		if _, ok := c.Cookie(s); ok {
			return true
		}
	}
	return false
}

// Cookies returns the jar's cookies ordered by name.
func (c *Client) Cookies() []*http.Cookie {
	var out []*http.Cookie
	for _, n := range c.jarNames() {
		out = append(out, c.jar[n])
	}
	return out
}

// Jar replaces the jar with a copy of cookies.
func (c *Client) Jar(cookies []*http.Cookie) {
	c.jar = map[string]*http.Cookie{}
	c.absorb(cookies)
}

// Fork returns a Client of the same handler with its own jar holding a copy of this one's and its own
// source address.
func (w *World) Fork(c *Client) *Client {
	n := w.NewClient()
	n.Bearer = c.Bearer
	n.Host, n.Origin = c.Host, c.Origin
	n.Jar(c.Cookies())
	return n
}

// JSONBody decodes the body into a map; it fails t when the body is not a JSON object.
func (r *Resp) JSONBody(t testing.TB) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("journeytest: response is not a JSON object (status %d): %q", r.Status, r.Body)
	}
	return m
}

// Field returns the string at key of a JSON object body, or "".
func (r *Resp) Field(key string) string {
	var m map[string]any
	if json.Unmarshal(r.Body, &m) != nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// Code returns the machine code of an error response, or the state of a journey response.
func (r *Resp) Code() string {
	if v := r.Field("error"); v != "" {
		return v
	}
	return r.Field("state")
}

// Token returns the Bearer credential a response carries, whichever backend issued it.
func (r *Resp) Token() string {
	for _, h := range []string{HeaderAccessToken, HeaderSessionToken} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	return ""
}

// Refresh returns the refresh token a response carries, or "".
func (r *Resp) Refresh() string { return r.Header.Get(HeaderRefreshToken) }

// Established reports whether the response completed a login: a session cookie or a Bearer token.
func (r *Resp) Established() bool {
	if r.Token() != "" {
		return true
	}
	for _, k := range r.Cookies {
		if k.MaxAge >= 0 && k.Value != "" && (strings.HasSuffix(k.Name, "access_token") || strings.HasSuffix(k.Name, "-session")) {
			return true
		}
	}
	return false
}

// Credentials are the identifier and password of a password login.
type Credentials struct {
	Email    string
	Password string
}

// LoginPassword posts the password credentials; under bearer it selects the Bearer transport.
func (c *Client) LoginPassword(cred Credentials, bearer bool) *Resp {
	c.T.Helper()
	req := Req{Method: http.MethodPost, Path: "/auth" + egauth.PathLogin, JSON: map[string]any{
		egauth.FieldIdentifier: cred.Email, egauth.FieldPassword: cred.Password,
	}}
	if bearer {
		req.Header = http.Header{egauth.HeaderTransport: {"bearer"}}
	}
	res := c.Do(req)
	c.keepTokens(res)
	if h := res.Field("flow"); h != "" {
		c.flow = h
	}
	return res
}

// Login signs email in with the world's password through the endpoint and returns the response; it
// fails t when the login did not establish a session.
func (c *Client) Login(email string, bearer bool) *Resp {
	c.T.Helper()
	res := c.LoginPassword(Credentials{Email: email, Password: Password}, bearer)
	if !res.Established() {
		c.T.Fatalf("journeytest: login of %s did not establish a session: %d %s", email, res.Status, res.Body)
	}
	return res
}

// Session fetches GET /session.
func (c *Client) Session() *Resp {
	return c.Do(Req{Path: "/auth" + egauth.PathSession})
}

func (c *Client) keepTokens(res *Resp) {
	if tok := res.Token(); tok != "" {
		c.Bearer = tok
	}
	if rt := res.Refresh(); rt != "" {
		c.refresh = rt
	}
}

// RefreshBearer renews the Bearer session with the refresh token the last login or refresh
// carried, and keeps the new tokens. The refresh token is single use, so a Client calls it once per
// token it holds; a cookie session renews through its jar instead.
func (c *Client) RefreshBearer() *Resp {
	c.T.Helper()
	bearer := c.Bearer
	c.Bearer = ""
	defer func() { c.Bearer = bearer }()
	res := c.Do(Req{Method: http.MethodPost, Path: "/auth" + egauth.PathRefresh, NoJar: true, Header: http.Header{
		HeaderRefreshToken:     {c.refresh},
		egauth.HeaderTransport: {"bearer"},
	}})
	if res.Token() != "" {
		bearer = res.Token()
	}
	c.keepTokens(res)
	return res
}
