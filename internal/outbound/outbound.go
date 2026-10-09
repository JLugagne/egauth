// Package outbound is the only builder of http.Client and http.Transport (G6). Every server-side
// fetch (OIDC discovery, JWKS, token exchange, userinfo, breach check, resource-server metadata) goes
// through a Client from here, so the SSRF guard, the redirect refusal and the timeouts cannot be
// bypassed by a caller-supplied transport.
//
// The guard runs in net.Dialer.Control on the address actually dialled, so it also holds against DNS
// rebinding and happy-eyeballs fallbacks. Environment proxies are ignored, otherwise the guard would
// only see the proxy address.
package outbound

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

var (
	// ErrBlockedAddress is returned when the dial guard refuses the resolved address.
	ErrBlockedAddress = errors.New("outbound: blocked address (SSRF guard)")
	// ErrRedirect is returned instead of following a 3xx response.
	ErrRedirect = errors.New("outbound: redirect refused")
	// ErrInsecureScheme is returned for a scheme other than https, unless the URL is plain http to a
	// literal address covered by the client's allowance.
	ErrInsecureScheme = errors.New("outbound: insecure scheme")
	// ErrZeroClient is returned by Do on a Client that did not come from New.
	ErrZeroClient = errors.New("outbound: zero Client")
	// ErrNilRequest is returned by Do for a nil request or URL.
	ErrNilRequest = errors.New("outbound: nil request")
)

const (
	dialTimeout           = 10 * time.Second
	keepAlive             = 30 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 10 * time.Second
	expectContinueTimeout = 1 * time.Second
	idleConnTimeout       = 90 * time.Second
	requestTimeout        = 30 * time.Second
	maxIdleConns          = 32
	maxResponseHeaderSize = 64 << 10
)

var observedHeaders = []string{"Accept", "Accept-Encoding", "Content-Type", "User-Agent"}

// Observer is told about every outbound request. OutboundStart receives a redacted copy of the
// request: only the Accept, Accept-Encoding, Content-Type and User-Agent headers, no body, and a URL
// without user information, query or fragment, and without path for a request sent through
// Client.DoSecretPath. Changing that copy has no effect on the request sent. The returned func, when
// non-nil, is called once with the outcome; its response has no body. A panic in either is
// recovered and discarded, so a faulty observer cannot fail or crash the request.
type Observer interface {
	OutboundStart(req *http.Request) func(resp *http.Response, err error)
}

// Config selects the allowances of the two scopes. Static applies to statically configured
// providers (Insecure.OutboundPrivateNetwork); Tenant applies to providers registered at runtime by a
// tenant (Insecure.TenantOutboundPrivateNetwork). The scopes never share an allowance.
type Config struct {
	Static   Allowance
	Tenant   Allowance
	Observer Observer
	// RootCAs replaces the system roots for the TLS handshake; nil keeps them. It exists so that a
	// test can trust a self-signed provider; the SSRF dial guard still applies.
	RootCAs *x509.CertPool
}

// Clients holds one Client per allowance scope. It is safe for concurrent use.
type Clients struct {
	static Client
	tenant Client
}

// New cannot fail: the allowances were validated by NewAllowance, and the zero Config yields
// clients that reach public addresses only.
func New(c Config) *Clients {
	return &Clients{
		static: newClient(c.Static, c.Observer, c.RootCAs),
		tenant: newClient(c.Tenant, c.Observer, c.RootCAs),
	}
}

// Static returns the client for statically configured providers and library fetches.
func (c *Clients) Static() *Client {
	return &c.static
}

// Tenant returns the client for providers registered at runtime by a tenant.
func (c *Clients) Tenant() *Client {
	return &c.tenant
}

// CloseIdle closes the idle connections of both scopes.
func (c *Clients) CloseIdle() {
	c.static.hc.CloseIdleConnections()
	c.tenant.hc.CloseIdleConnections()
}

// Client sends guarded requests. The zero Client refuses every request with ErrZeroClient.
type Client struct {
	hc           *http.Client
	hcSecretPath *http.Client
	allow        Allowance
}

func newClient(a Allowance, obs Observer, roots *x509.CertPool) Client {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
		Control:   a.control,
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		ExpectContinueTimeout:  expectContinueTimeout,
		IdleConnTimeout:        idleConnTimeout,
		MaxIdleConns:           maxIdleConns,
		MaxResponseHeaderBytes: maxResponseHeaderSize,
	}
	return Client{
		hc:           httpClient(transport, obs, false),
		hcSecretPath: httpClient(transport, obs, true),
		allow:        a,
	}
}

func httpClient(transport *http.Transport, obs Observer, hidePath bool) *http.Client {
	var rt http.RoundTripper = transport
	if obs != nil {
		rt = observed{base: transport, obs: obs, hidePath: hidePath}
	}
	return &http.Client{
		Transport:     rt,
		Timeout:       requestTimeout,
		CheckRedirect: refuseRedirect,
	}
}

func refuseRedirect(*http.Request, []*http.Request) error {
	return ErrRedirect
}

// Do sends req. It returns ErrInsecureScheme before any dial for a disallowed scheme, an error
// wrapping ErrBlockedAddress when the guard refuses the address, and ErrRedirect for a 3xx answer.
// The caller closes the body of a returned response.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c == nil || c.hc == nil {
		return nil, ErrZeroClient
	}
	return c.do(c.hc, req)
}

// DoSecretPath is Do for a URL whose path carries secret-derived data, such as the password hash
// prefix of a breach range query: the Observer sees the URL without its path, and a returned
// *url.Error carries only the scheme and host, so the error can be logged.
func (c *Client) DoSecretPath(req *http.Request) (*http.Response, error) {
	if c == nil || c.hcSecretPath == nil {
		return nil, ErrZeroClient
	}
	resp, err := c.do(c.hcSecretPath, req)
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = (&url.URL{Scheme: req.URL.Scheme, Host: req.URL.Host}).String()
	}
	return resp, err
}

func (c *Client) do(hc *http.Client, req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, ErrNilRequest
	}
	if err := c.checkScheme(req.URL); err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, err
	}
	return resp, nil
}

func (c *Client) checkScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		addr, err := netip.ParseAddr(u.Hostname())
		if err == nil && c.allow.coversAll(addr) && c.allow.Permits(addr) {
			return nil
		}
	}
	return errors.Join(ErrInsecureScheme, errors.New(u.Scheme+"://"+u.Host))
}

func (a Allowance) control(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return errors.Join(ErrBlockedAddress, errors.New("network "+network))
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return errors.Join(ErrBlockedAddress, err)
	}
	if !a.Permits(ap.Addr()) {
		return errors.Join(ErrBlockedAddress, errors.New(ap.Addr().String()))
	}
	return nil
}

type observed struct {
	base     *http.Transport
	obs      Observer
	hidePath bool
}

func (o observed) RoundTrip(req *http.Request) (*http.Response, error) {
	done := o.start(req)
	resp, err := o.base.RoundTrip(req)
	if done != nil {
		finish(done, redactedResponse(resp), err)
	}
	return resp, err
}

func (o observed) start(req *http.Request) (done func(*http.Response, error)) {
	defer func() {
		if recover() != nil {
			done = nil
		}
	}()
	return o.obs.OutboundStart(redactedRequest(req, o.hidePath))
}

func finish(done func(*http.Response, error), resp *http.Response, err error) {
	defer func() { _ = recover() }()
	done(resp, err)
}

func (o observed) CloseIdleConnections() {
	o.base.CloseIdleConnections()
}

func redactedRequest(req *http.Request, hidePath bool) *http.Request {
	c := req.Clone(req.Context())
	c.Body, c.GetBody = http.NoBody, nil
	c.Form, c.PostForm, c.MultipartForm, c.Trailer = nil, nil, nil, nil
	header := http.Header{}
	for _, h := range observedHeaders {
		if v := req.Header.Values(h); len(v) > 0 {
			header[h] = append([]string(nil), v...)
		}
	}
	c.Header = header
	u := *req.URL
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	if hidePath {
		u.Path, u.RawPath, u.Opaque = "", "", ""
	}
	c.URL = &u
	return c
}

func redactedResponse(resp *http.Response) *http.Response {
	if resp == nil {
		return nil
	}
	c := *resp
	c.Body = http.NoBody
	c.Header = resp.Header.Clone()
	c.Header.Del("Set-Cookie")
	c.Trailer = nil
	c.Request = nil
	return &c
}
