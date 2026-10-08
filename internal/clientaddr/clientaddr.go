// Package clientaddr is the only reader of http.Request.RemoteAddr and of forwarding headers. It
// turns a request into the client address the rate limiter and the BeforeEndpoint hook see, under
// the deployment's proxy policy (DESIGN §3.2, §6.8).
package clientaddr

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
)

const (
	headerForwardedFor = "X-Forwarded-For"
	minIPv4Bits        = 8
	minIPv6Bits        = 16
	ipv6KeyBits        = 64
	mappedBits         = 96
)

var (
	// ErrInvalidPolicy is returned for the zero Policy or an invalid prefix.
	ErrInvalidPolicy = errors.New("clientaddr: invalid proxy policy")
	// ErrPrefixTooBroad is returned by Trusted for /0, an IPv4 prefix shorter than /8 or an IPv6
	// prefix shorter than /16 (C-42).
	ErrPrefixTooBroad = errors.New("clientaddr: trusted proxy prefix too broad")
	// ErrNoClient is returned by Resolve when the peer address cannot be parsed; callers fail
	// closed.
	ErrNoClient = errors.New("clientaddr: no client address")
)

type mode uint8

const (
	modeDirect mode = iota + 1
	modeTrusted
)

// Policy says whom forwarding headers are accepted from. The zero Policy is invalid; build one with
// Direct or Trusted.
type Policy struct {
	mode    mode
	trusted []netip.Prefix
}

// Direct accepts no forwarding header: the client is the TCP peer.
func Direct() Policy {
	return Policy{mode: modeDirect}
}

// Trusted accepts X-Forwarded-For only from peers inside the given prefixes, and walks it from the
// right past every trusted hop. Forwarded and X-Real-Ip are never read. It returns
// ErrPrefixTooBroad or ErrInvalidPolicy for an unacceptable prefix.
func Trusted(first netip.Prefix, more ...netip.Prefix) (Policy, error) {
	all := append([]netip.Prefix{first}, more...)
	out := make([]netip.Prefix, 0, len(all))
	for _, p := range all {
		n, err := normalisePrefix(p)
		if err != nil {
			return Policy{}, err
		}
		out = append(out, n)
	}
	return Policy{mode: modeTrusted, trusted: out}, nil
}

func normalisePrefix(p netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, errors.Join(ErrInvalidPolicy, errors.New("invalid prefix"))
	}
	if p.Addr().Is4In6() {
		if p.Bits() < mappedBits+minIPv4Bits {
			return netip.Prefix{}, errors.Join(ErrPrefixTooBroad, errors.New(p.String()))
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-mappedBits)
	}
	limit := minIPv6Bits
	if p.Addr().Is4() {
		limit = minIPv4Bits
	}
	if p.Bits() < limit {
		return netip.Prefix{}, errors.Join(ErrPrefixTooBroad, errors.New(p.String()))
	}
	return p.Masked(), nil
}

// Client is the resolved client of one request.
type Client struct {
	addr netip.Addr
}

// Addr returns the client address, unmapped and without zone.
func (c Client) Addr() netip.Addr { return c.addr }

// Key returns the rate-limit key of the client: the address for IPv4, the /64 prefix for IPv6, so
// one host cannot rotate through its own subnet to escape the client budget.
func (c Client) Key() string {
	if c.addr.Is4() {
		return c.addr.String()
	}
	return netip.PrefixFrom(c.addr, ipv6KeyBits).Masked().String()
}

// IsZero reports whether c was not produced by Resolve.
func (c Client) IsZero() bool { return !c.addr.IsValid() }

// Resolver applies one Policy. It is safe for concurrent use.
type Resolver struct {
	policy Policy
	sink   event.Sink
	warned sync.Once
}

// New returns a Resolver for p. sink receives the one-shot ProxyHeadersIgnored warning; nil
// disables it. It returns ErrInvalidPolicy for the zero Policy.
func New(p Policy, sink event.Sink) (*Resolver, error) {
	switch p.mode {
	case modeDirect:
	case modeTrusted:
		if len(p.trusted) == 0 {
			return nil, ErrInvalidPolicy
		}
	default:
		return nil, ErrInvalidPolicy
	}
	return &Resolver{policy: p, sink: sink}, nil
}

// Resolve returns the client of r. It returns ErrNoClient when the peer address is unusable.
func (res *Resolver) Resolve(r *http.Request) (Client, error) {
	peer, ok := parseHost(r.RemoteAddr)
	if !ok {
		return Client{}, ErrNoClient
	}
	hops := forwardedFor(r)
	if res.policy.mode == modeDirect {
		if len(hops) > 0 && (peer.IsPrivate() || peer.IsLoopback()) {
			res.warn(r)
		}
		return Client{addr: peer}, nil
	}
	if !res.trusts(peer) {
		return Client{addr: peer}, nil
	}
	current := peer
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseHost(hops[i])
		if !ok {
			return Client{addr: current}, nil
		}
		current = hop
		if !res.trusts(hop) {
			return Client{addr: hop}, nil
		}
	}
	return Client{addr: current}, nil
}

func (res *Resolver) trusts(a netip.Addr) bool {
	for _, p := range res.policy.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (res *Resolver) warn(r *http.Request) {
	if res.sink == nil {
		return
	}
	res.warned.Do(func() {
		_ = audit.Emit(r.Context(), res.sink, event.ProxyHeadersIgnored, audit.Scope{}, audit.Detail{Reason: "direct_clients"}, nil)
	})
}

func forwardedFor(r *http.Request) []string {
	var out []string
	for _, line := range r.Header.Values(headerForwardedFor) {
		for part := range strings.SplitSeq(line, ",") {
			if s := strings.TrimSpace(part); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func parseHost(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return clean(ap.Addr())
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return clean(a)
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return clean(a)
		}
	}
	return netip.Addr{}, false
}

func clean(a netip.Addr) (netip.Addr, bool) {
	a = a.Unmap().WithZone("")
	return a, a.IsValid() && !a.IsUnspecified()
}
