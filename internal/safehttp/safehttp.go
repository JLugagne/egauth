// Package safehttp provides the hardened HTTP client used for every server-side fetch of a URL the
// process does not fully control.
//
// The threat is the same wherever the URL comes from: an OAuth provider or issuer URL supplied by a
// tenant (bring-your-own-SSO), a self-hosted breach-check mirror, or any future outbound call. A
// request to such a URL must not be able to reach the host's own network, and must not be silently
// redirected into it. Centralising the transport keeps one implementation of that policy rather than
// one per caller — which is how the breach-check client came to have no guard at all while the OAuth
// client had a carefully built one.
package safehttp

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlockedAddress is the dial-time error returned when a connection resolves to a disallowed IP
// range.
var ErrBlockedAddress = fmt.Errorf("safehttp: blocked address (SSRF guard)")

// blockedPrefixes are the address ranges a server-side fetch of a tenant-supplied URL must never
// reach. The list is expressed as prefixes rather than as calls into net.IP's classification
// helpers because the helpers normalise an address in exactly one way: To4 only recognises the
// IPv4-MAPPED form (::ffff:a.b.c.d), so an IPv4 address embedded in any other IPv6 layout fell
// through every branch and was reported as public. The affected literal forms are
// IPv4-COMPATIBLE (::7f00:1, covered by ::/96), IPv4-TRANSLATED (::ffff:0:7f00:1) and RFC 6052
// NAT64 (64:ff9b::7f00:1) — the last of which a NAT64/DNS64 network translates back to IPv4,
// exactly where the cloud metadata endpoint is reachable.
var blockedPrefixes = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network", incl. 0.0.0.1
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC6598 CGNAT / shared address space
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local, incl. 169.254.169.254 metadata
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. 255.255.255.255

	// IPv6
	netip.MustParsePrefix("::/128"),          // unspecified
	netip.MustParsePrefix("::1/128"),         // loopback
	netip.MustParsePrefix("::/96"),           // IPv4-COMPATIBLE (deprecated; ::7f00:1 is 127.0.0.1)
	netip.MustParsePrefix("::ffff:0:0/96"),   // IPv4-mapped
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4-translated (SIIT)
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),  // NAT64 local-use prefix
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("fc00::/7"),        // unique-local
	netip.MustParsePrefix("fe80::/10"),       // link-local
	netip.MustParsePrefix("ff00::/8"),        // multicast
}

// nat64Prefixes are the RFC 6052 well-known and local-use translation prefixes. An address inside
// one of them carries an IPv4 address in its low 32 bits, so the EMBEDDED address has to be
// classified too: a NAT64 network translates 64:ff9b::a9fe:a9fe back to 169.254.169.254, which
// would otherwise be a documented-looking IPv6 address that reaches the metadata service.
var nat64Prefixes = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// isBlockedAddr reports whether a single address is in a blocked prefix.
func isBlockedAddr(addr netip.Addr) bool {
	for i := range blockedPrefixes {
		if blockedPrefixes[i].Contains(addr) {
			return true
		}
	}
	return false
}

// embeddedIPv4 extracts the IPv4 address embedded in a NAT64 address, per RFC 6052 §2.2.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	for i := range nat64Prefixes {
		if !nat64Prefixes[i].Contains(addr) {
			continue
		}
		b := addr.As16()
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// Client returns an *http.Client that refuses to connect to an internal address and refuses to
// follow redirects.
//
// The transport dials through a net.Dialer whose Control hook rejects internal IP ranges, evaluated
// against the resolved address at dial time. That placement is what defeats DNS rebinding: a name
// that resolved to a public address when the URL was validated is re-checked when the connection is
// actually made.
//
// Proxy is deliberately nil. Honouring HTTP(S)_PROXY would make the Control hook inspect the
// PROXY's address rather than the resolved target, letting a caller route around the guard.
//
// Redirects are never followed: a server that answers 3xx would otherwise choose the next hop, which
// is how a fetch of a validated public URL reaches the metadata endpoint.
//
// timeout bounds the whole request, including body read.
func Client(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialControl,
	}
	transport := &http.Transport{
		// Proxy is intentionally nil: env proxies are not trusted, so the dial-time guard always
		// sees the resolved target rather than a proxy's address.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NoRedirect clones an existing client with redirect following disabled, so a caller-supplied client
// inherits the one property that must not be configurable. The dial-time guard cannot be preserved
// this way — a custom transport is the caller's choice — but redirects are the hop an attacker
// controls from the far end.
func NoRedirect(c *http.Client) *http.Client {
	if c == nil {
		return Client(0)
	}
	clone := *c
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

// IsBlockedIP reports whether ip falls in a range that must never be reached by a server-side fetch.
// It classifies the address itself and, for a NAT64-embedded address, the IPv4 address it carries.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		// An address shape netip cannot represent is not one to connect to.
		return true
	}
	addr = addr.Unmap()
	if isBlockedAddr(addr) {
		return true
	}
	if embedded, ok := embeddedIPv4(addr); ok {
		return isBlockedAddr(embedded)
	}
	return false
}

// DialControlForTest exposes the dial-time guard so the classification table can be asserted
// directly rather than inferred from a dial failure.
func DialControlForTest(network, address string) error { return dialControl(network, address, nil) }

// dialControl is the net.Dialer.Control hook. It runs after DNS resolution with the concrete address
// the OS is about to connect to, so it sees through DNS rebinding.
func dialControl(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("%w: network %q not allowed", ErrBlockedAddress, network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBlockedAddress, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: unresolvable address %q", ErrBlockedAddress, host)
	}
	if IsBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
	}
	return nil
}
