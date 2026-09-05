package oauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// SSRF hardening for server-side fetches against tenant-supplied URLs.
//
// The dynamic, multi-tenant ProviderStore (oauth/pgx) lets an integrator expose OIDC provider
// registration to (potentially untrusted) tenants — "bring-your-own-SSO". The issuer / token /
// JWKS / auth URLs are then fetched server-side: the JWKS endpoint to verify id_token
// signatures and the token endpoint during the code exchange (which carries the client_secret).
// Without validation, an attacker could register a provider pointing at the cloud metadata
// endpoint (169.254.169.254), localhost, or an internal RFC1918 host and trigger SSRF /
// secret exfiltration.
//
// Two layers of defence live here:
//   - ValidateExternalURL: a registration-time check (https scheme, non-empty host, no literal
//     internal/loopback host) used by UpsertProvider.
//   - SafeHTTPClient: a hardened *http.Client whose dialer rejects, at DIAL time (after DNS
//     resolution), any connection to a loopback / link-local / unique-local / private / unspecified
//     / multicast IP. Validating the resolved IP at dial time is what defeats DNS rebinding — a
//     name that resolves to a public IP at registration but to 127.0.0.1 at fetch time is still
//     blocked.

// ErrBlockedURL is returned by ValidateExternalURL when a URL is unusable or targets a
// disallowed (internal) host.
var ErrBlockedURL = errors.New("oauth: blocked URL")

// ErrBlockedAddress is the dial-time error returned by SafeHTTPClient's transport when a
// connection resolves to a disallowed IP range.
var ErrBlockedAddress = errors.New("oauth: blocked address (SSRF guard)")

// ValidateExternalURL validates a tenant-supplied URL that will be fetched server-side.
//
// It requires a non-empty https URL with a host, and rejects URLs whose host is a literal
// internal/loopback/link-local/private IP. It is a coarse, registration-time gate: the
// authoritative protection against DNS rebinding is the dial-time guard in SafeHTTPClient,
// because a hostname's resolution can change between registration and fetch.
func ValidateExternalURL(rawURL string) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("%w: empty URL", ErrBlockedURL)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBlockedURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not allowed (https required)", ErrBlockedURL, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", ErrBlockedURL)
	}
	// If the host is a literal IP, reject internal ranges outright. Hostnames are left to the
	// dial-time guard (which sees the actually-resolved IP and so is rebinding-proof).
	if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("%w: host %q resolves to a disallowed address", ErrBlockedURL, host)
	}
	return nil
}

// SafeHTTPClient returns an *http.Client suitable for fetching tenant-supplied URLs. Its
// transport dials through a net.Dialer whose Control hook rejects connections to internal IP
// ranges, evaluated against the resolved address at dial time (DNS-rebinding safe). It carries a
// 10s timeout to match the package default.
//
// The transport deliberately sets Proxy: nil and does NOT honor HTTP(S)_PROXY from the
// environment. If a proxy were used, the dial-time Control hook would inspect the PROXY's IP
// rather than the resolved target, letting a tenant route around the internal-IP SSRF guard
// (e.g. point a registered OIDC URL through a proxy that reaches 169.254.169.254 or an RFC1918
// host). Ignoring env proxies keeps the dial-time guard authoritative for every fetch.
//
// Operator note: integrators using the dynamic ProviderStore (bring-your-own-SSO) must not run
// these tenant-supplied fetches through a proxy that can reach internal ranges. Because the safe
// client now ignores env proxies, no HTTP(S)_PROXY needs to be unset for it; but any explicit
// proxy added to this transport in the future must apply the same dial-time IP guard to the
// proxy's own resolved address.
func SafeHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   safeDialControl,
	}
	transport := &http.Transport{
		// Proxy is intentionally nil: env proxies (HTTP(S)_PROXY) are not trusted, so the
		// dial-time Control hook always sees the resolved target IP, not a proxy's IP.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// safeDialControl is the net.Dialer.Control hook. It runs after DNS resolution with the concrete
// address the OS is about to connect to, so it sees through DNS rebinding. It rejects any dial to
// a blocked IP range.
func safeDialControl(network, address string, _ syscall.RawConn) error {
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
	if isBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
	}
	return nil
}

// privateIPv4Blocks are the RFC1918 private ranges plus the IPv4 link-local block (which covers
// the cloud metadata endpoint 169.254.169.254).
var privateIPv4Blocks = []net.IPNet{
	mustCIDR("10.0.0.0/8"),
	mustCIDR("172.16.0.0/12"),
	mustCIDR("192.168.0.0/16"),
	mustCIDR("169.254.0.0/16"),
	mustCIDR("100.64.0.0/10"), // RFC6598 carrier-grade NAT / shared address space
}

// isBlockedIP reports whether ip falls in a range that must never be reached by a server-side
// fetch of a tenant-supplied URL: loopback, link-local (incl. cloud metadata), unique-local,
// private (RFC1918 / CGN), unspecified, or multicast.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if ip.IsPrivate() { // covers RFC1918 (IPv4) and fc00::/7 unique-local (IPv6)
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		for i := range privateIPv4Blocks {
			if privateIPv4Blocks[i].Contains(v4) {
				return true
			}
		}
	}
	return false
}

func mustCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("oauth: invalid CIDR " + s + ": " + err.Error())
	}
	return *n
}
