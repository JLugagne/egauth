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

	"github.com/JLugagne/egauth/internal/safehttp"
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
// connection resolves to a disallowed IP range. It is the shared safehttp sentinel, so a caller can
// match it with errors.Is against either name.
var ErrBlockedAddress = safehttp.ErrBlockedAddress

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
// SafeHTTPClient returns an *http.Client suitable for fetching tenant-supplied URLs: it refuses to
// connect to an internal address (evaluated at dial time, so it is DNS-rebinding safe) and never
// follows a redirect. See internal/safehttp for the policy; it is shared with the other outbound
// callers in this module so there is one implementation rather than one per caller.
//
// Proxy is deliberately nil, so HTTP(S)_PROXY cannot route a request around the guard. The client
// carries a 10s timeout.
func SafeHTTPClient() *http.Client { return safehttp.Client(10 * time.Second) }

// isBlockedIP reports whether ip falls in a range that must never be reached by a server-side fetch
// of a tenant-supplied URL.
func isBlockedIP(ip net.IP) bool { return safehttp.IsBlockedIP(ip) }

// safeDialControl exposes the shared dial-time guard to this package's tests.
func safeDialControl(network, address string, _ syscall.RawConn) error {
	return safehttp.DialControlForTest(network, address)
}

func mustCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("oauth: invalid CIDR " + s + ": " + err.Error())
	}
	return *n
}
