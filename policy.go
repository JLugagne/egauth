package egauth

import (
	"net/http"
	"net/netip"
	"slices"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
)

// ProxyPolicy says which peers may set forwarding headers. Build it with DirectClients or
// TrustedProxies.
type ProxyPolicy interface {
	proxy() proxySpec
}

type proxySpec struct {
	set     bool
	trusted []netip.Prefix
}

func (p proxySpec) proxy() proxySpec { return p }

// DirectClients ignores every forwarding header: the client address is the TCP peer.
func DirectClients() ProxyPolicy {
	return proxySpec{set: true}
}

// TrustedProxies reads forwarding headers only from peers inside the prefixes. New rejects a /0,
// an IPv4 prefix shorter than /8, an IPv6 prefix shorter than /16, and an IPv6 prefix covering
// IPv4-compatible addresses or touching the IPv4-mapped or NAT64 ranges: write IPv4 proxies in
// IPv4 form.
func TrustedProxies(first netip.Prefix, more ...netip.Prefix) ProxyPolicy {
	return proxySpec{set: true, trusted: append([]netip.Prefix{first}, more...)}
}

// Tenancy says how a request is mapped to a tenant. Build it with SingleTenant, TenantBySubdomain
// or TenantFromRequest.
type Tenancy interface {
	tenancy() tenancySpec
}

type tenancyKind uint8

const (
	tenancySingle tenancyKind = iota + 1
	tenancySubdomain
	tenancyRequest
)

type tenancySpec struct {
	kind     tenancyKind
	resolver TenantResolver
}

func (t tenancySpec) tenancy() tenancySpec { return t }

// TenantResolver maps a request to its tenant. An error or a zero TenantID makes the request 401,
// with no fallback. It must be safe for concurrent use.
type TenantResolver interface {
	ResolveTenant(r *http.Request) (principal.TenantID, error)
}

// SingleTenant serves the zero TenantID only.
func SingleTenant() Tenancy {
	return tenancySpec{kind: tenancySingle}
}

// TenantBySubdomain takes the tenant from the leftmost host label; PublicOrigin must then hold
// exactly one {tenant} label, as in https://{tenant}.example.com.
func TenantBySubdomain() Tenancy {
	return tenancySpec{kind: tenancySubdomain}
}

// TenantFromRequest delegates tenant resolution to r, for example a header set by a trusted
// gateway. New rejects a nil r.
func TenantFromRequest(r TenantResolver) Tenancy {
	return tenancySpec{kind: tenancyRequest, resolver: r}
}

// SessionBackend selects how sessions are carried. Build it with JWT or Stateful.
type SessionBackend interface {
	backend() backendSpec
}

type backendKind uint8

const (
	backendJWT backendKind = iota + 1
	backendStateful
)

type backendSpec struct {
	kind backendKind
	keys Keys
}

func (b backendSpec) backend() backendSpec { return b }

// JWT carries sessions as short-lived access tokens signed with keys, backed by rotating refresh
// families in Storage.Tokens. New rejects nil keys.
func JWT(keys Keys) SessionBackend {
	return backendSpec{kind: backendJWT, keys: keys}
}

// Stateful carries sessions as opaque handles backed by rows in Storage.Sessions.
func Stateful() SessionBackend {
	return backendSpec{kind: backendStateful}
}

// Keys selects where the JWT signing keys come from: StaticKeys or TenantKeys, never both.
type Keys interface {
	keys() keySpec
}

type keyKind uint8

const (
	keysStatic keyKind = iota + 1
	keysTenant
)

type keySpec struct {
	kind       keyKind
	active     signing.Signer
	verifyOnly []signing.Verifier
}

func (k keySpec) keys() keySpec { return k }

// StaticKeys signs with active and also accepts tokens signed by verifyOnly, for a rotation. Key
// ids must be distinct. An HS256 active key cannot serve resource servers, so New rejects it with
// a non-empty Audiences.
func StaticKeys(active signing.Signer, verifyOnly ...signing.Verifier) Keys {
	return keySpec{kind: keysStatic, active: active, verifyOnly: slices.Clone(verifyOnly)}
}

// TenantKeys takes per-tenant signing keys from Storage.Keys, which New then requires.
func TenantKeys() Keys {
	return keySpec{kind: keysTenant}
}

// AdminPolicy says which session callers may act on other users through the facades. Build it with
// RoleAdmin or SelfServiceOnly.
type AdminPolicy interface {
	admin() adminSpec
}

type adminKind uint8

const (
	adminRole adminKind = iota + 1
	adminSelfOnly
)

type adminSpec struct {
	kind adminKind
	role string
}

func (a adminSpec) admin() adminSpec { return a }

// RoleAdmin lets a session caller whose current AppClaims.Roles holds role act on other users of
// its tenant. New rejects a blank role.
func RoleAdmin(role string) AdminPolicy {
	return adminSpec{kind: adminRole, role: role}
}

// SelfServiceOnly lets no session caller act on another user; only System callers can.
func SelfServiceOnly() AdminPolicy {
	return adminSpec{kind: adminSelfOnly}
}

// Transport selects which credential channels a deployment accepts. A login selects Bearer only
// through HeaderTransport, and only when the deployment allows it.
type Transport uint8

const (
	Cookies Transport = iota + 1
	Bearer
	CookiesAndBearer
)

func (t Transport) valid() bool {
	return t >= Cookies && t <= CookiesAndBearer
}

// OutboundObserver is told about every outbound request (OIDC discovery, token exchange, JWKS,
// breach checks). OutboundStart receives a redacted copy of the request; the returned func, when
// non-nil, is called once with the outcome. A panic in either is recovered and discarded.
type OutboundObserver interface {
	OutboundStart(req *http.Request) func(resp *http.Response, err error)
}
