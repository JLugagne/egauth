# oauth — OAuth2 / OIDC (PKCE-S256, id_token/nonce/JWKS)

import: `github.com/JLugagne/egauth/oauth`
providers: `github.com/JLugagne/egauth/oauth/providers`
source: `oauth/*.go`, `oauth/providers/*.go`

## Purpose

Authorization-code + PKCE-S256 flow exposed as composable HTTP handler builders. OIDC mode (opt-in per provider via `WithOIDC`) adds id_token signature verification against JWKS, nonce replay protection, and claim-derived `UserInfo`. State cookie carries CSRF token + PKCE verifier + nonce + provider + tenant, binding the in-flight attempt to the exact provider/tenant pair that started it (prevents cross-provider/cross-tenant state reuse). SSRF guard on all server-side fetches (discovery, token, JWKS). Pairs with `identity.Service` for JIT account linking/provisioning.

## Core types

```go
// Normalized identity returned by any provider after a successful exchange.
type UserInfo struct {
    ProviderID    string // stable "sub" / numeric id / snowflake; never changes
    Email         string
    EmailVerified bool
    Name          string
}

// Provider is a configured OAuth2 authorization-code provider.
// Constructed via New or a providers.* helper; not directly instantiated.
type Provider struct { /* unexported fields */ }

func (p *Provider) Name() string
func (p *Provider) AuthCodeURL(state, redirectURI, codeChallenge string, opts ...AuthCodeOption) string
func (p *Provider) Exchange(ctx context.Context, code, redirectURI, codeVerifier string, opts ...ExchangeOption) (*UserInfo, error)

// OIDCConfig enables id_token validation for a Provider (pass via WithOIDC).
type OIDCConfig struct {
    Issuer            string            // required; exact "iss" match
    JWKSURL           string            // optional override; host must match issuer host
    Audience          string            // defaults to clientID
    AllowedAlgs       []string          // default: RS256/384/512, ES256/384/512; "none"/HMAC always rejected
    Leeway            time.Duration     // clock skew tolerance (default 1m)
    ClaimsMapper      func(map[string]any) (*UserInfo, error) // default: OIDC standard claims
    HTTPClient        *http.Client      // default: 10s-timeout; use SafeHTTPClient() on untrusted path
    AllowInsecureURLs bool              // dev-only; never set in production
}

// ProviderStore — multi-tenant dynamic provider resolution.
type ProviderStore interface {
    GetProvider(ctx context.Context, tenantID, providerName string) (*Provider, error)
}

// MemoryStore is a thread-safe in-memory ProviderStore.
type MemoryStore struct { /* unexported */ }
func NewMemoryStore() *MemoryStore
func (m *MemoryStore) AddProvider(tenantID string, p *Provider) // tenantID="" → global/single-tenant
func (m *MemoryStore) GetProvider(ctx context.Context, tenantID, providerName string) (*Provider, error)

// IdentityLinker — narrow interface satisfied by identity.Service.
type IdentityLinker interface {
    LinkOrCreateIdentity(ctx context.Context, tenantID string, provider, providerID, email string, emailVerified bool) (*identity.User, error)
}

// FetchUserFunc — custom userinfo fetcher for oauth.New.
type FetchUserFunc func(ctx context.Context, client *http.Client, accessToken string) (*UserInfo, error)
```

## Provider constructor

```go
// New builds a Provider for any RFC 6749 authorization-code provider.
func New(
    name, clientID, clientSecret, authURL, tokenURL string,
    scopes []string,
    fetch FetchUserFunc,
    opts ...ProviderOption,
) *Provider
```

### ProviderOption

```go
WithScopes(scopes ...string) ProviderOption         // override default scopes
WithHTTPClient(c *http.Client) ProviderOption       // custom transport / test stub
WithOIDC(cfg OIDCConfig) ProviderOption             // enable OIDC id_token validation
WithInsecureURLs() ProviderOption                   // dev-only: allow http endpoints
```

### AuthCodeOption / ExchangeOption

```go
WithAuthNonce(nonce string) AuthCodeOption          // set automatically by BeginHandler for OIDC
WithExpectedNonce(nonce string) ExchangeOption      // set automatically by CallbackHandler for OIDC
```

## HTTP handlers

All handlers are `http.HandlerFunc` values — attach to any mux.

```go
// Begin: mints CSRF state + PKCE verifier (+ nonce for OIDC), stores in state cookie,
// redirects browser → provider authorization endpoint (HTTP 302).
func BeginHandler(p *Provider, opts ...HandlerOption) http.HandlerFunc

// Callback: validates state cookie (CSRF + provider/tenant binding), exchanges code (PKCE),
// fetches/verifies UserInfo, links/JIT-provisions identity, issues access+refresh token pair
// as auth cookies. On success: 204 No Content (or 303 if WithSuccessRedirect). State cookie
// always cleared regardless of outcome.
func CallbackHandler[C any](
    p *Provider,
    linker IdentityLinker,
    issuer tokens.Issuer[C],
    claimsOf identity.ClaimsBuilder[C],
    opts ...HandlerOption,
) http.HandlerFunc

// Dynamic variants resolve Provider from ProviderStore at request time (multi-tenant SSO).
func DynamicBeginHandler(store ProviderStore, providerName string, opts ...HandlerOption) http.HandlerFunc
func DynamicCallbackHandler[C any](store ProviderStore, providerName string, linker IdentityLinker, issuer tokens.Issuer[C], claimsOf identity.ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc
```

Callback query params read: `state` (CSRF), `code` (authorization code), `error` (provider-reported denial).

### HandlerOption

```go
WithCookies(c tokens.Cookies) HandlerOption                 // replace auth-cookie config wholesale (validated at construction)
WithCookieDomain(domain string) HandlerOption               // scope cookies to domain; demotes __Host- names to __Secure-
WithSameSite(mode http.SameSite) HandlerOption              // override SameSite on auth cookies
WithInsecureCookies() HandlerOption                         // dev-only: disable Secure attribute; demotes names to bare form
WithRedirectURL(rawURL string) HandlerOption                // explicit redirect_uri (required in prod)
WithStateCookieName(name string) HandlerOption              // default: "oauth_state"
WithStateTTL(d time.Duration) HandlerOption                 // default: 10m
WithoutPKCE() HandlerOption                                 // disable PKCE (non-compliant providers only)
WithSuccessRedirect(url string) HandlerOption               // 303 redirect on success instead of 204
WithFailureRedirect(url string) HandlerOption               // 303 redirect on failure with ?error=<code>
WithPersistentRefresh() HandlerOption                       // persistent refresh cookie ("remember me")
WithTenantResolver(f func(*http.Request) string) HandlerOption // derive tenantID from request
WithAllowUnverifiedEmail() HandlerOption                    // allow unverified emails (off by default)
```

State cookie: `HttpOnly`, `Secure` (unless `WithInsecureCookies`), `SameSite=Lax` (fixed — Strict breaks provider redirect).

## SSRF guard

```go
// Registration-time: rejects non-https, empty host, literal internal/loopback/RFC1918/link-local IPs.
func ValidateExternalURL(rawURL string) error

// Validated for OIDC endpoint URLs (issuer, token, auth, JWKS); allowInsecure for dev.
func ValidateOIDCEndpointURL(rawURL string, allowInsecure bool) error

// Hardened *http.Client for tenant-supplied URLs: dial-time IP guard (DNS-rebinding safe),
// blocks loopback/link-local/RFC1918/RFC6598/multicast/unspecified, Proxy=nil (env proxies ignored).
func SafeHTTPClient() *http.Client

// Utility for custom provider userinfo fetchers: bearer-auth GET with bounded response (1MiB).
func GetJSON(ctx context.Context, c *http.Client, rawURL, accessToken string, dst any) error
```

Blocked ranges: loopback, link-local unicast/multicast (`169.254.0.0/16` — covers cloud metadata `169.254.169.254`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), RFC6598 CGN (`100.64.0.0/10`), unspecified, multicast, IPv6 unique-local (`fc00::/7`).

## Errors

```go
var ErrExchangeFailed   = errors.New("oauth: authorization code exchange failed")
var ErrUserInfoFailed   = errors.New("oauth: fetching user info failed")
var ErrIDTokenInvalid   = errors.New("oauth: id_token validation failed")
var ErrNonceMismatch    = errors.New("oauth: id_token nonce mismatch")
var ErrBlockedURL       = errors.New("oauth: blocked URL")           // ValidateExternalURL
var ErrBlockedAddress   = errors.New("oauth: blocked address (SSRF guard)")  // SafeHTTPClient dial
var ErrJWKSHostMismatch = errors.New("oauth: JWKS source does not match issuer")
var ErrProviderNotFound = errors.New("oauth: provider not found")    // ProviderStore
```

Callback failure codes (query param when `WithFailureRedirect`): `invalid_state`, `state_mismatch`, `provider_mismatch`, `tenant_mismatch`, `access_denied`, `missing_code`, `exchange_failed`, `email_missing`, `email_unverified`, `account_exists`, `link_failed`, `token_issuance_failed`, `provider_not_found`.

## Providers (oauth/providers)

All constructors return `*oauth.Provider`. OIDC id_token validation is opt-in via `oauth.WithOIDC`; the issuer/JWKS constants/helpers below are provided for that purpose.

```go
// Apple — Sign in with Apple (OIDC, no userinfo endpoint; id_token mandatory)
func Apple(servicesID, clientSecretJWT string, opts ...oauth.ProviderOption) *oauth.Provider
// client secret is a short-lived ES256-signed JWT (not a static string); regenerate before expiry.
// WithOIDC with Audience: servicesID is mandatory — no userinfo endpoint exists.
const AppleIssuer  = "https://appleid.apple.com"
const AppleJWKSURL = "https://appleid.apple.com/auth/keys"

// Auth0
func Auth0(domain, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider
func Auth0Issuer(domain string) string   // includes trailing slash required by Auth0 "iss"
func Auth0JWKSURL(domain string) string

// Amazon Cognito
func Cognito(hostedUIDomain, region, userPoolID, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider
func CognitoIssuer(region, userPoolID string) string
func CognitoJWKSURL(region, userPoolID string) string

// Discord
func Discord(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider

// Facebook (OAuth2 only; EmailVerified always false)
func Facebook(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider

// GitHub
func GitHub(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider

// GitLab.com
func GitLab(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider
const GitLabIssuer  = "https://gitlab.com"
const GitLabJWKSURL = "https://gitlab.com/oauth/discovery/keys"

// GitLab self-hosted
func GitLabSelfHosted(baseURL, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider

// Google
func Google(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider
const GoogleIssuer  = "https://accounts.google.com"
const GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// Keycloak
func Keycloak(baseURL, realm, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider
func KeycloakIssuer(baseURL, realm string) string
func KeycloakJWKSURL(baseURL, realm string) string

// LinkedIn (OIDC)
func LinkedIn(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider
const LinkedInIssuer  = "https://www.linkedin.com/oauth"
const LinkedInJWKSURL = "https://www.linkedin.com/oauth/openid/jwks"

// Microsoft (Entra ID / Azure AD)
func Microsoft(tenant, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider
const MicrosoftTenantCommon        = "common"        // personal + work/school
const MicrosoftTenantOrganizations = "organizations" // work/school only
const MicrosoftTenantConsumers     = "consumers"     // personal only
const MicrosoftIssuerFmt  = "https://login.microsoftonline.com/%s/v2.0"  // fmt.Sprintf with tenant
const MicrosoftJWKSURLFmt = "https://login.microsoftonline.com/%s/discovery/v2.0/keys"

// Okta (org authorization server)
func Okta(domain, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider
func OktaIssuer(domain string) string
func OktaJWKSURL(domain string) string

// Okta custom authorization server (e.g. "default")
func OktaCustom(domain, authServerID, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider
func OktaCustomIssuer(domain, authServerID string) string
func OktaCustomJWKSURL(domain, authServerID string) string

// Generic OIDC — any standards-compliant issuer (Zitadel, Ping, OneLogin, Dex, …)
// Performs discovery synchronously at construction; errors deferred to first use.
// Do NOT call per-request; build once at startup or memoize in ProviderStore.
func OIDC(ctx context.Context, issuer, clientID, clientSecret string,
    providerOpts []oauth.ProviderOption, opts ...OIDCOption) *oauth.Provider

type OIDCOption func(*oidcSettings)
func WithDiscoveryHTTPClient(c *http.Client) OIDCOption  // use SafeHTTPClient() on untrusted path
func WithInsecureDiscoveryURLs() OIDCOption              // dev-only
func WithOIDCScopes(scopes ...string) OIDCOption         // default: {"openid","email","profile"}
func WithProviderName(name string) OIDCOption            // default: "oidc"; set stable key for identity linking
```

## Wiring

```go
import (
    "github.com/JLugagne/egauth/identity"
    "github.com/JLugagne/egauth/oauth"
    "github.com/JLugagne/egauth/oauth/providers"
    "github.com/JLugagne/egauth/tokens"
)

// 1. Build provider (OIDC id_token validation optional but recommended)
p := providers.Google(clientID, clientSecret,
    oauth.WithOIDC(oauth.OIDCConfig{
        Issuer:  providers.GoogleIssuer,
        JWKSURL: providers.GoogleJWKSURL,
    }),
)

// 2. Wire identity service (implements IdentityLinker)
identSvc := identity.NewService(db)

// 3. Wire token issuer
tokenIssuer := tokens.NewIssuer[MyClaims](signingKey)

// 4. Register handlers
mux.Handle("GET /auth/google", oauth.BeginHandler(p,
    oauth.WithRedirectURL("https://example.com/auth/google/callback"),
))
mux.Handle("GET /auth/google/callback", oauth.CallbackHandler(p, identSvc, tokenIssuer, MakeClaimsFunc,
    oauth.WithRedirectURL("https://example.com/auth/google/callback"),
    oauth.WithSuccessRedirect("/dashboard"),
    oauth.WithFailureRedirect("/login"),
))

// Multi-tenant dynamic variant
store := oauth.NewMemoryStore()
store.AddProvider("tenant-abc", p)
mux.Handle("GET /auth/google", oauth.DynamicBeginHandler(store, "google",
    oauth.WithTenantResolver(func(r *http.Request) string { return r.PathValue("tenant") }),
    oauth.WithRedirectURL("https://example.com/auth/google/callback"),
))
```

## Security notes

- **PKCE-S256**: on by default for all providers; disable only with `WithoutPKCE` for non-compliant providers.
- **State CSRF binding**: state cookie packs `state + PKCE verifier + nonce + provider + tenant`; callback verifies all five fields with constant-time comparison.
- **State cookie is opaque, NOT signed/encrypted**: it is a plain concatenation; the PKCE verifier and OIDC nonce sit in it **in plaintext**. Integrity model is "attacker can't read/write the cookie" (`HttpOnly` + `Secure` + `SameSite=Lax`), not tamper-evidence. Consumer must **never log/mirror request cookies** (the verifier/nonce would leak), and must re-derive the guarantee if moving `state` off the cookie (server-side handle, header, different prefix). Default name `oauth_state` is **not** `__Host-` prefixed (unlike tokens/sessions cookies); for subdomain cookie-tossing defence set `WithStateCookieName("__Host-oauth_state")` when serving over HTTPS with no cookie `Domain`.
- **Nonce replay**: nonce minted per flow (32 random bytes), bound in state cookie, verified against id_token `nonce` claim; single-use (state cookie cleared on any callback outcome).
- **JWKS id_token verification**: signature checked against issuer's JWKS; JWKS host must match issuer host (`ErrJWKSHostMismatch`); `"none"` and HMAC algs always rejected.
- **SSRF**: two-layer guard — `ValidateExternalURL` at registration time (https, no literal internal IP), `SafeHTTPClient` at dial time (post-DNS-resolution, DNS-rebinding-proof); env proxies ignored.
- **Unverified email**: rejected by default (`WithAllowUnverifiedEmail` to opt in); prevents account squatting.
- **Deferred config errors**: invalid provider config (non-https endpoint, bad OIDC config) is recorded at construction and surfaced on first use; never panics (safe for dynamic `ProviderStore` over tenant-controlled data).
- **Apple**: no userinfo endpoint — `WithOIDC` is mandatory, not optional.
- **Facebook**: no email-verified signal; `UserInfo.EmailVerified` is always `false`.

## Gotchas

- `WithRedirectURL` must be set explicitly in production and must be identical on `BeginHandler` and `CallbackHandler`; the fallback (derived from request) is only reliable for the callback handler.
- State cookie and nonce are single-use; do not retry the callback on the same cookie.
- For self-hosted issuers (Keycloak, GitLab self-hosted, Cognito), add the base URL / issuer to `SafeHTTPClient`'s SSRF allowlist by supplying a non-safe client via `oauth.WithHTTPClient` only if the issuer is on an internal host — otherwise `SafeHTTPClient` will block it.
- `providers.OIDC` performs network I/O at construction; build once at startup (or memoize in `ProviderStore`), never per request.
- Multi-tenant providers: use `WithTenantResolver` on both `Begin` and `Callback` handlers to bind the in-flight flow to the correct tenant; mismatch returns `tenant_mismatch`.
- Microsoft `"common"` / `"organizations"` tenants: the id_token `iss` contains the caller's home tenant GUID, not the literal `"common"` — prefer a specific tenant GUID for issuer validation.
- Auth0 issuer has a trailing slash in the `"iss"` claim; use `providers.Auth0Issuer(domain)`, not a manually constructed string.
- Apple client secret is a short-lived ES256-signed JWT; regenerate before it expires (Apple does not issue a static secret).
