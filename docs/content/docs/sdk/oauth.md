---
title: "OAuth and OIDC"
weight: 5
---

# OAuth 2.0 and OIDC (Social Login)

The `oauth` module provides out-of-the-box support for external identity providers — Google, GitHub, Discord, Microsoft (Entra ID), Apple, GitLab, LinkedIn, Facebook, Okta, Auth0, Keycloak and AWS Cognito — adhering to OAuth 2.1 best practices. Any other compliant OIDC issuer works via `providers.OIDC` (discovery), and any OAuth2 provider is a one-liner with `oauth.New`.

## Configuring a Provider

There is no central OAuth service to register. Instead, you build a `*oauth.Provider` directly for each provider you want to support. The ready-made constructors live in the `oauth/providers` subpackage, keeping the core `oauth` package free of provider-specific endpoints. Each constructor takes only the client ID and client secret (plus functional options). `egauth` implements Proof Key for Code Exchange (PKCE) natively and uses state cookies to prevent CSRF.

```go
import (
	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/oauth/providers"
)

google := providers.Google("google-client-id", "google-client-secret")

github := providers.GitHub("github-client-id", "github-client-secret")

discord := providers.Discord("discord-client-id", "discord-client-secret")
```

All constructors return a `*oauth.Provider`, so the handler and store APIs below are unchanged. To support a provider that does not ship with `egauth`, build your own `*oauth.Provider` with `oauth.New(...)` and a fetch func built on `oauth.GetJSON(...)`.

The redirect/callback URL is **not** a constructor argument. It is configured on the handler via the `oauth.WithRedirectURL(...)` option (see below). You may also pass `oauth.WithScopes(...)` or `oauth.WithHTTPClient(...)` to the constructor.

### OIDC

Any provider can be upgraded to a full OpenID Connect provider with ID-token verification by passing `oauth.WithOIDC(...)`:

```go
google := providers.Google("client-id", "client-secret",
	oauth.WithOIDC(oauth.OIDCConfig{
		Issuer:   providers.GoogleIssuer,
		JWKSURL:  providers.GoogleJWKSURL,
		Audience: "google-client-id",
	}),
)
```

`OIDCConfig` also accepts `AllowedAlgs`, `Leeway`, a custom `ClaimsMapper`, and an `HTTPClient`. By default discovery and JWKS fetches require HTTPS; see [Security Hardening]({{< ref "security-hardening" >}}) for the URL/SSRF enforcement details.

### Built-in providers

All constructors live in `oauth/providers`, take `(clientID, clientSecret, ...oauth.ProviderOption)`, and return a `*oauth.Provider`. OIDC providers also export `…Issuer` / `…JWKSURL` constants for `oauth.WithOIDC`.

| Constructor | Type | Issuer / JWKS constants | Notes |
| --- | --- | --- | --- |
| `providers.Google` | OIDC | `GoogleIssuer`, `GoogleJWKSURL` | |
| `providers.GitHub` | OAuth2 | — | Resolves the primary verified email from `/user/emails`. |
| `providers.Discord` | OAuth2 | — | |
| `providers.Microsoft` | OIDC | `MicrosoftIssuerFmt`, `MicrosoftJWKSURLFmt` | First arg is the **tenant** (`MicrosoftTenantCommon`, `…Organizations`, `…Consumers`, or a directory GUID / verified domain). Issuer/JWKS are `fmt.Sprintf`-formatted with the same tenant. |
| `providers.Apple` | OIDC | `AppleIssuer`, `AppleJWKSURL` | **Must** be used with `oauth.WithOIDC` (no userinfo endpoint). The "client secret" is a short-lived ES256-signed JWT you generate from your `.p8` key. The user's name is only sent on first authorization — persist it then. |
| `providers.GitLab` | OIDC | `GitLabIssuer`, `GitLabJWKSURL` | For self-managed instances use `providers.GitLabSelfHosted(baseURL, …)`. |
| `providers.LinkedIn` | OIDC | `LinkedInIssuer`, `LinkedInJWKSURL` | "Sign In with LinkedIn using OpenID Connect". |
| `providers.Facebook` | OAuth2 | — | Resolves the user from the Graph `/me` endpoint; Facebook exposes no email-verified signal, so `EmailVerified` is always `false`. |
| `providers.Okta` / `providers.OktaCustom` | OIDC | `OktaIssuer`/`OktaJWKSURL` (org), `OktaCustomIssuer`/`OktaCustomJWKSURL` | First arg is your Okta **domain**. `Okta` targets the org authorization server (`/oauth2/v1`); `OktaCustom(domain, authServerID, …)` targets a custom server (commonly `"default"`). |
| `providers.Auth0` | OIDC | `Auth0Issuer(domain)`, `Auth0JWKSURL(domain)` | First arg is your Auth0 **domain**. `Auth0Issuer` returns the issuer **with the trailing slash** Auth0 puts in the `iss` claim. |
| `providers.Keycloak` | OIDC | `KeycloakIssuer(base, realm)`, `KeycloakJWKSURL(base, realm)` | Args are the server **base URL** and **realm**. Endpoints live under `/realms/{realm}/protocol/openid-connect`. |
| `providers.Cognito` | OIDC | `CognitoIssuer(region, poolID)`, `CognitoJWKSURL(region, poolID)` | Args are the hosted-UI **domain**, **region**, and **user-pool ID**. OAuth endpoints are on the hosted-UI domain; the issuer/JWKS are on the `cognito-idp` host. |
| `providers.OIDC` | OIDC | (use the issuer you pass in) | Universal helper for any compliant IdP (Zitadel, Ping, OneLogin, Dex, …). Resolves endpoints from `{issuer}/.well-known/openid-configuration` at construction. See below. |

Microsoft example with id_token validation:

```go
import "fmt"

tenant := providers.MicrosoftTenantOrganizations
ms := providers.Microsoft(tenant, "client-id", "client-secret",
	oauth.WithOIDC(oauth.OIDCConfig{
		Issuer:   fmt.Sprintf(providers.MicrosoftIssuerFmt, tenant),
		JWKSURL:  fmt.Sprintf(providers.MicrosoftJWKSURLFmt, tenant),
		Audience: "client-id",
	}),
)
```

Per-tenant IdP example (Okta, Auth0, Keycloak, Cognito all follow this shape — a domain/base-URL argument plus matching `…Issuer` / `…JWKSURL` helpers):

```go
auth0 := providers.Auth0("your-tenant.us.auth0.com", "client-id", "client-secret",
	oauth.WithOIDC(oauth.OIDCConfig{
		Issuer:  providers.Auth0Issuer("your-tenant.us.auth0.com"),
		JWKSURL: providers.Auth0JWKSURL("your-tenant.us.auth0.com"),
	}),
)
```

### Any other OIDC issuer (discovery)

For a compliant IdP without a dedicated constructor (Zitadel, Ping, OneLogin, Dex, …), `providers.OIDC` resolves the authorize/token/userinfo endpoints from the issuer's discovery document at construction. It takes a `context.Context` (the discovery fetch is a network call — build the provider **once** at startup, not per request) and the `oauth.ProviderOption`s to apply to the resulting provider. You can leave `OIDCConfig.JWKSURL` empty and let the verifier discover `jwks_uri` itself:

```go
issuer := "https://idp.example.com"
p := providers.OIDC(ctx, issuer, "client-id", "client-secret",
	[]oauth.ProviderOption{
		oauth.WithOIDC(oauth.OIDCConfig{Issuer: issuer}),
	},
	providers.WithProviderName("example-idp"),
)
```

If discovery fails, the error is deferred (like an invalid endpoint passed to `oauth.New`) and surfaces on the first `AuthCodeURL`/`Exchange` call rather than panicking. On an untrusted/dynamic path, pass `providers.WithDiscoveryHTTPClient(oauth.SafeHTTPClient())`.

## The OAuth Flow

Because `egauth` is unopinionated about routing, it provides `http.HandlerFunc` factories that you attach to your router.

### 1. Begin the Flow

Mount `BeginHandler` to initiate the redirect to the provider. The handler sets a secure, `HttpOnly` CSRF state cookie. PKCE is on by default (pass `oauth.WithoutPKCE()` only for a provider that rejects it).

```go
// e.g. GET /auth/google/login
mux.Handle("/auth/google/login", oauth.BeginHandler(google,
	oauth.WithRedirectURL("https://yourapp.com/auth/google/callback"),
))
```

### 2. Handle the Callback

Mount `CallbackHandler` to receive the redirect from the provider. It exchanges the code, verifies the state cookie (and, for OIDC, the ID token), and fetches the user's profile.

`CallbackHandler` is generic over your custom claim type `C`. Rather than a bare callback, it takes three collaborators:

- a `linker oauth.IdentityLinker` — resolves the local user behind the external identity. Its single method is `LinkOrCreateIdentity(ctx, tenantID, provider, providerID, email string, emailVerified bool) (*identity.User, error)`. The `identity.Service` satisfies this interface.
- an `issuer tokens.Issuer[C]` — mints the token pair for the resolved user.
- a `claimsOf identity.ClaimsBuilder[C]` — `func(*identity.User) tokens.Claims[C]`, mapping the user to the claims embedded in the issued tokens.

```go
// e.g. GET /auth/google/callback
callback := oauth.CallbackHandler(
	google,
	identitySvc, // satisfies oauth.IdentityLinker via LinkOrCreateIdentity
	issuer,      // your tokens.Issuer[C]
	func(u *identity.User) tokens.Claims[C] {
		return tokens.Claims[C]{
			Subject:  u.ID,
			TenantID: u.TenantID,
			// leave ExpiresAt zero so the issuer's access TTL applies
		}
	},
	oauth.WithRedirectURL("https://yourapp.com/auth/google/callback"),
	oauth.WithSuccessRedirect("/dashboard"),
	oauth.WithFailureRedirect("/login?error=oauth"),
)

mux.Handle("/auth/google/callback", callback)
```

Useful handler options include `WithRedirectURL`, `WithSuccessRedirect`, `WithFailureRedirect`, `WithCookies`, `WithCookieDomain`, `WithSameSite`, `WithStateTTL`, `WithTenantResolver`, `WithAllowUnverifiedEmail`, and `WithoutPKCE`.

## Multi-Tenant (Bring Your Own SSO)

For applications where each tenant configures its own provider, use the dynamic handlers. They resolve a `*oauth.Provider` at request time from an `oauth.ProviderStore` (whose single method is `GetProvider(ctx, tenantID, providerName string) (*oauth.Provider, error)`). The package ships an in-memory implementation via `oauth.NewMemoryStore()`.

```go
store := oauth.NewMemoryStore()
store.AddProvider("tenant-123", providers.Google("client-id", "client-secret"))

mux.Handle("/auth/sso/login", oauth.DynamicBeginHandler(store, "google",
	oauth.WithRedirectURL("https://yourapp.com/auth/sso/callback"),
))

mux.Handle("/auth/sso/callback", oauth.DynamicCallbackHandler(
	store, "google",
	identitySvc, // oauth.IdentityLinker
	issuer,      // tokens.Issuer[C]
	func(u *identity.User) tokens.Claims[C] {
		return tokens.Claims[C]{Subject: u.ID, TenantID: u.TenantID}
	},
	oauth.WithRedirectURL("https://yourapp.com/auth/sso/callback"),
))
```

The state cookie is bound to the resolving provider and tenant. See [Security Hardening]({{< ref "security-hardening" >}}) for the binding and discovery hardening.
