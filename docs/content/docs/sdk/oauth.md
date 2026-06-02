---
title: "OAuth and OIDC"
weight: 5
---

# OAuth 2.0 and OIDC (Social Login)

The `oauth` module provides out-of-the-box support for external identity providers like Google, GitHub, and Discord, adhering to OAuth 2.1 best practices.

## Configuring a Provider

There is no central OAuth service to register. Instead, you build a `*oauth.Provider` directly for each provider you want to support. Each constructor takes only the client ID and client secret (plus functional options). `egauth` implements Proof Key for Code Exchange (PKCE) natively and uses state cookies to prevent CSRF.

```go
import "github.com/JLugagne/egauth/oauth"

google := oauth.Google("google-client-id", "google-client-secret")

github := oauth.GitHub("github-client-id", "github-client-secret")

discord := oauth.Discord("discord-client-id", "discord-client-secret")
```

The redirect/callback URL is **not** a constructor argument. It is configured on the handler via the `oauth.WithRedirectURL(...)` option (see below). You may also pass `oauth.WithScopes(...)` or `oauth.WithHTTPClient(...)` to the constructor.

### OIDC

Any provider can be upgraded to a full OpenID Connect provider with ID-token verification by passing `oauth.WithOIDC(...)`:

```go
google := oauth.Google("client-id", "client-secret",
	oauth.WithOIDC(oauth.OIDCConfig{
		Issuer:   "https://accounts.google.com",
		JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
		Audience: "google-client-id",
	}),
)
```

`OIDCConfig` also accepts `AllowedAlgs`, `Leeway`, a custom `ClaimsMapper`, and an `HTTPClient`. By default discovery and JWKS fetches require HTTPS; see [Security Hardening]({{< ref "security-hardening" >}}) for the URL/SSRF enforcement details.

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
store.AddProvider("tenant-123", oauth.Google("client-id", "client-secret"))

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
