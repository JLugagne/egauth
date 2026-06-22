---
title: "Tokens and HTTP"
weight: 3
---

# Tokens and HTTP Protection

The `tokens` module manages stateless Access Tokens (JWT) and stateful Refresh Tokens. It incorporates advanced theft-detection mechanics.

## Generating Tokens

`egauth` uses Go Generics to allow you to inject custom claims safely into your JWTs. The JWT issuer lives in the `tokens/jwt` package and is configured through a `jwt.Config[C]` struct.

```go
import (
	"github.com/JLugagne/egauth/tokens"
	jwtissuer "github.com/JLugagne/egauth/tokens/jwt"
)

// Define your custom claims struct
type MyClaims struct {
	Role  string `json:"role"`
	OrgID string `json:"org_id"`
}

// Initialize the Token Service via the Config struct (fields, not options)
tokenService := jwtissuer.New(jwtissuer.Config[MyClaims]{
	Store:            tokensStore,
	Issuer:           "https://auth.example.com",  // stamped at issuance AND verified
	ExpectedAudience: []string{"api.example.com"}, // any-of; verified on the access path
	SecretKey:        "super-secret-32-byte-key-here!!!", // HS256 signing key
	ClaimsProvider:   myClaimsProvider,            // required for Rotate (refresh)
})

// Build a Claims value (it carries the Subject, TenantID and custom data)
// and issue a Token Pair (Access + Refresh).
pair, err := tokenService.IssueTokenPair(ctx, tokens.Claims[MyClaims]{
	Subject:   userID,        // uuid.UUID
	TenantID:  "tenant-123",
	Audiences: []string{"api.example.com"},
	Roles:     []string{"admin"},
	AMR:       []string{tokens.AMRPassword},
	Custom: MyClaims{
		Role:  "admin",
		OrgID: "org-xyz",
	},
})

fmt.Println("Access Token:", pair.AccessToken)
```

> **Security Note:** Refresh tokens are opaque strings. Only their SHA-256 hash (via `tokens.HashToken`) is stored in the database.

`Issuer` and `ExpectedAudience` are verified on the access path: when `Issuer` is set the `iss` claim is checked, and when `ExpectedAudience` is set the token's `aud` must contain at least one of the listed values. See [Security Hardening]({{< ref "security-hardening" >}}) for the full rationale.

> **Multi-tenant:** the bare `VerifyAccessToken` is **deprecated** — it does no tenant binding. Set `Config.MultiTenant = true` (so `VerifyAccessToken` fails closed with `tokens.ErrTenantBindingRequired`) and call `VerifyAccessTokenForTenant(ctx, tenantID, token)`, which rejects a cross-tenant token with `tokens.ErrTenantMismatch`. Single-tenant apps leave `MultiTenant` false.

## Refresh Token Rotation & Theft Detection

Refresh tokens are single-use. When a user refreshes their access token, they are issued a completely new Token Pair via `Rotate`. The issuer must be constructed with a `ClaimsProvider`, which resolves fresh claims (status, scopes, roles) at rotation time rather than trusting values frozen at login.

If an attacker steals a Refresh Token and uses it, the user's client will eventually try to use the *same* Refresh Token. The `tokens` module detects this replay and (outside the configured `ReuseGracePeriod`) immediately revokes the **entire token family**, forcing everyone (including the attacker) to re-authenticate.

```go
newPair, err := tokenService.Rotate(ctx, "tenant-123", oldRefreshToken)
if err != nil {
	// If errors.Is(err, tokens.ErrRefreshTokenReused), a replay was detected
	// and the family was revoked.
}
```

## API Keys

API keys are long-lived credentials suitable for machine-to-machine calls, CI pipelines, or personal access tokens issued to developers. Unlike JWT access tokens they do not expire on a short TTL — they remain valid until explicitly revoked or until their optional `ExpiresAt` is reached.

### Issuing a key

```go
apiKey, err := tokenService.IssueAPIKey(ctx, "sk_live_", tokens.KeyTypeService, operatorUserID,
    tokens.Claims[MyClaims]{
        TenantID: "tenant-123",
        Scopes:   []string{"metrics:read", "deploys:write"},
    },
)
// apiKey.Token is the only moment the clear-text value is available.
// Store it nowhere — give it to the caller once and discard.
fmt.Println("Your API key:", apiKey.Token)
```

> **Security:** The clear-text token is returned **once** at issuance and is **never stored or retrievable** afterwards. Only the SHA-256 hash is persisted. Management operations (revoke, list) use the key's UUID (`apiKey.ID`), not the token value. For the full security rationale see [SECURITY.md](https://github.com/JLugagne/egauth/blob/main/SECURITY.md).

`KeyTypePAT` issues a personal access token tied to a human user (`actor.IsHuman()` returns true). `KeyTypeService` issues a machine identity whose `Actor.UserID` is empty — use `actor.KeyID` to identify the service principal.

### Revoking a key

```go
err := tokenService.RevokeAPIKey(ctx, "tenant-123", apiKey.ID)
// errors.Is(err, tokens.ErrAPIKeyNotFound) if the key does not exist.
// Revoking an already-revoked key is idempotent (returns nil).
```

After revocation, any call to `VerifyAPIKey` or `VerifyAPIKeyActor` for that key returns `tokens.ErrAPIKeyRevoked` — a distinct error from `ErrAPIKeyNotFound`, so callers can tell the difference between "unknown key" and "key was deliberately disabled". The revoked record is retained and remains visible in management listings; it is not deleted.

To revoke **every** credential a user holds at once — all their refresh tokens and all the API keys they issued — use `tokens.NewAccountRevoker(store)`. Its main use is wiring into `identity.WithDisableRevokers` so disabling an account automatically revokes its tokens and keys (see [Identity & Passwords]({{< ref "identity-and-passwords" >}})); the underlying store also exposes `RevokeAllRefreshTokensForUser` and `RevokeAllAPIKeysForUser` directly.

### Listing a user's keys

```go
keys, err := tokenService.ListAPIKeysByCreator(ctx, "tenant-123", operatorUserID)
for _, k := range keys {
    status := "active"
    if k.RevokedAt != nil {
        status = "revoked"
    }
    fmt.Printf("%s  %s  %s\n", k.ID, k.Prefix, status)
    // k.Token is always blank — the clear-text is unrecoverable after issuance.
}
```

`ListAPIKeysByCreator` returns both active and revoked keys. The `RevokedAt` field is set on soft-revoked entries. The `Token` field is always empty; if you need to look up a key during authentication use `VerifyAPIKey` (which hashes the raw value before the store lookup).

## Protecting HTTP Routes

`tokens.RequireAuth` wraps an `AuthenticatedHandlerFunc` to enforce access-token verification. Rather than hiding the identity in the request context, the verified `egauth.Actor` and your custom claims are passed **explicitly** as handler arguments.

```go
handler := tokens.RequireAuth(
	tokenService, // any tokens.Verifier[MyClaims]
	func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, custom MyClaims) {
		// actor.UserID (uuid.UUID) and actor.TenantID are the verified identity.
		fmt.Printf("User %s, Role: %s", actor.UserID, custom.Role)
	},
	// Optional: gate the route on step-up authentication (RFC 8176 AMR).
	tokens.WithRequiredAMR[MyClaims](tokens.AMRMFA),
)

mux.Handle("/api/private", handler)
```

By default `RequireAuth` reads a Bearer token from the `Authorization` header. Use `tokens.WithCookieAuth` to read from a cookie and `tokens.WithAutoRefresh` for opt-in transparent rotation.

**Multi-tenant routes.** By default `RequireAuth` verifies the token without tenant binding — correct for single-tenant apps, where every token is issued under the empty tenant. For a multi-tenant deployment served by a single shared signing key, add `tokens.WithAuthTenantResolver`, which makes the middleware resolve each request's tenant and verify through `VerifyAccessTokenForTenant`, so a token minted for tenant A cannot be replayed against tenant B:

```go
handler := tokens.RequireAuth(
	tokenService, // a verifier built with jwt.Config{MultiTenant: true}
	myHandler,
	// Map the request to its tenant (Host, path segment, upstream-set context...).
	// Returning "" means "tenant could not be resolved" → the request is rejected
	// 401 (fail-closed); the middleware never falls back to the tenant-unaware path.
	tokens.WithAuthTenantResolver[MyClaims](func(r *http.Request) string {
		return tenantFromHost(r.Host)
	}),
)
```

A resolved token whose signed `tenant_id` does not match the request tenant is rejected (`tokens.ErrTenantMismatch` → 401). The same resolver scopes any auto-refresh rotation. `tokens.WithRefreshTenantResolver` is retained as a deprecated alias.

The `tokens` package also provides ready-made HTTP handlers for the refresh and logout endpoints: `tokens.RefreshHandler` and `tokens.LogoutHandler`, both configurable with options such as `tokens.WithCookies`, `tokens.WithTrustedOrigins`, and `tokens.WithTenantResolver`.

### Inspecting scopes on the Actor

The `egauth.Actor` value passed to every `AuthenticatedHandlerFunc` carries the token's `Scopes` slice verbatim. Three helper methods let you check scopes without writing your own loop:

```go
actor.HasScope("reports:read")                        // true iff that one scope is present
actor.HasAllScopes("reports:read", "reports:write")   // true iff every listed scope is present
actor.HasAnyScope("admin", "reports:read")            // true iff at least one is present
```

`HasAllScopes` with no arguments returns `true` (vacuous truth). `HasAnyScope` with no arguments returns `false`. Both are allocation-free. `egauth` does not enforce scopes on its own — use `WithRequiredScopes` for a declarative per-route gate, or call the helpers directly when the logic is conditional.

### Custom gates with `WithGate`

`WithGate` lets you attach an application-supplied predicate that runs **after** all built-in gates (kind, required scopes, AMR, auth-age, forced-password-change) and **before** the protected handler. If the predicate returns a non-nil error the request is rejected with `403 Forbidden`. The error message is **not** echoed to the client.

```go
handler := tokens.RequireAuth(
    tokenService,
    myHandler,
    // Reject callers whose token does not cover the requested resource.
    tokens.WithGate[MyClaims](func(actor egauth.Actor, custom MyClaims) error {
        if !actor.HasScope("invoices:write") {
            return errors.New("missing invoices:write scope")
        }
        if custom.OrgID != expectedOrgID {
            return errors.New("org mismatch")
        }
        return nil
    }),
)
```

Use `WithGate` when your access rule depends on both the actor identity and the decoded custom claims, or when the condition is too dynamic for the static `WithRequiredScopes` list. For simple scope requirements `WithRequiredScopes` is terser and its rejection reason (`insufficient_scope`) is standard.

### CSRF same-origin check (on by default)

These endpoints are state-changing `POST`s authenticated purely by the refresh cookie, so `SameSite=Lax` alone does not fully prevent a forged cross-site refresh/logout. Both handlers therefore apply a **same-origin check by default**: a request whose `Origin` (or, failing that, `Referer`) host is neither the request's own `Host` nor an explicitly trusted origin is rejected with `403` and the code `cross_site_blocked`, and a `POST` carrying neither header is treated as untrusted.

- For a single-origin app this is zero-config: a same-origin browser `POST` just works.
- To permit additional cross-origin hosts (e.g. a separate front-end domain), pass `tokens.WithTrustedOrigins("app.example.com")` — supply hosts without scheme.
- To turn the check off entirely (restoring the pre-v1 accept-every-origin behavior), pass `tokens.WithInsecureNoOriginCheck()`. Only do this when CSRF is handled by a separate layer; the name is deliberately loud.
