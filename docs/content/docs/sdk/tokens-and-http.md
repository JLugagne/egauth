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

`Issuer` and `ExpectedAudience` are verified on `VerifyAccessToken`: when `Issuer` is set the `iss` claim is checked, and when `ExpectedAudience` is set the token's `aud` must contain at least one of the listed values. See [Security Hardening]({{< ref "security-hardening" >}}) for the full rationale.

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

The `tokens` package also provides ready-made HTTP handlers for the refresh and logout endpoints: `tokens.RefreshHandler` and `tokens.LogoutHandler`, both configurable with options such as `tokens.WithCookies`, `tokens.WithTrustedOrigins`, and `tokens.WithTenantResolver`.
