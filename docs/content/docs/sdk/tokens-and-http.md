---
title: "Tokens and HTTP"
weight: 3
---

# Tokens and HTTP Protection

The `tokens` module manages stateless Access Tokens (JWT) and stateful Refresh Tokens. It incorporates advanced theft-detection mechanics.

## Generating Tokens

`egauth` uses Go Generics to allow you to inject custom claims safely into your JWTs.

```go
import "github.com/JLugagne/egauth/tokens"

// Define your custom claims struct
type MyClaims struct {
	Role  string `json:"role"`
	OrgID string `json:"org_id"`
}

// Initialize the Token Service
tokenService := tokens.NewService[MyClaims](
	tokensStore,
	tokens.WithIssuer("my-app"),
	tokens.WithSymmetricKey([]byte("super-secret-32-byte-key-here!!!")),
)

// Issue a Token Pair (Access + Refresh)
pair, err := tokenService.Issue(ctx, userID, MyClaims{
	Role:  "admin",
	OrgID: "org-xyz",
}, tokens.WithTenant("tenant-123"))

fmt.Println("Access Token:", pair.AccessToken)
```

> **Security Note:** Refresh tokens are opaque strings. Only their SHA-256 hash is stored in the database.

## Refresh Token Rotation & Theft Detection

Refresh tokens are single-use. When a user refreshes their access token, they are issued a completely new Token Pair.

If an attacker steals a Refresh Token and uses it, the user's client will eventually try to use the *same* Refresh Token. The `tokens` module detects this replay and immediately revokes the **entire token family**, forcing everyone (including the attacker) to re-authenticate.

```go
newPair, err := tokenService.Refresh(ctx, oldRefreshToken, tokens.WithTenant("tenant-123"))
if err != nil {
	// If err == tokens.ErrTokenTheftDetected, the family was wiped.
}
```

## Protecting HTTP Routes

The SDK provides generic HTTP middlewares to validate Access Tokens natively.

```go
authMiddleware := tokens.RequireAuth(
	tokenService,
	// Optional: Enforce specific Authentication Method References (e.g., MFA)
	tokens.WithRequiredAMR("mfa"),
)

mux.Handle("/api/private", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Extract the validated generic claims from the request context
	claims, ok := tokens.ClaimsFromContext[MyClaims](r.Context())
	if ok {
		fmt.Printf("User Role: %s", claims.Custom.Role)
	}
})))
```
