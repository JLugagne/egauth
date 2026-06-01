---
title: "Tokens and HTTP Routing"
weight: 3
---

# Tokens and HTTP Routing

Once a user is successfully authenticated via the Identity module, you typically want to issue an Access Token (like a JWT) so they can access your APIs. `egauth` provides a strictly-typed `tokens` module for this.

## Setting Up the JWT Issuer

First, instantiate an in-memory or PostgreSQL store for tracking refresh tokens or API keys, and configure the JWT service. Note how `egauth` heavily utilizes **Generics** to allow you to inject Custom Claims.

```go
import (
    "time"
    "github.com/JLugagne/egauth/tokens"
    "github.com/JLugagne/egauth/tokens/jwt"
    "github.com/JLugagne/egauth/tokens/memory"
)

// Define your application's custom claims
type MyCustomClaims struct {
    Role string `json:"role"`
}

// 1. Initialize the Token Store
tokenStore := memory.NewStore[MyCustomClaims]()

// 2. Configure the JWT Service
cfg := jwt.Config[MyCustomClaims]{
    Store:      tokenStore,
    SecretKey:  "super-secret-key-change-me-in-production",
    Issuer:     "my-app",
    AccessTTL:  15 * time.Minute,
    RefreshTTL: 7 * 24 * time.Hour,
}
jwtService := jwt.New[MyCustomClaims](cfg)
```

## Issuing a Token

In your login HTTP handler, after verifying the password with `identityService`, you issue a Token Pair.

```go
claims := tokens.Claims[MyCustomClaims]{
    Subject:  authUser.ID,
    TenantID: "tenant-abc",
    Custom:   MyCustomClaims{Role: "admin"},
}

pair, err := jwtService.IssueTokenPair(ctx, claims)
if err != nil {
    // Handle error
}

// Return `pair.AccessToken` to the client
```

## Protecting HTTP Routes

To protect your API endpoints, use the provided HTTP middlewares. `egauth` has a clean `RequireAuth` wrapper that automatically handles token extraction and passes the Actor and custom claims down to your handler.

```go
import (
    "net/http"
    "github.com/JLugagne/egauth"
    "github.com/JLugagne/egauth/tokens"
)

// Create an authenticated handler
protectedHandler := tokens.RequireAuth[MyCustomClaims](
    jwtService, 
    func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, custom MyCustomClaims) {
        
        // You have immediate, type-safe access to the Actor and Custom Claims!
        fmt.Fprintf(w, "Hello User %s! Your role is %s", actor.UserID, custom.Role)
    },
)

// Mount the route using your favorite mux router
mux := http.NewServeMux()
mux.Handle("/api/protected", protectedHandler)
```

This pattern guarantees that the endpoint is unreachable without a valid, non-expired token containing a matching signature.
