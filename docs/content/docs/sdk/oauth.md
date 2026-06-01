---
title: "OAuth & OIDC"
weight: 5
---

# OAuth & OIDC Providers

`egauth` implements the OAuth2 authorization-code flow (with PKCE) as stateless, composable HTTP handlers. It supports OpenID Connect (OIDC) id_token validation natively.

The package exposes handler builders, not a router, and has zero third-party dependencies outside of the standard library.

## Setting Up a Provider

`egauth` ships with ready-made wrappers for Google, GitHub, and Discord, but you can configure any compliant provider.

```go
import "github.com/JLugagne/egauth/oauth"

// Set up a Google Provider with OIDC enabled
googleProvider := oauth.NewGoogleProvider(
    "YOUR_CLIENT_ID",
    "YOUR_CLIENT_SECRET",
    oauth.WithOIDC(oauth.OIDCConfig{
        Issuer:   "https://accounts.google.com",
        JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
        Audience: []string{"YOUR_CLIENT_ID"},
    }),
)
```

## Driving the Flow

You must expose two endpoints:
1. **Begin**: Generates the PKCE challenge, state, and nonce (if OIDC), saves them to an encrypted cookie, and redirects the user to the provider.
2. **Callback**: Exchanges the code for the `UserInfo`.

`egauth` provides builders that generate these handlers for you. You just provide the logic for what happens *after* a successful exchange.

```go
import "github.com/JLugagne/egauth/oauth"

// 1. Begin Handler
mux.Handle("/auth/google", oauth.BeginHandler(
    googleProvider,
    "https://myapp.com/auth/google/callback", // Redirect URI
    cookieSigner, // Something to securely sign the state cookie
))

// 2. Callback Handler
mux.Handle("/auth/google/callback", oauth.CallbackHandler(
    googleProvider,
    "https://myapp.com/auth/google/callback",
    cookieSigner,
    // Provide a callback function that handles the successful exchange:
    func(w http.ResponseWriter, r *http.Request, userInfo *oauth.UserInfo) {
        
        // userInfo.ProviderID (e.g., Google's "sub")
        // userInfo.Email
        // userInfo.Name

        // Step 1: Find or Create the User in your Identity Store
        // Step 2: Issue an egauth Session or JWT Token
        // Step 3: Redirect to the dashboard
        
        http.Redirect(w, r, "/dashboard", http.StatusFound)
    },
))
```

## OpenID Connect (OIDC) vs Standard OAuth

When you configure a provider `WithOIDC(...)`, `egauth` securely validates the JWT signature of the `id_token` returned by the provider (using the Issuer's JWKS) and derives the `UserInfo` from the cryptographically-attested claims. 

This skips an extra HTTP roundtrip to the provider's `/userinfo` endpoint and is highly recommended for providers that support OIDC (like Google and Apple).
