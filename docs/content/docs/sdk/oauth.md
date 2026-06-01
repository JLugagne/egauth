---
title: "OAuth and OIDC"
weight: 5
---

# OAuth 2.0 and OIDC (Social Login)

The `oauth` module provides out-of-the-box support for external identity providers like Google, GitHub, and Discord, adhering to OAuth 2.1 best practices.

## Configuration

To start, configure the providers you wish to support. `egauth` implements Proof Key for Code Exchange (PKCE) natively and uses state cookies to prevent CSRF.

```go
import "github.com/JLugagne/egauth/oauth"

oauthService := oauth.NewService(
	oauthStore,
	oauth.WithProvider(oauth.Google(
		"google-client-id",
		"google-client-secret",
		"https://yourapp.com/auth/google/callback",
	)),
	oauth.WithProvider(oauth.GitHub(
		"github-client-id",
		"github-client-secret",
		"https://yourapp.com/auth/github/callback",
	)),
)
```

## The OAuth Flow

Because `egauth` is unopinionated about routing, it provides `http.HandlerFunc` factories that you attach to your router.

### 1. Begin the Flow

Mount the `BeginHandler` to initiate the redirect to the provider. The handler sets a secure, `HttpOnly` CSRF state cookie.

```go
// e.g. GET /auth/google/login
mux.Handle("/auth/google/login", oauth.BeginHandler(oauthService, "google"))
```

### 2. Handle the Callback

Mount the `CallbackHandler` to receive the redirect from the provider. This handler will exchange the code, verify the nonce, and fetch the user's profile. 

If successful, it invokes a callback function where you define how to link this OAuth identity to your system's User (via the `identity` module) and issue a token/session.

```go
// e.g. GET /auth/google/callback
callback := oauth.CallbackHandler(oauthService, "google", func(w http.ResponseWriter, r *http.Request, userInfo *oauth.UserInfo) {
	
	// 1. Find or Create the User in your system using userInfo.Email
	// identityService.Register(...) or identityService.Authenticate(...)
	
	// 2. Issue a JWT or Session
	// tokenService.Issue(...)
	
	// 3. Redirect the user to the dashboard
	http.Redirect(w, r, "/dashboard", http.StatusFound)
})

mux.Handle("/auth/google/callback", callback)
```
