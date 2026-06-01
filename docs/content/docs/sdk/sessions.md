---
title: "Stateful Sessions"
weight: 4
---

# Stateful Sessions

While the `tokens` module is excellent for stateless JWTs, many applications require stateful sessions (e.g., for immediate revocation, strict device tracking, or administrative dashboards). 

`egauth` provides a robust `sessions` module that handles opaque token generation, secure hashing at rest, and lifecycle management (creation, rotation, sliding expiration).

## Setting Up the Session Service

Just like other `egauth` modules, you instantiate a store (in-memory, Redis, or PostgreSQL) and pass it to the service.

```go
import (
    "time"
    "github.com/JLugagne/egauth/sessions"
    "github.com/JLugagne/egauth/sessions/pgx" // Assuming a PostgreSQL backend
)

// 1. Initialize the Session Store
sessionStore := pgx.NewStore(dbPool)

// 2. Create the Session Service
sessionService := sessions.NewService(sessionStore)
```

## Creating a Session

When a user logs in, you generate a new session. `egauth` will mint a secure, high-entropy token, return it to you in plaintext (to send to the client as a cookie), and store only the **SHA-256 hash** in the database.

```go
// Inside your login handler:
session, plaintextToken, err := sessionService.CreateSession(
    ctx, 
    authUser.ID, 
    "tenant-abc", 
    r.UserAgent(), 
    r.RemoteAddr, 
    24 * time.Hour, // Session lifetime
)
if err != nil {
    // Handle error
}

// Send plaintextToken to the user via a secure, HTTP-only cookie
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    plaintextToken,
    HttpOnly: true,
    Secure:   true,
    Path:     "/",
})
```

## Validating and Sliding Sessions

To protect routes with stateful sessions, you extract the token from the cookie and validate it. 

```go
token := extractTokenFromCookie(r)

// Validate the session
session, err := sessionService.ValidateSession(ctx, token, sessions.WithTenant("tenant-abc"))
if err != nil {
    // Session is invalid, expired, or doesn't exist
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}
```

### Idle Timeout (Touch)

To implement an idle timeout (where active users stay logged in, but inactive users are logged out), use the `Touch` method. It slides the expiration time forward without altering the session token.

```go
// Slide the expiration to 30 minutes from now
session, err = sessionService.Touch(ctx, token, 30 * time.Minute, sessions.WithTenant(session.TenantID))
```

## Defeating Session Fixation (Rotate)

When a user's privileges change—such as stepping up with MFA, upgrading their role, or logging in from an anonymous session—you **must** rotate their session token to defeat session fixation attacks.

```go
// Rotate invalidates the old token and returns a fresh one for the SAME logical session
session, newPlaintextToken, err := sessionService.Rotate(ctx, token, 24 * time.Hour, sessions.WithTenant(session.TenantID))

// Update the user's cookie with the new token
```
