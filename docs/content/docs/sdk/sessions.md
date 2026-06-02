---
title: "Sessions"
weight: 4
---

# Sessions

If you prefer stateful, server-side tracking over JWTs, use the `sessions` module. This is particularly useful for monolithic web applications or admin dashboards where immediate, guaranteed revocation is critical.

## Initializing Sessions

`NewService` takes a `Store` plus optional `ServiceOption`s. The idle duration is **not** an option — you pass it per call (to `CreateSession`, `Touch`, and `Rotate`). The two options are `WithClock` (inject a clock, mainly for testing) and `WithMaxLifetime` (an absolute cap on how long a session may live, measured from `CreatedAt`).

```go
import (
	"time"

	"github.com/JLugagne/egauth/sessions"
	sessionspg "github.com/JLugagne/egauth/sessions/pgx"
)

sessionStore := sessionspg.NewStore(pool)
sessionSvc := sessions.NewService(
	sessionStore,
	sessions.WithMaxLifetime(12 * time.Hour),
)
```

## Creating & Rotating Sessions

Creating a session returns the `*Session` record, a secure high-entropy **opaque token** (the plaintext, returned as the second value), and an error. The `Session` struct stores only the SHA-256 `TokenHash` — there is no plaintext token field on it, so you must capture the returned token and put **that** in the cookie.

```go
// CreateSession(ctx, tenantID, userID, userAgent, ip, duration)
// The second return value is the plaintext token — the Session itself never holds it.
sess, token, err := sessionSvc.CreateSession(
	ctx,
	"tenant-123",
	userID, // uuid.UUID
	r.UserAgent(),
	clientIP,
	30*time.Minute, // idle duration for this session
)
if err != nil {
	return err
}
_ = sess // sess.ID, sess.ExpiresAt, sess.CreatedAt, etc.

// Send `token` to the client in an HttpOnly, Secure, SameSite=Lax cookie.
http.SetCookie(w, &http.Cookie{
	Name:     "session_id",
	Value:    token,
	HttpOnly: true,
	Secure:   true,
	SameSite: http.SameSiteLaxMode,
})
```

### Session Fixation Defense

When a user's privilege level changes (e.g., they log in, or complete MFA), you **must** rotate the session token to prevent Session Fixation attacks. `Rotate` issues a brand-new token for the same logical session (invalidating the old one) and returns that new plaintext token as its second value — re-cookie it.

```go
// Rotate(ctx, tenantID, token, duration) -> (*Session, newToken, error)
rotatedSess, newToken, err := sessionSvc.Rotate(ctx, "tenant-123", oldSessionToken, 30*time.Minute)
if err != nil {
	return err
}
_ = rotatedSess

// Update the client's cookie with the new token.
http.SetCookie(w, &http.Cookie{
	Name:     "session_id",
	Value:    newToken,
	HttpOnly: true,
	Secure:   true,
	SameSite: http.SameSiteLaxMode,
})
```

## Validating & Touching Sessions

When a request comes in, validate the session with `ValidateSession`, passing the tenant ID and the token from the cookie. To keep the session alive (sliding the idle expiry), call `Touch` with the **token** (not the session ID) and a fresh idle duration.

```go
// ValidateSession(ctx, tenantID, token) -> (*Session, error)
sess, err := sessionSvc.ValidateSession(ctx, "tenant-123", tokenFromCookie)
if err != nil {
	// Invalid, expired, or past its absolute lifetime cap.
	return
}

// Touch(ctx, tenantID, token, duration) -> (*Session, error)
// Slides the idle expiry forward (clamped to the absolute deadline, if one is set).
sess, err = sessionSvc.Touch(ctx, "tenant-123", tokenFromCookie, 30*time.Minute)
if err != nil {
	return
}
```

## Security Features

The `sessions` module ships two defenses worth calling out here. See [Security Hardening]({{< ref "security-hardening" >}}) for the full treatment.

### Absolute Lifetime Cap

`WithMaxLifetime` caps a session's total lifetime from its `CreatedAt`. Once `now` is past `CreatedAt + d`, `ValidateSession` rejects the session and `Touch`/`Rotate` can no longer keep it alive — they clamp the slid `ExpiresAt` so it never moves past the absolute deadline. This stops an idle-timeout slide from keeping a stolen-but-kept-warm token alive indefinitely. The zero value disables the cap (idle timeout only).

```go
sessionSvc := sessions.NewService(
	sessionStore,
	sessions.WithMaxLifetime(12*time.Hour),
)
```

### Revocation

For immediate revocation, use one of:

```go
// Revoke a single session by its token (e.g. an explicit logout on one device).
err := sessionSvc.RevokeSession(ctx, "tenant-123", tokenFromCookie)

// "Log out everywhere": delete every session belonging to a user in this tenant.
err = sessionSvc.RevokeAllForUser(ctx, "tenant-123", userID)
```

## Single-Tenant Facade

If your application is not multi-tenant, wrap the service in `sessions.NewSingleTenant(svc)`. It exposes the same methods with the `tenantID` argument dropped — e.g. `CreateSession(ctx, userID, userAgent, ip, duration)`, `ValidateSession(ctx, token)`, `Touch`, `Rotate`, `RevokeSession`, and `RevokeAllForUser(ctx, userID)`.

```go
single := sessions.NewSingleTenant(sessionSvc)
sess, token, err := single.CreateSession(ctx, userID, r.UserAgent(), clientIP, 30*time.Minute)
```
