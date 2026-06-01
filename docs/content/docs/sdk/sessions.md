---
title: "Sessions"
weight: 4
---

# Sessions

If you prefer stateful, server-side tracking over JWTs, use the `sessions` module. This is particularly useful for monolithic web applications or admin dashboards where immediate, guaranteed revocation is critical.

## Initializing Sessions

```go
import "github.com/JLugagne/egauth/sessions"

sessionStore := sessionspg.NewStore(pool)
sessionSvc := sessions.NewService(
	sessionStore,
	sessions.WithIdleTimeout(30 * time.Minute),
	sessions.WithAbsoluteTimeout(12 * time.Hour),
)
```

## Creating & Rotating Sessions

Creating a session returns a secure, high-entropy opaque token.

```go
sess, err := sessionSvc.Create(ctx, userID, sessions.WithTenant("tenant-123"))

// Send `sess.Token` to the client in an HttpOnly, Secure, SameSite=Lax cookie
http.SetCookie(w, &http.Cookie{
	Name:     "session_id",
	Value:    sess.Token,
	HttpOnly: true,
	Secure:   true,
	SameSite: http.SameSiteLaxMode,
})
```

### Session Fixation Defense

When a user's privilege level changes (e.g., they log in, or complete MFA), you **must** rotate the session token to prevent Session Fixation attacks.

```go
rotatedSess, err := sessionSvc.Rotate(ctx, oldSessionToken)
// Update the client's cookie with rotatedSess.Token
```

## Validating & Touching Sessions

When a request comes in, you validate the session. To keep the session alive (preventing the Idle Timeout), you can optionally `Touch` it.

```go
sess, err := sessionSvc.Verify(ctx, tokenFromCookie)
if err != nil {
	// Invalid or expired
	return
}

// Optionally extend the idle timeout (updates the LastActiveAt timestamp in the DB)
_ = sessionSvc.Touch(ctx, sess.ID)
```
