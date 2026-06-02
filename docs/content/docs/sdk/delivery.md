---
title: "Delivery & External Services"
weight: 8
---

# Delivery & External Services

Because `egauth` is designed to run without taking over your infrastructure, it does not hardcode connections to AWS SES, SendGrid, Twilio, or Redis. Instead, it exposes seams for you to implement.

## The Mailer

When a user requests a magic link or a password reset, `egauth` mints the token but delegates the actual delivery to you. `egauth` never sends email and ships no templating.

The `identity.Mailer` is not an interface — it is a struct of callbacks. You wire up only the flows you use; a `nil` callback means the corresponding flow simply skips delivery. Each callback receives a details struct (e.g. `identity.PasswordResetMail`) carrying the `User` and the plaintext `Token`.

```go
import (
	"context"
	"fmt"

	"github.com/JLugagne/egauth/identity"
)

mailer := identity.Mailer{
	PasswordReset: func(ctx context.Context, mail identity.PasswordResetMail) error {
		// Construct the URL from the plaintext token (treat it as a secret — never log it).
		url := fmt.Sprintf("https://myapp.com/reset?token=%s", mail.Token)

		// Example: Call SendGrid API, delivering to mail.User.Email
		// return sendgridClient.Send(mail.User.Email, "Reset your password", url)
		return nil
	},
	MagicLink: func(ctx context.Context, mail identity.MagicLinkMail) error {
		url := fmt.Sprintf("https://myapp.com/login?token=%s", mail.Token)
		// return sendgridClient.Send(mail.User.Email, "Your login link", url)
		return nil
	},
}
```

The other available callbacks are `EmailVerification`, `EmailChange`, and `RecoveryEmailVerification`, each receiving its own `*Mail` details struct.

### Wiring the Mailer

The `Mailer` is not injected into `identity.NewService`. Instead, you pass it to the request-handler factories in the `identity` package, which mint the token and hand it to the matching callback:

```go
resetHandler := identity.RequestPasswordResetHandler(svc, mailer)
mux.Handle("/auth/password-reset/request", resetHandler)
```

## Rate Limiting

To slow brute-force and abuse, rate limit your identity endpoints. `egauth` exposes a `ratelimit.Limiter` interface (`Allow(ctx, key) (allowed bool, retryAfter time.Duration)`) and a lightweight in-memory `TokenBucket` implementation. Rate limiting is applied as HTTP middleware wrapping your handlers — it is not injected into the identity service.

```go
import "github.com/JLugagne/egauth/ratelimit"

// A token bucket: burst of 5, refilling one token per minute.
limiter := ratelimit.NewTokenBucket(5, time.Minute)

// Wrap a handler, keying the budget per client IP.
limited := ratelimit.Wrap(limiter, ratelimit.ClientIP, resetHandler)
mux.Handle("/auth/password-reset/request", limited)
```

`ratelimit.ClientIP` keys per source address; supply your own `ratelimit.KeyFunc` to key per account or per destination instead. Use `ratelimit.Middleware(limiter, key)` when you want the `func(http.Handler) http.Handler` form.

See [Security Hardening]({{< ref "security-hardening" >}}) for the full per-IP / per-account / per-destination recipe and the SMS toll-fraud warning.
