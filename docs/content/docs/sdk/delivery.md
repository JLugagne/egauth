---
title: "Delivery & External Services"
weight: 8
---

# Delivery & External Services

Because `egauth` is designed to run without taking over your infrastructure, it does not hardcode connections to AWS SES, SendGrid, Twilio, or Redis. Instead, it exposes interfaces for you to implement.

## Mailer Interface

When a user requests a magic link or a password reset, `egauth` delegates the actual delivery to you.

```go
type MyMailer struct {}

func (m *MyMailer) SendPasswordReset(ctx context.Context, email, token string) error {
	// Construct the URL
	url := fmt.Sprintf("https://myapp.com/reset?token=%s", token)
	
	// Example: Call SendGrid API
	// return sendgridClient.Send(email, "Reset your password", url)
	return nil
}
```

You then inject this mailer into the handlers or services.

## Rate Limiting

To prevent brute force attacks, you should rate limit identity endpoints. `egauth` exposes a `ratelimit.Limiter` interface.

You can implement this interface using Redis, or use a lightweight in-memory Token Bucket for smaller deployments.

```go
import "github.com/JLugagne/egauth/ratelimit"

// A simple in-memory limiter allowing 5 requests per minute
limiter := ratelimit.NewMemoryLimiter(5, time.Minute)

// Pass it to the Identity Service to automatically throttle authentication attempts
identitySvc := identity.NewService(
	store, hasher, policy,
	identity.WithRateLimiter(limiter),
)
```
