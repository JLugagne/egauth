# infra — Actor, ratelimit, event, health, janitor

source: `actor.go`, `ratelimit/*.go`, `event/*.go`, `health/*.go`, `janitor/*.go`

## egauth (root)
import: `github.com/JLugagne/egauth`

```go
type Actor struct {
    UserID   uuid.UUID
    TenantID string
}
```
Authenticated principal. Passed explicitly to handlers — never via `context.Context`. `TenantID` empty string is the valid single-tenant partition.

## ratelimit
import: `github.com/JLugagne/egauth/ratelimit`

### Limiter interface
```go
type Limiter interface {
    Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration)
}
```
Concurrent-safe. `retryAfter` is zero when wait is unknown.

### KeyFunc
```go
type KeyFunc func(*http.Request) string
```
Derives the bucket key from a request. Default: `ClientIP` (reads `RemoteAddr`, does NOT trust `X-Forwarded-For`).

### TokenBucket (reference impl)
```go
func NewTokenBucket(burst int, refillInterval time.Duration, opts ...Option) *TokenBucket
func (tb *TokenBucket) Allow(ctx context.Context, key string) (bool, time.Duration)
func (tb *TokenBucket) Cleanup() int  // returns number of buckets removed
```
Per-key token-bucket. `burst` floored at 1, `refillInterval` floored at 1ns. `Cleanup` drops only fully-refilled buckets (no reset under pressure). **Periodic eviction mandatory** — see janitor.

### Options
```go
func WithClock(now func() time.Time) Option  // inject time source for deterministic tests
```

### Middleware / Wrap
```go
func Middleware(limiter Limiter, key KeyFunc) func(http.Handler) http.Handler
func Wrap(limiter Limiter, key KeyFunc, next http.HandlerFunc) http.HandlerFunc
func ClientIP(r *http.Request) string
```
On rejection: responds `429 Too Many Requests` with `Retry-After` header (seconds) when `retryAfter > 0`; does not call next handler.

### Errors
No sentinel errors exported. Rejection is signalled by `allowed == false` from `Allow`.

## event
import: `github.com/JLugagne/egauth/event`

### Sink interface
```go
type Sink interface {
    EmitEvent(ctx context.Context, e Event)
}
```
Must be concurrent-safe and non-blocking (buffer or dispatch async if backend is slow).

### SinkFunc adapter
```go
type SinkFunc func(ctx context.Context, e Event)
func (f SinkFunc) EmitEvent(ctx context.Context, e Event)
```

### Event type
```go
type Event struct {
    Type     Type           // required
    TenantID string         // "" when unknown
    UserID   string         // UUID as string; "" when unknown
    Reason   string         // short machine code, e.g. "invalid_credentials", "account_locked"
    Err      error          // underlying error for failure/outage events
    Attrs    map[string]any // extra structured context; never secrets/tokens/passwords
}
```

### Emit helper
```go
func Emit(ctx context.Context, sink Sink, e Event)
```
No-op when `sink == nil`. Services call this so call sites are nil-check-free.

### Constructors
```go
func NewSlogSink(logger *slog.Logger) Sink  // nil → slog.Default()
func MultiSink(sinks ...Sink) Sink          // nil entries skipped
```
`NewSlogSink` log levels: `Err != nil` → Error; known failure/anomaly events → Warn; rest → Info.

### Event kinds (Type = string)
```go
LoginSucceeded          = "login.succeeded"
LoginFailed             = "login.failed"
AccountLocked           = "account.locked"
UserRegistered          = "user.registered"
PasswordReset           = "password.reset"        // completed via reset token
PasswordChanged         = "password.changed"      // authenticated self-service
EmailVerified           = "email.verified"
EmailChanged            = "email.changed"
PhoneVerified           = "phone.verified"
RecoveryChannelEnrolled = "recovery_channel.enrolled"
MagicLinkLogin          = "magic_link.login"
AccountDeleted          = "account.deleted"
Logout                  = "logout"                // session revoked
AccountBlocked          = "account.blocked"       // policy denial (rate limit, IP/geo, risk)
AccountDisabled         = "account.disabled"      // reversible administrative suspension
AccountEnabled          = "account.enabled"       // administrative re-activation
RefreshReuseDetected    = "refresh.reuse_detected"
TokenFamilyRevoked      = "token.family_revoked"
MFAEnrolled             = "mfa.enrolled"
MFAConfirmed            = "mfa.confirmed"
MFAVerificationFailed   = "mfa.verification_failed"
MFADisabled             = "mfa.disabled"
DeliveryFailed          = "delivery.failed"       // swallowed mailer/delivery error
```

## health
import: `github.com/JLugagne/egauth/health`

### Pinger interface
```go
type Pinger interface {
    Ping(ctx context.Context) error
}
```
Implemented by **pgx-backed stores only** (lightweight round-trip query). In-memory stores do not implement it (no external dependency). Probe via type assertion:
```go
if p, ok := store.(health.Pinger); ok {
    if err := p.Ping(ctx); err != nil { /* report not-ready */ }
}
```

## janitor
import: `github.com/JLugagne/egauth/janitor`

### Types / functions
```go
type Janitor struct{ /* unexported */ }

func Start(ctx context.Context, interval time.Duration, fn func()) *Janitor
func (j *Janitor) Stop()
```
`Start` launches a background goroutine calling `fn` every `interval`. Stops on context cancellation or `Stop()`. `interval` floored at 1ns. `Stop` blocks until goroutine exits; idempotent.

### Stores requiring eviction
| store | eviction call |
|---|---|
| `sessions/memory.Store` | `DeleteExpired(ctx, tenantID)` |
| `otp/memory.Store` | `DeleteExpired(ctx, tenantID)` |
| `ratelimit.TokenBucket` | `Cleanup()` |

## Wiring
```go
// Slog event sink + token-bucket middleware + janitor for eviction
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

sink := event.NewSlogSink(nil) // nil → slog.Default()

tb := ratelimit.NewTokenBucket(10, time.Second)
j := janitor.Start(ctx, time.Minute, func() {
    tb.Cleanup()
})
defer j.Stop()

mux := http.NewServeMux()
mux.Handle("/login", ratelimit.Middleware(tb, ratelimit.ClientIP)(loginHandler))
```

## Gotchas
- **Janitor is mandatory for all in-memory stores** (`sessions/memory`, `otp/memory`, `ratelimit.TokenBucket`). Without it, a flood of unique keys causes unbounded memory growth — a trivial DoS vector.
- `event.Sink` nil = no-op; services always call `event.Emit`, never check nil themselves.
- `Actor` is never in `context.Context`; always passed as an explicit argument.
- `health.Pinger` is pgx-only; in-memory stores never satisfy it.
- `ClientIP` does not trust proxy headers; supply a custom `KeyFunc` when behind a trusted proxy.
- `ratelimit.TokenBucket.Cleanup` only removes fully-refilled buckets; it does not reset limits for keys still under pressure.
- `ratelimit.TokenBucket` eviction is O(1) by sampling, preventing DoS during cleanup under heavy load.
- `janitor` automatically recovers from panics in the cleanup function, ensuring the background loop stays alive.
- Multi-tenant janitor: fan out inside one goroutine by iterating `tenantIDs()` inside `fn`.
