# infra — Actor, ratelimit, event, health, janitor

source: `actor.go`, `ratelimit/*.go`, `event/*.go`, `health/*.go`, `janitor/*.go`

## egauth (root)
import: `github.com/JLugagne/egauth`

```go
// PrincipalKind classifies the authenticated entity: User (interactive login), PAT (personal access
// token acting on behalf of a human), or Service (machine/service identity).
type PrincipalKind string

const (
    User    PrincipalKind = "user"    // interactive login; IsHuman()=true
    PAT     PrincipalKind = "pat"     // personal access token; IsHuman()=true
    Service PrincipalKind = "service" // machine identity; IsMachine()=true
)

type Actor struct {
    // UserID is set for User and PAT actors; empty for Service actors (their subject is KeyID).
    UserID   uuid.UUID
    TenantID string
    // Kind classifies the actor. Zero value ("") is treated as User by IsHuman/IsMachine.
    Kind     PrincipalKind
    // KeyID is the API key UUID for PAT and Service actors; empty for User actors.
    KeyID    uuid.UUID
    // Scopes are the permission scopes carried by this actor's token. egauth does not
    // enforce scopes — they are exposed for application middleware (e.g. WithRequiredScopes).
    Scopes   []string
}

func (a Actor) IsHuman() bool   // true for User, PAT, and zero Kind
func (a Actor) IsMachine() bool // true only for Service
```
Authenticated principal. Passed explicitly to handlers — never via `context.Context`. `TenantID` empty string is the valid single-tenant partition.

### API key types (`tokens.KeyType`)
```go
const (
    KeyTypePAT     tokens.KeyType = "pat"     // personal access token (human actor)
    KeyTypeService tokens.KeyType = "service" // machine/service identity
)
```
Set at `IssueAPIKey` call time; persisted in the store; surfaced on the resulting `Actor.Kind`.

### Audit events — API key lifecycle
| Type | When | `Event.Reason` | Key `Attrs` |
|------|------|----------------|-------------|
| `api_key.created` | Key issued | — | `"key_type"` (pat/service), `"created_by"` |
| `api_key.auth.succeeded` | Verify succeeded | — | `"key_type"`, `"ip"`, `"user_agent"` (if RequestContext set) |
| `api_key.auth.failed` | Verify failed | `not_found` / `expired` / `tenant_mismatch` / `wrong_type` | — |
| `api_key.purged` | GC sweep | — | `"count"` |

Audit events never carry secrets, tokens, hashes, or raw user input — only the short machine codes above.

### `event.RequestContext`
```go
type RequestContext struct {
    IP        string // client IP; recorded as "ip" Attr on login.* and api_key.auth.* events
    UserAgent string // recorded as "user_agent" Attr
}
// Thread in as a variadic option to auth entry points.
func RequestContextFrom(opts ...RequestContext) RequestContext
func (rc RequestContext) ApplyTo(attrs map[string]any) map[string]any
const AttrIP        = "ip"
const AttrUserAgent = "user_agent"
```

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
PasswordReset           = "password.reset"          // completed via reset token
PasswordChanged         = "password.changed"        // authenticated self-service
EmailVerified           = "email.verified"
EmailChanged            = "email.changed"
PhoneVerified           = "phone.verified"
RecoveryChannelEnrolled = "recovery_channel.enrolled"
AccountDeleted          = "account.deleted"
Logout                  = "logout"                  // session/token revoked (see M9 logout section below)
AccountBlocked          = "account.blocked"         // policy denial (rate limit, IP/geo, risk)
AccountDisabled         = "account.disabled"        // reversible administrative suspension
AccountEnabled          = "account.enabled"         // administrative re-activation
RefreshReuseDetected    = "refresh.reuse_detected"
TokenFamilyRevoked      = "token.family_revoked"
MFAEnrolled             = "mfa.enrolled"
MFAConfirmed            = "mfa.confirmed"
MFAVerificationFailed   = "mfa.verification_failed"
MFADisabled             = "mfa.disabled"
DeliveryFailed          = "delivery.failed"         // swallowed mailer/delivery error
InsecureCookieMisuse    = "cookies.insecure_misuse" // non-Secure cookies on a non-loopback plaintext host
```

### M9 — login-method audit attributes

`login.succeeded` carries two extra `Attrs` keys that identify how the user authenticated:

| Auth path | `"method"` | `"amr"` (RFC 8176 list) | Notes |
|---|---|---|---|
| Password | `"password"` | `["pwd"]` | Emitted at first-factor success, BEFORE MFA. The second factor is covered by the separate `mfa.confirmed` event. |
| Passkey (WebAuthn) | `"passkey"` | `["hwk"]` | Emitted by `passkey.Service` for both conditional-UI and cross-device flows. |
| Magic link | `"magic_link"` | `["otp"]` | Emitted by `identity.Service.LoginWithMagicLink`. |

`login.failed` carries `Attrs["method"]` (e.g. `"password"`) when the provider is determinable;
the field is omitted when the rejection happens before the provider is known (e.g. a non-password
provider presented on the credential path).

`account.locked` carries `"ip"` and `"user_agent"` in `Attrs` when a `RequestContext` was
supplied to the login entry point (same `ApplyTo` mechanic as other events).

**Removed event type (M9):** `MagicLinkLogin` (`"magic_link.login"`) no longer exists. Magic-link
login now emits `login.succeeded` with `method="magic_link"` / `amr=["otp"]`. The HTTP handler
name `MagicLinkLoginHandler` is unchanged.

### M9 — logout auditing

Both auth-state models reuse the existing `event.Logout` (`"logout"`) type. The `Reason` field
distinguishes the sub-case:

| Source | `Event.Reason` | `Attrs` |
|---|---|---|
| `sessions.Service.RevokeSession` | `""` (empty) | `"ip"` / `"user_agent"` if `RequestContext` supplied |
| `sessions.Service.RevokeAllForUser` | `"all_sessions"` | `"ip"` / `"user_agent"` if `RequestContext` supplied |
| `tokens.LogoutHandler` | `"token_logout"` | `"ip"` / `"user_agent"` from `r.RemoteAddr` / `r.UserAgent()` |

`tokens.LogoutHandler` emits on successful family revoke only; a double-logout (token already
gone, `ErrRefreshTokenNotFound`) emits nothing. Register the sink via
`tokens.WithEventSink(sink)` (also aliased as the deprecated `WithHandlerEventSink`).

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
