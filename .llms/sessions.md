# sessions — server-side revocable sessions

import: `github.com/JLugagne/egauth/sessions`
memory store: `github.com/JLugagne/egauth/sessions/memory`
source: `sessions/*.go`

## Purpose

Stateful, opaque-token sessions backed by a pluggable `Store`. Revocation is immediate (a logout or admin action kills the session with no grace window). Complement to the `tokens` module (stateless JWTs): combine both — session cookie for browser, JWT for APIs — or pick one. Multi-tenancy is first-class: every method is scoped to a `tenantID`; empty string `""` is the single-tenant default partition.

Key properties vs stateless tokens:
- Revocation is O(1) and instant (no token still valid until expiry)
- Per-request store lookup required (latency trade-off)
- Idle-timeout via `Touch` (slide `ExpiresAt` on activity)
- Absolute-lifetime cap via `WithMaxLifetime` (slide cannot keep a stolen token warm indefinitely)
- Session fixation defense via `Rotate` (new token, same session ID, old token instantly invalid)

## Service interface

```go
type Service interface {
    // Returns (*Session, plaintextToken, error). Token is returned ONCE; store holds only the SHA-256 hash.
    CreateSession(ctx context.Context, tenantID string, userID uuid.UUID, userAgent string, ip string, duration time.Duration) (*Session, string, error)

    // Validates token, checks ExpiresAt and absolute cap. Returns ErrSessionNotFound on miss/expiry.
    ValidateSession(ctx context.Context, tenantID string, token string) (*Session, error)

    // Slides ExpiresAt to now+duration (clamped by absolute cap). Token unchanged.
    Touch(ctx context.Context, tenantID string, token string, duration time.Duration) (*Session, error)

    // Issues new token for same logical session (same ID), invalidates old token, resets lifetime.
    // CAS on token hash — concurrent rotations: first wins, second gets ErrSessionNotFound.
    // Returns (*Session, newPlaintextToken, error).
    Rotate(ctx context.Context, tenantID string, token string, duration time.Duration) (*Session, string, error)

    // Deletes session by token hash. Emits event.Logout via event.Sink if configured.
    // rc (optional) carries client IP/UA into the audit event Attrs; only the last value is used.
    RevokeSession(ctx context.Context, tenantID string, token string, rc ...event.RequestContext) error

    // Deletes ALL sessions for userID in tenantID. Idempotent. Emits event.Logout with
    // Reason="all_sessions". rc (optional) carries client IP/UA into the audit event Attrs.
    RevokeAllForUser(ctx context.Context, tenantID string, userID uuid.UUID, rc ...event.RequestContext) error
}
```

## Key types

```go
type Session struct {
    ID        uuid.UUID
    TenantID  string
    UserID    uuid.UUID
    TokenHash string    // SHA-256 hex of plaintext token; plaintext never stored
    UserAgent string
    IP        string
    ExpiresAt time.Time // idle deadline; clamped to CreatedAt+maxLifetime when cap is set
    CreatedAt time.Time // immutable; anchor for absolute-lifetime cap
}
```

## Constructors

```go
// panics on nil store
func NewService(store Store, opts ...ServiceOption) Service

// ServiceOptions:
func WithClock(now func() time.Time) ServiceOption       // override time source (tests)
func WithMaxLifetime(d time.Duration) ServiceOption      // absolute cap; zero = disabled
func WithEventSink(sink event.Sink) ServiceOption        // security-event sink for revocations (see M9 below)

// Single-tenant convenience wrapper — drops tenantID arg, always uses ""
func NewSingleTenant(svc Service) *SingleTenant

// SingleTenant methods (mirror Service minus tenantID):
func (s *SingleTenant) CreateSession(ctx, userID, userAgent, ip, duration) (*Session, string, error)
func (s *SingleTenant) ValidateSession(ctx, token) (*Session, error)
func (s *SingleTenant) Touch(ctx, token, duration) (*Session, error)
func (s *SingleTenant) Rotate(ctx, token, duration) (*Session, string, error)
func (s *SingleTenant) BindUser(ctx, token string, userID uuid.UUID, duration) (*Session, string, error)
func (s *SingleTenant) RevokeSession(ctx, token string, rc ...event.RequestContext) error
func (s *SingleTenant) RevokeAllForUser(ctx, userID uuid.UUID, rc ...event.RequestContext) error
func (s *SingleTenant) Service() Service  // escape hatch: returns underlying multi-tenant Service

// memory store
func memory.NewStore() *memory.Store  // implements sessions.Store; in-memory, O(1) hash lookup
```

## M9 — Logout audit events

When `WithEventSink` is configured, both revocation paths emit `event.Logout` to the sink. The optional `rc ...event.RequestContext` argument added to `RevokeSession` and `RevokeAllForUser` forwards client IP and User-Agent into the event's `Attrs` field. These variadic parameters are backward-compatible: existing call sites with no `rc` continue to compile and behave unchanged (IP/UA fields are simply omitted from the event).

| Revocation path | `event.Logout` fields |
|---|---|
| `RevokeSession` | `Type=Logout`, `UserID`, `TenantID`; `Attrs` includes IP/UA when `rc` is supplied |
| `RevokeAllForUser` | `Type=Logout`, `UserID`, `TenantID`, `Reason="all_sessions"`; `Attrs` includes IP/UA when `rc` is supplied |

`SingleTenant` wrappers forward the variadic unchanged, so single-tenant callers get the same audit coverage.

The token-model counterpart (`tokens.LogoutHandler` with `WithEventSink`) emits the same `event.Logout` type with `Reason="token_logout"`, giving a unified logout audit stream regardless of session model (JWT-family or server-side session).

## Store contract

```go
type Store interface {
    // Persists new session. Returns ErrTenantMismatch if session.TenantID != "" && != tenantID.
    CreateSession(ctx context.Context, tenantID string, session *Session) error

    // Retrieves by SHA-256 token hash scoped to tenant. Returns ErrSessionNotFound on miss.
    FindSessionByHash(ctx context.Context, tenantID string, tokenHash string) (*Session, error)

    // CAS update: applies only if stored hash == expectedTokenHash, else ErrSessionNotFound.
    // Mutable fields: TokenHash, ExpiresAt, UserAgent, IP. ID and TenantID are immutable.
    UpdateSession(ctx context.Context, tenantID string, session *Session, expectedTokenHash string) error

    // Deletes by session.ID within tenant.
    DeleteSession(ctx context.Context, tenantID string, id uuid.UUID) error

    // Deletes all sessions for userID within tenant.
    DeleteSessionsByUserID(ctx context.Context, tenantID string, userID uuid.UUID) error

    // Purges sessions where ExpiresAt < now within tenant. Returns count deleted.
    // Must be scheduled externally (janitor); not called automatically by Service.
    DeleteExpired(ctx context.Context, tenantID string) (int64, error)
}
```

## Middleware

`RequireSession` (`sessions/middleware.go`) — wraps a handler, enforces a valid session.

Token extraction order:
1. Cookie named `__Host-session_token` (`sessions.DefaultSessionCookieName`, secure by default; the `__Host-` prefix host-locks it). Override with `WithCookieName` only as an escape hatch.
2. `Authorization: Bearer <token>` header

On miss or invalid token → `401 Unauthorized` (plain text body).

On valid token → calls `ValidateSession`, builds `egauth.Actor{UserID, TenantID}`, invokes handler:

```go
type AuthenticatedSessionHandlerFunc func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session Session)

func RequireSession(svc Service, handler AuthenticatedSessionHandlerFunc, opts ...HandlerOption) http.HandlerFunc

func WithTenantResolver(f func(*http.Request) string) HandlerOption
// extracts tenantID from request (host header, path segment, JWT claim, etc.)
// MUST map the request through an explicit allowlist / canonical table — never the raw Host
// returning "" means "unresolved" -> the middleware rejects with 401 (fail-closed)
// default (no resolver configured at all): empty string (single-tenant partition)
```

No cookie is set by the middleware. The caller is responsible for writing the `Set-Cookie` header (using the plaintext token returned by `CreateSession` or `Rotate`). No `Secure`, `HttpOnly`, or `SameSite` flags are set by the library — cookie attributes are the caller's responsibility.

## Errors

```go
var ErrSessionNotFound = errors.New("sessions: session not found")
// Returned by: ValidateSession (miss, idle expiry, absolute-cap expiry), Touch, Rotate,
//              RevokeSession, Store.FindSessionByHash, Store.UpdateSession (CAS miss)

var ErrTenantMismatch = errors.New("sessions: tenant ID mismatch")
// Returned by: Store.CreateSession when session.TenantID != "" && != tenantID argument
```

Idle expiry and absolute-cap expiry both return `ErrSessionNotFound` — callers cannot distinguish them.

## Lifetime semantics

```
CreateSession(duration=D)  →  ExpiresAt = now+D, CreatedAt = now

Touch(duration=D)          →  ExpiresAt = min(now+D, CreatedAt+maxLifetime)
                               token unchanged; idle window resets

Rotate(duration=D)         →  ExpiresAt = min(now+D, CreatedAt+maxLifetime)
                               new token issued, old token immediately invalid
                               session.ID unchanged (same logical session)

WithMaxLifetime(M):
  ValidateSession checks now > CreatedAt+M  →  ErrSessionNotFound
  Touch/Rotate clamp: ExpiresAt never exceeds CreatedAt+M
  Zero value = no absolute cap (idle-timeout only)
```

## Eviction

`Store.DeleteExpired` is NOT called automatically. For the memory store, expired sessions accumulate in the map until explicitly purged.

`memory.Store.FindSessionByHash` does opportunistic eviction on hit (expired record found → evict + return `ErrSessionNotFound`), but rows that are never looked up after expiry remain until `DeleteExpired`.

Schedule with janitor:

```go
store := memory.NewStore()
j := janitor.Start(ctx, 5*time.Minute, func() {
    store.DeleteExpired(context.Background(), tenantID)
})
defer j.Stop()
```

For multi-tenant memory deployments, `DeleteExpired` must be called per tenant — there is no global sweep across all tenants in one call.

## Wiring

```go
import (
    "github.com/JLugagne/egauth/sessions"
    "github.com/JLugagne/egauth/sessions/memory"
)

store := memory.NewStore()
svc := sessions.NewService(store,
    sessions.WithMaxLifetime(7*24*time.Hour), // optional absolute cap
    sessions.WithEventSink(myAuditSink),      // optional: emit event.Logout on revocation (M9)
)

// Create
sess, token, err := svc.CreateSession(ctx, tenantID, userID, r.UserAgent(), ip, 24*time.Hour)
// write token to client (name MUST match the middleware default __Host-session_token; __Host- requires Secure + Path=/ + no Domain):
// http.SetCookie(w, &http.Cookie{Name:sessions.DefaultSessionCookieName, Value:token, Path:"/", HttpOnly:true, Secure:true, SameSite:http.SameSiteLaxMode})

// Middleware
// Map the request to a tenant through an EXPLICIT allowlist of canonical hosts. Never return the
// raw Host header: it is attacker-controlled, is not canonical (case, port, trailing dot, IDN),
// and an unknown Host must NOT silently become a tenant. An unmapped host yields "" and the
// middleware then rejects the request with 401 (fail-closed) instead of falling back to the
// single-tenant ("") partition.
tenantsByHost := map[string]string{"acme.example.com": "acme", "globex.example.com": "globex"}
tenantFromHost := func(r *http.Request) string {
    host := strings.ToLower(r.Host)
    if h, _, err := net.SplitHostPort(host); err == nil {
        host = h
    }
    return tenantsByHost[strings.TrimSuffix(host, ".")] // "" when unknown -> request refused
}
mux.Handle("/protected", sessions.RequireSession(svc, myHandler,
    sessions.WithTenantResolver(tenantFromHost),
))

// Activity: slide idle timeout
svc.Touch(ctx, tenantID, token, 24*time.Hour)

// Privilege change (login, MFA, role grant): rotate to defeat fixation
sess, newToken, err := svc.Rotate(ctx, tenantID, token, 24*time.Hour)
// re-issue Set-Cookie with newToken

// Logout — pass RequestContext to stamp client IP/UA in the audit event (M9)
rc := event.RequestContext{IP: r.RemoteAddr, UserAgent: r.UserAgent()}
svc.RevokeSession(ctx, tenantID, token, rc)

// "Log out everywhere" (password reset, compromise)
svc.RevokeAllForUser(ctx, tenantID, userID, rc)
```

## Gotchas

- `NewService` **panics** on nil store — wiring errors surface at startup, not at request time.
- Plaintext token is returned **once only** (at `CreateSession` / `Rotate`). Store the `Set-Cookie` response immediately; it cannot be recovered from the `Session` struct (only `TokenHash` is stored).
- `SingleTenant` hard-wires `tenantID=""`. Do **not** mix `SingleTenant` calls with direct multi-tenant `Service` calls against the same service in a multi-tenant app — IDOR risk.
- Concurrent `Rotate` on the same token: only the first succeeds. The second gets `ErrSessionNotFound` — handle it as a session conflict (re-validate or force re-login), not a transient error.
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`) are **not set by the library**. The middleware only reads the cookie — by default the hardened `__Host-session_token` (`sessions.DefaultSessionCookieName`); the caller writes it under the same name. The `__Host-` prefix is browser-enforced (`Secure`, `Path=/`, no `Domain`); use `WithCookieName` to opt out only when you genuinely can't meet those rules.
- `DeleteExpired` is per-tenant. A multi-tenant memory store needs one `DeleteExpired` call per active tenant per janitor tick; there is no single cross-tenant purge.
- `WithMaxLifetime` zero value disables the absolute cap entirely — a session with a long idle timeout can theoretically live forever if `Touch` is called before every expiry. Set an explicit cap for production.
- `ValidateSession` returns `ErrSessionNotFound` for both idle-expired and absolute-cap-expired sessions — no way to tell them apart from the error alone.
- The `pgx` backend (`sessions/pgx`) is a separate nested module; use it for persistent or horizontally-scaled deployments. The memory store is for tests and single-process single-restart scenarios only.
