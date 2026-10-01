# otp — delivery-agnostic one-time passcodes (email/SMS/step-up)

import: `github.com/JLugagne/egauth/otp`
memory store: `github.com/JLugagne/egauth/otp/memory`
source: `otp/service.go`, `otp/code.go`, `otp/handlers.go`

## Purpose

Short numeric one-time passcodes for passwordless login, email/phone
verification, or step-up auth. Delivery-agnostic: `Issue` returns a
`Challenge` containing the plaintext code; the application sends it over
whatever channel it chooses (email, SMS, push, etc.) — egauth never sends
anything. Verification is single-use, attempt-limited, and enumeration-safe
at the handler layer.

## Service interface

```go
type Service interface {
    Issue(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (*Challenge, error)
    Verify(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose, code string) error
    Invalidate(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) error
}
```

## Key types

```go
type Challenge struct {
    SubjectID uuid.UUID
    TenantID  string
    Purpose   string
    Code      string      // plaintext; returned ONCE; treat as credential; never log
    ExpiresAt time.Time
}

type OTP struct {
    SubjectID uuid.UUID
    TenantID  string
    Purpose   string
    CodeHash  string      // hex-encoded SHA-256; only the hash is persisted
    Attempts  int
    ExpiresAt time.Time
    CreatedAt time.Time
}
```

Both types implement `String()`, `GoString()` and `LogValue()` (slog), which render `Code` /
`CodeHash` as `REDACTED`. `%v`, `%+v`, `%#v`, `%s` and `slog` therefore never leak the code;
`Challenge.Code` remains the plaintext value returned for delivery.

## Constructors

```go
// Service
func NewService(store Store, opts ...ServiceOption) Service
    // panics on nil store; clamps invalid digits/TTL/maxAttempts to defaults

// ServiceOption functions
func WithDigits(n int) ServiceOption                  // default 6; panics outside [6, 10]
func WithTTL(d time.Duration) ServiceOption           // default 10m
func WithMaxAttempts(n int) ServiceOption             // default 5
func WithCooldown(d time.Duration) ServiceOption      // min gap between issues per subject+purpose; default 30s; non-positive disables
func WithClock(now func() time.Time) ServiceOption    // test injection; drives both TTL and cooldown
func WithEventSink(sink event.Sink) ServiceOption     // AccountBlocked event on code burn

// Single-tenant wrapper (omits tenantID, uses "" internally)
func NewSingleTenant(svc Service) *SingleTenant

// Memory store
func memory.NewStore() *memory.Store              // bounded by DefaultMaxEntries (100,000), self-evicting
func memory.NewBoundedStore(n int) *memory.Store  // pick the cap
func memory.NewUnboundedStore() *memory.Store     // explicit opt-out: schedule DeleteExpired with janitor
```

## Store contract

```go
// Store composes the stable-core OTPStore with the atomic-issuance OTPIssuer and the
// schedulable OTPReaper. Both the in-memory and pgx stores implement the whole Store.
type Store interface {
    OTPStore
    OTPIssuer
    OTPReaper
}

type OTPStore interface {
    // SaveOTP: upserts; resets Attempts on replace; records o.CreatedAt as the issuance
    // instant the cooldown measures from; ErrTenantMismatch on conflicting TenantID
    SaveOTP(ctx context.Context, tenantID string, o *OTP) error
    // GetOTP: returns outstanding code or ErrCodeNotFound
    GetOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (*OTP, error)
    // IncrementOTPAttempts: atomic pre-compare gate; returns new count; ErrCodeNotFound if absent
    IncrementOTPAttempts(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (int, error)
    // ConsumeOTP: atomic single-use AND identity guard. Removes the row only when its CodeHash
    // == expectedCodeHash; consumed=true only for the ONE caller that removes it. A reissued
    // (different-hash) row is left untouched and consumed=false, so a stale verification can
    // neither be accepted nor burn its fresh replacement.
    ConsumeOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose, expectedCodeHash string) (consumed bool, err error)
    // DeleteOTP: idempotent; used for expiry, burn, Invalidate
    DeleteOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) error
}

type OTPIssuer interface {
    // IssueOTP: ONE atomic operation that enforces the resend cooldown and persists o as the
    // new outstanding code. o.CreatedAt is the caller's clock (implementations MUST use it).
    // Returns ErrCooldownActive and stores nothing when the last issue for the same
    // (tenant, subject, purpose) was less than cooldown before o.CreatedAt; cooldown <= 0
    // disables the check. The last-issued instant MUST survive every terminal transition of
    // the code (consume, burn, expiry, eviction) — burning or verifying a code must not reset
    // the throttle.
    IssueOTP(ctx context.Context, tenantID string, o *OTP, cooldown time.Duration) error
}

type OTPReaper interface {
    // DeleteExpired: schedulable GC reaper; returns count deleted; scoped to one tenant
    DeleteExpired(ctx context.Context, tenantID string) (int64, error)
}
```

Empty `tenantID` (`""`) is the single-tenant partition; must still be passed.
`ErrTenantMismatch` if existing record's TenantID conflicts.

The interface split is deliberate: `OTPStore` is the frozen v1 core, and new optional
behaviour ships as a new capability interface (never as a new method on `Store`). A custom
adapter must implement all three.

## HTTP handlers

Both handlers: `POST` only; require `WithSubjectResolver`; parse form fields (body capped at `DefaultMaxBodyBytes` = 4 KiB).

### `IssueHandler(svc, deliver, ...HandlerOption)`

```
POST /otp/issue
```

- Resolves subject; calls `svc.Issue`; passes `*Challenge` to `deliver` asynchronously (goroutine, `context.WithoutCancel`).
- **Always responds `204`** (or success redirect), regardless of whether subject was resolved or delivery succeeded — no account-existence leak, no timing oracle.
- `deliver` signature: `func(ctx context.Context, ch *Challenge) error`
- Body: none (form fields unused).

### `VerifyHandler(svc, ...HandlerOption)`

```
POST /otp/verify
Form field: "code" (default; override with WithCodeField)
```

- **All failures collapse to `401 invalid_code`**: wrong code, missing/expired challenge, too many attempts, unresolved subject — client cannot distinguish them (challenge enumeration prevention).
- Success: runs `WithOnVerified` callback if set (callback owns response); otherwise `204` or success redirect.

| Condition | HTTP status | body |
|---|---|---|
| Success | `204` (or 303 / `WithOnVerified`) | — |
| Any failure | `401` | `invalid_code` |
| CSRF (trusted origins configured, blocked) | `403` | `cross_site_blocked` |
| Body too large | `413` | `request_too_large` |
| Malformed form | `400` | `invalid_request` |

Handler options:
```go
func WithSubjectResolver(f func(*http.Request) (uuid.UUID, bool)) HandlerOption  // required
func WithTenantResolver(f func(*http.Request) string) HandlerOption              // default: "" (single-tenant)
func WithPurpose(purpose string) HandlerOption                                   // default "login"
func WithPurposeResolver(f func(*http.Request) string) HandlerOption             // overrides WithPurpose
func WithCodeField(name string) HandlerOption                                    // default "code"
func WithMaxBodyBytes(n int64) HandlerOption                                     // default 4096; ≤0 disables cap
func WithSuccessRedirect(url string) HandlerOption                               // 303 on success
func WithFailureRedirect(url string) HandlerOption                               // 303 ?error=<code> on failure
func WithOnVerified(f func(http.ResponseWriter, *http.Request, uuid.UUID)) HandlerOption
func WithTrustedOrigins(origins ...string) HandlerOption                         // CSRF Origin/Referer allowlist
```

## Errors

```go
var ErrCodeNotFound    = errors.New("otp: no matching code")  // absent, expired, or burned
var ErrInvalidCode     = errors.New("otp: invalid code")      // wrong guess
var ErrTooManyAttempts = errors.New("otp: too many attempts") // code is burned
var ErrTenantMismatch  = errors.New("otp: tenant ID mismatch")
var ErrCooldownActive  = errors.New("otp: cooldown active; please wait before requesting another code") // Issue within Cooldown
```

`ErrCodeNotFound` and `ErrInvalidCode` are deliberately indistinguishable at the handler layer.
`IssueHandler` swallows `ErrCooldownActive` too: it still answers `204` and simply does not
deliver, so the cooldown is not a client-visible oracle.

## Code specifics

**Format:** numeric only, zero-padded (e.g. `"004217"`). Generated with `crypto/rand` + rejection-free `big.Int` sampling (no modulo bias).

**Length:** configurable via `WithDigits`; default 6.

**TTL:** default 10 minutes. Expiry checked in `Verify`; expired records deleted inline.

**Single-use + hash guard:** `ConsumeOTP` atomically removes the row only if its `CodeHash` equals the hash the verifier compared, so under concurrency only one caller observes `consumed=true`, and a code reissued between the verifier's read and consume leaves the fresh row untouched (`consumed=false`) — the stale verification fails instead of accepting or burning its replacement. A replayed correct code after consumption returns `ErrCodeNotFound`.

**Attempt limiting:** `IncrementOTPAttempts` called atomically BEFORE `compareCode`. On reaching `maxAttempts`, code is burned (`DeleteOTP`) and `AccountBlocked` event emitted. Default: 5 attempts. No `WithNoAttemptLimit` — attempts cannot be disabled; bad config clamps to default.

**Atomic issuance + cooldown:** `Issue` mints the code and persists it through the single store operation `Store.IssueOTP(..., cooldown)`, which enforces the resend cooldown and the upsert under one lock. Concurrent issue requests therefore cannot all pass the check: exactly one wins and the rest get `ErrCooldownActive`. Cooldown defaults to `DefaultCooldown` (30 s) and is configurable via `WithCooldown`; a non-positive value disables it.

**Issuance tombstone:** the last-issued instant is durable state that MUST survive every terminal transition of the previous code — `ConsumeOTP`, `DeleteOTP`, expiry and eviction. Burning or verifying a code therefore cannot reset the resend throttle or the per-code attempt budget: after 5 wrong guesses the attacker cannot re-issue immediately and start a fresh 5-guess budget. (The in-memory store keeps a separate `issued` map; the pgx store keeps a separate `otp_issuances` row — see `003_create_otp_issuances.sql`.)

**Hash:** hex-encoded SHA-256 of the raw numeric string. Low-entropy by design; the hash does NOT protect against a database exfiltration — protection comes from TTL + single-use + attempt limit.

**Delivery:** `Issue` returns `Challenge.Code` (plaintext, one-time). Application is responsible for delivery. `IssueHandler` dispatches delivery in a goroutine off the response path.

**Purpose:** arbitrary string scoping the code (e.g. `"login"`, `"email-verify"`, `"step-up"`). One outstanding code per `subjectID+purpose`. A successful `Issue` replaces the existing code for the same subject+purpose; an issue inside the cooldown returns `ErrCooldownActive`, stores nothing, and leaves the existing code outstanding.

**Eviction:** `DeleteExpired(ctx, tenantID)` is the GC reaper. The default memory store is bounded and self-evicting; `DeleteExpired` is required only for the explicit `NewUnboundedStore()` opt-in, where the map grows without bound unless called periodically.

**Low-level helper:**
```go
func HashCode(code string) string  // hex-encoded SHA-256; only persisted form
```

## Wiring

```go
store := memory.NewStore() // bounded by DefaultMaxEntries; no scheduler needed
svc   := otp.NewService(store,
    otp.WithTTL(10*time.Minute),
    otp.WithMaxAttempts(5),
    otp.WithEventSink(mySink),
)

// For janitor-evicted growth control instead, opt into the unbounded model and
// schedule DeleteExpired periodically:
//   store := memory.NewUnboundedStore()
//   j := janitor.Start(ctx, 5*time.Minute, func() {
//       store.DeleteExpired(context.Background(), tenantID)
//   })
//   defer j.Stop()

resolveSubject := func(r *http.Request) (uuid.UUID, bool) {
    // e.g. look up user by submitted email address
    userID, ok := lookupUserByEmail(r.PostFormValue("email"))
    return userID, ok
}

deliver := func(ctx context.Context, ch *otp.Challenge) error {
    return mailer.Send(ctx, ch.SubjectID, ch.Code, ch.ExpiresAt)
}

mux.Handle("/otp/issue",  otp.IssueHandler(svc, deliver,
    otp.WithSubjectResolver(resolveSubject),
    otp.WithPurpose("login"),
))
mux.Handle("/otp/verify", otp.VerifyHandler(svc,
    otp.WithSubjectResolver(resolveSubject),
    otp.WithPurpose("login"),
    otp.WithOnVerified(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
        // issue session/token pair
    }),
))
```

## Gotchas

- `Challenge.Code` is the plaintext — treat it as a credential; never log or store it. Only `CodeHash` is persisted. `Challenge`/`OTP` self-redact the code/hash in `%v`/`%#v`/`slog` output, but that is a safety net, not permission to log them.
- `IssueHandler` always returns `204` — do NOT rely on its status to determine whether a code was issued or delivery succeeded.
- All `VerifyHandler` failures are `401 invalid_code` — callers cannot distinguish a wrong guess from an expired/missing challenge. This is intentional (enumeration safety).
- `Issue` replaces any outstanding code for the same `subjectID+purpose` once the cooldown admits it. Inside the cooldown it returns `ErrCooldownActive`, stores nothing, and the old code stays valid.
- Memory store is bounded by default (`NewStore()` caps at `DefaultMaxEntries`, self-evicting expired then soonest-expiring). The explicit `NewUnboundedStore()` opt-in MUST have `DeleteExpired` called periodically; skipping it is a denial-of-service vector (unbounded map growth).
- `WithSubjectResolver` returning `ok=false` still produces a uniform `401 invalid_code` on `VerifyHandler` (not a different status).
- `NewSingleTenant` hard-wires `tenantID=""`. Do NOT mix with multi-tenant `Service` calls against the same store.
- `NewService` panics on nil store and on `digits` outside `[6, 10]`; invalid `ttl`/`maxAttempts` values are silently clamped to defaults, and a negative `cooldown` is clamped to 0 (disabled).
- A custom `Store` adapter MUST implement `IssueOTP` atomically (cooldown check + upsert in one lock/statement) and keep the last-issued instant across every code transition; a non-atomic read-then-write silently reopens the concurrent-issue and burn-resets-throttle holes. Run `otp/storetest` against your adapter.
- The strict same-origin CSRF check is ON by default (a request whose Origin/Referer host is not the request host or a trusted origin is rejected `403`, as is a POST carrying neither header). `WithTrustedOrigins` widens the allowlist (bare hosts or full origins); `WithInsecureNoOriginCheck` is the loud opt-out.
- The `deliver` callback in `IssueHandler` runs in a goroutine; errors are silently discarded. Instrument delivery failures in the callback itself.
