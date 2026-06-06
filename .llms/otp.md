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

## Constructors

```go
// Service
func NewService(store Store, opts ...ServiceOption) Service
    // panics on nil store; clamps invalid digits/TTL/maxAttempts to defaults

// ServiceOption functions
func WithDigits(n int) ServiceOption                  // default 6
func WithTTL(d time.Duration) ServiceOption           // default 10m
func WithMaxAttempts(n int) ServiceOption             // default 5
func WithClock(now func() time.Time) ServiceOption    // test injection
func WithEventSink(sink event.Sink) ServiceOption     // AccountBlocked event on code burn

// Single-tenant wrapper (omits tenantID, uses "" internally)
func NewSingleTenant(svc Service) *SingleTenant

// Memory store
func memory.NewStore() *memory.Store
```

## Store contract

```go
type Store interface {
    // SaveOTP: upserts; resets Attempts on replace; ErrTenantMismatch on conflicting TenantID
    SaveOTP(ctx context.Context, tenantID string, o *OTP) error
    // GetOTP: returns outstanding code or ErrCodeNotFound
    GetOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (*OTP, error)
    // IncrementOTPAttempts: atomic pre-compare gate; returns new count; ErrCodeNotFound if absent
    IncrementOTPAttempts(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (int, error)
    // ConsumeOTP: atomic single-use guard; consumed=true only for the ONE caller that removes the row
    ConsumeOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (consumed bool, err error)
    // DeleteOTP: idempotent; used for expiry, burn, Invalidate
    DeleteOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) error
    // DeleteExpired: schedulable GC reaper; returns count deleted; scoped to one tenant
    DeleteExpired(ctx context.Context, tenantID string) (int64, error)
}
```

Empty `tenantID` (`""`) is the single-tenant partition; must still be passed.
`ErrTenantMismatch` if existing record's TenantID conflicts.

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
```

`ErrCodeNotFound` and `ErrInvalidCode` are deliberately indistinguishable at the handler layer.

## Code specifics

**Format:** numeric only, zero-padded (e.g. `"004217"`). Generated with `crypto/rand` + rejection-free `big.Int` sampling (no modulo bias).

**Length:** configurable via `WithDigits`; default 6.

**TTL:** default 10 minutes. Expiry checked in `Verify`; expired records deleted inline.

**Single-use:** `ConsumeOTP` atomically removes the row; under concurrency only one caller observes `consumed=true`. A replayed correct code after consumption returns `ErrCodeNotFound`.

**Attempt limiting:** `IncrementOTPAttempts` called atomically BEFORE `compareCode`. On reaching `maxAttempts`, code is burned (`DeleteOTP`) and `AccountBlocked` event emitted. Default: 5 attempts. No `WithNoAttemptLimit` — attempts cannot be disabled; bad config clamps to default.

**Hash:** hex-encoded SHA-256 of the raw numeric string. Low-entropy by design; the hash does NOT protect against a database exfiltration — protection comes from TTL + single-use + attempt limit.

**Delivery:** `Issue` returns `Challenge.Code` (plaintext, one-time). Application is responsible for delivery. `IssueHandler` dispatches delivery in a goroutine off the response path.

**Purpose:** arbitrary string scoping the code (e.g. `"login"`, `"email-verify"`, `"step-up"`). One outstanding code per `subjectID+purpose`. `Issue` replaces any existing code for the same subject+purpose.

**Eviction:** `DeleteExpired(ctx, tenantID)` is the GC reaper. Memory store grows without bound unless called periodically.

**Low-level helper:**
```go
func HashCode(code string) string  // hex-encoded SHA-256; only persisted form
```

## Wiring

```go
store := memory.NewStore()
svc   := otp.NewService(store,
    otp.WithTTL(10*time.Minute),
    otp.WithMaxAttempts(5),
    otp.WithEventSink(mySink),
)

// Periodic eviction (mandatory for memory store in production)
go func() {
    t := time.NewTicker(5 * time.Minute)
    for range t.C {
        store.DeleteExpired(context.Background(), "")
    }
}()

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

- `Challenge.Code` is the plaintext — treat it as a credential; never log or store it. Only `CodeHash` is persisted.
- `IssueHandler` always returns `204` — do NOT rely on its status to determine whether a code was issued or delivery succeeded.
- All `VerifyHandler` failures are `401 invalid_code` — callers cannot distinguish a wrong guess from an expired/missing challenge. This is intentional (enumeration safety).
- `Issue` replaces any outstanding code for the same `subjectID+purpose`. Old code is invalidated immediately.
- Memory store MUST have `DeleteExpired` called periodically; skipping it is a denial-of-service vector (unbounded map growth).
- `WithSubjectResolver` returning `ok=false` still produces a uniform `401 invalid_code` on `VerifyHandler` (not a different status).
- `NewSingleTenant` hard-wires `tenantID=""`. Do NOT mix with multi-tenant `Service` calls against the same store.
- `NewService` panics on nil store; invalid `digits`/`ttl`/`maxAttempts` values are silently clamped to defaults (not panics).
- `WithTrustedOrigins` is disabled by default. When set, requests with an unrecognized or missing Origin/Referer are rejected `403`.
- The `deliver` callback in `IssueHandler` runs in a goroutine; errors are silently discarded. Instrument delivery failures in the callback itself.
