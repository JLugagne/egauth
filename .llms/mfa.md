# mfa — TOTP (RFC 6238) second-factor + single-use recovery codes

import: `github.com/JLugagne/egauth/mfa`
memory store: `github.com/JLugagne/egauth/mfa/memory`
source: `mfa/service.go`, `mfa/totp.go`, `mfa/recovery.go`, `mfa/handlers.go`

## Purpose

Authenticator-app TOTP second factor (RFC 6238 / RFC 4226) with single-use
recovery codes. Plugs into egauth via a `Store` interface (memory + pgx
implementations). Stateless service, stateful store; à-la-carte HTTP handlers.
SMS/phone factors are intentionally NOT supported.

## Whether MFA is required is YOUR decision, not the library's

The library supplies the second factor and the machinery to enforce it. It never decides on its own
that an account must present one: every point that could require MFA is off unless you turn it on.
That is deliberate — a library that silently demanded a second factor would break every application
whose users have not enrolled, and one that silently accepted a password when a factor exists would
make the factor decorative.

There are four decisions, all yours:

| Decision | Where you make it | Default if you do nothing |
|---|---|---|
| Require a second factor at password login | `identity.WithMFAGate(checker)` on `LoginHandler` / `MagicLinkLoginHandler` | no gate: a password yields a full pair |
| Require one at the OAuth callback | `oauth.WithMFAGate(checker)` on `CallbackHandler` | no gate: a provider login yields a full pair |
| Require one on a specific route of yours | `tokens.WithRequiredAMR(tokens.AMRMFA)` on `RequireAuth` / `ContextMiddleware` | no gate: any verified token passes |
| Require a fresh factor before a factor secret changes | `mfa.WithStepUpRequired(false)` to opt OUT | ON: `DisableHandler` and `RegenerateRecoveryCodesHandler` demand an elevated session |

`mfa.Service` (and `identity.Service`) satisfy the gate interface, so wiring is
`identity.WithMFAGate(mfaSvc)`.

The last row is the one default that is ON, and it is a different question from the other three.
Rows 1–3 are "must this user have MFA?" — your product policy. Row 4 is "may a session that has not
presented a factor destroy the factor?" — that is not a policy choice but the difference between a
factor and a decoration, so it is closed by default and opened explicitly with
`mfa.WithStepUpRequired(false)` (or `WithoutStepUp()`) when an outer layer enforces the same thing.

What follows from rows 1–3 being off: **completing MFA enrolment enforces nothing at login.** If you
mount `EnrollHandler` / `ConfirmHandler` / `VerifyHandler` (with the enrolment assurance gate wired,
as required below) without an MFA policy gate, users can enrol and confirm an authenticator, and the
next password login still issues a full session. That is not a defect — the library cannot know your
policy — but it is a wiring mistake that looks like a working setup, so check it deliberately when
you enable MFA.

**What is not left to policy:** *which session may enroll a factor* and *whether step-up may mint
from the interim token alone*. Both are fail-closed by default:

- `EnrollHandler` / `ConfirmHandler` refuse `403 assurance_required` unless you wire
  `mfa.WithCredentialAssurance(tokens.DenyInterim)` or the explicit
  `mfa.WithInsecureNoAssuranceCheck()` opt-out. Without the gate a password-only interim session
  could enroll its own factor and complete step-up with it.
- `StepUpHandler` refuses `500 misconfigured` without an authoritative
  `mfa.WithSessionStateResolver(...)`; the legacy echo behaviour is only available through
  `mfa.WithInsecureEchoSessionState()`. Minting the final renewable pair from the interim token's
  own subject would let an account disabled between the two factors obtain a fresh session.

## Service interface

```go
type Service interface {
    EnrollTOTP(ctx context.Context, tenantID string, userID uuid.UUID, account string) (*Enrollment, error)
    ConfirmTOTP(ctx context.Context, tenantID string, userID uuid.UUID, code string) ([]string, error)
    VerifyTOTP(ctx context.Context, tenantID string, userID uuid.UUID, code string) error
    VerifyRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, code string) error
    RegenerateRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) ([]string, error)
    DisableTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error
    IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)
}
```

## Key types

```go
type Enrollment struct {
    Secret string   // base32-encoded, no padding, uppercase; shown once
    URI    string   // otpauth:// provisioning URI for QR code
}

type TOTPEnrollment struct {
    UserID         uuid.UUID
    TenantID       string
    Secret         string      // base32, NOT hashed (server must recompute codes)
    ConfirmedAt    *time.Time  // nil = unconfirmed
    LastUsedStep   int64       // replay protection: last accepted time-step counter
    FailedAttempts int         // consecutive failures; reset on success
    CreatedAt      time.Time
}

type RecoveryCode struct {
    UserID    uuid.UUID
    TenantID  string
    CodeHash  string      // hex-encoded SHA-256 of normalized plaintext
    UsedAt    *time.Time
    CreatedAt time.Time
}
```

## Constructors

```go
// Service
func NewService(store Store, opts ...ServiceOption) Service
    // panics on nil store or invalid TOTP params

// ServiceOption functions
func WithIssuer(issuer string) ServiceOption          // default "egauth"
func WithDigits(d int) ServiceOption                  // default 6
func WithPeriod(p time.Duration) ServiceOption        // default 30s
func WithSkew(n int) ServiceOption                    // default 1 (±1 period clock drift)
func WithRecoveryCodeCount(n int) ServiceOption       // default 10
func WithMaxAttempts(n int) ServiceOption             // default 5; 0 → use default
func WithNoAttemptLimit() ServiceOption               // disable attempt limiting (insecure without external rate limit)
func WithClock(now func() time.Time) ServiceOption    // test injection
func WithEventSink(sink event.Sink) ServiceOption     // optional security-event sink

// Single-tenant wrapper (omits tenantID, uses "" internally)
func NewSingleTenant(svc Service) *SingleTenant

// Memory store
func memory.NewStore() *memory.Store              // bounded by DefaultMaxEntries recovery-attempt records
func memory.NewBoundedStore(n int) *memory.Store  // pick the cap; a record under an active lockout is NEVER evicted
func memory.NewUnboundedStore() *memory.Store     // explicit opt-out; reap with DeleteStaleRecoveryAttempts
func (s *memory.Store) DeleteStaleRecoveryAttempts(ctx, tenantID string, cutoff time.Time) (int64, error)
```

## Store contract

```go
// Store composes four capability interfaces. Both the in-memory and pgx stores implement the
// whole Store; new optional behaviour ships as a new capability rather than a method here.
type Store interface {
    TOTPStore
    RecoveryCodeStore
    RecoveryAttemptStore
    EnrollmentConfirmer
}

type TOTPStore interface {
    SaveTOTP(ctx context.Context, tenantID string, e *TOTPEnrollment) error
    GetTOTP(ctx context.Context, tenantID string, userID uuid.UUID) (*TOTPEnrollment, error)
    DeleteTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error
    // MarkTOTPUsed: returns false=replay; on true MUST reset FailedAttempts to 0
    MarkTOTPUsed(ctx context.Context, tenantID string, userID uuid.UUID, step int64) (bool, error)
    // IncrementTOTPAttempts: atomic pre-compare gate; returns new count; ErrNotEnrolled if absent
    IncrementTOTPAttempts(ctx context.Context, tenantID string, userID uuid.UUID, now time.Time, maxAttempts int, lockoutDuration time.Duration) (int, error)
    // ResetTOTPAttempts: clears the counter/LastAttemptAt (time-based decay + admin UnlockMFA)
    ResetTOTPAttempts(ctx context.Context, tenantID string, userID uuid.UUID) error
}

type RecoveryCodeStore interface {
    // ReplaceRecoveryCodes: atomically discards old hashes, stores new ones
    ReplaceRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID, codeHashes []string) error
    // ConsumeRecoveryCode: single-use; on success MUST reset FailedAttempts to 0
    ConsumeRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, codeHash string) error
    DeleteRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) error
}

type RecoveryAttemptStore interface {
    // IncrementRecoveryAttempts: isolated lockout gate for recovery codes (SEC-MFA-05);
    // the fix for the concurrent first-burst bypass (F-PGX-001) is an atomic upsert that
    // creates the absent row and increments it in one statement.
    IncrementRecoveryAttempts(ctx context.Context, tenantID string, userID uuid.UUID, now time.Time, maxAttempts int, lockoutDuration time.Duration) (int, error)
    ResetRecoveryAttempts(ctx context.Context, tenantID string, userID uuid.UUID) error
}

type EnrollmentConfirmer interface {
    // ConfirmEnrollment: atomically marks the enrollment confirmed AND persists the initial
    // recovery-code hashes (both or neither).
    ConfirmEnrollment(ctx context.Context, tenantID string, enrollment *TOTPEnrollment, codeHashes []string) error
}
```

Empty `tenantID` (`""`) is the single-tenant partition; must still be passed.
`ErrTenantMismatch` if existing record's TenantID conflicts.

## HTTP handlers

All handlers: `POST` only; require `WithUserResolver`; parse form fields.
`UserResolver func(r *http.Request) (userID uuid.UUID, tenant string, ok bool)`

| Handler | Route (suggested) | Success | Failure |
|---|---|---|---|
| `EnrollHandler` | `POST /mfa/enroll` | `200 {"secret":"…","uri":"otpauth://…"}` | 403 `assurance_required` (gate unwired/denied), 401/409/400/500 |
| `ConfirmHandler` | `POST /mfa/confirm` | `200 {"recovery_codes":["ABCD-EFGH-…",…]}` | 403 `assurance_required` (gate unwired/denied), 401/400/409/500 |
| `VerifyHandler` | `POST /mfa/verify` | `204` (or 303) | 401/429/400/500 |
| `VerifyRecoveryHandler` | `POST /mfa/verify-recovery` | `204` (or 303) | 401/429/500 |
| `RegenerateRecoveryCodesHandler` | `POST /mfa/recovery/regenerate` | `200 {"recovery_codes":[…]}` | 401/400/500 |
| `DisableHandler` | `POST /mfa/disable` | `204` (or 303) | 401/500 |
| `StepUpHandler` | `POST /mfa/step-up` | `204` (sets full access+refresh cookies) | 500 `misconfigured` (no session-state resolver), 401/429/500 |

Error body: plain text error code string.

| HTTP status | error string | sentinel |
|---|---|---|
| 429 | `too_many_attempts` | `ErrTooManyAttempts` |
| 401 | `invalid_code` | `ErrInvalidCode`, `ErrRecoveryCodeNotFound` |
| 409 | `already_enrolled` | `ErrAlreadyEnrolled` |
| 400 | `not_enrolled` | `ErrNotEnrolled` |
| 400 | `not_confirmed` | `ErrNotConfirmed` |
| 403 | `assurance_required` | assurance gate unwired or denied (`EnrollHandler`/`ConfirmHandler`) |
| 500 | `misconfigured` | `StepUpHandler` without `WithSessionStateResolver` |
| 500 | `mfa_error` | any other |

Handler options:
```go
func WithUserResolver(r UserResolver) HandlerOption   // required
func WithAccountField(name string) HandlerOption      // default "account"
func WithCodeField(name string) HandlerOption         // default "code"
func WithSuccessRedirect(rawURL string) HandlerOption // action handlers: 303 on success
func WithFailureRedirect(rawURL string) HandlerOption // 303 ?error=<code> on failure
func WithCredentialAssurance(fn func(*http.Request) error) HandlerOption // gate Enroll/Confirm; canonical: tokens.DenyInterim
func WithInsecureNoAssuranceCheck() HandlerOption      // explicit opt-out of the enrollment gate (insecure)
func WithSessionStateResolver(r issuance.Resolver) HandlerOption // authoritative account state; REQUIRED by StepUpHandler
func WithInsecureEchoSessionState() HandlerOption      // explicit opt-out restoring the legacy StepUp echo behavior
func WithMustChangeResolver(fn func(*http.Request) bool) HandlerOption // force-change signal for step-up
```

## Errors

```go
var ErrNotEnrolled         = errors.New("mfa: not enrolled")
var ErrAlreadyEnrolled     = errors.New("mfa: already enrolled")
var ErrNotConfirmed        = errors.New("mfa: enrollment not confirmed")
var ErrInvalidCode         = errors.New("mfa: invalid code")
var ErrRecoveryCodeNotFound = errors.New("mfa: recovery code not found")
var ErrTooManyAttempts     = errors.New("mfa: too many attempts")
var ErrTenantMismatch      = errors.New("mfa: tenant ID mismatch")
```

## TOTP specifics

**Algorithm:** HMAC-SHA1, per RFC 4226. Algorithm is fixed to SHA1 (universal authenticator-app support).

**Defaults:** 6 digits, 30s period, ±1 period skew (accepts previous/current/next window).

**Secret:** 160-bit random, base32-encoded (no padding, uppercase). Stored in recoverable form (NOT hashed) — server must recompute expected codes. See SECURITY.md for at-rest considerations.

**Provisioning URI format:** `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=SHA1&digits=…&period=…`

**Enroll/verify flow:**
1. `EnrollTOTP` → returns `Enrollment{Secret, URI}`; factor is UNCONFIRMED; re-enrollment allowed if not yet confirmed; `ErrAlreadyEnrolled` if confirmed factor exists.
2. User scans QR code / enters secret into authenticator app.
3. `ConfirmTOTP(code)` → validates code, marks confirmed, sets `LastUsedStep` (confirming code cannot replay), returns `[]string` recovery codes (shown ONCE).
4. `VerifyTOTP(code)` → replay-protected via `MarkTOTPUsed`; attempt-limited; `ErrNotConfirmed` if step 3 skipped.

**Replay protection:** `LastUsedStep` tracks most-recent accepted time-step counter. `MarkTOTPUsed` rejects step ≤ stored value (returns `false`) and resets `FailedAttempts` on acceptance.

**Attempt limiting:** `IncrementTOTPAttempts` is called atomically BEFORE `validateTOTP`. Slot is reserved pre-compare to prevent concurrent brute-force beyond the limit. Counter shared between TOTP and recovery code paths. Successful verify/consume resets to 0.

**Recovery codes:** 80-bit random, base32-encoded, grouped as `ABCD-EFGH-IJKL-MNOP`. Stored as hex-encoded SHA-256. Normalization strips dashes/whitespace and uppercases before hashing (tolerates formatting variation on re-entry). Default count: 10. Regenerating invalidates all existing codes.

**DisableTOTP:** idempotent; removes enrollment AND all recovery codes. Gate with `tokens.RequireAuth(..., tokens.WithMaxAuthAge(d))` to prevent a hijacked session silently stripping MFA.

**Rate limiting:** egauth does NOT apply per-IP rate limits to verify endpoints. Use `github.com/JLugagne/egauth/ratelimit.Middleware` to wrap `VerifyHandler` and `VerifyRecoveryHandler`.

**Low-level helpers (testing/tooling only):**
```go
func GenerateSecret() (string, error)
func GenerateCode(secret string, at time.Time, digits int, period time.Duration) (string, error)
func ProvisioningURI(secret, issuer, account string, digits int, period time.Duration) string
func HashRecoveryCode(code string) string
```

## Wiring

```go
store := memory.NewStore() // or pgx store
svc   := mfa.NewService(store,
    mfa.WithIssuer("MyApp"),
    mfa.WithEventSink(mySink),
)

// tokens.UserResolverFromContext reads the Actor injected by ContextMiddleware / RequireAuth;
// front each handler with one of those middlewares.
resolve := mfa.UserResolver(tokens.UserResolverFromContext)

// Enrollment is fail-closed: without an assurance gate these answer 403 assurance_required.
// tokens.DenyInterim refuses only an interim (pre-MFA) session.
enrollOpts := []mfa.HandlerOption{
    mfa.WithUserResolver(resolve),
    mfa.WithCredentialAssurance(tokens.DenyInterim),
}
mux.Handle("/mfa/enroll",             mfa.EnrollHandler(svc, enrollOpts...))
mux.Handle("/mfa/confirm",            mfa.ConfirmHandler(svc, enrollOpts...))
mux.Handle("/mfa/verify",             mfa.VerifyHandler(svc, mfa.WithUserResolver(resolve)))
mux.Handle("/mfa/verify-recovery",    mfa.VerifyRecoveryHandler(svc, mfa.WithUserResolver(resolve)))
mux.Handle("/mfa/recovery/regenerate",mfa.RegenerateRecoveryCodesHandler(svc, mfa.WithUserResolver(resolve)))
mux.Handle("/mfa/disable",            mfa.DisableHandler(svc, mfa.WithUserResolver(resolve)))

// Step-up is fail-closed: without an authoritative account-state resolver it answers
// 500 misconfigured. The identity.Service *interface* does not expose ResolveSessionState;
// the concrete service from identity.NewService does, so assert it (or supply your own).
sessionResolver, ok := identitySvc.(issuance.Resolver)
if !ok {
    panic("identity service does not expose authoritative session state")
}
mux.Handle("/mfa/step-up", mfa.StepUpHandler(svc, issuer, claimsOf,
    mfa.WithUserResolver(resolve),
    mfa.WithSessionStateResolver(sessionResolver),
))
```

## Gotchas

- `TOTPEnrollment.Secret` is stored in plaintext (server must recompute codes). Encrypt at rest; see SECURITY.md. `TOTPEnrollment` implements `String`/`GoString`/`LogValue` and redacts `Secret` on all fmt/slog paths.
- `ErrAlreadyEnrolled` is returned if attempting to re-enroll a CONFIRMED factor. Call `DisableTOTP` first.
- `VerifyTOTP` returns `ErrNotConfirmed` (not `ErrNotEnrolled`) if enrollment exists but was never confirmed.
- TOTP and recovery codes have **independent** attempt budgets (`IncrementTOTPAttempts` vs `IncrementRecoveryAttempts`, SEC-MFA-05): exhausting one does not lock the other. A successful verification on either path clears both counters.
- `MarkTOTPUsed` returning `false` for a cryptographically correct code means replay; treated as failure (slot already consumed, counter NOT reset).
- `WithNoAttemptLimit` leaves the factor online-brute-forceable; only use with an external rate limiter.
- `NewSingleTenant` hard-wires `tenantID=""`. Do NOT mix with multi-tenant `Service` calls against the same store.
- `NewService` panics (not errors) on nil store or invalid config — designed to fail at startup.
- Data handlers (`EnrollHandler`, `ConfirmHandler`, `RegenerateRecoveryCodesHandler`) always return JSON even when `WithSuccessRedirect` is set; only action handlers (`VerifyHandler`, `DisableHandler`) redirect on success.
