# mfa — TOTP (RFC 6238) second-factor + single-use recovery codes

import: `github.com/JLugagne/egauth/mfa`
memory store: `github.com/JLugagne/egauth/mfa/memory`
source: `mfa/service.go`, `mfa/totp.go`, `mfa/recovery.go`, `mfa/handlers.go`

## Purpose

Authenticator-app TOTP second factor (RFC 6238 / RFC 4226) with single-use
recovery codes. Plugs into egauth via a `Store` interface (memory + pgx
implementations). Stateless service, stateful store; à-la-carte HTTP handlers.
SMS/phone factors are intentionally NOT supported.

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
func memory.NewStore() *memory.Store
```

## Store contract

```go
type Store interface {
    SaveTOTP(ctx context.Context, tenantID string, e *TOTPEnrollment) error
    GetTOTP(ctx context.Context, tenantID string, userID uuid.UUID) (*TOTPEnrollment, error)
    DeleteTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error
    // MarkTOTPUsed: returns false=replay; on true MUST reset FailedAttempts to 0
    MarkTOTPUsed(ctx context.Context, tenantID string, userID uuid.UUID, step int64) (bool, error)
    // IncrementTOTPAttempts: atomic pre-compare gate; returns new count; ErrNotEnrolled if absent
    IncrementTOTPAttempts(ctx context.Context, tenantID string, userID uuid.UUID, now time.Time, maxAttempts int, lockoutDuration time.Duration) (int, error)

    // ReplaceRecoveryCodes: atomically discards old hashes, stores new ones
    ReplaceRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID, codeHashes []string) error
    // ConsumeRecoveryCode: single-use; on success MUST reset FailedAttempts to 0
    ConsumeRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, codeHash string) error
    DeleteRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) error
}
```

Empty `tenantID` (`""`) is the single-tenant partition; must still be passed.
`ErrTenantMismatch` if existing record's TenantID conflicts.

## HTTP handlers

All handlers: `POST` only; require `WithUserResolver`; parse form fields.
`UserResolver func(r *http.Request) (userID uuid.UUID, tenant string, ok bool)`

| Handler | Route (suggested) | Success | Failure |
|---|---|---|---|
| `EnrollHandler` | `POST /mfa/enroll` | `200 {"secret":"…","uri":"otpauth://…"}` | 401/409/400/500 |
| `ConfirmHandler` | `POST /mfa/confirm` | `200 {"recovery_codes":["ABCD-EFGH-…",…]}` | 401/400/409/500 |
| `VerifyHandler` | `POST /mfa/verify` | `204` (or 303) | 401/429/400/500 |
| `VerifyRecoveryHandler` | `POST /mfa/verify-recovery` | `204` (or 303) | 401/429/500 |
| `RegenerateRecoveryCodesHandler` | `POST /mfa/recovery/regenerate` | `200 {"recovery_codes":[…]}` | 401/400/500 |
| `DisableHandler` | `POST /mfa/disable` | `204` (or 303) | 401/500 |

Error body: plain text error code string.

| HTTP status | error string | sentinel |
|---|---|---|
| 429 | `too_many_attempts` | `ErrTooManyAttempts` |
| 401 | `invalid_code` | `ErrInvalidCode`, `ErrRecoveryCodeNotFound` |
| 409 | `already_enrolled` | `ErrAlreadyEnrolled` |
| 400 | `not_enrolled` | `ErrNotEnrolled` |
| 400 | `not_confirmed` | `ErrNotConfirmed` |
| 500 | `mfa_error` | any other |

Handler options:
```go
func WithUserResolver(r UserResolver) HandlerOption   // required
func WithAccountField(name string) HandlerOption      // default "account"
func WithCodeField(name string) HandlerOption         // default "code"
func WithSuccessRedirect(rawURL string) HandlerOption // action handlers: 303 on success
func WithFailureRedirect(rawURL string) HandlerOption // 303 ?error=<code> on failure
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

**Secret:** 160-bit random, base32-encoded (no padding, uppercase). Stored in recoverable form (NOT hashed) — server must recompute expected codes. A secret decoding to fewer than `mfa.MinSecretBytes` (16 = 128 bits, the RFC 4226 minimum) is rejected with `mfa.ErrWeakSecret` at enrollment AND at verification, so an empty or truncated secret can never key the HMAC. See SECURITY.md for at-rest considerations.

**Provisioning URI format:** `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=SHA1&digits=…&period=…`

**Enroll/verify flow:**
1. `EnrollTOTP` → returns `Enrollment{Secret, URI}`; factor is UNCONFIRMED; re-enrollment allowed if not yet confirmed; `ErrAlreadyEnrolled` if confirmed factor exists.
2. User scans QR code / enters secret into authenticator app.
3. `ConfirmTOTP(code)` → validates code, marks confirmed, sets `LastUsedStep` (confirming code cannot replay), returns `[]string` recovery codes (shown ONCE).
4. `VerifyTOTP(code)` → replay-protected via `MarkTOTPUsed`; attempt-limited; `ErrNotConfirmed` if step 3 skipped.

**Replay protection:** `LastUsedStep` tracks most-recent accepted time-step counter. `MarkTOTPUsed` rejects step ≤ stored value (returns `false`) and resets `FailedAttempts` on acceptance.

**Attempt limiting:** `IncrementTOTPAttempts` is called atomically BEFORE `validateTOTP`. Slot is reserved pre-compare to prevent concurrent brute-force beyond the limit. Counter shared between TOTP and recovery code paths. Successful verify/consume resets to 0.

**Recovery codes:** 80-bit random, base32-encoded, grouped as `ABCD-EFGH-IJKL-MNOP`. Stored as hex-encoded SHA-256. Normalization strips dashes/whitespace and uppercases before hashing (tolerates formatting variation on re-entry). Default count: 10. Regenerating invalidates all existing codes.

**DisableTOTP:** idempotent; removes enrollment AND all recovery codes. `DisableHandler` and `RegenerateRecoveryCodesHandler` ENFORCE step-up themselves: they refuse (403 `step_up_required`) any request whose credential does not prove a second factor (`tokens.Claims.SatisfiesStepUp` — AMR carries `mfa`/`otp`/`hwk` and the credential is not a pre-step-up interim one). The assurance comes from `mfa.WithAssuranceResolver`, defaulting to `tokens.AssuranceResolverFromContext`, so mounting them behind `tokens.ContextMiddleware` is all the wiring needed; a request with no resolvable assurance is refused (fail closed). Opt out with `mfa.WithInsecureNoStepUpCheck()`.

Do NOT rely on `tokens.WithMaxAuthAge(d)` alone for these routes: a pre-MFA interim credential is freshly issued, so an `auth_time` freshness window passes trivially. Add `tokens.WithRequiredAMR(tokens.AMRMFA)` (optionally alongside `WithMaxAuthAge` for a sudo-mode window) to state the same requirement at the routing layer.

**Rate limiting:** egauth does NOT apply per-IP rate limits to verify endpoints. Use `github.com/JLugagne/egauth/ratelimit.Middleware` to wrap `VerifyHandler` and `VerifyRecoveryHandler`.

**Low-level helpers (testing/tooling only):**
```go
func GenerateSecret() (string, error)
func GenerateCode(secret string, at time.Time, digits int, period time.Duration) (string, error)
func ProvisioningURI(secret, issuer, account string, digits int, period time.Duration) string
func ValidateSecret(secret string) error   // ErrWeakSecret if < MinSecretBytes of entropy
func HashRecoveryCode(code string) string
```

## Wiring

```go
store := memory.NewStore() // or pgx store
svc   := mfa.NewService(store,
    mfa.WithIssuer("MyApp"),
    mfa.WithEventSink(mySink),
)

resolve := mfa.UserResolver(func(r *http.Request) (uuid.UUID, string, bool) {
    // extract from auth middleware context
    claims, ok := tokens.ClaimsFromContext(r.Context())
    if !ok { return uuid.Nil, "", false }
    return claims.UserID, claims.TenantID, true
})

mux.Handle("/mfa/enroll",             mfa.EnrollHandler(svc, mfa.WithUserResolver(resolve)))
mux.Handle("/mfa/confirm",            mfa.ConfirmHandler(svc, mfa.WithUserResolver(resolve)))
mux.Handle("/mfa/verify",             mfa.VerifyHandler(svc, mfa.WithUserResolver(resolve)))
mux.Handle("/mfa/verify-recovery",    mfa.VerifyRecoveryHandler(svc, mfa.WithUserResolver(resolve)))

// Factor-mutating routes enforce step-up: mount them behind ContextMiddleware so the default
// tokens.AssuranceResolverFromContext can report the credential's assurance.
mux.Handle("/mfa/recovery/regenerate", tokens.ContextMiddleware[C](verifier,
    mfa.RegenerateRecoveryCodesHandler(svc, mfa.WithUserResolver(tokens.UserResolverFromContext)),
    tokens.WithCookieAuth[C](cookies)))
mux.Handle("/mfa/disable", tokens.ContextMiddleware[C](verifier,
    mfa.DisableHandler(svc, mfa.WithUserResolver(tokens.UserResolverFromContext)),
    tokens.WithCookieAuth[C](cookies)))

// The step-up route is the ONLY one that may admit the pre-MFA interim credential.
mux.Handle("/mfa/step-up", tokens.ContextMiddleware[C](verifier,
    mfa.StepUpHandler[C](svc, issuer, stepUpClaimsOf,
        mfa.WithUserResolver(tokens.UserResolverFromContext),
        mfa.WithMustChangeResolver(tokens.MustChangeResolverFromContext[C])),
    tokens.WithCookieAuth[C](cookies),
    tokens.WithInterimAllowed[C]()))
```

## Interim (pre-step-up) credential

`identity.WithMFAGate` / `oauth.WithMFAGate` hand an MFA-enrolled user a short-lived INTERIM
credential instead of a session: `tokens.Claims.Interim` is set, no step-up factor is present in its
AMR, no refresh cookie is written (and any refresh cookie from an earlier session is CLEARED) and,
with a `tokens.AccessTokenIssuer` (which `jwt.Service` implements), no refresh-token family is
persisted. The gated login reply is deliberately
distinguishable from a full login: header `X-Egauth-MFA-Required: 1` plus `200 {"mfa_required":true}`,
or a 303 to `identity.WithMFARequiredRedirect` / `oauth.WithMFARequiredRedirect`.

`tokens.RequireAuth` and `tokens.ContextMiddleware` refuse an interim credential with 403
`step_up_required` on EVERY route unless it opts in with `tokens.WithInterimAllowed()` — put that on
the step-up route only. `mfa.StepUpHandler` clears the interim state by re-issuing the full pair with
`AMR=[pwd, otp, mfa]`.

## Gotchas

- `TOTPEnrollment.Secret` is held in recoverable form (server must recompute codes). The pgx store envelope-encrypts it with a mandatory KEK; a custom store must encrypt at rest too — see SECURITY.md.
- `TOTPEnrollment` and `Enrollment` redact `Secret` (and the `URI`, which embeds it) on `fmt`/`slog`; JSON marshalling is deliberately NOT redacted, since returning the secret to the enrolling user is the point.
- A stored secret below `MinSecretBytes` makes `ConfirmTOTP`/`VerifyTOTP` return `ErrWeakSecret`, not `ErrInvalidCode` — that is a broken row, not a wrong code.
- `ErrAlreadyEnrolled` is returned if attempting to re-enroll a CONFIRMED factor. Call `DisableTOTP` first.
- `VerifyTOTP` returns `ErrNotConfirmed` (not `ErrNotEnrolled`) if enrollment exists but was never confirmed.
- Attempt counter is shared between TOTP and recovery code paths. Locking one locks both.
- `MarkTOTPUsed` returning `false` for a cryptographically correct code means replay; treated as failure (slot already consumed, counter NOT reset).
- `WithNoAttemptLimit` leaves the factor online-brute-forceable; only use with an external rate limiter.
- `NewSingleTenant` hard-wires `tenantID=""`. Do NOT mix with multi-tenant `Service` calls against the same store.
- `DisableHandler` / `RegenerateRecoveryCodesHandler` return 403 `step_up_required` when they cannot resolve the request's assurance. If they 403 unexpectedly, the route is not behind `tokens.ContextMiddleware` (or needs `mfa.WithAssuranceResolver`).
- Enroll / confirm / verify / verify-recovery are NOT step-up gated: they are how a factor is added or proven in the first place.
- `NewService` panics (not errors) on nil store or invalid config — designed to fail at startup.
- Data handlers (`EnrollHandler`, `ConfirmHandler`, `RegenerateRecoveryCodesHandler`) always return JSON even when `WithSuccessRedirect` is set; only action handlers (`VerifyHandler`, `DisableHandler`) redirect on success.
