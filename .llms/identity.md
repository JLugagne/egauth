# identity — accounts & credential verification

import: `github.com/JLugagne/egauth/identity`
memory store: `github.com/JLugagne/egauth/identity/memory`
source: `identity/*.go`

## Purpose
Manages the account lifecycle: registration, password login, password reset, email verification, magic-link login, authenticated password/email change, phone verification, recovery-email enrollment, account deletion, admin disable/enable, and JIT-provisioning of OAuth identities.
Does NOT issue tokens or sessions — pair with `tokens` (JWT access+refresh) or `sessions` (server-side) modules.

## Service interface
```go
type Service interface {
    Register(ctx context.Context, tenantID string, email, password string) (*User, error)
    Authenticate(ctx context.Context, tenantID string, provider, providerID, password string) (*User, error)
    RequestPasswordReset(ctx context.Context, tenantID string, email string) (token string, user *User, err error)
    ResetPassword(ctx context.Context, tenantID string, token, newPassword string) error
    RequestEmailVerification(ctx context.Context, tenantID string, userID uuid.UUID) (token string, err error)
    VerifyEmail(ctx context.Context, tenantID string, token string) (*User, error)
    LinkOrCreateIdentity(ctx context.Context, tenantID string, provider, providerID, email string, emailVerified bool) (*User, error)
    RequestMagicLink(ctx context.Context, tenantID string, email string) (token string, user *User, err error)
    LoginWithMagicLink(ctx context.Context, tenantID string, token string) (*User, error)
    // ChangePassword changes the user's password and triggers all registered AccountErasers to terminate sessions.
    ChangePassword(ctx context.Context, tenantID string, userID uuid.UUID, currentPassword, newPassword string) error
    RequestEmailChange(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string) (token string, err error)
    ConfirmEmailChange(ctx context.Context, tenantID string, token string) (*User, error)
    RequestPhoneVerification(ctx context.Context, tenantID string, userID uuid.UUID, phone string) (token string, err error)
    ConfirmPhoneVerification(ctx context.Context, tenantID string, token string) (*User, error)
    RequestRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string) (token string, err error)
    ConfirmRecoveryEmail(ctx context.Context, tenantID string, token string) (*User, error)
    RecoveryChannels(ctx context.Context, tenantID string, userID uuid.UUID) (RecoveryChannels, error)
    RequestPasswordResetViaRecovery(ctx context.Context, tenantID string, email string) (token string, user *User, channels RecoveryChannels, err error)
    DeleteAccount(ctx context.Context, tenantID string, userID uuid.UUID) error
    DisableUser(ctx context.Context, tenantID string, userID uuid.UUID) error
    EnableUser(ctx context.Context, tenantID string, userID uuid.UUID) error
}
```

## Key types

- `User{}` — account container:
  - `ID uuid.UUID`
  - `TenantID string`
  - `Email string`
  - `EmailVerifiedAt *time.Time`
  - `Phone *string` — E.164 normalized; nil when none enrolled
  - `PhoneVerifiedAt *time.Time` — nil when unverified or phone changed
  - `RecoveryEmail *string` — secondary recovery channel, not a login key; nil when none enrolled
  - `RecoveryEmailVerifiedAt *time.Time` — nil when unverified or recovery email changed
  - `CreatedAt time.Time`
  - `UpdatedAt time.Time`
  - `DeletedAt *time.Time` — soft-delete marker
  - `DisabledAt *time.Time` — admin suspension (reversible); nil when active

- `Identity{}` — one authentication method linked to a User:
  - `ID uuid.UUID`
  - `UserID uuid.UUID`
  - `TenantID string`
  - `Provider string` — e.g. `"password"`, `"google"`, `"github"`
  - `ProviderID string` — email for `"password"`, OAuth `sub` for external providers
  - `PasswordHash *string` — populated only for `"password"` provider
  - `FailedAttempts int` — consecutive failed auth attempts
  - `LockedUntil *time.Time` — nil or past = unlocked
  - `CreatedAt time.Time`
  - `UpdatedAt time.Time`

- `RecoveryChannels{}` — verified independent recovery channels:
  - `RecoveryEmail bool` — true when a verified recovery email is enrolled
  - `Phone bool` — true when a verified phone number is enrolled
  - `func (rc RecoveryChannels) Any() bool` — true if at least one channel is present

- `VerificationToken{}` — selector/verifier token record (used by store implementers):
  - `Selector string`, `VerifierHash string`, `UserID uuid.UUID`, `TenantID string`
  - `Kind string`, `Metadata []byte`, `ExpiresAt time.Time`, `CreatedAt time.Time`

- `AccountEraser` — `func(ctx context.Context, tenantID string, userID uuid.UUID) error`; registered via `WithAccountErasers`, run by `DeleteAccount` before soft-deleting

- `ClaimsBuilder[C any]` — `func(*User) tokens.Claims[C]`; maps an authenticated user to token claims for the handler layer

## Constructors

- `func NewService(store Store, hasher passwords.Hasher, policy passwords.Policy, opts ...ServiceOption) Service` — panics on nil store; hasher and policy may be nil for OAuth-only deployments (password ops return `ErrPasswordHasherRequired`/`ErrPasswordPolicyRequired` instead of panicking)
- `func NewSingleTenant(svc Service) *SingleTenant` — facade that hard-wires `tenantID=""` on every call; `(*SingleTenant).Service()` returns the wrapped `Service`
- memory: `func NewStore() *memory.Store` — in-memory implementation of `Store`

## Service options (`ServiceOption`)

- `func WithLockout(threshold int, duration time.Duration) ServiceOption` — overrides default (5 attempts, 15 min)
- `func WithPasswordResetTTL(d time.Duration) ServiceOption` — default 1h
- `func WithEmailVerificationTTL(d time.Duration) ServiceOption` — default 24h
- `func WithMagicLinkTTL(d time.Duration) ServiceOption` — default 15 min
- `func WithEmailChangeTTL(d time.Duration) ServiceOption` — default 1h
- `func WithPhoneVerificationTTL(d time.Duration) ServiceOption` — default 15 min
- `func WithRecoveryEmailTTL(d time.Duration) ServiceOption` — default 24h
- `func WithAccountErasers(erasers ...AccountEraser) ServiceOption` — cross-module revocation hooks for `DeleteAccount`
- `func WithEventSink(sink event.Sink) ServiceOption` — service-level security events
- `func WithClock(now func() time.Time) ServiceOption` — override time source (tests)

## Store contract
```go
type Store interface {
    // User
    CreateUser(ctx context.Context, tenantID string, email string) (*User, error)
    FindUserByID(ctx context.Context, tenantID string, id uuid.UUID) (*User, error)
    FindUserByEmail(ctx context.Context, tenantID string, email string) (*User, error)
    FindUserByPhone(ctx context.Context, tenantID string, phone string) (*User, error)
    UpdateUser(ctx context.Context, tenantID string, user *User) error
    UpdateUserEmail(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string, verifiedAt time.Time) error
    UpdateUserPhone(ctx context.Context, tenantID string, userID uuid.UUID, newPhone string, verifiedAt time.Time) error
    UpdateUserRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string, verifiedAt time.Time) error
    DeleteUser(ctx context.Context, tenantID string, id uuid.UUID) error
    DisableUser(ctx context.Context, tenantID string, id uuid.UUID, disabledAt time.Time) error
    EnableUser(ctx context.Context, tenantID string, id uuid.UUID) error

    // Identity
    AddIdentity(ctx context.Context, tenantID string, identity *Identity) error
    FindIdentitiesByUserID(ctx context.Context, tenantID string, userID uuid.UUID) ([]*Identity, error)
    FindIdentityByProvider(ctx context.Context, tenantID string, provider, providerID string) (*Identity, error)
    UpdateIdentityPassword(ctx context.Context, tenantID string, userID uuid.UUID, passwordHash string) error

    // Verification tokens (selector/verifier scheme)
    CreateVerificationToken(ctx context.Context, tenantID string, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte) (string, error)
    ConsumeVerificationToken(ctx context.Context, tenantID string, token, kind string) (uuid.UUID, []byte, error)
    DeleteExpiredVerificationTokens(ctx context.Context, tenantID string) (int64, error)

    // Lockout
    IncrementFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration) error
    ResetFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID) error
}
```

Store is intentionally monolithic for v0.x; methods may be added in minor releases. External implementers must run `identity/storetest` conformance suite on upgrades.

## HTTP handlers

All handlers are POST-only; non-POST returns 405. On success: 204 No Content (or 303 redirect if `WithSuccessRedirect` set). On failure: HTTP error text with status code (or 303 with `?error=<code>` if `WithFailureRedirect` set).

Request bodies are `application/x-www-form-urlencoded`. Default body cap: 4 KiB.

---

`func LoginHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc`
- POST — reads `email`, `password`, `remember_me` from form
- Success: issues access+refresh token pair, sets auth cookies → 204
- Errors: `401 invalid_credentials`, `429 account_locked`, `500 login_failed`

`func RegisterHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc`
- POST — reads `email`, `password`, `remember_me` from form
- Success: registers user, issues token pair, sets auth cookies → 204
- Errors: `409 email_taken`, `400 registration_failed`

`func RequestPasswordResetHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `email` from form
- Always → 204 (enumeration-safe; delivery dispatched async off response path)

`func ResetPasswordHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `token`, `password` from form
- Errors: `410 token_expired`, `400 invalid_token`, `400 password_rejected`

`func RequestEmailVerificationHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; reads current user from request
- Success → 204; delivery dispatched async
- Errors: `401 unauthorized`, `500 verification_request_failed`

`func VerifyEmailHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `token` from form
- Errors: `410 token_expired`, `400 invalid_token`

`func RequestMagicLinkHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `email` from form
- Always → 204 (enumeration-safe; delivery dispatched async)

`func MagicLinkLoginHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc`
- POST — reads `token`, `remember_me` from form
- Success: issues token pair, sets auth cookies → 204
- Errors: `410 token_expired`, `400 invalid_token`, `500 token_issuance_failed`

`func ChangePasswordHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; reads `current_password`, `new_password` from form
- Note: Changing the password proactively terminates all sessions by invoking registered `AccountEraser`s.
- Errors: `401 invalid_credentials`, `400 password_rejected`, `401 unauthorized`

`func RequestEmailChangeHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; reads `new_email` from form
- Delivery to new address dispatched async
- Errors: `400 invalid_email`, `409 email_taken`, `401 unauthorized`

`func ConfirmEmailChangeHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `token` from form
- Errors: `410 token_expired`, `400 invalid_token`, `409 email_taken`

`func RequestPhoneVerificationHandler(svc Service, sender SMSSender, opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; reads `phone` from form
- Delivery to phone by SMS dispatched async
- Errors: `400 invalid_phone`, `409 phone_taken`, `401 unauthorized`

`func ConfirmPhoneVerificationHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `token` from form
- Errors: `410 token_expired`, `400 invalid_token`, `409 phone_taken`

`func RequestRecoveryEmailHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; reads `recovery_email` from form
- Delivery to recovery address dispatched async
- Errors: `400 invalid_email`, `409 recovery_email_is_primary`, `401 unauthorized`

`func ConfirmRecoveryEmailHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `token` from form
- Errors: `410 token_expired`, `400 invalid_token`

`func DeleteAccountHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; clears auth cookies on success → 204
- Errors: `404 not_found`, `401 unauthorized`, `500 internal_error`

`func RequestPasswordResetViaRecoveryHandler(svc Service, mailer Mailer, sms SMSSender, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `email` from form
- Always → 204 (enumeration-safe); delivers to verified recovery channel(s) only

## Options (HandlerOption)

- `func WithProvider(provider string) HandlerOption` — identity provider for login (default `"password"`)
- `func WithCookies(c tokens.Cookies) HandlerOption` — replace cookie config wholesale
- `func WithCookieDomain(domain string) HandlerOption`
- `func WithSameSite(mode http.SameSite) HandlerOption`
- `func WithCookiePath(path string) HandlerOption` — sets both access and refresh cookie paths
- `func WithRefreshCookiePath(path string) HandlerOption` — scope refresh cookie only
- `func WithInsecureCookies() HandlerOption` — disable Secure flag (local HTTP dev only)
- `func WithSuccessRedirect(url string) HandlerOption` — 303 redirect on success instead of 204
- `func WithFailureRedirect(url string) HandlerOption` — 303 redirect with `?error=<code>` on failure
- `func WithFormFields(email, password, remember string) HandlerOption` — override default field names
- `func WithTenantResolver(f func(*http.Request) string) HandlerOption` — extract tenantID from request
- `func WithTokenField(name string) HandlerOption` — override token field name (default `"token"`)
- `func WithUserResolver(f func(*http.Request) (*User, bool)) HandlerOption` — supply authenticated user to authenticated handlers
- `func WithHandlerEventSink(sink event.Sink) HandlerOption` — handler-level security events (e.g. delivery failures)
- `func WithTrustedOrigins(origins ...string) HandlerOption` — enable CSRF origin check; pass hosts without scheme
- `func WithPasswordChangeFields(current, newField string) HandlerOption` — override `ChangePasswordHandler` field names
- `func WithEmailChangeField(name string) HandlerOption` — override `new_email` field name
- `func WithPhoneField(name string) HandlerOption` — override `phone` field name
- `func WithRecoveryEmailField(name string) HandlerOption` — override `recovery_email` field name
- `func WithMaxBodyBytes(n int64) HandlerOption` — request body cap (default 4096; non-positive disables)
- `func WithDeliveryConcurrency(n int) HandlerOption` — cap concurrent async deliveries per handler instance (default 64; non-positive disables, drops overflow with DeliveryFailed event)
- `func WithDeliveryTimeout(d time.Duration) HandlerOption` — per-delivery timeout (default 30s; non-positive disables)

## Errors (sentinels)

- `ErrUserNotFound` — user absent or soft-deleted
- `ErrEmailAlreadyExists` — email taken in tenant
- `ErrInvalidEmail` — RFC 5322 parse failure
- `ErrPhoneAlreadyExists` — phone taken by another live account in tenant
- `ErrInvalidPhone` — not a plausible E.164 number (`+` + 8–15 digits)
- `ErrRecoveryEmailIsPrimary` — recovery email equals the account's primary email
- `ErrNoRecoveryChannel` — no verified independent recovery channel enrolled
- `ErrIdentityNotFound` — identity absent
- `ErrIdentityAlreadyExists` — (provider, providerID) already linked in tenant
- `ErrTenantMismatch` — record's TenantID differs from argument
- `ErrInvalidCredentials` — authentication failed (unknown user, wrong password, no password identity)
- `ErrAccountLocked` — too many failed attempts; surfaced as 429
- `ErrAccountDisabled` — admin-suspended account; does not auto-clear
- `ErrPasswordPolicyRequired` — password op called with nil `passwords.Policy`
- `ErrPasswordHasherRequired` — password op called with nil `passwords.Hasher`
- `ErrVerificationTokenNotFound` — token unknown, malformed, or verifier mismatch (cases merged)
- `ErrVerificationTokenExpired` — token found and verified but past TTL
- `ErrDeliveryDropped` — carried by `DeliveryFailed` event when async delivery dropped due to concurrency cap; never returned to callers

## Delivery seams (Mailer / SMSSender)

```go
type Mailer struct {
    PasswordReset             func(ctx context.Context, mail PasswordResetMail) error
    EmailVerification         func(ctx context.Context, mail EmailVerificationMail) error
    MagicLink                 func(ctx context.Context, mail MagicLinkMail) error
    EmailChange               func(ctx context.Context, mail EmailChangeMail) error
    RecoveryEmailVerification func(ctx context.Context, mail RecoveryEmailMail) error
}

type SMSSender struct {
    PhoneVerification func(ctx context.Context, sms PhoneVerificationSMS) error
}
```

Delivery structs: `PasswordResetMail{User *User, Token string}`, `EmailVerificationMail{User *User, Token string}`, `MagicLinkMail{User *User, Token string}`, `EmailChangeMail{User *User, NewEmail string, Token string}`, `RecoveryEmailMail{User *User, RecoveryEmail string, Token string}`, `PhoneVerificationSMS{User *User, Phone string, Token string}`.

Handlers call delivery functions asynchronously off the response path (detached context, so request cancel does not abort delivery). Concurrency is bounded by a per-handler-instance semaphore (`WithDeliveryConcurrency`, default 64); overflow is dropped and surfaces as a `DeliveryFailed` event on the configured `HandlerOption` sink. A nil callback field silences that delivery channel. Tokens are plaintext credentials — treat as secrets, never log.

## Wiring

```go
import (
    "github.com/JLugagne/egauth/identity"
    "github.com/JLugagne/egauth/identity/memory"
    "github.com/JLugagne/egauth/passwords/argon2"
    "github.com/JLugagne/egauth/passwords/policy"
    "github.com/JLugagne/egauth/tokens"
)

store := memory.NewStore()
svc := identity.NewService(
    store,
    argon2.NewHasher(),
    policy.NewDefaultPolicy(),
    identity.WithAccountErasers(sessions.NewEraser(sessionStore)),
)

// Single-tenant shorthand
app := identity.NewSingleTenant(svc)
user, err := app.Register(ctx, "user@example.com", "S3cr3t!")

// HTTP (multi-tenant)
mux.Handle("/login", identity.LoginHandler(svc, issuer, claimsOf,
    identity.WithTenantResolver(func(r *http.Request) string { return r.Host }),
    identity.WithTrustedOrigins("app.example.com"),
))
mux.Handle("/password-reset/request", identity.RequestPasswordResetHandler(svc, mailer))
mux.Handle("/password-reset/confirm", identity.ResetPasswordHandler(svc))
```

## Audit events (M9 uniform login-method audit)

All login paths now emit a `login.succeeded` event (type `"login.succeeded"`) with two additional `Attrs` keys so every authentication path is auditable in a uniform shape:

| Auth path | `method` attr | `amr` attr |
|---|---|---|
| Password (`Authenticate`) | `"password"` | `["pwd"]` |
| Magic-link (`LoginWithMagicLink`) | `"magic_link"` | `["otp"]` |

**Important**: the `amr` on `login.succeeded` reflects only the credential verified at that step. Password login is a first-factor event — if the user has TOTP enrolled, the second factor is recorded by the separate `mfa.confirmed` event, not added to this `amr`.

`login.failed` emits `Attrs["method"] = "password"` on the password-provider path; the non-password rejection path emits `method = ""` rather than mislabelling an OAuth-provider attempt as password.

`account.locked` now carries `"ip"` / `"user_agent"` attrs when a `RequestContext` is supplied.

### Signature changes (pre-v1)

`Authenticate` and `LoginWithMagicLink` gained a trailing variadic `...event.RequestContext` parameter. Supply it to thread request IP / User-Agent into audit events:

```go
// Authenticate
user, err := svc.Authenticate(ctx, tenant, "password", email, password,
    event.RequestContext{IP: r.RemoteAddr, UserAgent: r.UserAgent()})

// LoginWithMagicLink
user, err := svc.LoginWithMagicLink(ctx, tenant, token,
    event.RequestContext{IP: r.RemoteAddr, UserAgent: r.UserAgent()})
```

`MagicLinkLoginHandler` passes `requestContext(r)` internally — no extra wiring needed for the HTTP layer.

`identity/servicetest.MockService.LoginWithMagicLinkFunc` was updated to match the new variadic signature.

### Removed event type

`MagicLinkLogin` (`"magic_link.login"`) was removed. Magic-link login now emits `login.succeeded` with `method="magic_link"`. The HTTP handler `MagicLinkLoginHandler` keeps its name unchanged.

## Gotchas

- `tenantID=""` is a valid partition (the single-tenant default); it must still be passed explicitly to `Service` methods.
- `NewService` panics only on nil store; nil hasher/policy is legal for OAuth-only deployments — password ops return `ErrPasswordHasherRequired`/`ErrPasswordPolicyRequired` rather than panicking.
- `Authenticate` with a nil hasher performs a decoy hash so a missing hasher is timing-indistinguishable from a wrong password; it always returns `ErrInvalidCredentials`.
- All `Request*` handlers (`RequestPasswordResetHandler`, `RequestMagicLinkHandler`, `RequestPasswordResetViaRecoveryHandler`, `RequestPhoneVerificationHandler`) are enumeration-safe: they always respond 204 regardless of account existence or delivery success.
- Token consumption is single-use and atomic; re-using a consumed token returns `ErrVerificationTokenNotFound`.
- `ResetPassword` validates and hashes the new password BEFORE consuming the token, so a policy rejection does not burn a single-use token.
- `DeleteAccount` runs all `AccountErasers` first; a revocation failure aborts before the soft-delete (cleanly retriable). Erasers should be idempotent.
- `DisableUser` does NOT run `AccountErasers` and does NOT revoke sessions; call session revocation separately if needed.
- A disabled account can not consume any verification token (including magic-link); `consumeForLiveUser` returns `ErrUserNotFound` for disabled accounts.
- `LinkOrCreateIdentity` refuses silent email-based account linking (returns `ErrEmailAlreadyExists` if provider email matches an existing account); explicit linking from an authenticated session is required.
- Verification token scheme is selector/verifier: selector stored in clear for O(1) lookup; only SHA-256 of verifier stored. Helpers: `GenerateVerificationToken()`, `SplitVerificationToken()`, `HashVerifier()`, `CompareVerifier()`.
- Token kind constants: `KindPasswordReset`, `KindEmailVerification`, `KindMagicLink`, `KindEmailChange`, `KindPhoneVerification`, `KindRecoveryEmailVerification`.
- Phone is a lower-assurance contact channel; the `mfa` module does not accept SMS as an authentication factor (NIST SP 800-63B).
- Recovery email uniqueness is NOT enforced (multiple accounts may share a recovery contact); it is intentionally not a login key.
- `WithTrustedOrigins` is disabled by default; CSRF protection is the consumer's responsibility when not set.
- Default body cap is 4 KiB to bound pre-auth argon2 DoS; disabling it (`WithMaxBodyBytes(0)`) requires an upstream body-size limit.
- `Store` interface is intentionally monolithic for v0.x; new methods may be added in minor releases without a major bump — run `identity/storetest` on every upgrade.
