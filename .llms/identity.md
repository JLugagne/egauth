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
    // ResetPassword consumes the token, re-keys the password, PURGES the user's pending
    // credential-bearing verification tokens (reset, magic link, email change, phone verification,
    // recovery email — NOT the verification of the current address) and runs every registered
    // AccountEraser. Purge + eraser errors are joined and returned AFTER the new hash is committed.
    ResetPassword(ctx context.Context, tenantID string, token, newPassword string) error
    RequestEmailVerification(ctx context.Context, tenantID string, userID uuid.UUID) (token string, err error)
    VerifyEmail(ctx context.Context, tenantID string, token string) (*User, error)
    LinkOrCreateIdentity(ctx context.Context, tenantID string, provider, providerID, email string, emailVerified bool) (*User, error)
    RequestMagicLink(ctx context.Context, tenantID string, email string) (token string, user *User, err error)
    LoginWithMagicLink(ctx context.Context, tenantID string, token string) (*User, error)
    // ChangePassword changes the user's password, purges the same pending token kinds as
    // ResetPassword and triggers all registered AccountErasers to terminate sessions. Cross-module
    // revocation is done BY egauth here, not left to the consumer.
    ChangePassword(ctx context.Context, tenantID string, userID uuid.UUID, currentPassword, newPassword string) error
    // RequestEmailChange mints a token delivered to newEmail. Confirming it proves control of the NEW
    // address — it does NOT prove account ownership, so a hijacked session is stopped by the
    // handler's step-up bar, not by this method. Direct callers must apply an equivalent bar.
    RequestEmailChange(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string) (token string, err error)
    ConfirmEmailChange(ctx context.Context, tenantID string, token string) (*User, error)
    RequestPhoneVerification(ctx context.Context, tenantID string, userID uuid.UUID, phone string) (token string, err error)
    ConfirmPhoneVerification(ctx context.Context, tenantID string, token string) (*User, error)
    RequestRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string) (token string, err error)
    ConfirmRecoveryEmail(ctx context.Context, tenantID string, token string) (*User, error)
    RecoveryChannels(ctx context.Context, tenantID string, userID uuid.UUID) (RecoveryChannels, error)
    RequestPasswordResetViaRecovery(ctx context.Context, tenantID string, email string) (token string, user *User, channels RecoveryChannels, err error)
    DeleteAccount(ctx context.Context, tenantID string, userID uuid.UUID) error
    // DisableUser stamps DisabledAt, PURGES the user's pending credential-bearing verification tokens
    // (so a magic link or email-change token minted before the suspension does NOT come back to life
    // on EnableUser) and runs every registered AccountRevoker.
    DisableUser(ctx context.Context, tenantID string, userID uuid.UUID) error
    EnableUser(ctx context.Context, tenantID string, userID uuid.UUID) error
    // EnsureActive: nil for a live account, ErrAccountDisabled when suspended, ErrUserNotFound
    // when unknown/soft-deleted/cross-tenant. The status gate for long-lived credential paths —
    // above all refresh rotation (see ActiveClaimsProvider).
    EnsureActive(ctx context.Context, tenantID string, userID uuid.UUID) error
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
- `AccountRevoker` — `func(ctx context.Context, tenantID string, userID uuid.UUID) error`; registered via `WithDisableRevokers`, run by `DisableUser` to invalidate active, re-establishable credentials (refresh tokens, API keys, sessions). Distinct from `AccountEraser`: disable is reversible, so revokers must NOT destroy enrollment data (MFA, passkeys) the account needs again after `EnableUser`.

- `ClaimsBuilder[C any]` — `func(*User) tokens.Claims[C]`; maps an authenticated user to token claims for the handler layer

- `ActiveChecker` — `interface { EnsureActive(ctx, tenantID, userID) error }`; the narrow status seam `Service` satisfies
- `RevocationRegistry` — `interface { RegisterAccountErasers(...AccountEraser); RegisterDisableRevokers(...AccountRevoker) }`; post-construction form of `WithAccountErasers`/`WithDisableRevokers`, implemented by the `Service` from `NewService`. For a composition root handed an ALREADY-BUILT service (the `webapp` preset, a DI container) that can no longer pass `ServiceOption`s. Register during wiring, before serving traffic; hook lists are copied on write so registration is concurrency-safe, but a hook added after an operation started does not run for it.

## Constructors

- `func NewService(store Store, hasher passwords.Hasher, policy passwords.Policy, opts ...ServiceOption) Service` — panics on nil store; hasher and policy may be nil for OAuth-only deployments (password ops return `ErrPasswordHasherRequired`/`ErrPasswordPolicyRequired` instead of panicking)
- `func NewSingleTenant(svc Service) *SingleTenant` — facade that hard-wires `tenantID=""` on every call; `(*SingleTenant).Service()` returns the wrapped `Service`
- `func ActiveClaimsProvider[C any](checker ActiveChecker, next tokens.ClaimsProvider[C]) tokens.ClaimsProvider[C]` — wraps a claims provider with the `EnsureActive` re-check refresh rotation needs. Rotation's `ClaimsProvider` is the ONLY place a refresh can be refused, so without this a disabled or deleted user keeps rotating — and every rotation resets the refresh expiry to `now+RefreshTTL`, renewing access indefinitely. The wrapper returns `ErrAccountDisabled`/`ErrUserNotFound` verbatim, which aborts `Rotate` (the presented token stays unconsumed) and makes `RefreshHandler` answer `401` and clear the cookies. Panics on a nil checker or provider (startup failure, not a silently skipped check).
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
- `func WithDisableRevokers(revokers ...AccountRevoker) ServiceOption` — cross-module revocation hooks for `DisableUser` (refresh tokens, API keys, sessions). Use `tokens.NewAccountRevoker(tokenStore)` for tokens/keys and `sessions.Service.RevokeAllForUser` for sessions.
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
    // UpdateUser persists ONLY Email + EmailVerifiedAt. Every other column belongs to a dedicated
    // operation (DisableUser/EnableUser, UpdateUserPhone, UpdateUserRecoveryEmail, DeleteUser) and
    // MUST NOT be written: a stale *User copy would otherwise clear DisabledAt and re-activate a
    // suspended account. Rejects soft-deleted users with ErrUserNotFound.
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
    // DeleteVerificationTokensForUser is the PER-USER revocation seam the credential-rotating flows
    // need (ResetPassword, ChangePassword, SetTemporaryPassword, DisableUser). An empty kinds list
    // purges every kind. Idempotent (unknown user / nothing pending = success), but a genuine backend
    // failure MUST be reported — a silent success leaves an attacker's pending token redeemable.
    DeleteVerificationTokensForUser(ctx context.Context, tenantID string, userID uuid.UUID, kinds ...string) error

    // Lockout
    // justLocked reports whether THIS atomic increment crossed the threshold (counter went from
    // below lockThreshold to at/above it). Derived inside the same atomic op, so under concurrent
    // failed logins exactly one caller sees true — the request that actually locked the account.
    // The service emits the once-per-lock account.locked event off this, NOT a stale pre-read.
    IncrementFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration) (justLocked bool, err error)
    ResetFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID) error
}
```

Store is intentionally monolithic for v0.x; methods may be added in minor releases. External implementers must run `identity/storetest` conformance suite on upgrades. The lockout/replay/single-use methods (`IncrementFailedAttempts`, refresh-token consume, TOTP mark-used) are **concurrency-critical**: implement them atomically (single-statement compare-and-set), never as read-then-write, or the service-layer guarantee silently breaks. Test custom adapters under parallel load with the contract suite.

## HTTP handlers

All handlers are POST-only; non-POST returns 405. On success: 204 No Content (or 303 redirect if `WithSuccessRedirect` set). On failure: HTTP error text with status code (or 303 with `?error=<code>` if `WithFailureRedirect` set).

Request bodies are `application/x-www-form-urlencoded`. Default body cap: 4 KiB.

Every handler resolves the request tenant ONCE (via `WithTenantResolver`) and pins that value for all of its store operations. With a resolver configured, a request it cannot map (resolver returns `""`) is refused with `401 tenant_unresolved` on EVERY handler below — including the otherwise enumeration-uniform `Request*` handlers — instead of operating on the single-tenant `""` partition. With no resolver configured the tenant is `""` (single-tenant mode) and nothing changes.

---

`func LoginHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc`
- POST — reads `email`, `password`, `remember_me` from form
- Success: issues access+refresh token pair, sets auth cookies → 204
- With `WithMFAGate` and an MFA-enrolled user: issues the short-lived INTERIM credential (access cookie only, no refresh) and replies `X-Egauth-MFA-Required: 1` + `200 {"mfa_required":true}` (or 303 to `WithMFARequiredRedirect`) — never the 204/successURL of a full login
- Errors: `401 invalid_credentials`, `429 account_locked`, `500 login_failed`, `500 mfa_check_failed` (gate error, fails closed)

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
- `WithMFAGate` applies here TOO (a magic link is a first factor): an enrolled user gets the interim credential + `mfa_required` response, so a compromised mailbox cannot bypass the second factor
- Errors: `410 token_expired`, `400 invalid_token`, `500 token_issuance_failed`, `500 mfa_check_failed`

`func ChangePasswordWithReissueHandler[C any](svc Service, issuer tokens.Issuer[C], claimsOf ClaimsBuilder[C], opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; same fields as `ChangePasswordHandler`
- Success: changes the password AND re-issues a FRESH FULL pair (both cookies) → 204
- REFUSES a pre-step-up interim credential — or an unresolvable assurance — with `403 step_up_required` (it would otherwise upgrade an interim credential into a full renewable session). Assurance comes from `WithAssuranceResolver` (default `tokens.AssuranceResolverFromContext`); mount behind `tokens.ContextMiddleware`
- Errors: `403 step_up_required`, `401 invalid_credentials`, `400 password_rejected`, `401 unauthorized`

`func ChangePasswordHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; reads `current_password`, `new_password` from form
- Note: Changing the password proactively terminates all sessions by invoking registered `AccountEraser`s AND purges the user's pending credential-bearing verification tokens.
- Errors: `401 invalid_credentials`, `400 password_rejected`, `401 unauthorized`

`func RequestEmailChangeHandler(svc Service, mailer Mailer, opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; reads `new_email` from form
- Delivery to new address dispatched async
- The login identifier is a takeover target, so it ENFORCES step-up itself (same bar as `DeleteAccountHandler`): refuses a pre-step-up interim credential — or an unresolvable assurance — with `403 step_up_required`; with `WithMFAGate` an MFA-enrolled user must present a step-up factor. `WithInsecureNoStepUpCheck` opts out
- Errors: `403 step_up_required`, `400 invalid_email`, `409 email_taken`, `401 unauthorized`, `500 mfa_check_failed`

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
- A verified recovery address drives `RequestPasswordResetViaRecovery`, so it ENFORCES the SAME step-up bar as `RequestEmailChangeHandler`
- Errors: `403 step_up_required`, `400 invalid_email`, `409 recovery_email_is_primary`, `401 unauthorized`, `500 mfa_check_failed`

`func ConfirmRecoveryEmailHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `token` from form
- Errors: `410 token_expired`, `400 invalid_token`

`func DeleteAccountHandler(svc Service, opts ...HandlerOption) http.HandlerFunc`
- POST — requires `WithUserResolver`; clears auth cookies on success → 204
- Irreversible, so it ENFORCES step-up itself: refuses a pre-step-up interim credential — or an unresolvable assurance — with `403 step_up_required`. Pass `WithMFAGate` too and an MFA-enrolled user must present a credential carrying a step-up factor (`AMRMFA`/`AMROTP`/`AMRWebAuthn`)
- Errors: `403 step_up_required`, `404 not_found`, `401 unauthorized`, `500 mfa_check_failed`, `500 internal_error`

`func RequestPasswordResetViaRecoveryHandler(svc Service, mailer Mailer, sms SMSSender, opts ...HandlerOption) http.HandlerFunc`
- POST — reads `email` from form
- Always → 204 (enumeration-safe); delivers to verified recovery channel(s) only

## Options (HandlerOption)

- `func WithProvider(provider string) HandlerOption` — identity provider for login (default `"password"`)
- `func WithCookies(c tokens.Cookies) HandlerOption` — replace cookie config wholesale (validated when the handler is built; an invalid value panics there, never per request)
- `func WithCookieDomain(domain string) HandlerOption` — demotes `__Host-` cookie names to `__Secure-` (host-lock opt-out)
- `func WithSameSite(mode http.SameSite) HandlerOption`
- `func WithCookiePath(path string) HandlerOption` — sets both access and refresh cookie paths; a non-`"/"` path demotes `__Host-` names to their bare form
- `func WithRefreshCookiePath(path string) HandlerOption` — scope refresh cookie only; demotes the refresh name the same way
- `func WithInsecureCookies() HandlerOption` — disable Secure flag (local HTTP dev only); demotes both names to their bare form
- `func WithSuccessRedirect(url string) HandlerOption` — 303 redirect on success instead of 204
- `func WithFailureRedirect(url string) HandlerOption` — 303 redirect with `?error=<code>` on failure
- `func WithFormFields(email, password, remember string) HandlerOption` — override default field names
- `func WithTenantResolver(f func(*http.Request) string) HandlerOption` — extract tenantID from request; resolved ONCE per request. Map the request through an explicit allowlist / canonical table, never the raw `Host`. A configured resolver returning `""` means "unresolved" and the handler refuses the request with `401 tenant_unresolved` (fail-closed) instead of using the single-tenant `""` partition; `""` is used only when no resolver is configured at all
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
- `func WithMFAGate(checker MFAEnrollmentChecker) HandlerOption` — gate `LoginHandler` AND `MagicLinkLoginHandler` on enrollment: an enrolled user gets the INTERIM credential (`tokens.Claims.Interim`, no step-up AMR marker, no refresh cookie, no persisted refresh family) instead of a session. Also strengthens `DeleteAccountHandler` (an enrolled user must present a step-up factor). `mfa.Service` satisfies the interface
- `func WithInterimTokenTTL(d time.Duration) HandlerOption` — lifetime of that interim credential (default `DefaultInterimTokenTTL` = 5 min; non-positive falls back to the default)
- `func WithMFARequiredRedirect(url string) HandlerOption` — 303 to `url` for the pre-step-up reply instead of `200 {"mfa_required":true}`; the `X-Egauth-MFA-Required: 1` header (`identity.MFARequiredHeader`) is set either way
- `func WithAssuranceResolver(f tokens.AssuranceResolver) HandlerOption` — supply the request's assurance to `ChangePasswordWithReissueHandler` / `DeleteAccountHandler`. DEFAULT `tokens.AssuranceResolverFromContext`; fails CLOSED (403 `step_up_required`) when nil or reporting `ok=false`
- `func WithInsecureNoStepUpCheck() HandlerOption` — loud opt-out of that enforcement (only when no login path can mint an interim credential)

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
// Map the request through an EXPLICIT allowlist of canonical hosts — never the raw Host header.
// An unmapped host resolves to "" and the handler then REFUSES the request (401
// tenant_unresolved); it never falls back to the single-tenant ("") partition, where a
// bootstrap/operator account may live.
tenantsByHost := map[string]string{"acme.example.com": "acme"}
tenantFromHost := func(r *http.Request) string {
    host := strings.ToLower(r.Host)
    if h, _, err := net.SplitHostPort(host); err == nil {
        host = h
    }
    return tenantsByHost[strings.TrimSuffix(host, ".")]
}
mux.Handle("/login", identity.LoginHandler(svc, issuer, claimsOf,
    identity.WithTenantResolver(tenantFromHost),
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
- `Authenticate` also spends a decoy hash on the **locked** (`ErrAccountLocked`) and **disabled** (`ErrAccountDisabled`) rejection branches, equalizing their response time with the unknown-user / wrong-password paths. (Locked/disabled are already disclosed at the status-code level — both → 429 by design — so the timing equalization is defence-in-depth: it keeps in-process timing uniform and survives a refactor that collapses 429→401.)
- `account.locked` fires off the store's atomic `justLocked` result (the request whose `IncrementFailedAttempts` crossed the threshold), NOT a pre-increment prediction. Under concurrent failed logins it is emitted exactly once and attributed to the correct request; it is suppressed when the store call errored (no lock was persisted).
- All `Request*` handlers (`RequestPasswordResetHandler`, `RequestMagicLinkHandler`, `RequestPasswordResetViaRecoveryHandler`, `RequestPhoneVerificationHandler`) are enumeration-safe: they always respond 204 regardless of account existence or delivery success.
- Token consumption is single-use and atomic; re-using a consumed token returns `ErrVerificationTokenNotFound`.
- `ResetPassword` validates and hashes the new password BEFORE consuming the token, so a policy rejection does not burn a single-use token.
- **Credential rotation purges pending token-borne credentials.** `ResetPassword`, `ChangePassword`, `SetTemporaryPassword` and `DisableUser` all call `Store.DeleteVerificationTokensForUser` for `KindPasswordReset`, `KindMagicLink`, `KindEmailChange`, `KindPhoneVerification` and `KindRecoveryEmailVerification`. Without it a recovery-email or email-change token minted while an attacker held the account stays redeemable for its whole TTL (up to 24h) and hands the account straight back after the victim's recovery — expiry-based GC is far too slow to serve as revocation. `KindEmailVerification` is deliberately KEPT: it only verifies the address the account already owns. A purge failure is joined into the returned error (never a silent success), and it runs AFTER the new hash / `DisabledAt` is committed so the account is authoritatively re-keyed and the call is retriable.
- `DeleteAccount` runs all `AccountErasers` first; a revocation failure aborts before the soft-delete (cleanly retriable). Erasers should be idempotent.
- `DisableUser` stamps `DisabledAt` and emits `AccountDisabled` FIRST (fail-closed: the account is authoritatively blocked even if a downstream revoker fails), then runs the registered `AccountRevoker`s (`WithDisableRevokers`) to revoke the user's refresh tokens, API keys and sessions, returning any joined revoker error so the idempotent call can be retried. It does NOT run `AccountErasers` (those are for permanent `DeleteAccount` and may destroy MFA/passkey enrollment that a reversible disable must preserve). With no revokers wired, `DisableUser` blocks new logins but leaves already-issued refresh families live and ROTATABLE — wire `tokens.NewAccountRevoker` and `sessions.Service.RevokeAllForUser` to kill them immediately, and wrap the issuer's provider in `ActiveClaimsProvider` so a rotation racing the disable is refused too. An already-issued stateless access token always survives until its `AccessTTL` expires.
- A disabled account can not consume any verification token (including magic-link); `consumeForLiveUser` returns `ErrUserNotFound` for disabled accounts. That gate only holds WHILE `DisabledAt` is set, which is why `DisableUser` also DELETES the credential-bearing kinds — otherwise `EnableUser` would resurrect them.
- `RequestEmailChangeHandler` and `RequestRecoveryEmailHandler` enforce a step-up bar themselves (like `DeleteAccountHandler`): a session alone must not be able to take the account's login identifier or install a recovery channel. They fail CLOSED — without `tokens.ContextMiddleware` in front (or an explicit `WithAssuranceResolver`) they return `403 step_up_required`.
- `LinkOrCreateIdentity` refuses silent email-based account linking (returns `ErrEmailAlreadyExists` if provider email matches an existing account); explicit linking from an authenticated session is required.
- Verification token scheme is selector/verifier: selector stored in clear for O(1) lookup; only SHA-256 of verifier stored. Helpers: `GenerateVerificationToken()`, `SplitVerificationToken()`, `HashVerifier()`, `CompareVerifier()`.
- Token kind constants: `KindPasswordReset`, `KindEmailVerification`, `KindMagicLink`, `KindEmailChange`, `KindPhoneVerification`, `KindRecoveryEmailVerification`.
- Phone is a lower-assurance contact channel; the `mfa` module does not accept SMS as an authentication factor (NIST SP 800-63B).
- Recovery email uniqueness is NOT enforced (multiple accounts may share a recovery contact); it is intentionally not a login key.
- `WithTrustedOrigins` is disabled by default; CSRF protection is the consumer's responsibility when not set.
- Default body cap is 4 KiB to bound pre-auth argon2 DoS; disabling it (`WithMaxBodyBytes(0)`) requires an upstream body-size limit.
- `Store` interface is intentionally monolithic for v0.x; new methods may be added in minor releases without a major bump — run `identity/storetest` on every upgrade.
