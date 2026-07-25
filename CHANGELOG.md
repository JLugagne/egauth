# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### BREAKING

- **MFA is now an ENFORCED control, not advisory.** The pre-step-up credential minted by an MFA-gated
  login is stamped `tokens.Claims.Interim` (new field, JWT claim `interim`, omitted for ordinary
  sessions) and is no longer accepted as a session:

  - `tokens.RequireAuth` / `tokens.ContextMiddleware` refuse an interim credential with
    `403 step_up_required` on **every** route unless the route opts in with the new
    `tokens.WithInterimAllowed[C]()`. **Action required:** add that option to the route hosting
    `mfa.StepUpHandler` (and any other endpoint that must be reachable before the second factor);
    without it the step-up flow cannot complete.
  - `mfa.DisableHandler` and `mfa.RegenerateRecoveryCodesHandler` now refuse any request whose
    credential does not prove a second factor (`Claims.SatisfiesStepUp()`: AMR carries `mfa`, `otp`
    or `hwk` and the credential is not interim) with `403 step_up_required`. A password-only session
    can no longer strip MFA or invalidate the victim's recovery codes.
  - `identity.ChangePasswordWithReissueHandler` (which mints a full renewable pair) and
    `identity.DeleteAccountHandler` (irreversible) now refuse an interim credential with
    `403 step_up_required`. With `identity.WithMFAGate` also passed, `DeleteAccountHandler`
    additionally requires an MFA-enrolled user to present a step-up factor.
  - All four checks **fail closed**: a request whose assurance cannot be resolved is refused. The
    assurance is read from the new `tokens.AssuranceResolverFromContext` by default, so mounting the
    handler behind `tokens.ContextMiddleware` is the only wiring needed. **Action required** for a
    deployment whose access token is verified by a middleware of its own: supply
    `mfa.WithAssuranceResolver` / `identity.WithAssuranceResolver`, or opt out explicitly with
    `mfa.WithInsecureNoStepUpCheck()` / `identity.WithInsecureNoStepUpCheck()`.

- **An MFA-gated login now CLEARS any existing refresh cookie.** The pre-step-up state claims not to
  be renewable, so it no longer leaves a refresh cookie from an earlier session in the browser. A
  client that observes a refresh cookie must therefore treat its disappearance after a login as
  "second factor required", not as a bug.

- **An MFA-gated login no longer replies `204`/`successURL`.** It was previously byte-identical to a
  full login, leaving the client no signal to drive the second factor. The pre-step-up reply now
  carries the `X-Egauth-MFA-Required: 1` header (`identity.MFARequiredHeader`) plus either
  `200 {"mfa_required":true}` or, when the new `identity.WithMFARequiredRedirect(url)` /
  `oauth.WithMFARequiredRedirect(url)` is set, a `303` to that URL. The full-login response is
  unchanged. **Action required** for browser-driven deployments using `WithSuccessRedirect`:
  configure the matching MFA-required redirect.

- **`tokens.WithMaxAuthAge` is no longer documented as sufficient** to gate a factor-mutating or
  destructive route: a freshly minted interim credential passes an `auth_time` freshness window
  trivially. Use `tokens.WithRequiredAMR(tokens.AMRMFA)`, optionally alongside `WithMaxAuthAge` for a
  sudo-mode window. The guidance in `mfa.Service.DisableTOTP`, `identity.Service.DeleteAccount`,
  `identity.Service.RecoveryChannels`, `SECURITY.md` and `.llms/mfa.md` has been corrected.

- **A configured tenant resolver that returns `""` now refuses the request** (`identity`, `tokens`,
  `otp`, `oauth`). Behavioural, not an API change: no signature moved. Previously `""` was passed
  through verbatim and the request operated on the empty tenant partition. A deployment that
  configured a resolver and relied on its `""` return to mean "the default partition" now receives
  `401 tenant_unresolved` (`403` on `oauth`) and must either map those requests explicitly or
  configure no resolver at all (single-tenant mode, where `""` remains the legitimate partition).

- **`identity.Service` gained `EnsureActive`, and `webapp.Config.Identity` must now implement
  `identity.RevocationRegistry`.** Both changes serve one guarantee: account deactivation ends
  access.

  - `EnsureActive(ctx, tenantID, userID) error` is a new method on the `identity.Service`
    **interface** (and on `identity.SingleTenant`). **Action required** only for code that
    implements `identity.Service` itself — add the method (or embed the real Service);
    `identity.servicetest.MockService` already has it, defaulting to "active" when its
    `EnsureActiveFunc` is unset.
  - `webapp.NewWebApp` now returns `webapp.ErrIdentityNotRegisterable` when `Config.Identity` does
    not implement the new `identity.RevocationRegistry` seam. The `Service` returned by
    `identity.NewService` does, so ordinary wiring is unaffected; a hand-written `identity.Service`
    passed to the preset must implement it (or embed the real Service). Failing construction is
    deliberate: without that seam the preset cannot revoke the refresh families it issues.
  - `webapp.NewWebApp` now MUTATES the service it is handed, registering an account revoker on it.
    Wire the preset once, at startup, before serving traffic.

### Added

- **The MFA login gate now covers every login path.** `identity.WithMFAGate` applies to
  `MagicLinkLoginHandler` as well as `LoginHandler` (a magic link is a first factor: a compromised
  mailbox no longer bypasses the second factor), and the new `oauth.WithMFAGate(checker)` +
  `oauth.WithInterimTokenTTL(d)` bring the same gate to `CallbackHandler` /
  `DynamicCallbackHandler`, so an IdP-account compromise no longer yields a full renewable local
  session. An enrollment-check error fails closed on every path.

- **`tokens.AccessTokenIssuer[C]`**, an optional extension of `tokens.Issuer` minting a standalone
  access token with no refresh token and no persisted refresh-token family
  (`IssueAccessToken(ctx, claims) (string, time.Time, error)`). `jwt.Service` and `jwt.SingleTenant`
  implement it, and the MFA-gated login paths use it for the interim credential — which previously
  minted a full pair and discarded its refresh token, leaving a full-`RefreshTTL` refresh row behind
  for a session that was never granted. Implementing it in a custom issuer is optional: egauth
  type-asserts and falls back to `IssueTokenPair`.

- **Assurance helpers** for enforcing step-up outside the middleware: `tokens.Claims.SatisfiesStepUp()`,
  `tokens.HasStepUpFactor(amr)`, `tokens.Claims.AsInterim(ttl)` (stamps `Interim`, strips every
  step-up AMR marker, sets the short expiry), plus the non-generic context bridge
  `tokens.Assurance`, `tokens.AssuranceResolver`, `tokens.AssuranceFromContext` and
  `tokens.AssuranceResolverFromContext`.

- **Forced-password-change for temporary credentials** (M7). Lets an admin provision a credential
  that requires the user to choose a new password at next login, without ever locking the user out:

  - `identity.AdminCreateUser(ctx, tenantID, email, tempPwd)` creates an account with a temporary
    password, and `identity.SetTemporaryPassword(ctx, tenantID, userID, tempPwd)` replaces an
    existing credential with one — both flag the identity so the user must set their own password
    before the app is usable.

  egauth deliberately does **not** offer periodic, age-based password rotation: fixed-interval
  expiry is discouraged by NIST SP 800-63B.

  At next login, when a credential is flagged, `LoginHandler` / `MagicLinkLoginHandler` issue a
  full, **renewable** pair whose access token carries `tokens.Claims.MustChangePassword=true` (JSON
  claim `must_change_password`). The flag is recorded on the refresh-token family and `Rotate`
  replays it onto every silent refresh (overriding the `ClaimsProvider`), so the renewed token is
  flagged iff the family was — a silent refresh cannot drop the flag and a user cannot escape the
  gate by waiting for the access token to expire. To force a change on a user's existing sessions,
  an admin revokes their token families (`SetTemporaryPassword` does this via its erasers).

  `tokens.WithPasswordChangeGate[C](resetURL)` enforces the gate generically in the `RequireAuth`
  middleware: after successful token verification, if `Claims.MustChangePassword` is true, the
  wrapped handler is bypassed and the request is redirected `303` to `resetURL` (or `403
  password_change_required` if `resetURL` is empty). The change-password and logout routes must
  be excluded from this middleware.

  On a successful `ChangePassword` / `ResetPassword`, `UpdateIdentityPassword` atomically stamps
  `PasswordChangedAt` and clears the flag; `ChangePasswordWithReissueHandler` re-issues a full
  access+refresh pair so the user is immediately authenticated.

  New `identity.Store` method: `UpdateIdentityPassword(ctx, tenantID, userID, passwordHash,
  changedAt time.Time, mustChange bool)` (stamps timestamp and flag in one atomic write). External
  store implementers must add this method; run `identity/storetest` to verify conformance.

  New `tokens.RefreshToken.MustChangePassword` field records the gate on the rotation family; the
  `tokens.Store` (`SaveRefreshToken` / `FindRefreshToken`) must persist and return it. External
  token-store implementers must carry this field; run `tokens/storetest` to verify conformance.

  New pgx migrations: `adapters/pgx/identity` migration `008_add_password_change_columns.sql` adds
  `password_changed_at` (nullable, informational "last changed" audit metadata — drives no behavior)
  and `must_change_password` (boolean, default false) to the `identities` table;
  `adapters/pgx/tokens` migration `005_add_refresh_token_must_change_password.sql` adds
  `must_change_password` (boolean, default false) to the `tokens` table so the gate survives refresh.

  Zero behavior change unless a credential is explicitly flagged via admin provisioning.

- **`identity.ActiveClaimsProvider` + `identity.Service.EnsureActive`: the account-status re-check
  refresh rotation needs.** `Rotate` resolves fresh claims through the issuer's `ClaimsProvider`,
  which is the only place a rotation can be refused. Wrapping your provider —
  `identity.ActiveClaimsProvider(svc, provider)` — aborts the refresh of a disabled or soft-deleted
  account with `ErrAccountDisabled` / `ErrUserNotFound` (the presented token stays unconsumed;
  `RefreshHandler` answers `401` and clears the cookies). `EnsureActive` is the underlying gate and
  is also the cheap status check for API-key and background-job paths that never re-run
  `Authenticate`. New narrow interface `identity.ActiveChecker` for wiring it from less than the
  whole Service.

- **`identity.RevocationRegistry`: post-construction registration of the revocation hooks.**
  `RegisterAccountErasers` / `RegisterDisableRevokers` do at wiring time what `WithAccountErasers` /
  `WithDisableRevokers` do at construction, for a composition root that only receives an
  already-built `Service` (a DI container, or the `webapp` preset). Hook lists are copied on write,
  so registration is safe alongside in-flight operations.

### Fixed

- **Account deactivation did not end access in the shipped `webapp` preset (HIGH).** The only
  `ClaimsProvider` egauth shipped never looked at the account: it took `_ context.Context`, could
  not fail, and the preset registered no disable revoker (it could not — `Config.Identity` arrives
  already constructed). So after `identity.DisableUser`, every `POST /auth/refresh` still returned
  `204` and each rotation reset the refresh expiry to `now+RefreshTTL` — access was not merely
  retained, it was renewed indefinitely, defeating offboarding, GDPR erasure and compromise
  response for anyone using the preset or the README quickstart. `NewWebApp` now wires both halves
  (revoker registration + `ActiveClaimsProvider`) and refuses to build when it cannot. Every shipped
  example, the README quickstart, `.llms/*`, `llms.txt` and the docs site taught the same broken
  provider and were corrected.

- **`identity/memory`'s `UpdateUser` blind-wrote the whole user row, clearing `DisabledAt`.** A
  stale `*User` copy — e.g. the one a concurrent `VerifyEmail` holds — replayed its old values over
  an administrative change, so a suspended account could be re-activated (and `Phone`,
  `PhoneVerifiedAt`, `RecoveryEmail`, `RecoveryEmailVerifiedAt` reverted) and log in again. The
  memory backend now persists only `Email`/`EmailVerifiedAt`, matching the pgx backend's narrow
  `UPDATE`; the field scope is now part of the documented `Store` contract and pinned for BOTH
  backends by `storetest.StoreUpdateUserFieldScopeContract`.

- **`tokens.NewAccountRevoker`'s doc claimed more than it does.** It said it invalidates "EVERY
  token a user holds" and kills "every active session". It revokes stored refresh tokens and API
  keys; an already-issued stateless access token survives until `AccessTTL` expires and the
  `sessions` module is untouched. The godoc, `SECURITY.md`, `.llms/tokens.md`, `.llms/identity.md`,
  `.llms/architecture.md` and the docs site now state exactly what is revoked, what survives and
  for how long. The `identity.Service.DisableUser` doc no longer claims that refresh tokens are not
  revoked by the call (they are, through the registered revokers).

- **HTTP handlers now fail CLOSED on an unresolved tenant** (`identity`, `tokens`, `otp`, `oauth`).
  A configured tenant resolver that could not map a request (the natural result of a map or DB
  lookup for an unknown `Host`) returned `""`, and that `""` was passed through verbatim: the
  request then authenticated, registered, reset a password, verified an OTP, rotated/revoked a
  refresh family or linked an OAuth identity **in the empty tenant partition** — which in a
  single-tenant/bootstrap deployment is exactly where the operator accounts live. `identity.LoginHandler`
  returned `204` against `""` and `identity.RegisterHandler` created an account there.

  Every handler now distinguishes "no resolver configured" (single-tenant mode: `""` is the
  legitimate default partition, unchanged) from "a resolver was configured and could not resolve"
  (refused). The refusal is `401 tenant_unresolved` on the `identity` and `tokens` handlers, `401`
  with the family's uniform code on `otp` (`unauthorized` for `IssueHandler`, `invalid_code` for
  `VerifyHandler`, so no new account-existence oracle is introduced) and `403 tenant_unresolved` on
  the `oauth` begin/callback handlers (matching the existing `tenant_mismatch` refusal).
  `sessions.RequireSession` and `tokens.RequireAuth` already behaved this way; the handler families
  now mirror them. The `WithTenantResolver` doc comments, `SECURITY.md` and the `.llms/*.md` guides
  document the contract, and the guides no longer teach `func(r *http.Request) string { return
  r.Host }` — resolvers must map the request through an explicit allowlist / canonical table.

- **Handlers resolve the tenant exactly once per request** (`identity`, `tokens`, `otp`, `oauth`).
  `identity.LoginHandler` resolved it three separate times (authentication, the
  forced-password-change check, the MFA-enrollment gate), so an impure resolver — an expiring cache
  entry, a transient store error returning `""` — made `MFAEnrollmentChecker.IsEnrolled` look for
  the second factor in the wrong partition, find none, and skip the MFA branch entirely, issuing a
  full renewable session on the password alone. Each handler now pins the single resolved value and
  reuses it for every store operation (`oauth.DynamicCallbackHandler` already did this).

- **A negative lockout argument no longer silently disables brute-force protection**
  (`identity`, `mfa`). `identity.WithLockout` and `mfa.WithMaxAttempts` were documented (and, for
  `WithLockout`, doc-commented) to treat any non-positive argument as "use the safe default" —
  only `WithNoLockout` / `WithNoAttemptLimit` are meant to disable the gate. In both services,
  `NewService`'s normalization mapped a NEGATIVE threshold/limit to the same internal value as
  the explicit opt-out, so e.g. `identity.WithLockout(-1, ...)` or `mfa.WithMaxAttempts(-1)`
  silently disabled lockout/attempt-limiting instead of falling back to the default. Both options
  now clamp any non-positive value (zero or negative) to the documented default, and the disabled
  state is reachable ONLY through `WithNoLockout` / `WithNoAttemptLimit` (now tracked via an
  explicit boolean field rather than overloading the threshold/limit itself).

- **`mfa.WithLockoutDuration(0)` now actually produces a permanent lockout, as documented**
  (`mfa`). The option's godoc, its field doc and SECURITY.md all state that `0` disables
  time-based lockout decay (permanent until `UnlockMFA` or `DisableTOTP`), but `NewService`
  could not distinguish a deliberate `WithLockoutDuration(0)` from an untouched field and always
  overwrote it with `DefaultLockoutDuration` — making the documented permanent-lockout setting
  unreachable. `WithLockoutDuration` now records that it was explicitly called, so `0` (or any
  negative value) is honored as "no decay".

- **Cookie configuration no longer panics at request time** (`tokens`, `identity`, `oauth`, `mfa`,
  `webapp`). `tokens.Cookies.withDefaults` panicked whenever a `__Host-` cookie name was paired with
  a `Domain`, a `Path != "/"` or `Insecure`, and it ran on the request path — including inside the
  pure read helpers `Cookies.Access` / `Cookies.Refresh`. Consequences: `webapp.Config.CookieDomain`
  broke every cookie-writing endpoint while `NewWebApp` reported no error; `WithCookieDomain`,
  `WithCookiePath`, `WithRefreshCookiePath` and `WithInsecureCookies` each produced an unusable
  handler; and `tokens.RequireAuth` with domain-scoped cookies panicked on EVERY request to a
  protected route, even an unauthenticated `GET` carrying no cookie at all.

  Those options are now self-consistent: they DEMOTE a cookie name that still carries the `__Host-`
  prefix to `__Secure-` (while the cookie stays `Secure` with `Path="/"`) or to its bare form,
  because setting a `Domain`, a path scope or `Insecure` is already an opt-out of host-lock
  semantics. New demoting derivations on `tokens.Cookies` — `WithDomain`, `WithPath`,
  `WithRefreshPath`, `WithInsecure` — plus `MustValidate`, expose the same behavior for hand-built
  values. `Validate` additionally rejects a `__Secure-` name on a non-`Secure` cookie.

  Validation moved to CONSTRUCTION: `tokens`/`identity`/`oauth`/`mfa` handler constructors and
  `tokens.RequireAuth` / `tokens.ContextMiddleware` call `MustValidate` (a startup panic on a
  genuinely invalid hand-built value), and `webapp.NewWebApp` returns it as an error. `DefaultCookies`
  is unchanged — `__Host-` remains the default.

### Security / disclosure (v1.0.0)

- **Audit-status disclosure.** egauth's security review to date is an AI-driven audit only; it
  has not had an independent third-party human security audit, and that risk is accepted for
  v1.0 — pin a reviewed commit, commission your own audit, or wait if that trade-off is
  unacceptable. "AI-audited" is **not** a synonym for "audited". The full review scope (what was
  reviewed and how, what was not, the accepted trade-offs) and the cautious-user escape hatch
  live in the new [`AUDIT.md`](AUDIT.md) ledger. The canonical sentence above is reused verbatim
  across the README, root package godoc (`doc.go`), `llms.txt`, and `SECURITY.md`, and its
  presence on those surfaces is enforced by a build-failing test (`disclosure_test.go`).
  Post-v1, any security-relevant change re-discloses its review status here (see AUDIT.md's
  re-disclosure policy). (#19)

## [0.7.0] - 2026-07-21

Security-hardening batch: CSRF coverage is completed across the state-changing handler families,
audit coverage is broadened to the OAuth and admin paths, and a set of concurrency/correctness
bugs are fixed.

### BREAKING

- **tokens/jwt (PAT subject):** `IssueAPIKey` for `KeyTypePAT` now pins the token's `Claims.Subject`
  to `createdBy`. A caller-supplied `Subject` naming a different user is rejected with the new
  `ErrPATSubjectMismatch` (previously it was honored verbatim). This guarantees a PAT is severed by
  `DisableUser` → `RevokeAllAPIKeysForUser`, which is scoped by `CreatedBy`. Leave `Subject` unset to
  default it.

### Added

- New audit events on previously SIEM-dark paths: OAuth login (`login.succeeded` /
  `login.failed{account_disabled}` with `method=oauth`), JIT provisioning
  (`user.registered{oauth_provision}`), and admin credential operations
  (`password.changed{admin_temporary_password}`, `user.registered{admin_created}`), mirroring the
  password path.
- New `event.Type` values: `mfa.verified`, `mfa.unlocked`, `credential.added`, `credential.removed`.
- CI coverage for the `adapters/otel` module (`go vet` + `go test -race`).

### Changed

- **CSRF secure-by-default documentation.** `tokens.WithTrustedOrigins` and `mfa.WithTrustedOrigins`
  are documented as *wideners* of an on-by-default strict same-origin check; disabling requires the
  explicit `WithInsecureNoOriginCheck` opt-out. `SECURITY.md` updated to match.

### Fixed

- **identity (CSRF gap):** `VerifyEmailHandler` and `RequestEmailVerificationHandler` now enforce the
  strict same-origin check their siblings apply; a cross-origin POST is rejected with `403
  cross_site_blocked` (previously processed).
- **internal/httputil:** an opaque `"null"` `Origin` is treated as untrusted rather than falling back
  to the weaker, more-spoofable `Referer`.
- **tokens/jwt (key cache):** an `Invalidate`/`InvalidateAll` racing an in-flight cache fill is no
  longer lost; the stale pre-rotation keyset is dropped instead of being re-cached for a full TTL.
- **oauth:** `DynamicBeginHandler` / `DynamicCallbackHandler` no longer mutate the shared
  closure-captured `opts` slice, so concurrent requests for different tenants can no longer alias one
  another's resolver.
- **mfa:** `NewService` rejects a sub-second `WithPeriod` at construction (previously a divide-by-zero
  panic on first use); `ConfirmTOTP` resets the failed-attempt budget on success so failed
  confirmations are not carried into the user's first-login budget.
- **passkey:** a per-handler `WithCookieKey` override shorter than `MinCookieKeyLength` now fails
  closed with `500 server_misconfigured`.
- **event:** a panicking `Sink` is contained (and logged) so a misbehaving audit sink cannot change a
  handler's client-visible behavior; `MultiSink` continues its fan-out past a panicking member.
- **adapters/pgx:** `AddIdentity` gates the insert on a live, same-tenant user (`ErrUserNotFound`
  otherwise), matching the memory store and closing a cross-tenant / soft-deleted linkage hole.
- **adapters/pgx (keystore):** `CreateTenant` is now atomic per tenant. Its check-then-insert ran
  unserialized, so concurrent calls for the same new tenant (with distinct key ids) could all win
  and insert multiple active signing keys; it now runs inside a transaction guarded by a per-tenant
  `pg_advisory_xact_lock`, so exactly one call wins and the rest get `ErrTenantExists`.

## [0.3.0] - 2026-06-06

Public-release hardening: secure-by-default behavior changes, a PostgreSQL storage-adapter
module split, plus documentation/naming/packaging cleanup and pre-1.0 API-stability changes,
in preparation for an open public release. Under v0.x SemVer the breaking changes below are a
minor bump. The pre-hardening tags `v0.1.0`–`v0.2.1` are retracted in `go.mod`.

### BREAKING

- **passkey (secure-by-default):** `passkey.NewService` now fails fast on insecure
  configuration. WebAuthn user verification is **required by default** (set
  `Config.UserVerification` explicitly to opt out); a `ChallengeStore` is **required**
  (`Config.ChallengeStore`) unless `Config.InsecureNoChallengeStore` is set; and the HMAC
  cookie key is supplied and validated at construction (`Config.CookieKey`, min length
  `MinCookieKeyLength`). New sentinels `ErrCookieKeyMissing` and `ErrChallengeStoreMissing`.
  Existing callers must add `CookieKey` + `ChallengeStore` (or the explicit opt-outs).
- **mfa (secure-by-default):** the second factor is now attempt-limited. `VerifyTOTP` and the
  recovery-code path reserve a slot via the new `mfa.Store.IncrementTOTPAttempts` atomically
  *before* the constant-time compare and lock the factor after `DefaultMaxAttempts` (5) failures
  (`ErrTooManyAttempts`, HTTP 429); a successful verification resets the counter. Limiting is ON
  by default — tune it with `mfa.WithMaxAttempts` or disable it explicitly with
  `mfa.WithNoAttemptLimit`. Adds `failed_attempts` to `mfa_totp` (pgx migration
  `002_add_totp_failed_attempts.sql`). External `mfa.Store` implementers must add
  `IncrementTOTPAttempts` and reset `failed_attempts` on a successful `MarkTOTPUsed` /
  `ConsumeRecoveryCode`.
- **tokens/jwt:** `jwt.VerifyRefreshToken` and `jwt.VerifyAPIKey` now take a `tenantID string`
  parameter (after `ctx`) so multi-tenant callers can verify tokens saved under a real tenant —
  the lookup was previously hard-wired to the empty tenant and reported not-found for any token
  saved under a real one. Single-tenant callers pass `""` (or use the `SingleTenant` facade,
  whose signature is unchanged).
- **pgx storage moved to a nested module:** the PostgreSQL stores + migration runner now live in
  the separate module `github.com/JLugagne/egauth/adapters/pgx` (packages `adapters/pgx/identity`,
  `adapters/pgx/tokens`, …) instead of `egauth/<domain>/pgx`. Core consumers no longer pull the
  `pgx` driver or the testcontainers/Docker dependency chain. Update imports to
  `github.com/JLugagne/egauth/adapters/pgx/<domain>` and add
  `go get github.com/JLugagne/egauth/adapters/pgx`. The `Store` interfaces and the exported
  `*storetest` conformance suites stay in core as the documented backend-extension seam.

### Added

- `tokens/basic`: a non-generic convenience layer over the generic token API, specialized to
  no-custom-claims, so the common login/refresh/protect path can be wired without writing
  `[struct{}]`. The generic `tokens` / `tokens/jwt` API is unchanged and remains the path for
  custom claims.
- Four OAuth providers since v0.2.0 — **Amazon Cognito, Discord, GitLab, and Keycloak** —
  bringing `oauth/providers` to **12** (Apple, Auth0, Cognito, Discord, Facebook, GitHub, GitLab,
  Google, Keycloak, LinkedIn, Microsoft, Okta).
- This `CHANGELOG.md`, backfilled from git history.

### Changed

- Documentation, naming, and packaging consistency improvements across the repository
  (module/name consistency, README, package docs, pinned CI linter, relaxed `go` directive).
- Documented that `identity.Store` / `tokens.Store` are cohesive, pre-1.0-evolving persistence
  contracts (new methods may be added in minor releases); they are intentionally not split into
  optional capability interfaces.

### Fixed

- Documentation drift and packaging rough edges surfaced during the public-release audit
  (non-compiling package example, duplicated doc comments, dangling references, stale provider
  list, tracked coverage artifact).

## [0.2.1] - 2026-06-04

### Changed

- Synchronized the `oauth/providers` documentation with the actual code and
  added a CI check that validates the provider docs to prevent future drift.

## [0.2.0] - 2026-06-04

### Added

- Extracted the OAuth providers into a dedicated `oauth/providers` package and
  added support for 8 identity providers.

### Changed

- OAuth provider documentation kept in sync with the code and checked in CI.

## [0.1.0] - 2026-06-03

Initial public release.

### Added

- Composable, multi-tenant authentication library with an explicit, mandatory
  `tenantID` argument across stores.
- OAuth/OIDC support, including a `ProviderStore` and dynamic handlers for
  multi-tenant provider configuration.
- Configurable Argon2 cost parameters with `NeedsRehash` for transparent
  rehash-on-login.
- Session management with an absolute maximum lifetime and a
  revoke-all-sessions-for-user capability.
- Independent recovery channel and a phone/SMS verification flow.
- Context-cancellation support on expensive code paths.
- Store `Ping` health-check seam.
- Comprehensive developer manual and documentation, including a quickstart,
  runnable examples, and package-level docs, with a CI doc-symbol check to
  guard the docs against API drift.
- MIT License, `CONTRIBUTING.md`, a Makefile, a GitHub Actions
  security/testing pipeline, and a GitHub Pages workflow for the Hugo docs.

### Changed

- HS256 JWT signing keys are redacted in log and print output.

### Security

- Enforced WebAuthn user verification (SEC-01).
- SSRF-hardened server-side OIDC fetches (SEC-02).
- Verified `iss` and `aud` on the access-token path (SEC-03).
- Reject malformed Argon2 PHC parameters instead of panicking (SEC-04).
- Single-use passkey challenge consumption to block login replay (SEC-05).
- Required HTTPS and bound JWKS to the issuer via OIDC discovery.
- Bounded the JWKS key count and RSA modulus/exponent size (SEC-11).
- Bound the OAuth state cookie to the provider and tenant (SEC-12).
- Capped the passkey `Finish` ceremony request-body size (DOS-01).
- Memory session store: O(1) hash lookup and eviction of expired sessions to
  prevent unbounded growth (DoS hardening).
- Deferred OIDC configuration errors instead of panicking per request.
- Completed and documented a panic/DoS sweep (3 confirmed issues fixed,
  4 refuted).
