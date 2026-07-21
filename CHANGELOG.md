# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
