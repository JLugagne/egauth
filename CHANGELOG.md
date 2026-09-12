# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.13.0] — 2026-09-13

### Added

- **Exported same-origin / CSRF primitive** (#127): new `origin` package with
  `origin.Allowed`, `origin.NormalizeHosts`, `origin.TrustedSet` and
  `origin.Middleware(...)` (plus `WithTrustedOrigins` / `WithInsecureNoOriginCheck`) so an
  application can gate its **own** cookie-authenticated routes with the exact strict
  same-origin check the built-in handlers apply, instead of hand-rolling a weaker one.
- **Access-token revocation** (#126): `tokens.WithAccessTokenRevocation(checker)`,
  `tokens.AccessTokenRevocationChecker` / `...Func` and `tokens.NewRevocationTracker(bus)`
  let `RequireAuth` / `ContextMiddleware` reject an already-issued access token after a
  logout, password change or account disable, before its `AccessTTL` elapses. The tracker
  consumes the `revocation` bus, so one event can invalidate the refresh family and the
  live access tokens together. Opt-in: no per-request lookup when unset.

### Fixed

- **`WithTrustedOrigins` now normalizes full origins** (#124): every option (`tokens`,
  `identity`, `otp`, `mfa`, `authflow`, `sessions`, `passkey`) accepts both full origins
  (`https://app.example.com`) and bare hosts (`app.example.com`) and normalizes them to the
  bare host before matching. Previously a full-origin entry never matched and the legitimate
  origin was rejected `403 cross_site_blocked`; matching stays exact, so lookalike hosts are
  still rejected.
- **OTP codes are redacted** (#125): `otp.Challenge` and `otp.OTP` implement
  `String`/`GoString`/`LogValue`, so `%v`, `%+v`, `%#v` and `slog` render `Code` / `CodeHash`
  as `REDACTED`. `Challenge.Code` remains available for delivery.

### Changed

- Documentation for every `WithTrustedOrigins` option now states that both full origins and
  bare hosts are accepted; new `.llms/origin.md` and expanded `.llms/tokens.md`,
  `.llms/recipes.md`, `.llms/secure-defaults-matrix.md` and `SECURITY.md` sections cover the
  `origin` primitive and the access-token revocation window.

## [v0.12.0] — 2026-09-10

### Security

- **Signed release tags.** Release tags are now created with a verifiable signature
  (keyless Sigstore/gitsign by default; OpenPGP or SSH supported) and must pass
  `scripts/verify-release-tag.sh` before they are pushed. Tags up to and including
  `v0.11.0`, including all `adapters/pgx` tags, were cut before this control and carry no
  signature: `git verify-tag` rejects them. Treat those tags as unverified and prefer the
  first signed release; see [SECURITY.md](SECURITY.md#verifying-a-release) for consumer
  verification instructions.
- **Release artifact provenance.** SBOM release assets can now be signed/attested so
  consumers can verify them against the same identity as the tag; see
  [RELEASING.md](RELEASING.md) Step 7 for the signing and verification commands.

## [v0.11.0] — 2026-09-09

### Security

- **Passkey login enforces account lifecycle** (#116): a new `passkey.Config.AccountGate`
  (wire `passkey.NewIdentityAccountGate(identityStore)`) refuses login ceremonies for
  accounts administratively disabled with `identity.DisableUser` (which preserves passkey
  enrollment) or soft-deleted — `BeginLogin` refuses up front, `FinishLogin` /
  `FinishDiscoverableLogin` refuse after a valid assertion with 403 `account_disabled` /
  `account_deleted`, and the blocked attempt is audited as an `AccountBlocked` event. The
  fullstack example wires the gate.
- **Published example signing keys denied** (#112): the `tokens/jwt` denylist now also
  rejects two publicly published valid-length signing keys (a godoc example key and a
  docs-published key) so copy-paste deployments fail fast instead of shipping
  attacker-known HMAC secrets; the `webapp` example/tests generate keys with `crypto/rand`.
- **authflow cookies are Secure by default** (#113): the MFA flow cookie and
  `StatefulSessionMinter` session cookie no longer derive `Secure` from `r.TLS` (behind a
  TLS-terminating proxy the attribute was silently dropped, breaking `__Host-` cookies and
  exposing non-prefixed session tokens). `Secure` is always on; an explicit
  `WithInsecureCookies` opt-out serves local HTTP development, cannot drop `Secure` from
  `__Host-` names, and emits a one-shot `InsecureCookieMisuse` event on non-loopback
  plaintext hosts.
- **Host-locked flow and ceremony cookies** (#114): `authflow` defaults to
  `__Host-auth_flow_token` and `passkey` to `__Host-passkey_ceremony`, structurally
  defeating sibling-subdomain cookie-tossing of the HMAC-sealed flow/ceremony state;
  attribute misconfigurations fail construction (`ValidateHandlerConfig` /
  engine validation) and plain names remain an explicit opt-out.
- **Default CSRF origin check on authflow step-up** (#115): `authflow.StepUpHandler` now
  applies the library-wide origin check (403 `cross_site_blocked` for cross-origin
  requests), with the same `WithTrustedOrigins` / `WithInsecureNoOriginCheck` options and
  semantics as identity/tokens/mfa — it was the only state-changing POST without one.
- **SSRF guard covers the static OIDC path** (#117): operator-configured OIDC
  discovery/JWKS fetches default to the SSRF-safe HTTP client (dial-time
  internal-address guard, DNS-rebinding-proof, redirects never followed) and discovered
  endpoints (`userinfo_endpoint` et al.) are validated before use; a plain client only
  behind the explicit `AllowInsecureURLs` dev opt-in.
- **OAuth state signing key minimum length** (#118): `WithStateSigningKey` enforces
  `MinStateSigningKeyLength` (32 bytes) — shorter keys now fail handler construction
  instead of producing offline-brute-forceable state cookies.
- **Uncacheable auth responses** (#119): every token/session-cookie response (login,
  register, refresh, logout, OAuth callback, MFA/OTP/passkey/authflow handlers, and the
  auto-refresh middleware — including its GETs) sends `Cache-Control: no-store` /
  `Pragma: no-cache`, so shared caches cannot retain live token material.
- **Step-up requires an account-lifecycle validator** (#120): constructing an authflow
  engine with a `MFAGate` but no `AccountValidator` is now a construction error, and
  `ProcessStepUp` fails closed without one — an account disabled after the challenge can
  no longer complete step-up and mint credentials.
- **TrustedOrigins format normalized in webapp** (#121): `webapp.Config.TrustedOrigins`
  now accepts both full origins (`https://app.example.com`) and bare hosts
  (`app.example.com`) — the previously documented format silently never matched and
  403'd the legit front-end, tempting operators into disabling the origin check; invalid
  entries fail construction.

### Internal

- CI: every job is capped with `timeout-minutes` so a hung job cannot burn the default
  360-minute runner budget; pgx testcontainers postgres readiness timeout raised to 60s
  (eliminates load-related `TestPgxStore_Contract` flakiness); docs-pages workflow moved
  to per-job least-privilege permissions with a checksum-verified Hugo install (#122).

## [v0.10.0] — 2026-09-08

### Added

- **Unified authentication state machine** (#71): a single state machine governs the
  account lifecycle across login, lockout, disablement, and recovery paths.
- **Unified cross-module revocation bus** (#72): revocation events fan out to all
  stores (tokens, sessions, MFA factors) through one in-process bus.

### Security

- **Published example keys rejected** (#104, #105): `tokens/jwt` and `passkey`
  refuse attacker-known keys published in examples/docs (exact-match denylist,
  all-zero cookie-key guard); the fullstack example generates keys with
  `crypto/rand` and the docs use `os.Getenv` patterns.
- **Uniform login responses by default** (#106): locked and disabled accounts
  answer 401 `invalid_credentials` like unknown identifiers, closing the
  429-vs-401 enumeration oracle; deployments wanting verbose lockout feedback
  opt in with `identity.WithVerboseLockoutStatus`.
- **MFA step-up preserves must-change** (#107): `mfa.StepUpHandler` propagates
  `MustChangePassword` from the interim token's verified claims by default;
  `WithMustChangeResolver` remains an explicit override.
- **No tokens minted for disabled accounts** (#108): `RequestMagicLink`,
  `RequestPasswordReset`, `RequestPasswordResetViaRecovery`, and
  `RequestEmailVerification` return empty results for disabled accounts
  (decoy-timed), with matching store-level `disabled_at IS NULL` guards.
- **Hardened OAuth state cookie** (#109): a state signing key is now required
  (startup `ValidateHandlerConfig`, fail-closed handlers), and the default state
  cookie is `__Host-`-prefixed with Secure/`Path=/`/no-Domain enforced.
- **Spoof-proof redirect scheme** (#110): `X-Forwarded-Proto` is never trusted;
  the Host-derived `redirect_uri` fallback is dev-only and emits a
  `oauth.redirect_fallback_misuse` warning event when used.
- **`adapters/otel` covered by govulncheck** (#111).

### Dependencies

- Updated `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/text`,
  `jackc/pgx/v5`, and related modules.

## [v0.9.0] — 2026-09-06

### Security & Hardening

- **Comprehensive Security Audit Hardening** (Issues #60–#65, #89–#102):
  - **Tokens & Keystore** (SEC-TOK): Retained revoked token families with `RevokedAt` timestamp for auditability while rejecting replayed tokens with `ErrTokenFamilyRevoked`. Added `HistoricalKeyStore` with soft-retire and retention options to prevent premature hard deletion of expired signing keys. Enforced atomic refresh rotation to prevent token burning on provider errors. Enforced explicit API key principal types (`user`, `service`, `system`, `pat`).
  - **Identity & Passwords** (SEC-ID): Fully sanitized PII on account deletion (`DeleteUser`), redacting/clearing `Phone` and `RecoveryEmail` for GDPR compliance. Integrated offline breach detection in `policy.NewDefaultPolicy()` to reject compromised dictionary passwords. Added uniform timing / decoy token generation on non-existent account reset requests.
  - **Sessions & WebApp** (SEC-SES): Made `RevokeSession` idempotent and emitted audit logout events. Added panic observation handlers to `janitor.Janitor` and clamped non-positive intervals to safe defaults. Sanitized `CookieDomain` configuration in `webapp.NewWebApp`.
  - **MFA, OTP & Passkey** (SEC-MFA, SEC-PSK, SEC-OTP): Added `EnrollmentConfirmer` for atomic TOTP confirmation and recovery code persistence. Added `RecoveryAttemptStore` to isolate recovery code lockout from TOTP attempt exhaustion. Allowed backup recovery codes in `StepUpHandler`. Bound tenant context via AAD in KEK encryption for TOTP secrets. Enforced cooldown on OTP reissue and synchronized challenge generation prior to returning HTTP 204. Automatically revoked cloned passkey credentials upon signature counter regression. Bound ceremony cookies to tenant ID.
  - **OAuth & OIDC** (SEC-OAU): Bound tenant ID and provider name via AAD in KEK encryption for client secrets. Added HMAC-SHA256 integrity protection to OAuth state cookies. Implemented bounded capacity and LRU eviction in pgx `providerCache`.
  - **Global & Multi-Tenancy** (SEC-GLO): Synchronized tenant context propagation between `tokens.ContextMiddleware` and OTP handlers. Introduced `StopContext` and `WithStopTimeout` for bounded janitor shutdown.

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
