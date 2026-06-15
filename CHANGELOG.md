# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
