# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Public-release hardening (M1): documentation, naming, and packaging cleanup plus
pre-1.0 API-stability changes, in preparation for an open public release.

### Added

- `tokens/basic`: a non-generic convenience layer over the generic token API,
  specialized to no-custom-claims, so the common login/refresh/protect path can
  be wired without writing `[struct{}]`. The generic `tokens` / `tokens/jwt`
  API is unchanged and remains the path for custom claims.
- This `CHANGELOG.md`, backfilled from git history.

### Changed

- **BREAKING (passkey, secure-by-default):** `passkey.NewService` now fails fast
  on insecure configuration. WebAuthn user verification is **required by default**
  (set `Config.UserVerification` explicitly to opt out); a `ChallengeStore` is
  **required** (`Config.ChallengeStore`) unless `Config.InsecureNoChallengeStore`
  is set; and the HMAC cookie key is supplied and validated at construction
  (`Config.CookieKey`, min length `MinCookieKeyLength`). New sentinels
  `ErrCookieKeyMissing` and `ErrChallengeStoreMissing`. Existing callers must add
  `CookieKey` + `ChallengeStore` (or the explicit opt-outs).
- Documentation, naming, and packaging consistency improvements across the
  repository (module/name consistency, README, package docs, pinned CI linter,
  relaxed `go` directive).
- Documented that `identity.Store` / `tokens.Store` are cohesive, pre-1.0-evolving
  persistence contracts (new methods may be added in minor releases); they are
  intentionally not split into optional capability interfaces.

### Fixed

- Documentation drift and packaging rough edges surfaced during the
  public-release audit (non-compiling package example, duplicated doc comments,
  dangling references, stale provider list, tracked coverage artifact).

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
