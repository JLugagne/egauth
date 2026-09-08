# Auth & session audit — egauth (`github.com/JLugagne/egauth`), commit `6f16690`

Worktree: `.security-audit/2026-09-08-1945/wt-auth-session` (all PoC tests run with `GOWORK=off`).
Findings machine-readable: `auth-session.json` (4 entries: 2 Medium, 2 Low).

## What was checked

- **Password verify / enumeration**: `identity/service.go Authenticate` (decoyHash on every non-compare path, Argon2id cost is input-length independent), `passwords/argon2` floors (19 MiB min, clamped), pre-auth DoS ordering (policy → existence → hash), `mapAuthError` status mapping, webapp preset wiring.
- **Lockout**: atomic `IncrementFailedAttempts` with exactly-once `justLocked` (memory + pgx single-statement), decay/sliding-window logic, `UpdateIdentityPassword` resets counters (reset/unlock works, no bypass), success resets only when attempts > 0.
- **Reset / magic-link / verification tokens**: selector (128-bit) / verifier (256-bit) split, SHA-256 hash-at-rest, constant-time compare, tenant+kind binding, guarded single-use consume (memory lock, pgx guarded DELETE), expiry handling. Consume-before-hash ordering (no pre-auth KDF DoS).
- **JWT**: signer-resolved-before-alg pinning (no `none`/confusion — covered by `algconfusion_test.go`), `kid` must name a known signer, exp via injected clock, iss/aud gated only when configured but `Validate()` requires Issuer + positive TTLs, tenant binding enforced in `VerifyAccessTokenForTenant` + tenant-scoped keyfunc (no static fallback), refresh opaque 256-bit, API keys 256-bit + SHA-256 at rest + soft-revoke enforced at the single verify chokepoint.
- **Refresh rotation**: family theft detection with reuse grace; within-grace replay returns `ErrRefreshConcurrent` (no new tokens) and client-context mismatch revokes; atomic-rotator path + non-atomic consume-then-save with rollback; `ClaimsProvider` failure aborts BEFORE consume (retry-safe); `AuthTime` preserved across rotation (step-up freshness can't be refreshed away); must-change flag replayed across rotation.
- **Middleware gates**: `serveAuthenticated` fails closed, tenant resolved before verify+rotate, auto-refresh only on `ErrTokenExpired`, `WithRequiredAMR`/`WithMaxAuthAge`/`WithRequiredScopes`/`WithRequiredKind`/`WithGate` all evaluated on both fresh and rotated claims; `__Host-` secure-by-default cookies with `Validate()`.
- **Sessions**: `Rotate`/`BindUser` fixation primitives (compare-and-set on old hash), 30-day absolute cap by default, tenant-scoped stores, logout/revocation paths.
- **MFA/OTP**: attempt reservation BEFORE compare (TOTP, confirm, recovery, OTP), replay protection (`MarkTOTPUsed` strictly-newer step, OTP hash-guarded consume, recovery single-use `used_at IS NULL`), enrollment must confirm, disable requires step-up by default, recovery codes 80-bit + hashed, OTP 6–10 digits + cooldown + burn-on-limit.
- **Passkey**: ChallengeStore required by default (single-use consume-before-verify), UV defaults to required, clone detection deletes credential, attestation policy errors mapped before persist.
- **OAuth**: PKCE S256 on by default, state+provider+tenant binding in callback, `iss` mix-up check, email-unverified refused by default, no silent linking onto existing emails (takeover refused), empty ProviderID rejected.
- **Tenant isolation**: stores partition by tenant, SingleTenant wrappers hard-wire `""`, middleware rejects empty resolved tenant when a resolver is configured.
- **Account lifecycle**: disable/delete gates in `Authenticate`, `consumeForLiveUser`, `LinkOrCreateIdentity`; eraser/revoker cascades on reset/change/temp-password/delete (opt-in wiring, documented).

## Findings (per-finding summary)

- **AS-01 (Medium, high conf, CWE-204)** — Login status oracle: default `LoginHandler` answers 429 for locked/disabled accounts vs 401 for unknown/wrong. Unauthenticated enumeration; ships in webapp preset. Fix: default `uniformAuthErrors=true` (opt-in verbose).
- **AS-02 (Medium, high conf, CWE-863)** — MFA `StepUpHandler` drops `MustChangePassword` unless `WithMustChangeResolver` is wired; stepped-up family evades `WithPasswordChangeGate` indefinitely (default unbounded refresh lifetime). Fix: default the flag from the verified interim claims.
- **AS-03 (Low, high conf, CWE-863)** — `RequestMagicLink`/`RequestPasswordReset` mint tokens for disabled accounts (mint gates only `DeletedAt`); consume rejects later, after delivery. Fix: uniform `("", nil, nil)` for disabled at mint time.
- **AS-04 (Low, medium conf, CWE-352)** — OAuth state cookie unsigned unless `WithStateSigningKey`, and not `__Host-` locked; forgeable without a Begin round trip (login-CSRF shape with cookie-planting + lure). Fix: `__Host-` default name + signing validation.

## Ruled out (checked, no finding)

- Alg confusion / `none` / `kid` / `jku` injection: signer-first resolution + alg pinning; `jku`/`x5u` unsupported by construction.
- `exp`/`iat`/`nbf` validation bypass: `exp` enforced via parser clock; no `nbf` stamped; `aud`/`iss` enforced when configured and required by `Validate()`.
- Refresh `ReuseGracePeriod` abuse: within-grace replay yields `ErrRefreshConcurrent`, never tokens; cross-client replay revokes; post-grace replay revokes. Only revocation *timing* is grace-dependent — no attacker token gain. Multi-replica `rotationClients` miss degrades to benign-concurrency, same consequence.
- Concurrent rotation double-use: atomic rotator path or consume-race → `Concurrent` without family kill; guarded deletes keep single-use.
- Session fixation: fresh families/cookies at login, `Rotate`/`BindUser` CAS primitives, `__Host-` cookies defeat tossing for auth cookies.
- Logout/revocation: `LogoutHandler` revokes family + clears cookies; access tokens valid ≤ AccessTTL (15 min webapp default) — standard stateless tradeoff, not a flaw.
- MFA/TOTP/recovery/OTP attempt-limit bypass & replay: reserve-before-compare + atomic single-use everywhere (memory + pgx).
- TOTP secret at rest: KEK-sealed with tenant:user AAD in pgx; plaintext only in process memory.
- WebAuthn replay / challenge reuse / UV bypass: single-use challenge store, UV-required default, counter-clone handling.
- OAuth state/PKCE/email-verified/linking: all bound by default; `WithoutPKCE`/`WithAllowUnverifiedEmail` are explicit, documented opt-outs.
- Tenant isolation bypass: partition-scoped stores, tenant-bound JWT verify, fail-closed empty-tenant resolver.
- Weak-password acceptance: default policy min-8 + 4 character classes + denylist + breach checker; applied before token consume on reset and before hashing on register/change.
- API keys: 256-bit entropy, hash-only storage, type-pinned subjects, scope carriage on claims, revocation enforced at verify.
- Timing enumeration on password/OTP/recovery compares: decoy hashing + constant-time compares; Argon2id cost input-independent.
- `VerifyEmail` using `time.Now()` instead of injected clock: test determinism nit, not security.
- Rate-limit gaps (per-IP throttling left to `ratelimit.Middleware` by design), audit-log coverage, `.md`-only issues: noted, out of scope per rules.
