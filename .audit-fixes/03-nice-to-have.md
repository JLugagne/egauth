# Nice-to-have fixes (5 / 11)

DONE: N2 (rune length — commit 3e34d04), N3 (clock injection — aaca811/cbeb699/2f8163a), N5 (migration versioning — f0fbfa2), N6 (error taxonomy + dead sentinels — 55971a6), N11 (Store Ping seam — b60673a).

Polish / maturity.

---

## [ ] N1 — Account recovery via independent verified channel
**Where:** `identity`. Add enrollment of a recovery email/phone or backup factor; require it for sensitive recovery/factor-reset. Composes with I4/I5/I15 to break the single-email-channel takeover chain.

## [x] N2 — Password strength + DefaultPolicy rune length — DONE (3e34d04)
**Where:** `passwords/policy/default.go`. **Bug:** uses `len(password)` (bytes) not runes → multibyte mismeasured; DefaultPolicy has no denylist. **Fix:** `utf8.RuneCountInString` (match passphrase.go); optional strength-estimator hook. **Test (confirm-first):** multibyte password mismeasured today.
**DONE:** switched MinLength/MaxLength to `utf8.RuneCountInString` (confirmed-first test covers both the under-count and over-restrict directions). Denylist/strength-hook left to the passphrase policy (which already has denylist + BreachChecker) — not duplicated into DefaultPolicy.

## [x] N3 — Library-wide clock injection — DONE (aaca811 sessions, cbeb699 identity, 2f8163a jwt)
**Where:** identity (lockout), tokens/jwt (TTL), sessions (expiry) call `time.Now()` directly. **Fix:** `WithClock`/shared clock seam (mfa/otp already have it). **Test:** deterministic expiry/lockout with injected clock.
**DONE:** Added the mfa/otp-style `now func() time.Time` seam to all three service layers, each defaulted to `time.Now` and nil-guarded in the constructor:
- **sessions** — `WithClock` ServiceOption (NewService gained `opts ...ServiceOption`; distinct from the existing store-level `Option`). Routes CreateSession (single captured `now` for consistent ExpiresAt/CreatedAt), ValidateSession, Touch, Rotate.
- **identity** — `WithClock` ServiceOption. Routes the lockout GATE in Authenticate (`LockedUntil.After`) and the EmailVerifiedAt/UpdatedAt stamps in ConfirmEmailChange + LinkOrCreateIdentity. Deterministic test drives the gate locked→unlocked via a MockStore-supplied `LockedUntil` and an advancing clock.
- **tokens/jwt** — `Clock func() time.Time` field on Config (struct-config package, no functional options). Routes issuePair TTL + Rotate/VerifyRefreshToken/VerifyAPIKey expiry checks, AND wires `jwt.WithTimeFunc(s.now)` into VerifyAccessToken's `ParseWithClaims` so golang-jwt validates exp/nbf against the same clock (verified by a mutation test: removing WithTimeFunc fails the deterministic-expiry test).

**Deferred (out of this item's scope):** the lockout STAMP (`LockedUntil = now + lockDuration`) is computed by the identity Store (memory `time.Now().Add`, pgx SQL `now() + interval`), not the service, so it stays on the store's own clock; the storetest contract still covers it with a real clock. End-to-end deterministic lockout across the real `lockDuration` would require threading a clock into the memory/pgx stores (pgx passes a duration to SQL `now()`, not a timestamp, so its IncrementFailedAttempts contract would change) — a separate, larger change. The "identity (lockout)" tick here means the service GATE, not full store-clock injection.

## [ ] N4 — Top-level facade / document composable design
**Where:** root pkg (only exports Actor). **Fix:** optional convenience facade wiring the common stack, OR explicitly document the database/sql-style composable intent + wiring snippet (overlaps C4).

## [x] N5 — Migration versioning / rollback — DONE (f0fbfa2)
**Where:** pgx `Migrate()` Execs every .sql each call, no version table, no down path. **Fix:** `schema_migrations` version table applying only un-applied files, or document using an external migration tool. **Test:** re-running Migrate is a no-op after applied.
**DONE:** Added a shared `internal/pgxmigrate` helper (`Run(ctx, Querier, fs.FS)`) recording each applied file in a `schema_migrations(version PRIMARY KEY, applied_at)` table and skipping already-recorded files; the six byte-identical Migrate bodies collapsed to one-line delegates (`pgxmigrate.Run(ctx, db, MigrationsFS)`), each package keeping its own embedded FS. The helper's `Querier` (Exec + QueryRow) is satisfied structurally by every store's `DBQuerier`, `*pgxpool.Pool`, and `pgx.Tx`. Atomicity without a `Begin`: the version INSERT is appended to the migration body and Exec'd in one no-arg call, so the simple-query protocol's implicit transaction commits DDL + version row together even on a bare pool (`ON CONFLICT DO NOTHING`, quote-escaped literal). Documented contract: migrations must be idempotent, single-implicit-transaction-compatible (no CONCURRENTLY/VACUUM/explicit BEGIN), never edited once applied; the table is a re-run optimization, not crash-safe exactly-once. Tested via testcontainers (no-op proven with a non-idempotent migration that would error/double-insert if re-run; incremental application of only un-applied files).
**Not done (explicitly out of scope):** no down/rollback path — this library ships forward-only migrations; a rollback path or external-tool integration (golang-migrate, etc.) remains a separate decision if ever needed.

## [x] N6 — Error taxonomy consistency + dead sentinels — DONE (55971a6)
**Where:** identity/tokens/sessions/passwords unprefixed vs mfa/oauth/otp/passkey prefixed; oauth ErrStateMismatch/ErrMissingCode/ErrEmailMissing + passkey ErrSessionInvalid are dead (signaled as raw strings). **Fix:** standardize prefixing; return declared sentinels or remove dead exports. **Test:** errors.Is works against the documented sentinels.
**DONE:** prefixed identity/tokens/sessions/passwords sentinels with the package name (errors.Is unaffected). oauth's 3 dead sentinels removed (the callback signals via HTTP/redirect, not Go errors — no errors.Is seam; doc note records why). passkey ErrSessionInvalid wired live by routing loadSession failures through the existing fail() switch (same HTTP output). All affected package tests pass.

## [ ] N7 — Honor context cancellation
**Where:** library-wide (0 ctx.Err/Done/Cause in non-test). **Fix:** check ctx in long/CPU-bound paths where feasible; at minimum document cancellation is observed only via pgx driver on I/O.

## [ ] N8 — CAPTCHA / bot hooks + webhooks
**Where:** sensitive handlers. **Fix:** optional CAPTCHA/bot-check hook + webhook/event-emission seam (overlaps I11). **Test:** hook invoked; request blocked when check fails.

## [ ] N9 — Phone / SMS verification flow
**Where:** identity + otp + SMS delivery (I8). **Fix:** phone field + verification flow layering otp with SMS delivery; OR document the exclusion at top level. Currently mfa explicitly excludes SMS.

## [ ] N10 — SemVer / CHANGELOG / stability statement
**Where:** repo root. **Fix:** tag SemVer releases, add CHANGELOG, publish stability statement once API settles. (git tag -l empty today.)

## [x] N11 — Health / readiness / Store Ping seam — DONE (b60673a)
**Where:** Store interfaces. **Fix:** optional `Ping`/`HealthCheck` on Store (or document pinging pgxpool directly). **Test:** Ping surfaces store connectivity.
**DONE:** New `health` package exposing an optional `Pinger` interface (`Ping(ctx) error`), implemented on all six pgx Stores via a `SELECT 1` round-trip over the existing `DBQuerier` (works for `*pgxpool.Pool` and `pgx.Tx`; no extra pool handle needed by callers). Readiness probes type-assert `store.(health.Pinger)`. In-memory stores deliberately don't implement it (no unhealthy backend), so it stays optional, not part of core `Store`. Tested via testcontainers in sessions/pgx (nil while up, error once the pool is closed) + compile-time conformance assertions in the other five pgx packages.
