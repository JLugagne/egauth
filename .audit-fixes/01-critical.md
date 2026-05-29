# Critical fixes (0 / 4)

Block "safe-by-default" and "complete". Do these first.

---

## [x] C1 — Pre-auth hashing-DoS: bound credential input

**Status:** DONE — `passwords.MaxPasswordLength=1024` const; argon2 `Hash`/`Compare` reject oversized before the KDF; identity handlers wrap bodies in `http.MaxBytesReader` (`DefaultMaxBodyBytes=4KiB`, `WithMaxBodyBytes` opt) → 413. Tests: `TestArgon2Hasher_RejectsOversizedPassword` (red→green), `TestLoginHandler_RejectsOversizedBody`. 77 identity + 10 argon2 tests green.
**Where:** `passwords/argon2/hasher.go`, `identity/service.go` (Authenticate / decoyHash ~171-191), `identity/handlers.go` (login/reset use plain `r.ParseForm()`)
**Problem:** Raw attacker-controlled password reaches argon2id (64MB,4t) on every login incl. unknown accounts (decoyHash). No `http.MaxBytesReader`, `MaxLength` enforced only in Register/Reset, hasher rejects only empty string. Multi-MB POST = memory/CPU amplification DoS.
**Fix:**
1. Add a hard credential-length guard inside `argon2.Hasher.Hash`/`Compare` (reject > e.g. 1024 bytes → `ErrPasswordTooLong`).
2. Enforce a length ceiling on the `Authenticate` path before Compare/decoyHash.
3. Wrap login + all `Request*`/reset handler bodies in `http.MaxBytesReader` (e.g. 4KB) before `ParseForm`.
**Test (confirm-first):** `hasher_test.go`: feeding a 5MB password currently hashes; assert it returns `ErrPasswordTooLong`. Handler test: oversized body → 413/400 not 500.

## [x] C2 — Rate limiting / throttling seam + reference limiter

**Status:** DONE — new `ratelimit/` pkg: `Limiter` interface (`Allow(ctx,key)->(bool,retryAfter)`), in-memory `TokenBucket` reference (burst + refill interval, injectable clock, `Cleanup()` to bound memory), framework-agnostic `Middleware`/`Wrap` (429 + `Retry-After`, default `ClientIP` key). 6 tests green. NOTE: consumers wrap any endpoint (login/reset/verify/OTP) via the middleware; optional per-module default-on wiring left as follow-up.
**Where:** new `ratelimit/` pkg; wire into `identity/handlers.go`, `tokens/handlers.go`, `mfa`/`otp` verify, `oauth` begin.
**Problem:** No throttling anywhere; login/Request*/verify hammerable; email-bomb vector; TOTP brute-force depends on consumer.
**Fix:** Define a small pluggable `Limiter` interface (`Allow(ctx, key) (bool, retryAfter)`) keyed per-account and per-IP; ship an in-memory token-bucket reference; add `WithLimiter` option + middleware/handler hooks; default-on for the most sensitive endpoints (with documented opt-out).
**Test:** limiter unit tests (bucket refill, concurrency); handler returns 429 + `Retry-After` when exhausted.

## [x] C3 — Authenticated change-password flow

**Status:** DONE — `Service.ChangePassword(ctx,userID,current,new)` (policy-first, constant-time current verify, decoy on no-password accounts) + `ChangePasswordHandler` (userResolver-gated, `WithPasswordChangeFields`, 401/400 mapping). MockService updated. Tests: `TestService_ChangePassword` (4 cases) + `TestChangePasswordHandler` (4 cases). 87 identity tests green.
**Where:** `identity/service.go` (Service iface ~26-64), `identity/handlers.go`
**Problem:** No `ChangePassword`; only token-gated reset mutates password.
**Fix:** `ChangePassword(ctx, userID, current, new) error` — re-verify current (constant-time), validate+hash new via policy, `UpdateIdentityPassword`, then revoke other refresh families / sessions. Authenticated handler behind middleware.
**Test:** wrong current → error, no mutation; correct → hash changes, old sessions revoked; new password must pass policy.

## [ ] C4 — Onboarding docs: README quickstart + examples + doc.go

**Status:** todo (do LAST, after API settles)
**Where:** `README.md` (9 bytes), new `example_test.go`, `doc.go` in identity/tokens/sessions/passwords.
**Problem:** Only usage model is "wire it yourself" but zero guidance; no `Example` funcs; no package docs on the 4 login-critical packages.
**Fix:** README with copy-pasteable login+refresh wiring; `Example*` funcs for the recommended stack; `doc.go` package overviews; state the composable-packages design intent explicitly.
**Test:** `Example` funcs compile and run (`go test`); `go doc` renders.
