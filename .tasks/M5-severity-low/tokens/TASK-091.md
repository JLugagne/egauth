---
id: TASK-091
title: "Auto-refresh race clears freshly minted cookies, defeating the documented ReuseGracePeriod anti-lockout design"
description: "SECURITY.md promises that a replay within ReuseGracePeriod is treated as benign concurrency precisely 'to avoid logging users out on ordinary request concurrency (parallel tabs, prefetch, concurrent sub-resource loads racing the same cookie)'. The server side delivers this (jwt.Service.Rotate keeps…"
milestone: M5-severity-low
epic: tokens
status: in_progress
priority: low
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `tokens` reproducing the flaw: SECURITY.md promises that a replay within ReuseGracePeriod is treated as benign concurrency precisely 'to avoid logging users out on ordinary request concurrency (parallel tabs, pr…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Make the benign outcome distinguishable and non-destructive: have Rotate return a distinct sentinel (e.g. tokens.ErrRefreshConcurrent, wrapping ErrRefreshTokenReused for compatibility) for the within-grace replay and the lost-Consume-race cases, and have RequireAuth and RefreshHandler skip cookies.C…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./tokens/...
- [x] The audit attack scenario no longer succeeds: SECURITY.md promises that a replay within ReuseGracePeriod is treated as benign concurrency precisely 'to avoid logging users out on ordinary request concurrenc…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `tokens/middleware.go:140`  •  **Category:** race  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
SECURITY.md promises that a replay within ReuseGracePeriod is treated as benign concurrency precisely 'to avoid logging users out on ordinary request concurrency (parallel tabs, prefetch, concurrent sub-resource loads racing the same cookie)'. The server side delivers this (jwt.Service.Rotate keeps the family alive within grace), but the client side does not: when two parallel requests carry the same expired access cookie + refresh cookie, both enter the auto-refresh branch of RequireAuth. The winner gets new cookies via SetAccess/SetRefresh; the loser's Rotate returns ErrRefreshTokenReused (either from the within-grace check or from losing the atomic ConsumeRefreshToken race in the store) and the middleware unconditionally executes cfg.cookies.Clear(w). If the browser processes the losing response after the winning one (roughly half the time), the Set-Cookie MaxAge=-1 headers wipe the freshly issued refresh cookie. The plaintext of the live refresh token is gone forever (only its hash is stored), so the user is fully logged out — exactly the outcome the grace period exists to prevent. The same indiscriminate Clear on any Rotate error exists in RefreshHandler (tokens/handlers.go:143), so apps using the dedicated refresh endpoint with concurrent tabs hit it too. The comment 'clear cookies so a poisoned family cannot keep retrying' is wrong for the within-grace/lost-race case: the family is explicitly NOT poisoned there. Impact is availability/forced re-authentication (which also pushes users toward more password entry), not credential compromise.

**Evidence**
```go
middleware.go:136-142: `pair, err := cfg.rotator.Rotate(r.Context(), tenantID, refreshToken)\nif err != nil {\n\t// Rotation failed (reuse/expired/not found): clear cookies so a\n\t// poisoned family cannot keep retrying, then reject.\n\tcfg.cookies.Clear(w)\n\tunauthorized(w)\n\treturn\n}` — and jwt Rotate returns the identical tokens.ErrRefreshTokenReused for the benign within-grace path ('rejected ... but the family is kept alive') as for the after-grace theft path, so the caller cannot distinguish them.
```

**Recommended fix**
Make the benign outcome distinguishable and non-destructive: have Rotate return a distinct sentinel (e.g. tokens.ErrRefreshConcurrent, wrapping ErrRefreshTokenReused for compatibility) for the within-grace replay and the lost-Consume-race cases, and have RequireAuth and RefreshHandler skip cookies.Clear (or clear only the access cookie) for that error, returning 401/retry so the winner's cookies survive. Keep the unconditional Clear for after-grace reuse, expiry and not-found.
