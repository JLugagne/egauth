---
id: TASK-095
title: "jwt.New and Config.Validate never check Store (or ClaimsProvider) for nil — the only module constructor without the fail-fast nil-store guard"
description: "Every other module constructor fails fast on a nil store: identity.NewService, sessions.NewService, otp.NewService and mfa.NewService panic, and passkey.NewService returns ErrNilStore — each with a comment explaining the convention ('fail fast at startup rather than with a nil-pointer panic deep in…"
milestone: M6-severity-info
epic: tokens
status: done
priority: low
type: chore
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `tokens/jwt` reproducing the flaw: Every other module constructor fails fast on a nil store: identity.NewService, sessions.NewService, otp.NewService and mfa.NewService panic, and passkey.NewService returns ErrNilSt…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Panic in jwt.New on a nil Store (matching the documented convention) and add nil-Store / nil-ClaimsProvider checks to Config.Validate so startup validation catches it.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./tokens/jwt/...
- [x] The audit attack scenario no longer succeeds: Every other module constructor fails fast on a nil store: identity.NewService, sessions.NewService, otp.NewService and mfa.NewService panic, and passkey.NewServ…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([INFO])
**Location:** `tokens/jwt/issuer.go:218`  •  **Category:** misuse-resistance  •  **Verifier consensus:** info (1/1 confirmed real)

**What's wrong & impact**
Every other module constructor fails fast on a nil store: identity.NewService, sessions.NewService, otp.NewService and mfa.NewService panic, and passkey.NewService returns ErrNilStore — each with a comment explaining the convention ("fail fast at startup rather than with a nil-pointer panic deep in a request"). jwt.New (and therefore basic.NewIssuer) accepts cfg.Store == nil without complaint, and even the comprehensive Config.Validate does not flag it. The misconfiguration then surfaces as a nil-pointer panic on the first IssueTokenPair/Rotate/VerifyRefreshToken inside a live request (net/http logs the panic and kills the connection). VerifyAccessToken keeps working (it is stateless), so the broken state can pass a shallow smoke test and only blow up when refresh traffic arrives. Fail-closed, so no auth impact — purely a robustness/consistency gap in the constructor contract.

**Evidence**
```go
jwt.New builds the Service with `store: cfg.Store` and no nil check (issuer.go:218-253); Config.Validate (issuer.go:119-166) validates keys/Issuer/TTLs but never cfg.Store or cfg.ClaimsProvider. Compare identity/service.go:293 `if store == nil { panic("identity: NewService requires a non-nil Store") }` and passkey/service.go:119 `if store == nil { return nil, ErrNilStore }`.
```

**Recommended fix**
Panic in jwt.New on a nil Store (matching the documented convention) and add nil-Store / nil-ClaimsProvider checks to Config.Validate so startup validation catches it.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
