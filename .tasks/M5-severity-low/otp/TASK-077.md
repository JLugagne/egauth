---
id: TASK-077
title: "otp digits clamp does not enforce the documented 'safe minimum' — 1–3 digit codes are accepted"
description: "NewService's comment claims 'Clamp to safe minimums so a misconfiguration cannot produce predictable ... codes', but the clamp only catches digits <= 0."
milestone: M5-severity-low
epic: otp
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `otp` reproducing the flaw: NewService's comment claims "Clamp to safe minimums so a misconfiguration cannot produce predictable ...
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Clamp digits to a real floor (>= 6, or at minimum 4 with a documented warning) and a sane ceiling (e.g. <= 10), or panic at construction like mfa.NewService does, so the comment's promise matches the behavior.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./otp/...
- [x] The audit attack scenario no longer succeeds: NewService's comment claims "Clamp to safe minimums so a misconfiguration cannot produce predictable ...
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `otp/service.go:67`  •  **Category:** misuse-resistance  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
NewService's comment claims "Clamp to safe minimums so a misconfiguration cannot produce predictable ... codes", but the clamp only catches digits <= 0. WithDigits(1) yields a 10-value code space — with the default 5 attempts an attacker wins 50% of the time per challenge; WithDigits(3) gives 0.5% per challenge, compounding across resends. The code overpromises what the guard delivers, so a consumer who passes a small value (e.g. believing the library will floor it) gets trivially guessable codes. There is also no upper bound: a very large digits value makes big.Int Exp/Sprintf allocate proportionally (config-time footgun only).

**Evidence**
```go
// Clamp to safe minimums so a misconfiguration cannot produce predictable/never-expiring codes ... if s.digits <= 0 { s.digits = DefaultDigits } (otp/service.go:65-69) — digits 1..5 pass through unchanged.
```

**Recommended fix**
Clamp digits to a real floor (>= 6, or at minimum 4 with a documented warning) and a sane ceiling (e.g. <= 10), or panic at construction like mfa.NewService does, so the comment's promise matches the behavior.

### 2026-06-11 — Closed by close-auditor
WithDigits godoc updated to document [6,10] range and panic. SECURITY.md OTP section updated to mention digit bounds. All Actions and DoD verified.
