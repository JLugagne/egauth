---
id: TASK-076
title: "ConfirmTOTP has no attempt limit — unbounded online guessing of the enrollment-confirmation code"
description: "VerifyTOTP and VerifyRecoveryCode reserve an atomic attempt slot before comparing, but ConfirmTOTP calls validateTOTP with no reserveAttempt and no counter of any kind, so a caller can guess the confirming code without bound (~3 valid candidates per 10^6 with default skew; expected ~333k requests to…"
milestone: M5-severity-low
epic: mfa
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `mfa` reproducing the flaw: VerifyTOTP and VerifyRecoveryCode reserve an atomic attempt slot before comparing, but ConfirmTOTP calls validateTOTP with no reserveAttempt and no counter of any kind, so a caller…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Reserve an attempt slot in ConfirmTOTP exactly as VerifyTOTP does, and on exhaustion delete the pending (unconfirmed) enrollment so the flow must restart from EnrollTOTP.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./mfa/...
- [x] The audit attack scenario no longer succeeds: VerifyTOTP and VerifyRecoveryCode reserve an atomic attempt slot before comparing, but ConfirmTOTP calls validateTOTP with no reserveAttempt and no counter of a…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `mfa/service.go:185`  •  **Category:** brute-force  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
VerifyTOTP and VerifyRecoveryCode reserve an atomic attempt slot before comparing, but ConfirmTOTP calls validateTOTP with no reserveAttempt and no counter of any kind, so a caller can guess the confirming code without bound (~3 valid candidates per 10^6 with default skew; expected ~333k requests to hit). Success both activates the factor and returns a fresh set of plaintext recovery codes to the caller (durable credentials that survive a password change). The realistic exposure is an application that gates EnrollHandler behind step-up/re-auth but leaves ConfirmHandler reachable with a weaker session — the attacker confirms a victim's pending enrollment and exfiltrates the recovery codes without ever proving possession of the secret. It is also an internal inconsistency with the package's own reserve-before-compare discipline.

**Evidence**
```go
step, ok := validateTOTP(enrollment.Secret, code, s.now(), s.digits, s.period, s.skew); if !ok { return nil, ErrInvalidCode } (service.go:185-188) — no IncrementTOTPAttempts/reserveAttempt call anywhere in ConfirmTOTP, unlike VerifyTOTP (service.go:214).
```

**Recommended fix**
Reserve an attempt slot in ConfirmTOTP exactly as VerifyTOTP does, and on exhaustion delete the pending (unconfirmed) enrollment so the flow must restart from EnrollTOTP.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
