---
id: TASK-061
title: "MFA attempt lockout is permanent and also blocks recovery codes, with no decay or unlock primitive"
description: "Once FailedAttempts exceeds maxAttempts (default 5), VerifyTOTP and VerifyRecoveryCode both return ErrTooManyAttempts from the overLimit gate BEFORE any code comparison runs. The only operations that reset the counter are MarkTOTPUsed and ConsumeRecoveryCode — both of which sit after the gate, so a…"
milestone: M4-severity-medium
epic: mfa
status: done
priority: normal
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `mfa` reproducing the flaw: Once FailedAttempts exceeds maxAttempts (default 5), VerifyTOTP and VerifyRecoveryCode both return ErrTooManyAttempts from the overLimit gate BEFORE any code comparison runs.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Make the lockout time-bound: store a lockedUntil timestamp (or reset FailedAttempts when now - lastFailedAt exceeds a window) instead of an unbounded counter; alternatively add an explicit ResetAttempts store/service primitive and document the operator flow, and consider letting a valid recovery cod…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./mfa/...
- [x] The audit attack scenario no longer succeeds: Once FailedAttempts exceeds maxAttempts (default 5), VerifyTOTP and VerifyRecoveryCode both return ErrTooManyAttempts from the overLimit gate BEFORE any code co…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `mfa/service.go:218`  •  **Category:** dos  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
Once FailedAttempts exceeds maxAttempts (default 5), VerifyTOTP and VerifyRecoveryCode both return ErrTooManyAttempts from the overLimit gate BEFORE any code comparison runs. The only operations that reset the counter are MarkTOTPUsed and ConsumeRecoveryCode — both of which sit after the gate, so a locked factor can never be unlocked by any code, correct or not, including a valid recovery code (VerifyRecoveryCode reserves a slot and returns ErrTooManyAttempts before ConsumeRecoveryCode is ever attempted, service.go:260-267). The counter has no time decay and the Store interface exposes no reset primitive; the only escape is DisableTOTP (deleting the factor) — which the library's own guidance (service.go:38-41) says to gate behind MFA step-up, which a locked factor cannot satisfy, or a manual out-of-band DB write. Attack: anyone who reaches the victim's second-factor step (stuffed/phished password, or the victim simply fat-fingering 5 codes cumulatively across logins without an intervening success) permanently locks BOTH the TOTP factor and all recovery codes, denying the legitimate user any self-service path back into the account.

**Evidence**
```go
if s.overLimit(n) { s.emitBlocked(ctx, tenantID, userID, "totp"); return ErrTooManyAttempts } (service.go:218-221); same gate in VerifyRecoveryCode before ConsumeRecoveryCode (service.go:265-268); the only counter resets are in MarkTOTPUsed (memory/store.go:78 "e.FailedAttempts = 0") and ConsumeRecoveryCode (memory/store.go:124), both unreachable once locked; errors.go:24-27 acknowledges "(or an operator must reset it)" but no reset API exists in the Store interface (store.go).
```

**Recommended fix**
Make the lockout time-bound: store a lockedUntil timestamp (or reset FailedAttempts when now - lastFailedAt exceeds a window) instead of an unbounded counter; alternatively add an explicit ResetAttempts store/service primitive and document the operator flow, and consider letting a valid recovery code (high entropy, single-use) clear the lock since it cannot be brute-forced within any realistic budget.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
