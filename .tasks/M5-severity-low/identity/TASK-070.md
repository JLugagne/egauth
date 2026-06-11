---
id: TASK-070
title: "identity.WithLockout(0, ...) silently disables brute-force lockout — opposite semantics to mfa.WithMaxAttempts(0)"
description: "WithLockout assigns threshold/duration with no validation, and a threshold <= 0 disables lockout entirely: the stores only lock when `lockThreshold > 0 && ident.FailedAttempts >= lockThreshold` (identity/memory/store.go:362), and the AccountLocked event is likewise gated on `s.lockThreshold > 0` (se…"
milestone: M5-severity-low
epic: identity
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `identity` reproducing the flaw: WithLockout assigns threshold/duration with no validation, and a threshold <= 0 disables lockout entirely: the stores only lock when `lockThreshold > 0 && ident.FailedAttempts >= l…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Align WithLockout with the mfa convention: treat a non-positive threshold (and non-positive duration) as "use the defaults", and add an explicit identity.WithNoLockout() opt-out for deployments that knowingly throttle elsewhere. Document the disable semantics either way.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/...
- [x] The audit attack scenario no longer succeeds: WithLockout assigns threshold/duration with no validation, and a threshold <= 0 disables lockout entirely: the stores only lock when `lockThreshold > 0 && ident…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `identity/service.go:214`  •  **Category:** misuse-resistance  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
WithLockout assigns threshold/duration with no validation, and a threshold <= 0 disables lockout entirely: the stores only lock when `lockThreshold > 0 && ident.FailedAttempts >= lockThreshold` (identity/memory/store.go:362), and the AccountLocked event is likewise gated on `s.lockThreshold > 0` (service.go:453). The sibling mfa module deliberately hardened the identical knob the other way: mfa.WithMaxAttempts documents "A non-positive value is treated as 'use the default'" and disabling requires the explicit, greppable WithNoAttemptLimit (mfa/service.go:83-88). A consumer who learns the mfa convention and writes identity.WithLockout(0, 0) expecting "default" instead turns the README-advertised brute-force lockout ("enforces brute-force lockout") fully off, leaving password login throttled only by the Argon2 cost. Same applies to a negative or zero duration with a positive threshold (LockedUntil lands at/before now, so the lock never bites).

**Evidence**
```go
identity/service.go:214 `func WithLockout(threshold int, duration time.Duration) ServiceOption { return func(s *service) { s.lockThreshold = threshold; s.lockDuration = duration } }` — no validation; identity/memory/store.go:362 `if lockThreshold > 0 && ident.FailedAttempts >= lockThreshold { ... }`; contrast mfa/service.go:83-88 where non-positive means "use the default" and disabling requires WithNoAttemptLimit.
```

**Recommended fix**
Align WithLockout with the mfa convention: treat a non-positive threshold (and non-positive duration) as "use the defaults", and add an explicit identity.WithNoLockout() opt-out for deployments that knowingly throttle elsewhere. Document the disable semantics either way.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified