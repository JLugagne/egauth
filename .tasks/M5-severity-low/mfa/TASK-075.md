---
id: TASK-075
title: "mfa digits validation allows 1-digit TOTP and silently overflows above 9 digits"
description: "NewService panics only on digits <= 0 while claiming to reject parameters 'that cannot produce valid codes'. WithDigits(1) produces 10-value second-factor codes (3 valid candidates per attempt with default skew ±1 — near-certain bypass within the 5-attempt budget)."
milestone: M5-severity-low
epic: mfa
status: done
priority: low
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `mfa` reproducing the flaw: NewService panics only on digits <= 0 while claiming to reject parameters "that cannot produce valid codes".
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Panic at construction unless 6 <= digits <= 8 (the RFC range universally supported by authenticator apps).
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./mfa/...
- [x] The audit attack scenario no longer succeeds: NewService panics only on digits <= 0 while claiming to reject parameters "that cannot produce valid codes".
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `mfa/service.go:122`  •  **Category:** misuse-resistance  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
NewService panics only on digits <= 0 while claiming to reject parameters "that cannot produce valid codes". WithDigits(1) produces 10-value second-factor codes (3 valid candidates per attempt with default skew ±1 — near-certain bypass within the 5-attempt budget). Conversely, digits >= 10 makes pow10 exceed uint32 (pow10(10)=10^10) and the `uint32(pow10(digits))` cast in hotp truncates, producing a modulus that is not 10^digits (and pow10 overflows int on 32-bit platforms for large n) — codes that no compliant authenticator app will ever generate, plus an effectively reduced/skewed code space. RFC 4226/6238 define 6-8 digits.

**Evidence**
```go
case s.digits <= 0: panic("mfa: digits must be positive") (service.go:122-123); mod := bin % uint32(pow10(digits)) (totp.go:82) with func pow10(n int) int { r := 1; for ...; r *= 10 } (totp.go:86-92).
```

**Recommended fix**
Panic at construction unless 6 <= digits <= 8 (the RFC range universally supported by authenticator apps).

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified