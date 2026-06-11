---
id: TASK-081
title: "Residual enumeration timing channel: pre-rehash accounts verify faster than the current-cost decoy"
description: "The decoy path (unknown account) always hashes at the hasher's CURRENT configured cost (h.time/h.memory/h.threads via Hash). The real path (Compare) runs Argon2id at the cost recorded IN THE STORED HASH."
milestone: M5-severity-low
epic: passwords
status: done
priority: low
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `passwords/argon2` reproducing the flaw: The decoy path (unknown account) always hashes at the hasher's CURRENT configured cost (h.time/h.memory/h.threads via Hash).
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Document this residual channel explicitly (it currently is not), and/or have the decoy path mirror the weakest acceptable cost rather than the current target so the gap is not directly correlated with the upgrade. Operators raising cost should be advised the enumeration-resistance is degraded until…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./passwords/argon2/...
- [x] The audit attack scenario no longer succeeds: The decoy path (unknown account) always hashes at the hasher's CURRENT configured cost (h.time/h.memory/h.threads via Hash).
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `passwords/argon2/hasher.go:283`  •  **Category:** timing-oracle  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
The decoy path (unknown account) always hashes at the hasher's CURRENT configured cost (h.time/h.memory/h.threads via Hash). The real path (Compare) runs Argon2id at the cost recorded IN THE STORED HASH. After the operator raises the cost parameters (the documented rehash-on-login upgrade), every existing user whose hash has not yet been rehashed verifies at the OLD, lower (faster) cost, while a non-existent account is decoy-hashed at the NEW, higher (slower) cost. The measurable timing gap reveals 'this email is a registered account that logged in before the cost bump', a partial enumeration oracle that persists until all users have re-authenticated. This is a consequence of rehash-on-login but weakens the constant-time guarantee SECURITY.md advertises.

**Evidence**
```go
Decoy uses configured cost: Hash() builds the PHC with `h.memory, h.time, h.threads` (line 201/207-208). Compare() uses the stored cost: it parses `memory/time/threads` from the hash (line 238-243) and calls `argon2.IDKey(..., time, memory, threads, keyLen)` (line 283) — the stored, possibly-lower values, not h.*.
```

**Recommended fix**
Document this residual channel explicitly (it currently is not), and/or have the decoy path mirror the weakest acceptable cost rather than the current target so the gap is not directly correlated with the upgrade. Operators raising cost should be advised the enumeration-resistance is degraded until the fleet is rehashed; consumer rate-limiting (already the stated mitigation for residual timing) covers the rest.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
