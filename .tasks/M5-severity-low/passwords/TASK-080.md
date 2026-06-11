---
id: TASK-080
title: "Compare runs Argon2id with an unbounded memory parameter parsed from the stored hash (OOM DoS on verify)"
description: "Compare parses the memory/time/threads cost parameters out of the stored PHC string and feeds them straight to argon2.IDKey. The code validates only LOWER bounds (time<1, threads<1, keyLen==0, memory<8*threads) to avoid panics, but places no UPPER bound on the memory parameter (a uint32, up to ~4.29…"
milestone: M5-severity-low
epic: passwords
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `passwords/argon2` reproducing the flaw: Compare parses the memory/time/threads cost parameters out of the stored PHC string and feeds them straight to argon2.IDKey.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Add an upper-bound sanity check on the parsed memory (and optionally time) before calling IDKey, e.g. reject `memory` above a generous ceiling (a few hundred MiB, well above any legitimately configured cost) as ErrInvalidPassword, consistent with the existing 'reject malformed stored hash as a misma…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./passwords/argon2/...
- [x] The audit attack scenario no longer succeeds: Compare parses the memory/time/threads cost parameters out of the stored PHC string and feeds them straight to argon2.IDKey.
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `passwords/argon2/hasher.go:266`  •  **Category:** dos  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
Compare parses the memory/time/threads cost parameters out of the stored PHC string and feeds them straight to argon2.IDKey. The code validates only LOWER bounds (time<1, threads<1, keyLen==0, memory<8*threads) to avoid panics, but places no UPPER bound on the memory parameter (a uint32, up to ~4.29e9 KiB ~= 4 TiB). argon2.IDKey allocates memory*1024 bytes, so a single stored hash row carrying e.g. m=4000000000 causes the next verification of that account to attempt a multi-gigabyte/terabyte allocation, OOM-killing or hanging the process. The code's own comments treat the stored hash as untrusted input from 'an import, migration, or a hand-edited DB row' and the fuzz test comment cites a 'tampered datastore' as in-scope, so a value-write to the password-hash column (SQL injection, malicious import file, compromised migration) escalates from a single-row data write to a whole-process availability outage hit on the victim's next login. NeedsRehash does not flag an excessively HIGH memory value (it only flags params below target), so such a row is considered valid and reaches the KDF.

**Evidence**
```go
`if memory < 8*uint32(threads) { return passwords.ErrInvalidPassword }` (line 273-275) is the only memory check — a lower bound. Compare then calls `argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)` (line 283) with the unbounded stored `memory`.
```

**Recommended fix**
Add an upper-bound sanity check on the parsed memory (and optionally time) before calling IDKey, e.g. reject `memory` above a generous ceiling (a few hundred MiB, well above any legitimately configured cost) as ErrInvalidPassword, consistent with the existing 'reject malformed stored hash as a mismatch' policy. This bounds resource use on the verify path for corrupt/tampered rows.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
