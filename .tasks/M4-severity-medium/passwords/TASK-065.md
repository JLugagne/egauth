---
id: TASK-065
title: "Empty-password probe defeats decoy-hash enumeration defence (Hash short-circuits, Compare does not)"
description: "Hash() returns ErrHashFailed immediately for an empty password, before doing any Argon2id work, while Compare() has no empty-password guard and runs the full KDF (argon2.IDKey) on an empty candidate. The identity enumeration defence relies on these two being timing-equivalent: the unknown-account pa…"
milestone: M4-severity-medium
epic: passwords
status: done
priority: normal
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `passwords/argon2` reproducing the flaw: Hash() returns ErrHashFailed immediately for an empty password, before doing any Argon2id work, while Compare() has no empty-password guard and runs the full KDF (argon2.IDKey) on…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Add an early guard at the top of Compare: since Hash rejects empty passwords, no stored hash can ever correspond to "", so `if password == "" { return passwords.ErrInvalidPassword }` before any KDF restores symmetry with the decoy path (both return instantly) and can never produce a false match. Add…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./passwords/argon2/...
- [x] The audit attack scenario no longer succeeds: Hash() returns ErrHashFailed immediately for an empty password, before doing any Argon2id work, while Compare() has no empty-password guard and runs the full KD…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match (SECURITY.md already described the intended behaviour; no change needed)
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `passwords/argon2/hasher.go:181`  •  **Category:** timing-oracle  •  **Verifier consensus:** medium (1/1 confirmed real)

**What's wrong & impact**
Hash() returns ErrHashFailed immediately for an empty password, before doing any Argon2id work, while Compare() has no empty-password guard and runs the full KDF (argon2.IDKey) on an empty candidate. The identity enumeration defence relies on these two being timing-equivalent: the unknown-account path calls decoyHash -> Hasher.Hash(ctx, password), and the real path calls Hasher.Compare(ctx, hash, password). With password="" the two paths are NOT equivalent. Attack: submit a login with the email under test and an EMPTY password. A non-existent account (or an account with no password identity) takes the decoy path -> Hash("") returns instantly with no Argon2 pass (fast). An existing account that has a password hash takes Compare(ctx, hash, "") which runs a full ~64MB Argon2id pass (slow, tens of ms). The response-time difference reveals which emails are registered password accounts, defeating the user-enumeration defence that SECURITY.md explicitly promises ('equivalent hashing cost even when the user, identity, or password hash is absent'). Identity.Authenticate applies no empty-password pre-check (no len/empty guard found), so the empty password reaches both paths unfiltered. No timing-symmetry test exists for the empty-password case.

**Evidence**
```go
Hash: `if password == "" { return "", passwords.ErrHashFailed }` (line 181-183) returns before the KDF. Compare has no equivalent guard: it proceeds to `comparisonHash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)` (line 283) even when password=="".
```

**Recommended fix**
Add an early guard at the top of Compare: since Hash rejects empty passwords, no stored hash can ever correspond to "", so `if password == "" { return passwords.ErrInvalidPassword }` before any KDF restores symmetry with the decoy path (both return instantly) and can never produce a false match. Add a contract/timing test asserting the empty-password case is handled symmetrically on Hash and Compare.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
