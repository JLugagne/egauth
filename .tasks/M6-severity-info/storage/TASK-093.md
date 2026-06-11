---
id: TASK-093
title: "pgx CreateSession is an upsert that silently rebinds an existing (tenant_id, token_hash) row to a new user and session ID"
description: "CreateSession uses ON CONFLICT (tenant_id, token_hash) DO UPDATE SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, ... — so inserting a session whose token hash already exists silently replaces the existing row's owner (user_id), primary key and expiry instead of failing."
milestone: M6-severity-info
epic: storage
status: done
priority: low
type: chore
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `adapters/pgx/sessions` reproducing the flaw: CreateSession uses ON CONFLICT (tenant_id, token_hash) DO UPDATE SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, ...
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Use a plain INSERT and surface the unique-violation (map pgcode 23505 to a distinct error); in the memory store, reject CreateSession when the byHash key already exists. A duplicate 256-bit token hash should be treated as an integrity failure, not absorbed.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: cd adapters/pgx && go test ./sessions/...
- [x] The audit attack scenario no longer succeeds: CreateSession uses ON CONFLICT (tenant_id, token_hash) DO UPDATE SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, ...
- [x] memory and pgx stores behave identically here, pinned by the `storetest` contract
- [x] Build & vet clean | run: cd adapters/pgx && go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([INFO])
**Location:** `adapters/pgx/sessions/store.go:56`  •  **Category:** misuse-resistance  •  **Verifier consensus:** info (1/1 confirmed real)

**What's wrong & impact**
CreateSession uses ON CONFLICT (tenant_id, token_hash) DO UPDATE SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, ... — so inserting a session whose token hash already exists silently replaces the existing row's owner (user_id), primary key and expiry instead of failing. Via the Service this is unreachable (tokens are 256-bit random), but Store is an exported interface and the doc says CreateSession 'persists a NEW session'; a direct store consumer (or a future caller with lower-entropy tokens) gets last-write-wins token rebinding instead of an integrity error. The memory store has the analogous behavior (CreateSession blindly overwrites the byHash index entry, leaving the prior session orphaned), so neither store defends the uniqueness invariant. Note also the conflict branch does not update created_at, so a 'new' session would inherit the old row's absolute-lifetime clock.

**Evidence**
```go
ON CONFLICT (tenant_id, token_hash) DO UPDATE
		SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, user_agent = EXCLUDED.user_agent, ip = EXCLUDED.ip, expires_at = EXCLUDED.expires_at
```

**Recommended fix**
Use a plain INSERT and surface the unique-violation (map pgcode 23505 to a distinct error); in the memory store, reject CreateSession when the byHash key already exists. A duplicate 256-bit token hash should be treated as an integrity failure, not absorbed.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
