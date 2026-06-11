---
id: TASK-094
title: "Expired-row visibility diverges between memory and pgx stores (RevokeSession behaves differently on expired tokens)"
description: "pgx FindSessionByHash has no expires_at predicate (WHERE token_hash = $1 AND tenant_id = $2) and returns expired-but-unreaped rows, while sessions/memory FindSessionByHash opportunistically evicts an expired match and reports ErrSessionNotFound (memory/store.go:56-59). ValidateSession/Touch/Rotate a…"
milestone: M6-severity-info
epic: storage
status: done
priority: low
type: chore
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `adapters/pgx/sessions` reproducing the flaw: pgx FindSessionByHash has no expires_at predicate (WHERE token_hash = $1 AND tenant_id = $2) and returns expired-but-unreaped rows, while sessions/memory FindSessionByHash opportun…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Define expired-row visibility in the Store interface doc and align both stores (simplest: add AND expires_at >= now() to the pgx query, matching the memory store), then add a contract test in storetest.StoreContractTesting asserting FindSessionByHash on an expired session returns ErrSessionNotFound…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: cd adapters/pgx && go test ./sessions/...
- [x] The audit attack scenario no longer succeeds: pgx FindSessionByHash has no expires_at predicate (WHERE token_hash = $1 AND tenant_id = $2) and returns expired-but-unreaped rows, while sessions/memory FindSe…
- [x] memory and pgx stores behave identically here, pinned by the `storetest` contract
- [x] Build & vet clean | run: cd adapters/pgx && go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([INFO])
**Location:** `adapters/pgx/sessions/store.go:68`  •  **Category:** misuse-resistance  •  **Verifier consensus:** info (1/1 confirmed real)

**What's wrong & impact**
pgx FindSessionByHash has no expires_at predicate (WHERE token_hash = $1 AND tenant_id = $2) and returns expired-but-unreaped rows, while sessions/memory FindSessionByHash opportunistically evicts an expired match and reports ErrSessionNotFound (memory/store.go:56-59). ValidateSession/Touch/Rotate are unaffected because the service re-checks expiry, but service.RevokeSession calls FindSessionByHash directly (service.go:172): on pgx, revoking an expired token succeeds and emits a Logout event; on memory it returns ErrSessionNotFound. Consumers whose logout handler surfaces the revoke error will see different behavior in tests (memory) vs production (pgx), and event-sink consumers see Logout events for already-dead sessions only on one backend. No authentication bypass results — this is a contract-consistency gap the shared storetest contract does not cover.

**Evidence**
```go
SELECT id, tenant_id, user_id, token_hash, user_agent, ip, expires_at, created_at
		FROM sessions
		WHERE token_hash = $1 AND tenant_id = $2  -- no expires_at filter, unlike memory store's opportunistic eviction
```

**Recommended fix**
Define expired-row visibility in the Store interface doc and align both stores (simplest: add AND expires_at >= now() to the pgx query, matching the memory store), then add a contract test in storetest.StoreContractTesting asserting FindSessionByHash on an expired session returns ErrSessionNotFound on every backend.

### 2026-06-11 — Closed after opus remediation: all Actions and DoD verified
