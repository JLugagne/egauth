---
id: TASK-085
title: "UpdateUser soft-delete gate diverges between memory and pgx stores and is not pinned by the storetest contract"
description: "The pgx UpdateUser gates the write on `deleted_at IS NULL`, so it refuses to mutate a soft-deleted user and returns ErrUserNotFound. The memory store's UpdateUser (identity/memory/store.go, lines 88-116) performs no DeletedAt check at all — it updates any existing same-tenant row, including a soft-d…"
milestone: M5-severity-low
epic: storage
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `adapters/pgx/identity` reproducing the flaw: The pgx UpdateUser gates the write on `deleted_at IS NULL`, so it refuses to mutate a soft-deleted user and returns ErrUserNotFound.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Make the two stores agree and pin it in storetest: add a `deleted_at IS NULL` / `existing.DeletedAt == nil` gate to the memory UpdateUser (the stricter pgx behaviour is the safer choice), and add a contract case asserting UpdateUser on a soft-deleted user returns ErrUserNotFound so both backends are…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: cd adapters/pgx && go test ./identity/...
- [x] The audit attack scenario no longer succeeds: The pgx UpdateUser gates the write on `deleted_at IS NULL`, so it refuses to mutate a soft-deleted user and returns ErrUserNotFound.
- [x] memory and pgx stores behave identically here, pinned by the `storetest` contract
- [x] Build & vet clean | run: cd adapters/pgx && go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match (no documented behaviour change; fix closes a divergence not yet in docs)
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `adapters/pgx/identity/store.go:137`  •  **Category:** tenant-isolation  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
The pgx UpdateUser gates the write on `deleted_at IS NULL`, so it refuses to mutate a soft-deleted user and returns ErrUserNotFound. The memory store's UpdateUser (identity/memory/store.go, lines 88-116) performs no DeletedAt check at all — it updates any existing same-tenant row, including a soft-deleted/anonymized one, resurrecting its email and email_verified_at. The storetest contract (identity/storetest/contract.go) only exercises UpdateUser with a foreign-tenant record (line 206) and a live user (line 239); it never asserts behaviour against a soft-deleted user, so this divergence is invisible to the shared conformance suite. Today both backends are protected at the service layer (UpdateUser is only reached via VerifyEmail after a live-user gate and via JIT provisioning of a fresh user), so it is not currently exploitable; the risk is forward-looking — a future caller that trusts the storetest contract as the behavioural spec could rely on UpdateUser rejecting a deleted account and get silently different (resurrection-permitting) behaviour on the memory backend.

**Evidence**
```go
pgx: `UPDATE users SET email = $1, email_verified_at = $2, updated_at = $3 WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL`  vs  memory: `existing, exists := s.users[user.ID]; if !exists || existing.TenantID != tenantID { return ErrUserNotFound }` (no DeletedAt check before overwriting).
```

**Recommended fix**
Make the two stores agree and pin it in storetest: add a `deleted_at IS NULL` / `existing.DeletedAt == nil` gate to the memory UpdateUser (the stricter pgx behaviour is the safer choice), and add a contract case asserting UpdateUser on a soft-deleted user returns ErrUserNotFound so both backends are held to it.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
