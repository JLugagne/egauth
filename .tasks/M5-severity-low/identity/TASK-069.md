---
id: TASK-069
title: "FindUserByID does not filter DeletedAt/DisabledAt in either store, leaving the suspension gate dependent on each caller"
description: "FindUserByID in the memory store returns the user with no DeletedAt or DisabledAt filtering (the only guard is tenant match), and the pgx FindUserByID likewise selects WHERE id=$1 AND tenant_id=$2 with NO `deleted_at IS NULL` filter (adapters/pgx/identity/store.go:87-104) — unlike FindUserByEmail in…"
milestone: M5-severity-low
epic: identity
status: in_progress
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `identity/memory` reproducing the flaw: FindUserByID in the memory store returns the user with no DeletedAt or DisabledAt filtering (the only guard is tenant match), and the pgx FindUserByID likewise selects WHERE id=$1…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Keep FindUserByID returning soft-deleted rows for inspection (the contract depends on it), but make the authorization invariant explicit: gate on DisabledAt/DeletedAt at every authentication/authorization caller (Authenticate, consumeForLiveUser, and the LinkOrCreateIdentity fix above), and add a st…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/memory/...
- [x] The audit attack scenario no longer succeeds: FindUserByID in the memory store returns the user with no DeletedAt or DisabledAt filtering (the only guard is tenant match), and the pgx FindUserByID likewise…
- [x] memory and pgx stores behave identically here, pinned by the `storetest` contract
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `identity/memory/store.go:57`  •  **Category:** misuse-resistance  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
FindUserByID in the memory store returns the user with no DeletedAt or DisabledAt filtering (the only guard is tenant match), and the pgx FindUserByID likewise selects WHERE id=$1 AND tenant_id=$2 with NO `deleted_at IS NULL` filter (adapters/pgx/identity/store.go:87-104) — unlike FindUserByEmail in both stores, which excludes soft-deleted rows (memory/store.go:35; pgx store.go:111). This is intentional for inspection paths (the storetest contract at storetest/contract.go:254-257 and the consumeForLiveUser comment at service.go:540 rely on FindUserByID still returning soft-deleted rows so callers can re-check state), so it is not itself a bug. But it makes every authorization decision that flows through FindUserByID dependent on the CALLER remembering to re-check DisabledAt/DeletedAt. The LinkOrCreateIdentity already-linked branch is precisely the caller that forgot (see the high finding above). This is a footgun for any future caller of FindUserByID on an authorization path and for any new store implementation.

**Evidence**
```go
// identity/memory/store.go FindUserByID (line 57):
user, exists := s.users[id]
if !exists || user.TenantID != tenantID {   // no DeletedAt / no DisabledAt check
    return nil, identity.ErrUserNotFound
}

// adapters/pgx/identity/store.go FindUserByID (line ~87):
WHERE id = $1 AND tenant_id = $2          // no `AND deleted_at IS NULL`, unlike FindUserByEmail
```

**Recommended fix**
Keep FindUserByID returning soft-deleted rows for inspection (the contract depends on it), but make the authorization invariant explicit: gate on DisabledAt/DeletedAt at every authentication/authorization caller (Authenticate, consumeForLiveUser, and the LinkOrCreateIdentity fix above), and add a storetest contract assertion that exercises an OAuth-linked, suspended account through LinkOrCreateIdentity and asserts it is refused — so the gate cannot silently regress in either store.
