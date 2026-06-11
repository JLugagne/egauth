---
id: TASK-083
title: "Documented login-over-anonymous-session Rotate flow cannot re-bind the user, and stores diverge if a consumer forces it via UpdateSession"
description: "The Rotate doc explicitly tells consumers to call it for 'login over an existing anonymous session', but neither Rotate nor any Service method can change the session's UserID — the post-login session keeps the pre-auth identity. A consumer following this guidance will either ship a broken/ambiguous…"
milestone: M5-severity-low
epic: sessions
status: done
priority: low
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `sessions` reproducing the flaw: The Rotate doc explicitly tells consumers to call it for 'login over an existing anonymous session', but neither Rotate nor any Service method can change the session's UserID — the…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Pick one contract and enforce it in both stores: have memory.UpdateSession copy only TokenHash/ExpiresAt/UserAgent/IP onto the existing record (pinning UserID and CreatedAt like pgx does), add UserID/CreatedAt-immutability assertions to storetest.StoreContractTesting, and fix the Rotate doc — either…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./sessions/...
- [x] The audit attack scenario no longer succeeds: The Rotate doc explicitly tells consumers to call it for 'login over an existing anonymous session', but neither Rotate nor any Service method can change the se…
- [x] memory and pgx stores behave identically here, pinned by the `storetest` contract
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `sessions/service.go:24`  •  **Category:** misuse-resistance  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
The Rotate doc explicitly tells consumers to call it for 'login over an existing anonymous session', but neither Rotate nor any Service method can change the session's UserID — the post-login session keeps the pre-auth identity. A consumer following this guidance will either ship a broken/ambiguous identity binding or bypass the service and mutate Session.UserID through Store.UpdateSession directly. There the two store implementations diverge: sessions/memory UpdateSession copies the whole struct (sCopy := *session), persisting a changed UserID and even a changed CreatedAt — which feeds the WithMaxLifetime absolute-deadline computation in absoluteDeadline() — while adapters/pgx/sessions only SETs token_hash, user_agent, ip, expires_at and silently drops UserID/CreatedAt changes. The Store doc says only 'token hash, expiry, and last-seen user-agent/IP' are mutable, so the memory store violates the contract; tests against the memory store will pass while production (pgx) behaves differently, and the shared storetest contract (sessions/storetest/contract.go) never asserts UserID/CreatedAt immutability under UpdateSession. CreatedAt mutability in the memory store also means a direct store caller can extend a session past its intended absolute lifetime cap.

**Evidence**
```go
service.go:26-27 doc: "Call it after any privilege change — login over an existing anonymous session"; sessions/memory/store.go:124-126: "sCopy := *session\n\tsCopy.TenantID = existing.TenantID // tenant is immutable\n\ts.sessions[session.ID] = &sCopy" (UserID/CreatedAt copied from caller) vs adapters/pgx/sessions/store.go:91: "SET token_hash = $1, user_agent = $2, ip = $3, expires_at = $4" (UserID/CreatedAt never written)
```

**Recommended fix**
Pick one contract and enforce it in both stores: have memory.UpdateSession copy only TokenHash/ExpiresAt/UserAgent/IP onto the existing record (pinning UserID and CreatedAt like pgx does), add UserID/CreatedAt-immutability assertions to storetest.StoreContractTesting, and fix the Rotate doc — either state that login must create a NEW session via CreateSession (recommended), or add an explicit service primitive that atomically rotates the token and re-binds the user.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
