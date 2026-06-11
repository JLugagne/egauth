---
id: TASK-071
title: "ResetPassword provides no session/token revocation hook and omits the revoke reminder"
description: "ResetPassword consumes the reset token and updates the password hash (clearing lockout via UpdateIdentityPassword) but does not run the AccountErasers and exposes no mechanism to revoke the user's existing sessions / refresh-token families. Password reset is the canonical account-recovery flow used…"
milestone: M5-severity-low
epic: identity
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `identity` reproducing the flaw: ResetPassword consumes the reset token and updates the password hash (clearing lockout via UpdateIdentityPassword) but does not run the AccountErasers and exposes no mechanism to r…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Either run the registered AccountErasers (or a dedicated session-revocation eraser subset) after a successful ResetPassword, or at minimum document in the ResetPassword contract — as ChangePassword does — that the caller SHOULD revoke the user's other sessions and refresh-token families on reset, an…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/...
- [x] The audit attack scenario no longer succeeds: ResetPassword consumes the reset token and updates the password hash (clearing lockout via UpdateIdentityPassword) but does not run the AccountErasers and expos…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `identity/service.go:566`  •  **Category:** session-fixation  •  **Verifier consensus:** info (1/1 confirmed real)

**What's wrong & impact**
ResetPassword consumes the reset token and updates the password hash (clearing lockout via UpdateIdentityPassword) but does not run the AccountErasers and exposes no mechanism to revoke the user's existing sessions / refresh-token families. Password reset is the canonical account-recovery flow used when a user believes they are compromised; if an attacker holds an active session or refresh-token family, a successful reset does not evict them. DeleteAccount runs registered erasers (service.go:718) and ChangePassword's doc explicitly tells the caller to revoke other sessions (service.go:92-94 / SECURITY.md), but ResetPassword's contract (service.go:60-67, :565) gives no such reminder and the library offers no eraser hook on this path, so a typical consumer is likely to leave the attacker's session live after a recovery reset.

**Evidence**
```go
if err := s.store.UpdateIdentityPassword(ctx, tenantID, user.ID, hash); err != nil {
	return err
}
s.emit(ctx, event.Event{Type: event.PasswordReset, ...})
return nil   // no eraser run, no documented revoke obligation
```

**Recommended fix**
Either run the registered AccountErasers (or a dedicated session-revocation eraser subset) after a successful ResetPassword, or at minimum document in the ResetPassword contract — as ChangePassword does — that the caller SHOULD revoke the user's other sessions and refresh-token families on reset, and provide the same WithAccountErasers wiring used by DeleteAccount.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
