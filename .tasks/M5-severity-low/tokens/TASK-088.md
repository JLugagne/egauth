---
id: TASK-088
title: "LogoutHandler silently swallows family-revocation failure and reports logout success"
description: "LogoutHandler is documented (and accepted) as idempotent for an absent or already-gone token, but it also returns success when revocation actively FAILS: the FindRefreshToken error branch silently skips revocation, and the RevokeFamily error is explicitly discarded with `_ =`. On any transient store…"
milestone: M5-severity-low
epic: tokens
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `tokens` reproducing the flaw: LogoutHandler is documented (and accepted) as idempotent for an absent or already-gone token, but it also returns success when revocation actively FAILS: the FindRefreshToken error…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Distinguish 'token not found' (keep idempotent success) from an actual store error: if FindRefreshToken fails with anything other than ErrRefreshTokenNotFound, or RevokeFamily returns an error, still clear the cookies but respond with a failure (500 or the failure redirect with error=logout_incomple…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./tokens/...
- [x] The audit attack scenario no longer succeeds: LogoutHandler is documented (and accepted) as idempotent for an absent or already-gone token, but it also returns success when revocation actively FAILS: the Fi…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `tokens/handlers.go:175`  •  **Category:** misuse-resistance  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
LogoutHandler is documented (and accepted) as idempotent for an absent or already-gone token, but it also returns success when revocation actively FAILS: the FindRefreshToken error branch silently skips revocation, and the RevokeFamily error is explicitly discarded with `_ =`. On any transient store/DB error during logout the handler still clears the local cookies and replies 204/redirect-success, so the user (and the application) believe the global logout succeeded while every refresh token in the rotation family remains valid server-side until expiry (default RefreshTTL in the docs is 720h). Attack scenario: an attacker who previously stole a refresh token from the family (the exact scenario 'log out everywhere' exists to remediate) keeps a usable credential for up to 30 days after the victim logged out, with zero signal that revocation did not happen. This contrasts with the rotation path, where SECURITY.md explicitly promises 'a revocation that fails is surfaced rather than silently swallowed' — the logout path makes the opposite choice. Note this is also unobservable: unlike jwt.Rotate, LogoutHandler emits no event.Sink event, so a consumer cannot even alert on failed revocations.

**Evidence**
```go
handlers.go:171-181: `if refreshToken, ok := cfg.cookies.Refresh(r); ok {\n\ttenantID := cfg.tenant(r)\n\thash := HashToken(refreshToken)\n\tif rt, err := revoker.FindRefreshToken(r.Context(), tenantID, hash); err == nil {\n\t\t_ = revoker.RevokeFamily(r.Context(), tenantID, rt.FamilyID)\n\t}\n}\n\ncfg.cookies.Clear(w)\nredirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)`
```

**Recommended fix**
Distinguish 'token not found' (keep idempotent success) from an actual store error: if FindRefreshToken fails with anything other than ErrRefreshTokenNotFound, or RevokeFamily returns an error, still clear the cookies but respond with a failure (500 or the failure redirect with error=logout_incomplete) so the client can retry, and/or emit an event (e.g. event.TokenFamilyRevoked vs a new revocation-failed event) so deployments can alert on un-revoked families.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
