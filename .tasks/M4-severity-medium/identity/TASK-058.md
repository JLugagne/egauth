---
id: TASK-058
title: "RequestPasswordResetViaRecoveryHandler returns 500 on backend error, breaking documented enumeration-uniformity"
description: "Unlike the primary RequestPasswordResetHandler (which swallows ALL service errors with `_` and always replies 204/redirect), the via-recovery handler surfaces any service error as HTTP 500 'internal_error'. The service RequestPasswordResetViaRecovery returns a non-nil error at two paths that are rea…"
milestone: M4-severity-medium
epic: identity
status: done
priority: normal
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `identity` reproducing the flaw: Unlike the primary RequestPasswordResetHandler (which swallows ALL service errors with `_` and always replies 204/redirect), the via-recovery handler surfaces any service error as…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Swallow the service error exactly like RequestPasswordResetHandler and RequestMagicLinkHandler do: assign err to `_` and always reply with the uniform 204/success redirect. Observe backend errors via the event sink / store instrumentation, never via a differential HTTP status on this endpoint.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/...
- [x] The audit attack scenario no longer succeeds: Unlike the primary RequestPasswordResetHandler (which swallows ALL service errors with `_` and always replies 204/redirect), the via-recovery handler surfaces a…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match (no doc change needed: existing doc already promises enumeration-uniform; the fix delivers that promise)
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `identity/handlers.go:1186`  •  **Category:** enumeration  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
Unlike the primary RequestPasswordResetHandler (which swallows ALL service errors with `_` and always replies 204/redirect), the via-recovery handler surfaces any service error as HTTP 500 'internal_error'. The service RequestPasswordResetViaRecovery returns a non-nil error at two paths that are reachable ONLY for an EXISTING account: FindIdentitiesByUserID (service.go:1069) and CreateVerificationToken (service.go:1085). An unknown account always returns (nil,nil) -> 204. So a transient backend error during the identity/token step yields a 500 ONLY when the submitted email maps to a real account that has a password identity and a verified recovery channel, while every unknown/OAuth-only/no-channel account yields 204. That status asymmetry is a structural account-existence oracle. SECURITY.md promises this endpoint is 'enumeration-uniform' (it is the whole point of the via-recovery variant), so the implementation fails to deliver the documented property for the backend-error case. Practical exploitability is gated on inducing backend errors, hence medium not high.

**Evidence**
```go
token, user, channels, err := svc.RequestPasswordResetViaRecovery(...)
if err != nil {
    cfg.fail(w, r, http.StatusInternalServerError, "internal_error")
    return
}  // vs RequestPasswordResetHandler: token, user, _ := svc.RequestPasswordReset(...) (error discarded)
```

**Recommended fix**
Swallow the service error exactly like RequestPasswordResetHandler and RequestMagicLinkHandler do: assign err to `_` and always reply with the uniform 204/success redirect. Observe backend errors via the event sink / store instrumentation, never via a differential HTTP status on this endpoint.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
