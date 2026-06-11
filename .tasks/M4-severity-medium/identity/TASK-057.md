---
id: TASK-057
title: "Disabled account login returns HTTP 500 and is an account-state enumeration oracle"
description: "Authenticate returns the dedicated ErrAccountDisabled for an administratively suspended account (service.go:434 and :484). mapAuthError, the only mapper used by LoginHandler, handles ErrAccountLocked and ErrInvalidCredentials but has no case for ErrAccountDisabled, so it falls into the default branc…"
milestone: M4-severity-medium
epic: identity
status: done
priority: normal
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `identity` reproducing the flaw: Authenticate returns the dedicated ErrAccountDisabled for an administratively suspended account (service.go:434 and :484).
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Add an explicit case for ErrAccountDisabled in mapAuthError returning a deliberate status (e.g. 403 "account_disabled" if observable suspension is acceptable, matching the lockout decision, or fold it into the generic 401 "invalid_credentials" if disabled-state must not be inferable).
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/...
- [x] The audit attack scenario no longer succeeds: Authenticate returns the dedicated ErrAccountDisabled for an administratively suspended account (service.go:434 and :484).
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `identity/handlers.go:475`  •  **Category:** enumeration  •  **Verifier consensus:** medium (1/1 confirmed real)

**What's wrong & impact**
Authenticate returns the dedicated ErrAccountDisabled for an administratively suspended account (service.go:434 and :484). mapAuthError, the only mapper used by LoginHandler, handles ErrAccountLocked and ErrInvalidCredentials but has no case for ErrAccountDisabled, so it falls into the default branch and responds 500 "login_failed". This is both a correctness defect (a deterministic auth decision is reported as an internal error) and an undocumented enumeration channel: probing a known email of a disabled account yields 500, while an unknown email or a wrong password yields 401. An attacker can therefore distinguish disabled (existing, suspended) accounts from non-existent ones and from active-but-wrong-password ones. SECURITY.md lists only lockout (429), registration (409) and change-email (409) as the intended account-existence disclosures; disabled-state disclosure is not among them.

**Evidence**
```go
func mapAuthError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrAccountLocked):
		return http.StatusTooManyRequests, "account_locked"
	case errors.Is(err, ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid_credentials"
	default:
		return http.StatusInternalServerError, "login_failed"  // ErrAccountDisabled lands here
	}
}
```

**Recommended fix**
Add an explicit case for ErrAccountDisabled in mapAuthError returning a deliberate status (e.g. 403 "account_disabled" if observable suspension is acceptable, matching the lockout decision, or fold it into the generic 401 "invalid_credentials" if disabled-state must not be inferable). Add a handler-level test asserting the chosen status so it cannot silently regress to 500.

### 2026-06-11 — Closed by close-auditor
All Actions and DoD verified. SECURITY.md updated to document ErrAccountDisabled → 429 alongside ErrAccountLocked.
