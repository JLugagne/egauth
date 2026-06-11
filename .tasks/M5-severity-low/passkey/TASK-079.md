---
id: TASK-079
title: "BeginLogin reveals whether an account has any passkey enrolled (no_credentials oracle)"
description: "BeginLogin returns ErrNoCredentials when the resolved user has zero registered passkeys, which BeginLoginHandler maps to HTTP 400 'no_credentials', whereas a user with passkeys gets 200 plus a challenge. A caller able to drive the begin-login endpoint with a chosen/identified userID can therefore di…"
milestone: M5-severity-low
epic: passkey
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `passkey` reproducing the flaw: BeginLogin returns ErrNoCredentials when the resolved user has zero registered passkeys, which BeginLoginHandler maps to HTTP 400 'no_credentials', whereas a user with passkeys get…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Document this disclosure explicitly in SECURITY.md alongside the other intentional account-existence exceptions, or recommend that consumers gate BeginLoginHandler behind an authenticated/identified subject and rate-limit it. If the threat model forbids enumeration, return a generic challenge-style…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./passkey/...
- [x] The audit attack scenario no longer succeeds: BeginLogin returns ErrNoCredentials when the resolved user has zero registered passkeys, which BeginLoginHandler maps to HTTP 400 'no_credentials', whereas a us…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `passkey/service.go:207`  •  **Category:** enumeration  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
BeginLogin returns ErrNoCredentials when the resolved user has zero registered passkeys, which BeginLoginHandler maps to HTTP 400 'no_credentials', whereas a user with passkeys gets 200 plus a challenge. A caller able to drive the begin-login endpoint with a chosen/identified userID can therefore distinguish 'account exists and has a passkey' from 'account has no passkey'. Depending on how the consumer's UserResolver derives the subject (e.g. directly from a submitted username before any authentication), this is a passkey-enrolment enumeration oracle. egauth does not rate-limit ceremony attempts (documented), so the oracle is only bounded by the consumer's own throttling.

**Evidence**
```go
if len(u.creds) == 0 {
	return nil, nil, ErrNoCredentials
}
// handlers.go fail(): case errors.Is(err, ErrNoCredentials): http.Error(w, "no_credentials", http.StatusBadRequest)
```

**Recommended fix**
Document this disclosure explicitly in SECURITY.md alongside the other intentional account-existence exceptions, or recommend that consumers gate BeginLoginHandler behind an authenticated/identified subject and rate-limit it. If the threat model forbids enumeration, return a generic challenge-style response (or a uniform error) regardless of credential presence.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
