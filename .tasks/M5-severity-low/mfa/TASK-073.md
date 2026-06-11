---
id: TASK-073
title: "mfa handlers have no Origin/Referer CSRF option, unlike the otp handlers"
description: "All six mfa handlers are state-changing POST endpoints authenticated by whatever the UserResolver reads (typically a session cookie), yet handlerConfig offers no trustedOrigins option — the sibling otp package ships WithTrustedOrigins and checks originAllowed on every request (otp/handlers.go:74-81,…"
milestone: M5-severity-low
epic: mfa
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `mfa` reproducing the flaw: All six mfa handlers are state-changing POST endpoints authenticated by whatever the UserResolver reads (typically a session cookie), yet handlerConfig offers no trustedOrigins opt…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Add mfa.WithTrustedOrigins with the same originAllowed enforcement as the otp handlers (at minimum on DisableHandler, RegenerateRecoveryCodesHandler and EnrollHandler), and mention the mfa handlers in SECURITY.md's CSRF section.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./mfa/...
- [x] The audit attack scenario no longer succeeds: All six mfa handlers are state-changing POST endpoints authenticated by whatever the UserResolver reads (typically a session cookie), yet handlerConfig offers n…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `mfa/handlers.go:154`  •  **Category:** csrf  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
All six mfa handlers are state-changing POST endpoints authenticated by whatever the UserResolver reads (typically a session cookie), yet handlerConfig offers no trustedOrigins option — the sibling otp package ships WithTrustedOrigins and checks originAllowed on every request (otp/handlers.go:74-81, 217-226). SECURITY.md's CSRF section covers only the identity/tokens handlers. If a consumer's session cookie is not SameSite=Lax (e.g. SameSite=None for an embedded or cross-subdomain app), a cross-site form POST to DisableHandler silently strips the victim's second factor (MFA downgrade), and one to RegenerateRecoveryCodesHandler invalidates their recovery codes. The library gives such a consumer no built-in mitigation to turn on, breaking hardening parity within the same SDK.

**Evidence**
```go
guarded() runs method check → resolve → ParseForm → fn (mfa/handlers.go:154-176) with no origin check; handlerConfig (lines 17-23) has no trustedOrigins field, whereas otp/handlerConfig does and enforces it via cfg.originAllowed(r).
```

**Recommended fix**
Add mfa.WithTrustedOrigins with the same originAllowed enforcement as the otp handlers (at minimum on DisableHandler, RegenerateRecoveryCodesHandler and EnrollHandler), and mention the mfa handlers in SECURITY.md's CSRF section.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
