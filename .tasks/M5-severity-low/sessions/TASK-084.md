---
id: TASK-084
title: "No absolute session lifetime by default — Touch can keep a stolen token alive forever"
description: "WithMaxLifetime is opt-in and the zero value disables the absolute cap entirely (absoluteDeadline returns ok=false when maxLifetime <= 0). The package doc's recommended usage pattern (doc.go:22, 'on activity: svc.Touch(...) // slide idle timeout') means a default-configured service lets any session…"
milestone: M5-severity-low
epic: sessions
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `sessions` reproducing the flaw: WithMaxLifetime is opt-in and the zero value disables the absolute cap entirely (absoluteDeadline returns ok=false when maxLifetime <= 0).
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Make the absolute cap secure-by-default: apply a generous default maxLifetime (e.g. 30 days) in NewService and require an explicit opt-out (WithNoMaxLifetime or WithMaxLifetime(0) documented as insecure), or at minimum add session absolute-lifetime guidance to SECURITY.md so the trade-off is a docum…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./sessions/...
- [x] The audit attack scenario no longer succeeds: WithMaxLifetime is opt-in and the zero value disables the absolute cap entirely (absoluteDeadline returns ok=false when maxLifetime <= 0).
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `sessions/service.go:204`  •  **Category:** misuse-resistance  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
WithMaxLifetime is opt-in and the zero value disables the absolute cap entirely (absoluteDeadline returns ok=false when maxLifetime <= 0). The package doc's recommended usage pattern (doc.go:22, 'on activity: svc.Touch(...) // slide idle timeout') means a default-configured service lets any session — including a stolen cookie an attacker keeps warm with periodic requests — live indefinitely: each Touch slides ExpiresAt to now+duration with no upper bound. OWASP session guidance calls for an absolute timeout in addition to the idle timeout; here the secure behavior requires the consumer to know about and opt into WithMaxLifetime, and SECURITY.md never mentions session lifetimes as an accepted trade-off. The clamp machinery (clampExpiry, SEC-08) is correct and well-tested when enabled — the gap is purely that it is off by default.

**Evidence**
```go
func (s *service) absoluteDeadline(session *Session) (time.Time, bool) {
	if s.maxLifetime <= 0 {
		return time.Time{}, false
	}
```

**Recommended fix**
Make the absolute cap secure-by-default: apply a generous default maxLifetime (e.g. 30 days) in NewService and require an explicit opt-out (WithNoMaxLifetime or WithMaxLifetime(0) documented as insecure), or at minimum add session absolute-lifetime guidance to SECURITY.md so the trade-off is a documented decision rather than a silent default.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
