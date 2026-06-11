---
id: TASK-063
title: "OTP IssueHandler dispatches delivery on an unbounded, untimed goroutine (toll-fraud / goroutine-exhaustion amplification)"
description: "IssueHandler spawns a fresh `go func()` per request to run the consumer's deliver callback (email/SMS) on a detached context, with NO concurrency bound and NO per-delivery timeout. The documented subject-resolution model includes resolving the subject from a submitted email, so this endpoint can be…"
milestone: M4-severity-medium
epic: otp
status: in_progress
priority: normal
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `otp` reproducing the flaw: IssueHandler spawns a fresh `go func()` per request to run the consumer's deliver callback (email/SMS) on a detached context, with NO concurrency bound and NO per-delivery timeout.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Mirror identity.handlerConfig.dispatchDelivery: add a shared buffered-channel semaphore created once per handler instance (non-blocking acquire, drop-on-full) and a per-delivery context.WithTimeout, both configurable. This bounds the goroutine fan-out and prevents a hung Mailer/SMSSender from leakin…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./otp/...
- [x] The audit attack scenario no longer succeeds: IssueHandler spawns a fresh `go func()` per request to run the consumer's deliver callback (email/SMS) on a detached context, with NO concurrency bound and NO p…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `otp/handlers.go:131`  •  **Category:** dos  •  **Verifier consensus:** medium (1/1 confirmed real)

**What's wrong & impact**
IssueHandler spawns a fresh `go func()` per request to run the consumer's deliver callback (email/SMS) on a detached context, with NO concurrency bound and NO per-delivery timeout. The documented subject-resolution model includes resolving the subject from a submitted email, so this endpoint can be unauthenticated. A flood of requests for valid/guessable subjects spawns unbounded concurrent goroutines and fans out into unbounded outbound mail/SMS (mail-bombing / SMS toll-fraud), and a slow/hung deliver pins each goroutine forever (the context is WithoutCancel with no timeout), so goroutines leak without bound. The identity package treats this exact pattern as a footgun and defends it with a shared bounded semaphore (DefaultDeliveryConcurrency) plus WithDeliveryTimeout in dispatchDelivery; the OTP IssueHandler has neither, so an inconsistent hardening gap leaves the cheapest amplification path unguarded even when a consumer rate-limits in front.

**Evidence**
```go
if ch, err := svc.Issue(r.Context(), cfg.tenant(r), subjectID, cfg.purposeOf(r)); err == nil && deliver != nil {
    ctx := context.WithoutCancel(r.Context())
    go func() { _ = deliver(ctx, ch) }()
}
```

**Recommended fix**
Mirror identity.handlerConfig.dispatchDelivery: add a shared buffered-channel semaphore created once per handler instance (non-blocking acquire, drop-on-full) and a per-delivery context.WithTimeout, both configurable. This bounds the goroutine fan-out and prevents a hung Mailer/SMSSender from leaking goroutines, independent of any external rate limiter.
