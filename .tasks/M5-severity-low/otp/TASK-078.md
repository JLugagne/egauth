---
id: TASK-078
title: "OTP Verify TOCTOU: code compared against stale read, consumed by key — a superseded code can still verify and burns its replacement"
description: "Verify reads the record once (GetOTP, line 109), compares the presented code against that stale CodeHash (line 133), then consumes whatever row currently exists for (tenant, subject, purpose) — ConsumeOTP takes no hash, so it is guarded only on existence, not identity (otp/store.go:23, memory/store.…"
milestone: M5-severity-low
epic: otp
status: in_progress
priority: low
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `otp` reproducing the flaw: Verify reads the record once (GetOTP, line 109), compares the presented code against that stale CodeHash (line 133), then consumes whatever row currently exists for (tenant, subjec…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Make consumption identity-guarded: extend ConsumeOTP (and the burn/expiry DeleteOTP calls) to take the expected CodeHash (or CreatedAt) and delete only the row that matches — a guarded compare-and-delete, mirroring the selector/verifier tokens' guarded delete.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./otp/...
- [x] The audit attack scenario no longer succeeds: Verify reads the record once (GetOTP, line 109), compares the presented code against that stale CodeHash (line 133), then consumes whatever row currently exists…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `otp/service.go:146`  •  **Category:** race  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
Verify reads the record once (GetOTP, line 109), compares the presented code against that stale CodeHash (line 133), then consumes whatever row currently exists for (tenant, subject, purpose) — ConsumeOTP takes no hash, so it is guarded only on existence, not identity (otp/store.go:23, memory/store.go:85-95). If Issue replaces the code between the read and the consume (e.g. a resend triggered via the open, enumeration-uniform IssueHandler), a verification of the OLD, superseded code A succeeds and deletes the NEW code B. The same applies to the expiry/burn deletes (lines 115, 128, 136), which can delete a freshly reissued valid code. Impact: a code that was deliberately invalidated by reissue remains accepted within the race window, and a legitimate fresh code is silently destroyed. SECURITY.md only promises single-use among parallel verifications of the SAME code, which still holds — this is the Issue/Verify interleave it does not cover. Window is small (one store round-trip), hence low.

**Evidence**
```go
record, err := s.store.GetOTP(...) ... if !compareCode(record.CodeHash, code) ... consumed, err := s.store.ConsumeOTP(ctx, tenantID, subjectID, purpose) — ConsumeOTP(ctx, tenantID, subjectID, purpose string) (consumed bool, err error) carries no expected CodeHash (otp/store.go:23).
```

**Recommended fix**
Make consumption identity-guarded: extend ConsumeOTP (and the burn/expiry DeleteOTP calls) to take the expected CodeHash (or CreatedAt) and delete only the row that matches — a guarded compare-and-delete, mirroring the selector/verifier tokens' guarded delete.
