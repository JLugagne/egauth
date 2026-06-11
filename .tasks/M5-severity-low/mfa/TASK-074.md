---
id: TASK-074
title: "mfa handlers do not cap the request body (otp caps at 4 KiB)"
description: "guarded() calls r.ParseForm() without wrapping the body in http.MaxBytesReader. Because no maxBytesReader is installed, net/http falls back to its 10 MB internal urlencoded-form limit, so any authenticated client can make the server read and buffer 10 MB per request on every mfa endpoint (the code f…"
milestone: M5-severity-low
epic: mfa
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `mfa` reproducing the flaw: guarded() calls r.ParseForm() without wrapping the body in http.MaxBytesReader.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Port otp's parseLimitedForm into the mfa guarded() preamble: a DefaultMaxBodyBytes (4 KiB) cap via http.MaxBytesReader with a WithMaxBodyBytes override, returning 413 on *http.MaxBytesError.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./mfa/...
- [x] The audit attack scenario no longer succeeds: guarded() calls r.ParseForm() without wrapping the body in http.MaxBytesReader.
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `mfa/handlers.go:170`  •  **Category:** dos  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
guarded() calls r.ParseForm() without wrapping the body in http.MaxBytesReader. Because no maxBytesReader is installed, net/http falls back to its 10 MB internal urlencoded-form limit, so any authenticated client can make the server read and buffer 10 MB per request on every mfa endpoint (the code field needs a few bytes). The otp package in the same SDK deliberately added DefaultMaxBodyBytes = 4 KiB and MaxBytesReader for exactly this reason (otp/handlers.go:12-13, 201-215), so the mfa handlers are a recognized-but-missing hardening within the project's own threat model.

**Evidence**
```go
if err := r.ParseForm(); err != nil { cfg.fail(w, r, http.StatusBadRequest, "invalid_request") ... } (mfa/handlers.go:170-173) — no MaxBytesReader anywhere in mfa/ (grep confirms), versus otp's parseLimitedForm with http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes).
```

**Recommended fix**
Port otp's parseLimitedForm into the mfa guarded() preamble: a DefaultMaxBodyBytes (4 KiB) cap via http.MaxBytesReader with a WithMaxBodyBytes override, returning 413 on *http.MaxBytesError.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
