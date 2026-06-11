---
id: TASK-089
title: "Validate() does not enforce a minimum RefreshLength/APIKeyLength, allowing low-entropy guessable opaque tokens"
description: "Config.Validate (lines 119-165) carefully enforces a 32-byte minimum on every HS256 SecretKey/SigningKey, but it performs NO check on RefreshLength or APIKeyLength. New() only substitutes the safe default of 32 bytes when the value is exactly 0 (lines 223-228); any other positive value is accepted v…"
milestone: M5-severity-low
epic: tokens
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `tokens/jwt` reproducing the flaw: Config.Validate (lines 119-165) carefully enforces a 32-byte minimum on every HS256 SecretKey/SigningKey, but it performs NO check on RefreshLength or APIKeyLength.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Add a minimum-length guard (e.g. >= 16 bytes, ideally >= 32 to match the 128/256-bit entropy expectation) for RefreshLength and APIKeyLength in Config.Validate, and reject (or clamp-up with a documented floor) sub-minimum values in New, mirroring the existing MinSecretKeyLength enforcement.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./tokens/jwt/...
- [x] The audit attack scenario no longer succeeds: Config.Validate (lines 119-165) carefully enforces a 32-byte minimum on every HS256 SecretKey/SigningKey, but it performs NO check on RefreshLength or APIKeyLen…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `tokens/jwt/issuer.go:223`  •  **Category:** misuse-resistance  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
Config.Validate (lines 119-165) carefully enforces a 32-byte minimum on every HS256 SecretKey/SigningKey, but it performs NO check on RefreshLength or APIKeyLength. New() only substitutes the safe default of 32 bytes when the value is exactly 0 (lines 223-228); any other positive value is accepted verbatim. A consumer who sets RefreshLength: 4 (or APIKeyLength: 4) for, say, shorter cookies, gets 32-bit opaque tokens. Refresh tokens and API keys are looked up by exact SHA-256 hash equality with no library-side rate limiting (rate limiting is explicitly the consumer's responsibility per SECURITY.md), so a 32-bit secret is online-brute-forceable against the lookup. Because Validate visibly validates key length but silently omits token length, a consumer running Validate at startup is misled into believing token strength is checked.

**Evidence**
```go
if cfg.RefreshLength == 0 {\n\t\tcfg.RefreshLength = 32\n\t}\n\tif cfg.APIKeyLength == 0 {\n\t\tcfg.APIKeyLength = 32\n\t}  // Validate() never checks a minimum for either field
```

**Recommended fix**
Add a minimum-length guard (e.g. >= 16 bytes, ideally >= 32 to match the 128/256-bit entropy expectation) for RefreshLength and APIKeyLength in Config.Validate, and reject (or clamp-up with a documented floor) sub-minimum values in New, mirroring the existing MinSecretKeyLength enforcement.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified