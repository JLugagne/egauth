---
id: TASK-067
title: "jwt.New silently accepts an arbitrarily weak HS256 signing key; MinSecretKeyLength is enforced only by the opt-in Config.Validate"
description: "resolveKeyset (called by jwt.New and basic.NewIssuer) only rejects an EMPTY key: in single-key mode `if cfg.SecretKey == '' { return ... }` and in keyset mode `if k.Secret == '' { ..."
milestone: M4-severity-medium
epic: tokens
status: done
priority: normal
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `tokens/jwt` reproducing the flaw: resolveKeyset (called by jwt.New and basic.NewIssuer) only rejects an EMPTY key: in single-key mode `if cfg.SecretKey == "" { return ...
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Enforce len(key) >= MinSecretKeyLength inside resolveKeyset/New (panic, matching the existing fail-fast convention) for both SecretKey and every SigningKeys[].Secret. If test code genuinely needs short keys, add an explicit greppable escape hatch (e.g.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./tokens/jwt/...
- [x] The audit attack scenario no longer succeeds: resolveKeyset (called by jwt.New and basic.NewIssuer) only rejects an EMPTY key: in single-key mode `if cfg.SecretKey == "" { return ...
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `tokens/jwt/issuer.go:178`  •  **Category:** misuse-resistance  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
resolveKeyset (called by jwt.New and basic.NewIssuer) only rejects an EMPTY key: in single-key mode `if cfg.SecretKey == "" { return ... }` and in keyset mode `if k.Secret == "" { ... }`. A consumer who passes SecretKey: "secret" or a 8-16 byte value gets a fully working issuer. The 32-byte floor (MinSecretKeyLength) lives only in Config.Validate, which the docs describe as something production callers "SHOULD" call — it is not invoked by New. The package doc overstates the guarantee: tokens/doc.go:29 says "jwt.New panics on an unusable signing key (fail-fast at startup)", and the README quickstart relies on a comment ("// >= 32 bytes") rather than enforcement. This is inconsistent with the sibling module passkey, whose NewService hard-fails on a CookieKey shorter than 32 bytes (SECURITY.md even says passkey 'mirrors jwt.New' fail-fast). Impact: an HS256 key short enough to brute-force (or a human-memorable string) lets an attacker who captures any single access token recover the signing key offline and then forge arbitrary access tokens for any user/tenant — a full authentication bypass. Precondition: the consumer configures a weak key and skips Validate, which the quickstart path (basic.NewIssuer) makes easy.

**Evidence**
```go
resolveKeyset, single-key mode: `if cfg.SecretKey == "" { return nil, "", nil, nil, errors.New("no signing key configured (set SecretKey or SigningKeys)") }` — no length check; keyset mode checks only `if k.Secret == "" { ... }`. The 32-byte check exists only in Validate: `case len(cfg.SecretKey) < MinSecretKeyLength:` (issuer.go:126). tokens/doc.go:29: "jwt.New panics on an unusable signing key (fail-fast at startup)."
```

**Recommended fix**
Enforce len(key) >= MinSecretKeyLength inside resolveKeyset/New (panic, matching the existing fail-fast convention) for both SecretKey and every SigningKeys[].Secret. If test code genuinely needs short keys, add an explicit greppable escape hatch (e.g. Config.InsecureAllowWeakKey) mirroring passkey's InsecureNoChallengeStore pattern. At minimum, fix the tokens/doc.go claim so it does not say New fail-fasts on an "unusable" key when it only rejects an empty one.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
