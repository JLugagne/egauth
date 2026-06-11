---
id: TASK-068
title: "Refresh rotation structurally cannot preserve per-session AMR: ClaimsProvider gets only (userID, tenantID) and RefreshToken persists no AMR, so even hand-rolled MFA elevation decays or leaks across sessions"
description: "SECURITY.md:96-97 states 'On refresh the AMR is re-evaluated by the ClaimsProvider, not frozen at login.' But ClaimsProvider.ClaimsForUser receives only the user ID and tenant (tokens/rotation.go:20) — no family ID, no session identifier, and no previously-issued AMR. The persisted tokens.RefreshTok…"
milestone: M4-severity-medium
epic: tokens
status: done
priority: normal
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `tokens` reproducing the flaw: SECURITY.md:96-97 states 'On refresh the AMR is re-evaluated by the ClaimsProvider, not frozen at login.' But ClaimsProvider.ClaimsForUser receives only the user ID and tenant (tok…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: surface the rotation family to the provider so per-session AMR re-evaluation becomes possible (chosen variant — see Discussion)
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./tokens/...
- [x] The audit attack scenario no longer succeeds: the provider now receives the rotation family ID + preserved auth_time, so per-session AMR re-evaluation is implementable (neither silent decay nor blanket elevation are forced)
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `tokens/rotation.go:20`  •  **Category:** misuse-resistance  •  **Verifier consensus:** medium (1/1 confirmed real)

**What's wrong & impact**
SECURITY.md:96-97 states 'On refresh the AMR is re-evaluated by the ClaimsProvider, not frozen at login.' But ClaimsProvider.ClaimsForUser receives only the user ID and tenant (tokens/rotation.go:20) — no family ID, no session identifier, and no previously-issued AMR. The persisted tokens.RefreshToken (tokens/token.go:79-91) deliberately carries AuthTime across rotations ('carried unchanged onto every rotated descendant') but has NO AMR field, and the Rotate path (tokens/jwt/issuer.go:584) overwrites claims wholesale from the provider, restoring only TenantID, ExpiresAt and AuthTime (lines 594-599) — claims.AMR is whatever the per-USER provider returns. Consequence: a diligent consumer who works around finding 1 by hand-minting an MFA-elevated pair (IssueTokenPair with AMR=['pwd','otp','mfa']) after mfa.VerifyHandler faces an impossible choice on the first silent refresh: (a) a provider that cannot know about the MFA event returns AMR without 'mfa', so the step-up assurance silently decays after one access-token TTL (~15 min) and WithRequiredAMR(AMRMFA) starts rejecting a legitimately-elevated user — pushing consumers to drop the gate; or (b) the provider returns AMRMFA for every session of any MFA-enrolled user (the only signal it can compute from userID), which ELEVATES the attacker's pre-MFA password-only refresh family to AMRMFA on its first rotation — a step-up bypass: a stolen password yields a session that, after one /refresh call, passes the WithRequiredAMR(AMRMFA) gate without ever presenting a second factor. The library already solved this exact problem for AuthTime (preserved per-family precisely so refresh cannot manufacture freshness, issuer.go:596-599) but left AMR — the other half of the same step-up gate — without an equivalent per-family carrier, so the documented 're-evaluated' semantics cannot be implemented correctly by any consumer.

**Evidence**
```go
tokens/rotation.go:20: `ClaimsForUser(ctx context.Context, userID uuid.UUID, tenantID string) (Claims[C], error)` (no family/AMR input). tokens/token.go:79-91: RefreshToken{Hash, FamilyID, UserID, TenantID, AuthTime, ExpiresAt, CreatedAt, ConsumedAt} — no AMR. tokens/jwt/issuer.go:584-599: `claims, err := s.claimsProvider.ClaimsForUser(ctx, rt.UserID, rt.TenantID)` ... `claims.TenantID = rt.TenantID; claims.ExpiresAt = time.Time{}; claims.AuthTime = rt.AuthTime` — AuthTime restored from the family, AMR taken verbatim from the per-user provider.
```

**Recommended fix**
Persist AMR on tokens.RefreshToken alongside AuthTime (set on the initial pair, carried unchanged onto every rotated descendant), and on Rotate intersect/cap the provider-returned AMR with the family's stored AMR (the provider may REMOVE factors — e.g. MFA was disabled — but never ADD one the family never proved). Alternatively, pass the family's stored AMR and AuthTime into ClaimsProvider (e.g. ClaimsForRotation(ctx, userID, tenantID, prior RotationContext)) so the re-evaluation the docs promise is actually informed. Add a storetest contract case pinning that AMR round-trips and survives rotation, mirroring the existing auth_time case (tokens/storetest/contract.go:169).

### 2026-06-11 — Implementation note (chosen approach)
Implemented the second recommended variant (inform the re-evaluation) rather than the AMR-persist-and-cap variant, because it removes the structural impossibility without changing the store schema/contract or the `ClaimsProvider` interface signature (no break for the many existing implementers).

`Rotate` now attaches a `tokens.RotationContext{FamilyID, AuthTime}` to the context handed to `ClaimsProvider.ClaimsForUser`. A provider recovers it with `tokens.RotationContextFromContext(ctx)` and can therefore re-evaluate assurance for the *specific* family/session being rotated — keyed by `FamilyID` — instead of being limited to the per-user signal. This makes the documented "AMR re-evaluated, not frozen" semantics actually implementable: a provider can preserve a legitimately MFA-elevated session's AMR across silent refreshes, or deliberately downgrade it (e.g. MFA disabled), without being forced into either silent decay or blanket elevation (the step-up bypass).

New API in `tokens/rotation.go`: `RotationContext` struct, `WithRotationContext` (issuer-side setter) and `RotationContextFromContext` (provider-side getter). The `ClaimsForUser` signature is unchanged, so the carrier is additive and providers that ignore it keep compiling. Regression test: `TestRotate_ClaimsProviderReceivesRotationContext` in `tokens/jwt/rotation_test.go`. `SECURITY.md` updated around the "AMR is re-evaluated" sentence. The AMR-persist-on-RefreshToken + storetest-contract variant was intentionally NOT done, so the store layer is untouched.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
