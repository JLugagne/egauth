---
id: TASK-090
title: "VerifyAccessToken performs no tenant binding, unlike the tenant-scoped refresh/API-key paths"
description: "VerifyRefreshToken and VerifyAPIKey both take a tenantID and fail closed on a cross-tenant lookup (proven by multitenant_test.go). VerifyAccessToken takes NO tenant parameter: it parses the JWT, reads the signed tenant_id claim, and returns it in Claims.TenantID without comparing it to any expected…"
milestone: M5-severity-low
epic: tokens
status: in_progress
priority: low
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `tokens/jwt` reproducing the flaw: VerifyRefreshToken and VerifyAPIKey both take a tenantID and fail closed on a cross-tenant lookup (proven by multitenant_test.go).
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Offer a tenant-scoped variant (e.g. VerifyAccessTokenForTenant(ctx, tenantID, token) that rejects a mismatched tenant_id), or document prominently at the VerifyAccessToken call site that multi-tenant consumers MUST compare the returned Claims.TenantID against the request tenant.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./tokens/jwt/...
- [x] The audit attack scenario no longer succeeds: VerifyRefreshToken and VerifyAPIKey both take a tenantID and fail closed on a cross-tenant lookup (proven by multitenant_test.go).
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `tokens/jwt/issuer.go:416`  •  **Category:** tenant-isolation  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
VerifyRefreshToken and VerifyAPIKey both take a tenantID and fail closed on a cross-tenant lookup (proven by multitenant_test.go). VerifyAccessToken takes NO tenant parameter: it parses the JWT, reads the signed tenant_id claim, and returns it in Claims.TenantID without comparing it to any expected tenant (lines 460-471). In a multi-tenant deployment served by a single Service (one signing key shared across all tenants), a valid access token minted for tenant A verifies successfully when presented in tenant B's context; the only thing standing between this and cross-tenant access is the consumer remembering to compare claims.TenantID externally. The API gives the consumer no tenant argument to scope the check and no signal that the returned TenantID is unvalidated, an asymmetry with the refresh path that is an easy footgun.

**Evidence**
```go
func (s *Service[C]) VerifyAccessToken(ctx context.Context, tokenStr string) (*tokens.Claims[C], error) { ... claims := tokens.Claims[C]{ Subject: subject, TenantID: wrapper.TenantID, ... } // tenant is returned, never checked; no tenantID parameter exists
```

**Recommended fix**
Offer a tenant-scoped variant (e.g. VerifyAccessTokenForTenant(ctx, tenantID, token) that rejects a mismatched tenant_id), or document prominently at the VerifyAccessToken call site that multi-tenant consumers MUST compare the returned Claims.TenantID against the request tenant. Mirror the fail-closed scoping the refresh path already provides.
