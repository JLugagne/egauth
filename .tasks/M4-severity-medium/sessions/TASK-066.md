---
id: TASK-066
title: "Tenant resolver failure fails open into the single-tenant ('') partition"
description: "RequireSession treats an empty string from a configured tenantResolver exactly like the intentional single-tenant partition. The resolver signature is func(*http.Request) string, so the natural 'could not resolve tenant' value (unknown Host header, missing path segment, absent claim) is '' — and the…"
milestone: M4-severity-medium
epic: sessions
status: done
priority: normal
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `sessions` reproducing the flaw: RequireSession treats an empty string from a configured tenantResolver exactly like the intentional single-tenant partition.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: When a tenantResolver IS configured, treat an empty return as resolution failure and respond 401 (or change the option to accept func(*http.Request) (string, bool) / (string, error)). Keep "" as the partition only for the nil-resolver single-tenant case.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./sessions/...
- [x] The audit attack scenario no longer succeeds: RequireSession treats an empty string from a configured tenantResolver exactly like the intentional single-tenant partition.
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `sessions/middleware.go:44`  •  **Category:** tenant-isolation  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
RequireSession treats an empty string from a configured tenantResolver exactly like the intentional single-tenant partition. The resolver signature is func(*http.Request) string, so the natural 'could not resolve tenant' value (unknown Host header, missing path segment, absent claim) is "" — and the middleware then performs the session lookup in the "" partition instead of rejecting the request. In a multi-tenant deployment where any session exists under tenant "" (e.g. bootstrap/admin sessions, accidental mixing with the SingleTenant wrapper, sessions created before tenant onboarding), an attacker holding such a token can authenticate to tenant-scoped routes simply by sending a request the resolver cannot map (e.g. an unmapped Host). The handler then receives an Actor with TenantID ""; any handler that derives the tenant from the request rather than from actor.TenantID performs cross-tenant data access. There is no way for a resolver to signal failure, and the WithTenantResolver doc only describes the nil-resolver case, not the empty-return case.

**Evidence**
```go
tenantID := ""
		if cfg.tenantResolver != nil {
			tenantID = cfg.tenantResolver(r)
		}

		session, err := svc.ValidateSession(r.Context(), tenantID, token)
```

**Recommended fix**
When a tenantResolver IS configured, treat an empty return as resolution failure and respond 401 (or change the option to accept func(*http.Request) (string, bool) / (string, error)). Keep "" as the partition only for the nil-resolver single-tenant case. Document explicitly that a configured resolver must never return "" for an unresolved tenant.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
