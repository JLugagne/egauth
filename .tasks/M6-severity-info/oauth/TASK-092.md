---
id: TASK-092
title: "DynamicCallbackHandler resolves the tenant multiple times and assumes a pure resolver; the exchange provider is bound to the first resolution while the cookie check and identity-link use later resolutions"
description: "In the dynamic path the tenant resolver is invoked at least three times for one callback: once in DynamicCallbackHandler (handlers.go:378, used to fetch the provider that performs the token exchange), once inside the delegated CallbackHandler for the cookieTenant binding check (handlers.go:204), and…"
milestone: M6-severity-info
epic: oauth
status: in_progress
priority: low
type: chore
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `oauth` reproducing the flaw: In the dynamic path the tenant resolver is invoked at least three times for one callback: once in DynamicCallbackHandler (handlers.go:378, used to fetch the provider that performs…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Resolve the tenant exactly once at the top of the request and thread that single value (and the resolved provider) through the binding check, the exchange, and LinkOrCreateIdentity, instead of re-invoking cfg.tenant(r) in the delegated static handler. Document that the tenant resolver MUST be a pure…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./oauth/...
- [x] The audit attack scenario no longer succeeds: In the dynamic path the tenant resolver is invoked at least three times for one callback: once in DynamicCallbackHandler (handlers.go:378, used to fetch the pro…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([INFO])
**Location:** `oauth/handlers.go:378`  •  **Category:** tenant-isolation  •  **Verifier consensus:** info (1/1 confirmed real)

**What's wrong & impact**
In the dynamic path the tenant resolver is invoked at least three times for one callback: once in DynamicCallbackHandler (handlers.go:378, used to fetch the provider that performs the token exchange), once inside the delegated CallbackHandler for the cookieTenant binding check (handlers.go:204), and once for LinkOrCreateIdentity (handlers.go:235). The provider used for the actual code exchange is resolved from the FIRST call's tenant, but the security gate (cookieTenant must equal cfg.tenant(r)) and the identity write are evaluated against LATER calls. The whole isolation argument therefore rests on the implicit assumption that the consumer-supplied func(*http.Request) string is pure and deterministic within a request. Realistic resolvers (subdomain/host, path param, header, validated session) are deterministic, so I found no exploitable divergence and file this only as a hardening note: a resolver that consults mutable state could let the cookie/tenant check pass for tenant Y while the exchange ran against tenant X's provider, or link the resulting identity into a different partition than the one whose provider minted the token. There is no impure-resolver evidence in the library itself, so this is informational, not a confirmed bug.

**Evidence**
```go
DynamicCallbackHandler: `tenant := cfg.tenant(r)` then `p, err := store.GetProvider(r.Context(), tenant, providerName)` ... `CallbackHandler(p, linker, issuer, claimsOf, opts...)(w, r)`; the delegated handler independently re-derives `cfg.tenant(r)` at handlers.go:204 (`stateMatches(cookieTenant, cfg.tenant(r))`) and handlers.go:235 (`linker.LinkOrCreateIdentity(r.Context(), cfg.tenant(r), ...)`).
```

**Recommended fix**
Resolve the tenant exactly once at the top of the request and thread that single value (and the resolved provider) through the binding check, the exchange, and LinkOrCreateIdentity, instead of re-invoking cfg.tenant(r) in the delegated static handler. Document that the tenant resolver MUST be a pure function of the request.
