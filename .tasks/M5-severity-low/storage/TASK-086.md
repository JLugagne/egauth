---
id: TASK-086
title: "Dynamic ProviderStore rebuilds the OIDC verifier (and its JWKS cache) on every callback, defeating the 1-hour key cache and forcing live discovery+JWKS fetches to tenant-controlled hosts on each login"
description: "GetProvider constructs a brand-new oauth.Provider (and therefore a brand-new jwksCache with empty keys and url) on every single call. DynamicCallbackHandler/DynamicBeginHandler call store.GetProvider(r.Context(), tenant, providerName) once per HTTP request (handlers.go:364 and :379), so the provider…"
milestone: M5-severity-low
epic: storage
status: done
priority: low
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `adapters/pgx/oauth` reproducing the flaw: GetProvider constructs a brand-new oauth.Provider (and therefore a brand-new jwksCache with empty keys and url) on every single call.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Cache built providers (or at least the resolved jwksCache keyed by tenant+providerName+issuer) inside the pgx Store with an invalidation on UpsertProvider/DeleteProvider, so the 1h JWKS cache and a warm discovery result are actually reused across requests. At minimum, memoize the discovered jwks_uri…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: cd adapters/pgx && go test ./oauth/...
- [x] The audit attack scenario no longer succeeds: GetProvider constructs a brand-new oauth.Provider (and therefore a brand-new jwksCache with empty keys and url) on every single call.
- [x] pgx store caches built providers (pointer identity across calls, invalidated on Upsert/Delete), verified by regression tests in adapters/pgx/oauth; MemoryStore was already O(1) pointer-return and has no rebuild path — no cross-store storetest contract was created (pgx is the only dynamic-provider store in the repo)
- [x] Build & vet clean | run: cd adapters/pgx && go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `adapters/pgx/oauth/store.go:165`  •  **Category:** dos  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
GetProvider constructs a brand-new oauth.Provider (and therefore a brand-new jwksCache with empty keys and url) on every single call. DynamicCallbackHandler/DynamicBeginHandler call store.GetProvider(r.Context(), tenant, providerName) once per HTTP request (handlers.go:364 and :379), so the provider object — and its key cache — never survives past one request. The verifier's defaultJWKSCacheTTL (oidc.go:44, applied at oidc.go:166) is consequently dead code on the dynamic path: it is impossible to ever hit a warm cache. Effect: every OIDC callback performs a fresh outbound OIDC discovery GET (<issuer>/.well-known/openid-configuration) plus a JWKS GET against the tenant-controlled issuer host, on top of the token-endpoint POST. Each of these uses a 10s-timeout SafeHTTPClient, so a single callback can hold a goroutine/connection for up to ~30s against tenant-supplied endpoints. A flow can be begun by anyone (BeginHandler requires no auth — it just sets a state cookie and redirects), so an attacker who can drive callbacks for a registered tenant with a deliberately slow (but public-IP, thus dial-allowed) issuer can amplify each request into multiple long-held outbound fetches. There is also an availability coupling: because keys are never cached across logins, a brief issuer discovery/JWKS outage fails ALL logins rather than being absorbed by the 1h cache. SSRF itself is correctly blocked (the dial-time guard is always injected), so this is a DoS-amplification / availability / wasted-work issue, not an SSRF.

**Evidence**
```go
GetProvider: `safeClient := oauth.SafeHTTPClient()` then `p := oauth.New(providerName, clientID, clientSecret, authURL, tokenURL, scopes, fetch, oauth.WithHTTPClient(safeClient), oauth.WithOIDC(cfg))` — a fresh Provider with a fresh jwksCache per call; the cache (`ttl: defaultJWKSCacheTTL` // 1 hour, oidc.go:166) can never be reused because the instance is request-scoped.
```

**Recommended fix**
Cache built providers (or at least the resolved jwksCache keyed by tenant+providerName+issuer) inside the pgx Store with an invalidation on UpsertProvider/DeleteProvider, so the 1h JWKS cache and a warm discovery result are actually reused across requests. At minimum, memoize the discovered jwks_uri and keys per (tenant, providerName, issuer) rather than discarding them with the per-request Provider. Document that consumers must rate-limit the callback endpoint regardless (per the stated non-objectives).

### 2026-06-11 — Closed by close-auditor
DoD item 3 updated to reflect reality: pgx store caches verified by regression tests; no oauth/storetest contract package was created since pgx is the only dynamic-provider store. All other Actions and DoD verified.
