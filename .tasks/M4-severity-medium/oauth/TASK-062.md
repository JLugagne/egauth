---
id: TASK-062
title: "Userinfo-path fetchers accept an empty/missing provider subject (sub), enabling cross-account identity collision"
description: "The shared OIDC userinfo fetcher (oidcUserInfoFetcher, used by Okta, OktaCustom, Auth0, Keycloak, Cognito and the generic providers.OIDC) and every other access-token userinfo fetcher (google.go:47, microsoft.go:71, linkedin.go:42, gitlab.go:55, discord.go:40, facebook.go:38) build a UserInfo whose…"
milestone: M4-severity-medium
epic: oauth
status: done
priority: normal
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `oauth/providers` reproducing the flaw: The shared OIDC userinfo fetcher (oidcUserInfoFetcher, used by Okta, OktaCustom, Auth0, Keycloak, Cognito and the generic providers.OIDC) and every other access-token userinfo fetc…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Reject an empty ProviderID in every fetcher (e.g. in oidcUserInfoFetcher, the per-provider fetchers, and stringifyID's callers) returning an error like fmt.Errorf("%w: provider returned no subject id", oauth.ErrUserInfoFailed), mirroring defaultOIDCClaimsMapper's `sub == ""` rejection.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./oauth/providers/...
- [x] The audit attack scenario no longer succeeds: The shared OIDC userinfo fetcher (oidcUserInfoFetcher, used by Okta, OktaCustom, Auth0, Keycloak, Cognito and the generic providers.OIDC) and every other access…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `oauth/providers/okta.go:76`  •  **Category:** tenant-isolation  •  **Verifier consensus:** medium (1/1 confirmed real)

**What's wrong & impact**
The shared OIDC userinfo fetcher (oidcUserInfoFetcher, used by Okta, OktaCustom, Auth0, Keycloak, Cognito and the generic providers.OIDC) and every other access-token userinfo fetcher (google.go:47, microsoft.go:71, linkedin.go:42, gitlab.go:55, discord.go:40, facebook.go:38) build a UserInfo whose ProviderID is taken verbatim from the provider response with NO non-empty check. stringifyID returns "" for a missing, null, or non-string/non-number 'sub', and Google/Microsoft/LinkedIn map a missing string 'sub' to "". The id_token validation path explicitly rejects this (oidc.go:256 `if sub == "" { return ...missing sub claim }`), but the userinfo path does not, and the callback handler (oauth/handlers.go:235) passes info.ProviderID straight into LinkOrCreateIdentity without guarding against "". LinkOrCreateIdentity then calls FindIdentityByProvider(tenant, provider, ""), which (identity/memory/store.go:241) matches the FIRST stored identity that has an empty ProviderID. Attack: against a non-conformant or attacker-influenced userinfo endpoint (realistic on the generic providers.OIDC escape hatch and the planned per-tenant bring-your-own-SSO path, or any IdP that transiently omits 'sub'), the first JIT-provisioned user with an empty sub creates an identity keyed on ProviderID=""; a second, different OAuth principal that also yields an empty sub resolves to that first identity and is signed in AS the first user — account confusion / takeover. The email-verified gate does not help because both principals can be verified at the same provider.

**Evidence**
```go
return &oauth.UserInfo{
    ProviderID:    stringifyID(u.Sub),  // "" when sub is missing/null/non-scalar
    Email:         u.Email,
    EmailVerified: u.EmailVerified,
    Name:          u.Name,
}, nil   // no empty-ProviderID guard, unlike oidc.go:256
```

**Recommended fix**
Reject an empty ProviderID in every fetcher (e.g. in oidcUserInfoFetcher, the per-provider fetchers, and stringifyID's callers) returning an error like fmt.Errorf("%w: provider returned no subject id", oauth.ErrUserInfoFailed), mirroring defaultOIDCClaimsMapper's `sub == ""` rejection. Add a defensive `if info.ProviderID == ""` check in CallbackHandler (oauth/handlers.go, alongside the existing Email=="" check) so the property holds regardless of the fetcher.
