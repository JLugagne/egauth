---
id: TASK-060
title: "Login with a non-password provider performs NO credential check (auth bypass via WithProvider)"
description: "Service.Authenticate only runs the password/credential branch when provider == 'password' (service.go:397). For any other provider it falls through to the block at lines 468-489, which looks up the identity by (provider, providerID), loads the user, checks DisabledAt, and then emits LoginSucceeded a…"
milestone: M4-severity-medium
epic: identity
status: done
priority: normal
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `identity` reproducing the flaw: Service.Authenticate only runs the password/credential branch when provider == "password" (service.go:397).
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Make the form login path refuse non-password providers: either have Authenticate return ErrInvalidCredentials (after a decoy hash) for any provider != "password" that has no verifiable secret, or have LoginHandler/MagicLinkLoginHandler reject a non-password cfg.provider at construction. If a generic…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/...
- [x] The audit attack scenario no longer succeeds: Service.Authenticate only runs the password/credential branch when provider == "password" (service.go:397).
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `identity/service.go:468`  •  **Category:** misuse-resistance  •  **Verifier consensus:** medium (1/1 confirmed real)

**What's wrong & impact**
Service.Authenticate only runs the password/credential branch when provider == "password" (service.go:397). For any other provider it falls through to the block at lines 468-489, which looks up the identity by (provider, providerID), loads the user, checks DisabledAt, and then emits LoginSucceeded and returns the user WITHOUT ever inspecting the supplied password (the password argument is silently ignored). LoginHandler forwards cfg.provider straight into Authenticate (handlers.go:306) and reads providerID from the attacker-controlled email form field. WithProvider (handlers.go:102) is documented merely as "sets the identity provider used for authentication (default \"password\")", inviting a consumer to set it to e.g. "google"/"github". A consumer who does so turns the public login form into a passwordless bypass: anyone who supplies a known external identifier (e.g. an OAuth sub) and any/empty password is authenticated and issued a token pair. There is no guard, warning, or test for this configuration.

**Evidence**
```go
// Fallback for other providers (if any)
ident, err := s.store.FindIdentityByProvider(ctx, tenantID, provider, providerID)
... 
user, err := s.store.FindUserByID(ctx, tenantID, ident.UserID)
...
s.emit(ctx, event.Event{Type: event.LoginSucceeded, ...})
return user, nil   // password never compared
```

**Recommended fix**
Make the form login path refuse non-password providers: either have Authenticate return ErrInvalidCredentials (after a decoy hash) for any provider != "password" that has no verifiable secret, or have LoginHandler/MagicLinkLoginHandler reject a non-password cfg.provider at construction. If a generic external-identity lookup is genuinely wanted, expose it under a clearly named method (e.g. ResolveIdentity) that is not reachable from a credential-style login handler, and document that it performs no authentication.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
