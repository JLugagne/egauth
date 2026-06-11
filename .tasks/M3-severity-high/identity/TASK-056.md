---
id: TASK-056
title: "OAuth/JIT login bypasses account suspension (DisabledAt) on the already-linked path"
description: "LinkOrCreateIdentity's 'already linked' branch returns the owning user with NO check of user.DisabledAt (or user.DeletedAt). The OAuth CallbackHandler (oauth/handlers.go:236) calls linker.LinkOrCreateIdentity(...) and, on success, immediately calls issuer.IssueTokenPair(claimsOf(user)) and writes ac…"
milestone: M3-severity-high
epic: identity
status: done
priority: high
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `identity` reproducing the flaw: LinkOrCreateIdentity's 'already linked' branch returns the owning user with NO check of user.DisabledAt (or user.DeletedAt).
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Add the account-state gate inside LinkOrCreateIdentity's already-linked branch before returning the user: load the user, then `if user.DeletedAt != nil { return nil, ErrUserNotFound }` and `if user.DisabledAt != nil { return nil, ErrAccountDisabled }` — mirroring Authenticate (service.go:482) and co…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/...
- [x] The audit attack scenario no longer succeeds: LinkOrCreateIdentity's 'already linked' branch returns the owning user with NO check of user.DisabledAt (or user.DeletedAt).
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([HIGH])
**Location:** `identity/service.go:794`  •  **Category:** auth-bypass  •  **Verifier consensus:** high/high/high (3/3 confirmed real)

**What's wrong & impact**
LinkOrCreateIdentity's 'already linked' branch returns the owning user with NO check of user.DisabledAt (or user.DeletedAt). The OAuth CallbackHandler (oauth/handlers.go:236) calls linker.LinkOrCreateIdentity(...) and, on success, immediately calls issuer.IssueTokenPair(claimsOf(user)) and writes access+refresh auth cookies (oauth/handlers.go:241-247) without any account-state gate. Consequently a user whose account has been administratively suspended (DisabledAt set via DisableUser) but who has a linked OAuth identity can re-complete the social-login flow and receive a full access+refresh token pair. This directly violates the password path, which DOES reject a disabled account (identity/service.go:432 and the 'cannot authenticate via any provider' check at service.go:482), the verification/magic-link path (consumeForLiveUser re-checks DisabledAt at service.go:559), and the documented contract of DisableUser ('subsequent authentication is refused', service.go:168-169, 1090). DisableUser only stamps DisabledAt and leaves identity rows intact (memory/store.go:457-463; pgx store.go), so the OAuth identity link remains fully resolvable. Attacker scenario: an admin suspends a compromised or abusive account (e.g. after detecting fraud/ATO); the attacker, who controls the linked Google/social account, clicks 'Sign in with Google', sails through the callback, and is handed a fresh valid session — full re-entry despite the suspension. Note: the soft-delete (DeletedAt) variant of this same gap is incidentally mitigated because DeleteUser scrambles each identity's provider_id (memory/store.go:169-173; pgx store.go:203-206), so FindIdentityByProvider no longer matches the real provider subject — but that protection does not extend to DisabledAt, which performs no such scrambling.

**Evidence**
```go
// identity/service.go LinkOrCreateIdentity, case 1:
// 1. Already linked? Return the owning user.
ident, err := s.store.FindIdentityByProvider(ctx, tenantID, provider, providerID)
if err == nil {
    return s.store.FindUserByID(ctx, tenantID, ident.UserID)   // line 794 — no DisabledAt/DeletedAt gate
}

// oauth/handlers.go callback (line ~236):
user, err := linker.LinkOrCreateIdentity(r.Context(), cfg.tenant(r), p.Name(), info.ProviderID, info.Email, info.EmailVerified)
...
pair, err := issuer.IssueTokenPair(r.Context(), claimsOf(user))   // issues tokens for a suspended user
cfg.cookies.SetAccess(w, pair.AccessToken)
cfg.cookies.SetRefresh(w, pair.RefreshToken, ...)
```

**Recommended fix**
Add the account-state gate inside LinkOrCreateIdentity's already-linked branch before returning the user: load the user, then `if user.DeletedAt != nil { return nil, ErrUserNotFound }` and `if user.DisabledAt != nil { return nil, ErrAccountDisabled }` — mirroring Authenticate (service.go:482) and consumeForLiveUser (service.go:552-560). Map ErrAccountDisabled to a 403 in oauth/handlers.go mapLinkError so the suspended user gets a clean denial instead of a session. This is the correct single chokepoint because it covers every consumer of LinkOrCreateIdentity, not just the shipped OAuth handler.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified

**Verifier reasoning (high-severity cross-check)**
Confirmed in the actual code, every claim checks out. (1) identity/service.go:791-795: LinkOrCreateIdentity's already-linked branch is literally `ident, err := s.store.FindIdentityByProvider(...); if err == nil { return s.store.FindUserByID(ctx, tenantID, ident.UserID) }` — no DisabledAt or DeletedAt gate. (2) oauth/handlers.go:235-249: CallbackHandler calls linker.LinkOrCreateIdentity, then on success immediately calls issuer.IssueTokenPair(claimsOf(user)) and sets access+refresh cookies; claimsOf is a ClaimsBuilder that cannot return an error, and mapLinkError (handlers.go:319-328) has no ErrAccountDisabled case, so there is no compensating gate in the handler layer. (3) Neither store filters by account state: memory FindIdentityByProvider (identity/memory/store.go:236-248) and pgx FindIdentityByProvider (adapters/pgx/identity/store.go:276-288) match on provider/provider_id only, and FindUserByID deliberately returns disabled/soft-deleted users (per the comment at service.go:540-542). (4) DisableUser only stamps DisabledAt (memory store.go:452-466; pgx store.go:526-538) and leaves identity rows — including the OAuth provider_id — intact, so the link remains fully resolvable while suspended. (5) This is NOT a documented trade-off: the User.DisabledAt doc (identity/identity.go:36-40) promises 'A disabled account is rejected at authentication (Authenticate returns ErrAccountDisabled; passwordless logins are refused)', the DisableUser interface doc (service.go:168-177) says 'subsequent authentication is refused' with the ONLY documented carve-out being already-issued sessions/refresh tokens, and SECURITY.md's deactivation section (lines 113-116) only covers pending verification tokens. Every sibling login path enforces the gate (Authenticate at service.go:432 and 482; consumeForLiveUser at 552-561 covering magic-link/verification), making the OAuth path an inconsistency against the module's own contract, not a design choice. (6) The finding's note about DeletedAt being incidentally mitigated is also accurate: DeleteUser scrambles each identity's ProviderID (memory store.go:169-173), but DisableUser performs no such scrambling. Severity high is appropriate: it is an authentication-policy bypass (suspended account regains a full access+refresh session via the shipped social-login handler) with a realistic precondition — control of the linked OAuth account, which the suspended/abusive user or an ATO attacker holding the social account typically has. Not critical because it only re-admits the legitimately-linked identity holder; it is not a third-party takeover.
