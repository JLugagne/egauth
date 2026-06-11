---
id: TASK-055
title: "Documented AMR/step-up model is unwireable: no library primitive produces an MFA-bearing token, and every first-party login handler issues a fully-privileged refreshable pair on a single factor"
description: "SECURITY.md (lines 94-97) promises 'Tokens carry an AMR claim (RFC 8176) recording the factors used to obtain them; tokens.WithRequiredAMR(...) gates a route on those factors (e.g. require AMRMFA)' and presents this as the supported step-up/AAL2 model."
milestone: M3-severity-high
epic: identity
status: done
priority: high
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `identity` reproducing the flaw: SECURITY.md (lines 94-97) promises 'Tokens carry an AMR claim (RFC 8176) recording the factors used to obtain them; tokens.WithRequiredAMR(...) gates a route on those factors (e.g.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Ship the producing half of the documented model: (a) add an MFA-gated login option, e.g. identity.WithMFAGate(mfa.Service), under which LoginHandler checks IsEnrolled after password success and, for enrolled users, issues a short-lived INTERIM access token with AMR=[AMRPassword] and NO refresh token…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/...
- [x] The audit attack scenario no longer succeeds: SECURITY.md (lines 94-97) promises 'Tokens carry an AMR claim (RFC 8176) recording the factors used to obtain them; tokens.WithRequiredAMR(...) gates a route on…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([HIGH])
**Location:** `identity/handlers.go:313`  •  **Category:** misuse-resistance  •  **Verifier consensus:** medium/medium/info (2/3 confirmed real)

**What's wrong & impact**
SECURITY.md (lines 94-97) promises 'Tokens carry an AMR claim (RFC 8176) recording the factors used to obtain them; tokens.WithRequiredAMR(...) gates a route on those factors (e.g. require AMRMFA)' and presents this as the supported step-up/AAL2 model. The library ships only the ENFORCEMENT half (tokens/middleware.go:78 WithRequiredAMR). Nothing in the library can PRODUCE a token whose AMR reflects a verified second factor: (1) identity.LoginHandler (handlers.go:286) calls svc.Authenticate (password only, line 306) and immediately issues the complete access+refresh pair via issuePairAndSetCookies (line 313, impl 360-368) — same for RegisterHandler, MagicLinkLoginHandler and oauth.CallbackHandler (oauth/handlers.go:242). (2) The AMR content comes solely from the consumer's ClaimsBuilder, typed `func(*User) tokens.Claims[C]` (handlers.go:20) — it receives no context.Context and the identity.User struct (identity/identity.go:10-42) carries NO MFA-enrolled or MFA-satisfied field, so the builder cannot even query mfa.Service.IsEnrolled, let alone know whether MFA was verified in this session. (3) mfa.VerifyHandler (mfa/handlers.go:103-112) on a correct TOTP just calls cfg.ok(w, r) — 204 or redirect; it takes no Issuer, mints nothing, elevates nothing, and is itself 'guarded' (requires an already-authenticated session, mfa/handlers.go:154-175), so it presupposes exactly the pre-MFA token it should be replacing. (4) A repo-wide search confirms the AMR constants (AMRPassword/AMROTP/AMRWebAuthn/AMRMFA, tokens/token.go:11-16) are referenced by ZERO production code outside their definition and the middleware that checks them — no handler, service or helper ever sets them; the passkey module mints no tokens at all, so even AMRWebAuthn has no producer. Attack scenario: a consumer follows the documented flow (LoginHandler -> mfa.VerifyHandler -> app). An attacker who has only the victim's password POSTs to the login endpoint and receives a complete, refreshable session (access JWT + rotating refresh cookie) before any MFA challenge — the 'pre-MFA' state IS a full session, indefinitely renewable via /refresh, even though the application intends to require MFA. Meanwhile WithRequiredAMR(AMRMFA) is unwireable: no token ever carries 'mfa', so the consumer either never enables the gate (MFA becomes decorative) or enables it and must hand-roll token re-issuance with no library support. The library's own code acknowledges the gap (handlers.go:847: 'A first-class enforceable step-up primitive is planned') while SECURITY.md presents it as a current capability — a classic insecure-by-default footgun.

**Evidence**
```go
identity/handlers.go:306-313: `user, err := svc.Authenticate(r.Context(), cfg.tenant(r), cfg.provider, email, password)` ... `if err := issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, remember); err != nil` (full pair on password alone). identity/handlers.go:20: `type ClaimsBuilder[C any] func(*User) tokens.Claims[C]` (no ctx, no factor info). identity/identity.go:10-42: User has Email/Phone/Recovery fields but no MFA state. mfa/handlers.go:106-110: `if err := svc.VerifyTOTP(r.Context(), tenant, uid, r.PostForm.Get(cfg.codeField)); err != nil { cfg.failErr(w, r, err); return } cfg.ok(w, r)` (success = 204, no token). identity/handlers.go:847: 'A first-class enforceable step-up primitive is planned.'
```

**Recommended fix**
Ship the producing half of the documented model: (a) add an MFA-gated login option, e.g. identity.WithMFAGate(mfa.Service), under which LoginHandler checks IsEnrolled after password success and, for enrolled users, issues a short-lived INTERIM access token with AMR=[AMRPassword] and NO refresh token (or a refresh token bound to an 'mfa-pending' scope), instead of the full pair; (b) add an exported step-up completion handler, e.g. mfa.StepUpHandler[C](svc mfa.Service, issuer tokens.Issuer[C], claimsOf ...), that on VerifyTOTP/VerifyRecoveryCode success re-issues the full pair with AMR=[AMRPassword, AMROTP, AMRMFA] and sets the cookies — mirroring issuePairAndSetCookies; (c) extend ClaimsBuilder (or add a v2 builder) to receive context.Context and the verified factors so consumers can stamp AMR correctly; (d) until then, correct SECURITY.md to state that AMR production is entirely consumer-implemented and document the pre-MFA full-session hazard explicitly.

**Verifier reasoning (high-severity cross-check)**
The finding's individual factual observations check out, but its security conclusion ("high", insecure-by-default footgun, unwireable model) does not survive scrutiny — the risk is both documented as a consumer responsibility and neutralized by the fail-closed enforcement half.

Confirmed facts: identity/handlers.go:306-313 LoginHandler does issue a full access+refresh pair on password alone via issuePairAndSetCookies (lines 360-368); ClaimsBuilder (handlers.go:20) is `func(*User) tokens.Claims[C]` with no ctx/factor info; identity/identity.go User carries no MFA state; mfa/handlers.go VerifyHandler just calls cfg.ok() on success and mints nothing; no production code sets AMRMFA (repo-wide grep); identity/handlers.go:847 says "A first-class enforceable step-up primitive is planned."

Why refuted as a security issue:
1. AMR production being the application's job is the documented design, not a hidden gap. tokens/token.go:34-37: "AMR ... is set by the application when issuing the pair (e.g. after a second factor) and is enforced by the RequireAuth middleware via WithRequiredAMR. On refresh it is whatever the ClaimsProvider returns." docs/content/docs/sdk/mfa.md (lines 53-60) explicitly instructs the consumer after VerifyTOTP success: "Issue a new token with the AMR claim set to 'mfa'", and docs/sdk/tokens-and-http.md line 42 shows the consumer's code setting `AMR: []string{tokens.AMRPassword}` when issuing. So the "producing half is consumer-implemented" is stated in three places a consumer must read to integrate (the consumer must write the ClaimsBuilder anyway).
2. The documented enforcement model fails CLOSED, not open. tokens/middleware.go:184-205 stepUpSatisfied returns 403 for any token lacking the required AMR values, and since no library code ever spuriously stamps AMRMFA, a password-only attacker can NEVER pass WithRequiredAMR(AMRMFA). A consumer who follows SECURITY.md's documented model (enable the gate) gets an immediate, loud, total 403 at integration time — forcing them to wire AMR production — not a silently bypassable control. The finding's attack scenario requires the consumer to deploy MFA while enabling NO gate and assuming mfa.VerifyHandler (documented as "checks a ... code and replies 204") enforces something its doc never claims.
3. "Unwireable" is overstated: every primitive needed is exported — mfa.Service.VerifyTOTP, tokens.Issuer.IssueTokenPair, tokens.Cookies.SetAccess/SetRefresh, and the ctx-receiving ClaimsProvider that re-evaluates AMR on refresh. Only the turnkey convenience handlers lack the bridge, and that gap is openly acknowledged in code as planned work. Step-up composition being the application's job matches this SDK's pervasive, documented pattern (rate limiting, CSRF tokens, idempotency are likewise consumer-side per SECURITY.md and the PRD non-objectives).

Residual substance: SECURITY.md's "Step-up / AAL enforcement" bullet (lines 94-97) sits under "What egauth guarantees" and would read more honestly if it stated explicitly that AMR production is entirely consumer-implemented (as token.go and the SDK docs do), and a first-class step-up issuance handler would improve misuse-resistance. That is a documentation-clarity/feature gap (info-level defence-in-depth suggestion), not a vulnerability: no library control is bypassable, no insecure default grants access, and the failure mode of the documented model is denial, not bypass.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
