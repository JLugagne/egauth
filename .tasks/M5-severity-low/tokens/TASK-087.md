---
id: TASK-087
title: "Auth cookies do not use (or support enforcing) the __Host- prefix, enabling subdomain cookie tossing / refresh-token fixation"
description: "The default cookie names are plain 'access_token' / 'refresh_token' and nothing in Cookies validates or encourages the __Host- prefix. With host-only cookies (Domain empty), any attacker-controlled or XSS'd sibling subdomain (evil.example.com, a common reality in multi-app SaaS estates) can set a 'r…"
milestone: M5-severity-low
epic: tokens
status: in_progress
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `tokens` reproducing the flaw: The default cookie names are plain 'access_token' / 'refresh_token' and nothing in Cookies validates or encourages the __Host- prefix.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Default DefaultAccessCookieName/DefaultRefreshCookieName to '__Host-access_token' / '__Host-refresh_token' (the secure defaults — Secure on, Path '/', no Domain — already satisfy the prefix requirements), and have withDefaults()/SetAccess/SetRefresh fail fast or strip the prefix expectations when a…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./tokens/...
- [x] The audit attack scenario no longer succeeds: The default cookie names are plain 'access_token' / 'refresh_token' and nothing in Cookies validates or encourages the __Host- prefix.
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `tokens/cookies.go:10`  •  **Category:** session-fixation  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
The default cookie names are plain 'access_token' / 'refresh_token' and nothing in Cookies validates or encourages the __Host- prefix. With host-only cookies (Domain empty), any attacker-controlled or XSS'd sibling subdomain (evil.example.com, a common reality in multi-app SaaS estates) can set a 'refresh_token' cookie with Domain=example.com that the browser will send to the app host alongside — and, depending on path/age ordering, ahead of — the legitimate cookie. Cookies.Refresh uses r.Cookie(name), which returns the FIRST matching cookie, so the attacker-planted value can win. Consequences: (1) refresh-token fixation — the victim's auto-refresh/RefreshHandler rotates the ATTACKER's token family and writes the resulting access+refresh pair into the victim's browser, silently signing the victim into the attacker's account so subsequent victim activity (uploads, payment details, generated API keys) lands in an attacker-readable session; SameSite/HttpOnly do not defend against this, and identity.WithTrustedOrigins does not cover cookie planting. (2) Cheap DoS of header-based auth — extractAccessToken prefers the cookie over the Authorization header (middleware.go:162-166), so a planted garbage 'access_token' cookie makes every request 401 (non-expired-invalid tokens are rejected outright, never falling through to the valid Bearer header). The __Host- prefix is the standard browser-enforced fix (requires Secure, no Domain, Path=/ — all of which match DefaultCookies), and a library cookie layer is exactly where it belongs.

**Evidence**
```go
cookies.go:9-12: `const (\n\tDefaultAccessCookieName  = \"access_token\"\n\tDefaultRefreshCookieName = \"refresh_token\"\n)` — combined with cookies.go:168-175 Refresh() returning the first r.Cookie match and middleware.go:161-166 preferring the cookie over the Authorization header.
```

**Recommended fix**
Default DefaultAccessCookieName/DefaultRefreshCookieName to '__Host-access_token' / '__Host-refresh_token' (the secure defaults — Secure on, Path '/', no Domain — already satisfy the prefix requirements), and have withDefaults()/SetAccess/SetRefresh fail fast or strip the prefix expectations when a consumer sets Domain or a non-'/' path with a __Host- name. At minimum, document the subdomain cookie-tossing risk in SECURITY.md and make the prefix trivially opt-in.
