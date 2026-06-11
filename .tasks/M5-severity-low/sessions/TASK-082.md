---
id: TASK-082
title: "Hardcoded 'session_token' cookie name forecloses __Host- prefix hardening against cookie-tossing fixation"
description: "RequireSession reads the session from a hardcoded cookie named 'session_token' with no configuration option. The library never sets this cookie itself, so the only defense against subdomain/sibling-host cookie tossing (an attacker on evil.example.com sets Domain=.example.com session_token containing…"
milestone: M5-severity-low
epic: sessions
status: done
priority: low
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `sessions` reproducing the flaw: RequireSession reads the session from a hardcoded cookie named 'session_token' with no configuration option.
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Add a WithCookieName HandlerOption (mirroring WithTenantResolver) so consumers can use __Host-session_token, and document the __Host- prefix as the recommended deployment in the package doc / SECURITY.md alongside the existing HttpOnly/Secure guidance.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./sessions/...
- [x] The audit attack scenario no longer succeeds: RequireSession reads the session from a hardcoded cookie named 'session_token' with no configuration option.
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `sessions/middleware.go:26`  •  **Category:** session-fixation  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
RequireSession reads the session from a hardcoded cookie named 'session_token' with no configuration option. The library never sets this cookie itself, so the only defense against subdomain/sibling-host cookie tossing (an attacker on evil.example.com sets Domain=.example.com session_token containing the attacker's OWN valid token, so the victim transparently operates inside the attacker's session and their submitted data — uploads, payment details — lands in the attacker's account; token rotation does not help because the planted token is legitimately valid) is the __Host- cookie name prefix, which browsers enforce as host-locked/Secure/no-Domain. Because the name is hardcoded without the prefix, a consumer cannot adopt __Host-session_token without abandoning the middleware. The planted attacker cookie also shadows a valid Authorization: Bearer header, since the cookie is consulted first (lines 26-29) and the header only when the cookie is absent.

**Evidence**
```go
cookie, err := r.Cookie("session_token")
		if err == nil {
			token = cookie.Value
		}
```

**Recommended fix**
Add a WithCookieName HandlerOption (mirroring WithTenantResolver) so consumers can use __Host-session_token, and document the __Host- prefix as the recommended deployment in the package doc / SECURITY.md alongside the existing HttpOnly/Secure guidance.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
