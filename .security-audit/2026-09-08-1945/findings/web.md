# WEB audit — XSS, CSRF, CORS, cookies, headers, clickjacking, open redirect

Worktree: `.security-audit/2026-09-08-1945/wt-web` (commit `6f16690`).
PoC suite (all localhost/httptest, run with `GOWORK=off`):
`.security-audit/2026-09-08-1945/wt-web/oauth/zz_webaudit_poc_test.go`
— `go test ./oauth/ -run TestWebAudit -v -count=1` → 5/5 PASS; full `./oauth/...` suite still green.

## Findings (2, both Low, both behavior-proven by PoC)

### WEB-01 — OAuth state cookie unsigned by default (Low, CVSS 3.4, CWE-565, medium confidence)
`oauth/state.go` (`packState`/`unpackState`) + `oauth/handlers.go` (`setStateCookie`,
`WithStateSigningKey`, `DefaultStateCookieName = "oauth_state"`).
Without a signing key the state cookie is an unauthenticated 5-field value
(state, PKCE verifier, OIDC nonce, provider, tenant); `unpackState` accepts any
well-formed self-minted value, so a cookie-write primitive (subdomain under a shared
parent `Domain`, or plaintext HTTP with `WithInsecureCookies`) lets an attacker forge
the state/provider/tenant binding the callback trusts. Default name is not `__Host-`
prefixed, widening the tossing precondition. PoC: forged cookie +
`?state=attacker-state&code=...` → 204 + auth cookies issued unsigned; same forgery
with `WithStateSigningKey` → 403 `invalid_state`.
Remediation: require a state signing key in production (or derive from tenant keystore),
emit a misuse event when unsigned, consider a `__Host-` default state-cookie name.

### WEB-02 — `redirect_uri` derived from Host/X-Forwarded-Proto when unconfigured (Low, CVSS 3.4, CWE-601, medium confidence)
`oauth/handlers.go` (`resolveRedirectURL`, `requestScheme`, `isValidHost`,
`WithRedirectURL`, `WithAllowedHosts`). With neither option set, `redirect_uri` is
`scheme://host/path` from the raw `Host` header (syntax-only validation) and the
spoofable `X-Forwarded-Proto` header, sent to the provider and reused at exchange.
Bounded to Low because exploitation also needs a provider that honors unregistered
`redirect_uri`s plus a Host-poisoning primitive. PoC: `Host: evil.example` +
`X-Forwarded-Proto: https` → 302 to provider with
`redirect_uri=https://evil.example/...`; with `WithAllowedHosts("app.example.com")`
→ 400. Remediation: require explicit `redirect_uri`/allowlist in production, don't
trust `X-Forwarded-Proto` without a declared trusted proxy, treat Host fallback as
dev-only.

## Checked and ruled out (with evidence)

- **Stored/reflected XSS — ruled out.** No HTML templating engine in the library;
  `internal/httputil.WriteJSON` sets `Content-Type: application/json` (Go escapes
  `<>&`); errors go through `http.Error` (plain text) or `Fail`/`RedirectOrStatus`
  (303 + `?error=` with server-chosen constant codes only — `q.Get("error")` /
  `q.Get("state")` in the OAuth callback are compared, never reflected). Example
  `GET /me` writes `userID=<uuid> role=<server string>` as text. No user input lands
  in an HTML sink.
- **CSRF state-changing GETs — ruled out as exploitable.** `tokens` Refresh/Logout,
  `identity` Register/Login, `otp` Issue/Verify, `mfa` guarded handlers, `passkey`
  ceremony + rename handlers are all POST-only (`Allow: POST` + 405 otherwise) AND
  fail-closed on origin (`httputil.OriginAllowed`: missing Origin/Referer → reject;
  HTTPS downgrade `https`→`http` rejected; `InsecureNoOriginCheck` is explicit
  opt-out). OAuth Begin/Callback are GET by protocol necessity and are protected by
  state comparison + PKCE + single-use state cookie + provider/tenant binding.
  `tokens` auto-refresh-on-GET only rotates the victim's own session and needs the
  `Lax` refresh cookie (top-level navigations only; `HttpOnly` so script can't read
  the result) — no cross-site attacker benefit.
- **CORS — ruled out.** The library emits no `Access-Control-Allow-Origin` headers
  anywhere (asserted on the OAuth Begin response in the PoC suite); there is no
  wildcard-with-credentials or reflected-Origin logic. Cross-origin API access is left
  to the host app's own middleware.
- **Auth/session cookie flags — ruled out (defaults secure).** `tokens.Cookies`:
  `HttpOnly` always set (not configurable), `Secure` on by default (`Insecure`
  opt-out), `SameSite=Lax` default, `__Host-` default names
  (`__Host-access_token`, `__Host-refresh_token`) with `Validate()` enforcing the
  `__Host-` contract (no Domain, `Path=/`, Secure). `sessions` defaults to
  `__Host-session_token` (host-locked, anti cookie-tossing fixation). Passkey
  ceremony cookie is HMAC-sealed (`cookieKey`, `MinCookieKeyLength` enforced,
  challenge expiry re-checked at Finish) with `HttpOnly`/`Secure`-by-default/Lax.
  OAuth state cookie is `HttpOnly`/`Secure`-by-default/Lax and host-only by default
  (asserted in PoC).
- **Open redirect via success/failure URLs — ruled out.** `successURL`/`failureURL`
  (`tokens`, `identity`, `otp`, `mfa`, `authflow`, `oauth`) are static operator
  configuration passed to `http.Redirect`/`RedirectOrStatus`; no handler reads a
  `next`/`returnTo`/redirect target from query, form, or headers. `WithErrorParam`
  only appends a constant `error` code.
- **Security headers / clickjacking — no finding (host-app responsibility).**
  Handlers emit no CSP/HSTS/X-Frame-Options/Referrer-Policy, but the library serves
  no framable interactive HTML (JSON, 204s, 303s, plain-text errors), so there is no
  vulnerable sink in-scope; header policy belongs to the host app. Noted as a
  hardening recommendation for consumers, not a library defect.
- **`examples/fullstack` permissive wiring — ruled out as a finding, noted for
  docs.** The demo uses `WithInsecureNoOriginCheck` on all routes,
  `WithInsecureCookies` for passkey, and a 32-byte zero `cookieKey`, each with an
  adjacent `In production…` comment. Demo-only and explicitly marked; flagged here
  so reviewers confirm the comments survive, not as a defect. Related library-side
  hardening note: `passkey.NewService` enforces key *length* only, so an all-zero
  32-byte key (as in the demo) is accepted — consider an all-zero/known-weak-key
  rejection plus keeping the demo's `crypto/rand` TODO prominent.

## Per-finding PoC mapping
- WEB-01 → `TestWebAuditUnsignedStateCookieForgedBindingAccepted` (fails-secure
  demonstration: currently 204, want 403) +
  `TestWebAuditSignedStateCookieRejectsForgery` (control: 403 with key) +
  `TestWebAuditStateCookieAttributes` (flags/host-only/no-CORS evidence).
- WEB-02 → `TestWebAuditBeginDerivesRedirectURIFromHostHeader` (evil Host reflected
  into `redirect_uri`) + `TestWebAuditBeginAllowedHostsBlocksEvilHost` (control:
  400 with allowlist).
