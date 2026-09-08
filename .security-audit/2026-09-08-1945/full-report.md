# Security audit — full report (run 2026-09-08-1945)

- Commit audited: `6f16690` (`chore: point adapters at egauth v0.10.0`, main)
- Project: `github.com/JLugagne/libauth` (module `github.com/JLugagne/egauth`) — Go 1.26.7 auth library (JWT/sessions, passwords/Argon2id, MFA/TOTP, OTP, passkeys/WebAuthn, OAuth/OIDC, keystore, Postgres via `adapters/pgx`, in-memory stores). See `00-profile.md`.
- Method: 6 worktree-isolated subagent audits (injection, auth-session, input-exposure, secrets, web, config-infra; no LLM agent — no LLM calls in scope) + read-only attack-chain analysis. Every finding has an executed PoC test unless marked otherwise. Full-score details for each auditor live in `findings/<category>.json` + `findings/<category>.md`; PoC copies in `poc-tests/`; chain narratives in `attack-chains.md`; machine-readable merged list in `merged-findings.json`.
- Counts: **8 findings — High 1, Medium 3, Low 4. Confidence: confirmed 6, likely 2, theoretical 0.** Raw corpus was 10; two pairs merged (same file/sink, same root cause):
  - `ENUM-01` = `AS-01` (auth-session) + `IE-01` (input-exposure): identical login 429-vs-401 oracle.
  - `STATE-01` = `AS-04` (auth-session) + `WEB-01` (web): identical unsigned/non-host-locked OAuth state cookie.
- Attack chains: **4 identified** (none raises severity above the max individual finding).

## High

### SECRETS-01 — Published valid-length HS256 signing keys in example and docs enable token forgery on copy-paste deployments
- ID: `SECRETS-01` · Category: secrets · CWE: CWE-798 · OWASP: A07:2021
- CVSS: **7.4** · Vector: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` · Confidence: **confirmed**
- Files: `examples/fullstack/main.go:125`, `docs/content/docs/sdk/tokens-and-http.md:31`
- Description: Both sites publish a key string that passes the 32-byte `MinSecretKeyLength` gate (52-byte example literal, exactly-32-byte docs literal). Any deployment that copy-pastes without replacing the key mints HS256 tokens with an attacker-known key; the attacker replays the published string into their own `jwt.New` instance and forges access tokens the victim verifies (proven cross-instance in PoC). Both sites carry replace-me comments and short keys panic — the gap is that a syntactically valid, publicly-known key is indistinguishable from a real one at construction.
- PoC: `poc-tests/secrets-keys_test.go` (`TestPOC_FullstackExampleSecretForgesTokens`, `TestPOC_DocsSecretForgesTokens`)
- Remediation: Replace both literals with a `crypto/rand` generation snippet plus secret-manager guidance; never publish a valid-length key. Add a denylist in `jwt.New`/`Validate` rejecting these exact published strings so pasted deployments fail fast; docs example should use an obviously-invalid placeholder or `os.Getenv` pattern.

## Medium

### SECRETS-02 — Attacker-known passkey ceremony-cookie HMAC keys in example and docs
- ID: `SECRETS-02` · Category: secrets · CWE: CWE-321 · OWASP: A07:2021
- CVSS: **5.9** · Vector: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` · Confidence: **confirmed**
- Files: `examples/fullstack/main.go:157` (`make([]byte, 32)` = 32 zero bytes, passes length gate), `docs/content/docs/sdk/mfa.md:97` (exactly-32-byte literal, passes gate)
- Description: Copy-paste deployments HMAC passkey ceremony cookies with an attacker-known key, enabling ceremony-state (challenge binding) forgery that the server trusts. Bounded: a real WebAuthn ceremony is still required, so this is ceremony-state forgery, not direct authentication.
- PoC: `poc-tests/secrets-keys_test.go` (`TestPOC_FullstackZeroCookieKeyAccepted`, `TestPOC_DocsCookieKeyAccepted`)
- Remediation: `crypto/rand` generation snippets; reject all-zero keys at `passkey.NewService` construction; denylist the published docs string.

### ENUM-01 — Login status oracle: locked/disabled accounts answer 429 vs 401 by default (account enumeration) [merged AS-01 + IE-01]
- ID: `ENUM-01` · Categories flagged: auth-session, input-exposure · CWE: CWE-204 · OWASP: A07:2021 Identification and Authentication Failures
- CVSS: **5.3** · Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` · Confidence: **confirmed**
- Files: `identity/handlers.go` (`mapAuthError`, `uniformAuthErrors=false` default), `identity/service.go`, `webapp/webapp.go` (preset never sets `WithUniformAuthErrors`)
- Description: Default `LoginHandler` maps `ErrAccountLocked`/`ErrAccountDisabled` to HTTP 429 `account_locked` while unknown identifiers and wrong passwords map to 401 `invalid_credentials`. A disabled account answers 429 on the very first attempt vs 401 for unknown (single-shot oracle); real accounts flip to 429 after the lockout threshold while unknown identifiers stay 401 forever. This undercuts the service layer's decoy-hash anti-enumeration work at the HTTP boundary and ships in the default webapp preset. Proven end-to-end at the handler layer by two independent PoCs.
- PoC: `poc-tests/auth-session-enum_test.go`, `poc-tests/input-exposure-enum_test.go`
- Remediation: Make uniform 401 `invalid_credentials` the default in `newHandlerConfig` (keep a distinct opt-in such as `WithVerboseLockoutStatus` for deployments accepting the oracle for UX), and/or set `WithUniformAuthErrors()` in the webapp preset.

### AS-02 — MFA step-up drops MustChangePassword by default (forced-password-change bypass)
- ID: `AS-02` · Category: auth-session · CWE: CWE-863 · OWASP: A01:2021
- CVSS: **4.3** · Vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` · Confidence: **confirmed**
- Files: `mfa/handlers.go` (`StepUpHandler`, nil `mustChangeResolve` default), `identity/handlers.go`, `tokens/context.go`, `tokens/jwt/issuer.go`
- Description: `StepUpHandler` re-issues the full access+refresh pair after a valid second factor but only propagates `Claims.MustChangePassword` when the host wires `WithMustChangeResolver`. The interim token from the login MFA gate carries the flag, so a must-change, MFA-enrolled user completing step-up on default wiring gets a fresh refresh family with `flag=false`; rotation replays `false` on every silent refresh and `WithPasswordChangeGate` stops diverting. With default unbounded refresh lifetime the evasion persists until the next interactive login. PoC completes a real recovery-code step-up and shows the flag lost (resolver-wired control preserves it).
- PoC: `poc-tests/auth-session-mustchange_test.go`
- Remediation: Default the must-change decision to the interim token's verified claims (`ClaimsFromContext` in `mfa/handlers.go StepUpHandler`) when `mustChangeResolve` is nil; keep `WithMustChangeResolver` as override; document that custom `StepUpClaimsBuilders` must re-check `identity.PasswordChangeRequired`.

## Low

### AS-03 — Password-reset / magic-link tokens minted for disabled accounts (issuance-time liveness gap)
- ID: `AS-03` · Category: auth-session · CWE: CWE-863 · OWASP: A01:2021
- CVSS: **3.7** · Vector: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` · Confidence: **confirmed**
- Files: `identity/service.go` (`RequestMagicLink`, `RequestPasswordReset`), `identity/memory/store.go`, `adapters/pgx/identity/store.go` (gates check only `DeletedAt`, never `DisabledAt`)
- Description: Single-use selector/verifier tokens are minted and returned for delivery for administratively disabled accounts, while unknown identifiers yield `("", nil, nil)`. Shipped handlers mask this with uniform 204, but Service-API consumers branching on the return value or mailer invocation get a liveness signal, and suspended users keep receiving credential emails. Consume-time gate (`consumeForLiveUser`) correctly rejects the token later — proven in PoC — so this is a liveness/issuance gap, not ATO.
- PoC: `poc-tests/auth-session-disabled-token_test.go`
- Remediation: Check `DisabledAt` at mint time mirroring `consumeForLiveUser` — return `("", nil, nil)` after a decoy token when the resolved user is disabled; optionally extend pgx/memory `CreateVerificationToken` guards with `AND disabled_at IS NULL` as defense-in-depth.

### STATE-01 — OAuth state cookie unsigned and not host-locked by default (login-CSRF craftability) [merged AS-04 + WEB-01]
- ID: `STATE-01` · Categories flagged: auth-session, web · CWE: CWE-352 (also CWE-565) · OWASP: A01:2021
- CVSS: **3.4** · Vector: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` · Confidence: **confirmed**
- Files: `oauth/state.go` (`packState`/`unpackState`), `oauth/handlers.go` (`setStateCookie`, default name `oauth_state`)
- Description: The state cookie carries CSRF state + PKCE verifier + nonce + provider + tenant with HMAC integrity only when the host sets `WithStateSigningKey`; otherwise any well-formed 5-field value is accepted without a `Begin` round trip. An attacker with a cookie-write primitive (sibling-subdomain tossing under a shared parent `Domain`, or plaintext HTTP with `WithInsecureCookies`) can forge the binding and drive the victim's browser through the callback into a session bound to the attacker's linked identity (login CSRF / session swap, not victim-ATO). The non-`__Host-` default name widens the tossing precondition. PoC: self-minted cookie reaches token exchange/issuance unsigned; identical forgery rejected 403 in signed mode.
- PoC: `poc-tests/auth-session-state_test.go`, `poc-tests/web-state-redirect_test.go`
- Remediation: Default the state cookie name to a `__Host-`-prefixed value with Secure/no-Domain/`Path=/` validation (mirroring `tokens.Cookies.Validate`); warn or fail when `WithStateSigningKey` is unset in non-test builds (startup `Validate()` on handler config); document that shared-Domain opt-outs accept the login-CSRF residual.

### WEB-02 — redirect_uri derived from raw Host + spoofable X-Forwarded-Proto when unconfigured
- ID: `WEB-02` · Category: web · CWE: CWE-601 · OWASP: A01:2021
- CVSS: **3.4** · Vector: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` · Confidence: **likely** (behavior proven; full exploit additionally needs a lax provider + Host-poisoning position)
- Files: `oauth/handlers.go` (`resolveRedirectURL`, `requestScheme`, `isValidHost`)
- Description: With neither `WithRedirectURL` nor `WithAllowedHosts` set, `redirect_uri` is built as `requestScheme(r)+"://"+r.Host+path` where the scheme trusts `X-Forwarded-Proto` and the host is syntax-only validated, then sent to the provider and reused at the code exchange. Strict providers (exact `redirect_uri` registration — the common case) kill the leg outright, bounding severity to Low. PoC: `Host: evil.example` + `X-Forwarded-Proto: https` emits a 302 with `redirect_uri=https://evil.example/...`; `WithAllowedHosts` control rejects 400.
- PoC: `poc-tests/web-state-redirect_test.go`
- Remediation: Require explicit `WithRedirectURL`/`WithAllowedHosts` in production (misuse event on Host fallback, dev-only fallback); never trust `X-Forwarded-Proto` without a declared trusted proxy.

### CFG-01 — govulncheck does not cover the adapters/otel module (process finding)
- ID: `CFG-01` · Category: config-infra · CWE: CWE-1104 · OWASP: A06:2021
- CVSS: **3.1** · Vector: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` · Confidence: **likely** (static workflow proof; no PoC applicable to a coverage gap)
- Files: `.github/workflows/ci.yml` (job `govulncheck`), `adapters/otel/go.mod`
- Description: The `govulncheck` job scans core + `adapters/pgx`, but the third module `adapters/otel` (real `otel* v1.46.0` deps) only gets `go vet` + `go test`. A future OTel SDK CVE would not fail CI. No current CVE is chained here — latent detection gap, not an active step.
- PoC: none (pure config coverage gap)
- Remediation: Add a govulncheck step for `adapters/otel` mirroring the pgx pattern, or a per-module matrix over the three module roots.

## Attack chains (full section — see also attack-chains.md)

4 chains identified; none raises severity above the max individual finding:

1. **Enumeration → forced-password-change evasion** (ENUM-01 → AS-02): oracle output focuses credential-stuffing on validated live accounts; a compromised must-change+MFA account that completes default step-up keeps a persistent family dodging `WithPasswordChangeGate`. Stays Medium — still needs password + second factor.
2. **Disabled-account oracle → reset/magic-link liveness corroboration + unwanted delivery** (ENUM-01 + AS-03): second liveness channel via Service-API return/mailer invocation; suspended users get credential emails (phishing-ready pretext). Stays Medium, effective impact Low — consume-time gate terminates the chain (no ATO).
3. **Unsigned state + Host-derived redirect_uri → login-CSRF / code diversion on lax providers** (STATE-01 + WEB-02): forged binding plus poisoned `redirect_uri`; victim ends up in the attacker's-identity session (swap, not victim-ATO). Stays Low — needs cookie-write or Host control + lax provider + lure.
4. **Copy-paste demo bundle → total forgery on pasted deployments** (SECRETS-01 + SECRETS-02 + demo wiring): published JWT key gives arbitrary account/tenant impersonation; known ceremony key adds ceremony-state forgery. Stays High (7.4 ceiling already total) — scoped to copy-paste deployments; library defaults are fail-closed.

Explicitly rejected: AS-03+AS-02 (disabled principals can't step up), AS-03+SECRETS-01 (independent), CFG-01+anything (no current CVE), anything+injection (empty corpus breaks classic escalation), WEB-02 standalone open-redirect (static success/failure URLs, no `next` param).

## Excluded / considered but not findings

- **Injection (agent: 0 findings, 5 negative PoCs, suites green):** pgx stores use `$n` bind args (payload `' OR '1'='1` stays in args, never SQL text); migration-filename breakout proven impossible via quote-doubling; JWT rejects alg=none/wrong-key/unknown-kid/truncated/10 MB blobs; 16 hostile PHC strings (zero params, 4 TiB, overflow) rejected fast without panic; OAuth state separator/CRLF/tamper rejected; passkey CBOR behind 64 KiB caps; no LDAP/XPath/template/shell/zip/msgp sinks; headers static; `internal/doctest` exec/file use is dev-only. Negative PoC sample kept at `poc-tests/injection-state-negative_test.go`.
- **SSRF (input-exposure, ruled out):** dynamic BYO-SSO path uses `SafeHTTPClient` everywhere (discovery/JWKS/token exchange), registration allowlist, no redirects; loopback dial blocked (`ErrBlockedAddress`, server never hit), abbreviated/decimal/hex IP forms fail closed. Static-path plain clients are trusted integrator config. HIBP client: integrator URL, hex-only suffix, capped fail-closed reads. PoC: `poc-tests/input-exposure-ssrf_test.go`.
- **XXE:** no XML parsing in the module. **Mass assignment:** explicit form fields, no JSON tags on `User`/`Identity`, HMAC-sealed ceremony state; hostile `tenant_id`/`roles`/`scopes` ignored. **Sensitive exposure:** `TokenPair`/`APIKey` never render via fmt/slog (`poc-tests/input-exposure-redact_test.go`); secret-free events/errors.
- **Auth/session internals (ruled out):** alg-confusion/none/kid/jku, exp/nbf/aud/iss; refresh reuse-grace yields no tokens on replay; no concurrent-rotation double-use; no session fixation (fresh families, CAS rotate/bind, `__Host-` cookies); logout revokes family; MFA/OTP attempt limits + single-use atomicity hold; TOTP secrets KEK-sealed; WebAuthn replay/UV/clone handled; OAuth PKCE/tenant/issuer/email-verified/linking guards hold; tenant isolation in stores/JWT keyfunc/middleware; Argon2id floors; lockout exactly-once atomicity; API-key entropy/storage/revocation.
- **Web (ruled out):** no XSS sinks (no HTML templating; JSON content-type; constant error codes); CSRF-safe (mutation handlers POST-only + origin checks; OAuth GETs state/PKCE-bound); no CORS headers emitted; auth cookie flags secure by default; no open redirect via success/failure URLs (static config).
- **Secrets (ruled out, 10 items):** KEK exact-32B/`crypto/rand` nonces; JWKS never emits `k`; git history clean; CI holds no embedded secrets (ephemeral `testpass` service container only); test-fixture keys confined to `_test.go`; OAuth `client_secret` KEK-enveloped; `Insecure*` opt-outs explicit/fail-closed; docs TOTP snippet is standard self-enrollment display.
- **Config/infra (ruled out):** workflows least-privilege (`contents: read`), SHA-pinned actions, no `pull_request_target`/exfil; no Dockerfiles/IaC; no pprof/`/debug`/metrics endpoints (`health/` is a `Pinger` interface; `NewWebApp` mounts 4 auth routes); no insecure defaults or default tenants/keys.
- **Out of scope per audit rules (not findings):** rate-limit gaps, missing audit logs, `.md`-only issues (except copy-pasteable key literals, filed), ReDoS, UUID-unguessability, URL logging, physical-access models, LLM prompt handling (no LLM in scope).
