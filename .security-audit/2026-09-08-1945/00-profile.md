# Project profile — security audit run 2026-09-08-1945

## Identity
- Repo: `github.com/JLugagne/libauth` (module `github.com/JLugagne/egauth`, Go 1.26.7)
- Type: **Go authentication library / toolkit** (not a standalone deployable app). Composable auth modules consumed by host apps.
- Commit audited: `6f16690 chore: point adapters at egauth v0.10.0` (main, 2026-09-08)

## Languages / frameworks
- Language: Go only. No JS/TS, no Python, no Dockerfiles, no Terraform/K8s manifests.
- HTTP: stdlib `net/http` handlers + middleware (no Gin/Echo/Chi as dependency — check `webapp`, `internal/httputil`).
- Crypto: `golang.org/x/crypto` (Argon2id, bcrypt compat?), `github.com/golang-jwt/jwt/v5`, `github.com/go-webauthn/webauthn` (passkey), `github.com/fxamacker/cbor/v2`, `github.com/google/uuid`.
- DB: Postgres via `adapters/pgx` (jackc/pgx/v5) + in-memory stores per module; SQL migrations under `adapters/pgx/*/migrations`.
- No subprocess/shell execution, no HTML templating engine, no LLM calls, no CLI entry point found (library + `examples/fullstack` demo).

## Entry points (attacker-reachable in host apps)
- HTTP handlers/middleware: `identity` (register/login/recovery/verification/change-email/phone), `mfa`/`otp` (TOTP, recovery codes, OTP codes), `passkey` (WebAuthn ceremonies), `oauth` (authorization-code + PKCE, OIDC discovery, callback), `sessions` (middleware, rotation), `tokens` (JWT mint/verify, refresh rotation, API keys, cookies, revoke, RequireAuth gate), `webapp` (route wiring, CSRF), `authflow` (unified state machine), `health`, `revocation` bus.
- Token parsers: JWT (`tokens/jwt`), Argon2 PHC strings (`passwords/argon2`), OAuth `state` cookie (`oauth/state.go`), WebAuthn CBOR/base64 (`passkey`) — all fuzzed in CI.
- No standalone web server `main()` in core module (library); `examples/fullstack` is demo only.

## Auth model
- Principals: `Actor{UserID, TenantID, Kind, KeyID, Scopes, Roles, Groups}` (`actor.go`), context-propagated.
- Credentials: passwords (Argon2id, breach check via HIBP k-anonymity + offline), TOTP/MFA, OTP, passkeys/WebAuthn, OAuth/OIDC external IdPs, JWT access + opaque single-use refresh rotation with family theft detection, API keys (SHA-256 stored), sessions (hashed tokens), email/phone verification + password-reset selector/verifier tokens.
- Defences claimed in SECURITY.md: SHA-256 hash-at-rest, constant-time compares + decoy-hash anti-enumeration, lockout on by default, refresh reuse grace window, selector/verifier reset tokens, PKCE+S256 + single-use state cookie, tenant isolation.

## External systems / sinks
- **DB**: Postgres (pgx adapter) + memory stores. SQL injection scope: check pgx stores for string-concat SQL.
- **Outbound HTTP**: OIDC discovery (`.well-known/openid-configuration`), token exchange, userinfo, JWKS fetch (`keystore/jwks.go`), HIBP breach API (`passwords/breach/hibp`). SSRF scope: `oauth/ssrf.go`, `oauth/oidc_discovery.go`, `oidc.go`, allowlists — verify.
- **Cookies/headers**: session/JWT/state cookies (`tokens/cookies.go`, `oauth/state.go`, `passkey/cookiekey.go`), CSRF (`webapp`), CORS/security headers (`internal/httputil`).
- **Filesystem**: keystore/KEK, migration SQL reads — low risk, no user-controlled paths expected.
- **No shell, no SSTI, no XXE, no LLM, no queue workers.**

## CI/CD (SCA coverage)
- `.github/workflows/ci.yml`: govulncheck (core + adapters/pgx), golangci-lint, fuzz short pass, coverage, docs drift. Top-level `permissions: contents: read`. Actions pinned by SHA. No OSV/Trivy/Dependabot visible — check.
- `.github/workflows/pages.yml`: needs review for permissions/scope.
- No Dockerfile, no IaC to audit.

## Audit scoping (category → applies?)
- Injection (SQL/NoSQL, deserialization, path traversal): YES — pgx SQL, JWT/CBOR/PHC/state parsers.
- Auth & session: YES — core of this library, highest priority.
- Input validation & data exposure (SSRF, mass assignment, sensitive exposure, IDOR): YES — OIDC/JWKS/HIBP outbound HTTP, tenant isolation, error/log leakage.
- Secrets (hardcoded creds, git history, CI): YES.
- Web-specific (XSS, CSRF, CORS, cookies, headers, clickjacking): YES — handlers/cookies/CSRF/CORS.
- Config & infra surface (CI permissions, unpinned actions, debug endpoints, default creds): YES — limited to CI workflows + health/debug endpoints (no Docker/IaC).
- AI/LLM-specific: NO — project makes no LLM calls. Not spawned.
- Dependency/SCA re-scan: NO — covered by govulncheck in CI; only flag if CI scanning is missing/misconfigured/non-gating.
