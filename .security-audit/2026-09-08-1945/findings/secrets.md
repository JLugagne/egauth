# SECRETS audit — 2026-09-08 (commit 6f16690)

Worktree: `.security-audit/2026-09-08-1945/wt-secrets` (all PoC/tests run there).
PoC file: `wt-secrets/secrets_audit_poc_test.go` — 4/4 PASS (`GOWORK=off go test -run TestPOC_ -v .`).

## Method

1. Trufflehog-style regex sweep (`aws_|AKIA|sk-|ghp_|gho_|xox[bpas]-|-----BEGIN.*PRIVATE KEY|password\s*[:=]|client_secret|secret\s*[:=]`) across the worktree (excluding go.sum/.git).
2. Targeted review of KEK (`keystore/kek.go`), JWKS (`keystore/jwks.go`), cookie/HMAC keys (`passkey/cookiekey.go`, `service.go`), JWT key validation (`tokens/jwt/issuer.go`, `weak_key_test.go`), redaction (`tokens/redact.go`, `tokens/jwt/redact.go`), CI workflows, `examples/fullstack`, docs snippets.
3. Git-history spot check: `git log -p --all` piped through secret regexes.
4. PoC tests proving each finding is attacker-readable AND usable (cross-instance token forgery / constructor acceptance).

## Findings (2)

### SECRETS-01 — Published valid-length HS256 signing keys (example + docs) — CVSS 7.4 (High), confidence HIGH
- `examples/fullstack/main.go:125` — `SecretKey: "replace-with-a-32-byte-minimum-secret-in-production!"` (52 bytes).
- `docs/content/docs/sdk/tokens-and-http.md:31` — `SecretKey: "super-secret-32-byte-key-here!!!"` (exactly 32 bytes).
- Both pass the `MinSecretKeyLength` (32) gate, so a copy-paste deployment boots fine and mints tokens with a publicly-known key. PoC: attacker instance built from the published string alone forges access tokens the victim instance verifies (`TestPOC_FullstackExampleSecretForgesTokens`, `TestPOC_DocsSecretForgesTokens`).
- Remediation: generation snippet + secret-manager guidance instead of valid-length literals; denylist the published strings in `jwt.New`/`Validate` so pasted deployments fail fast.

### SECRETS-02 — Attacker-known passkey ceremony-cookie HMAC keys (example + docs) — CVSS 5.9 (Medium), confidence HIGH
- `examples/fullstack/main.go:157` — `cookieKey := make([]byte, 32)` = 32 zero bytes; passes `MinCookieKeyLength` (32), known to every repo reader.
- `docs/content/docs/sdk/mfa.md:97` — `[]byte("very-secure-32-byte-secret-key!!")`, exactly 32 bytes, passes the gate.
- Copy-paste deployments HMAC ceremony cookies with an attacker-known key → ceremony-state (challenge binding) forgery. PoC: both keys accepted by `passkey.NewService` (`TestPOC_FullstackZeroCookieKeyAccepted`, `TestPOC_DocsCookieKeyAccepted`). Impact bounded: a real WebAuthn ceremony is still required, so this is ceremony-state forgery, not direct auth bypass.
- Remediation: `crypto/rand` generation snippets; reject all-zero keys in `NewService`; denylist the docs literal.

## Checked and ruled OUT

- **KEK handling** (`keystore/kek.go`): `NewKEK` enforces exactly 32 bytes (AES-256), `NewManager` rejects nil KEK, nonces from `crypto/rand`, no plaintext/no-encryption mode. No default KEK anywhere. NOT a finding.
- **JWKS endpoint** (`keystore/jwks.go`): HS256 entries are metadata-only (`kty:oct`, kid/alg/use, NEVER the `k` secret — stated in type doc and enforced in `Manager.JWKS`). Asymmetric entries publish public params only. NOT a finding.
- **Git history**: `git log -p --all` + secret-regex sweep found no key material (single regex hit was minified JS `logger` noise). No `BEGIN PRIVATE KEY`, no `AKIA/ghp_/sk-live` tokens. NOT a finding.
- **CI workflows** (`.github/workflows/ci.yml`, `pages.yml`): no embedded secrets; `POSTGRES_PASSWORD: testpass` + `TEST_DATABASE_URL` are an ephemeral GitHub-service container for the integration job only. Actions SHA-pinned, `contents: read`. NOT a finding.
- **Test-fixture keys** (`passkey/handlers_test.go` `testCookieKey`, `tokens/jwt/*_test.go` legacy secrets, `keystore/keystoretest` `testKEK = bytes.Repeat("k")`, `mfa/storetest` `"SHARED-SECRET"`): confined to `_test.go`/conformance suites, never shipped on prod paths. NOT findings.
- **Secret logging/redaction**: `tokens.TokenPair`/`APIKey`, `jwt.SigningKey`/`Config`/`Service` all redact on `String`/`GoString`/`slog.LogValue`; JSON marshalling intentionally unredacted for the legitimate issuance path (documented in `tokens/redact.go`). `SECURITY.md` directs loading keys from a secret store and never logging them. NOT a finding.
- **OAuth `client_secret` storage**: pgx store envelope-encrypts with mandatory KEK (`NewStore` panics on nil KEK) and only sends the secret server-side to the token endpoint, with the SEC-OAU-07 redirect-leak guard. NOT a finding.
- **`Insecure*` opt-outs** (`InsecureAllowWeakKey`, `InsecureNoChallengeStore`, `InsecureNoOriginCheck`, `WithInsecureCookies` in the fullstack demo): explicit, greppable, fail-closed defaults; the demo's insecure cookie/origin choices are local-demo ergonomics with production comments. Out of secrets scope (no hardcoded key material). NOT findings.
- **Docs TOTP snippet** (`docs/.../mfa.md` printing `enrollment.URI` with `secret=`): the enrolling user's own secret shown back to them in the standard otpauth enrollment flow. NOT a finding.
- **`.md`-only issues**: none beyond the two docs key literals already filed as SECRETS-01/02 (both are copy-pasteable code, in scope per brief).

## Counts

- Findings: 2 (confidence high: 2, medium: 0, low/theoretical: 0).
- PoC paths (all in worktree, all passing): `secrets_audit_poc_test.go` → `TestPOC_FullstackExampleSecretForgesTokens`, `TestPOC_DocsSecretForgesTokens`, `TestPOC_DocsCookieKeyAccepted`, `TestPOC_FullstackZeroCookieKeyAccepted`.
- Ruled out: 10 items (KEK, JWKS, git history, CI, test fixtures, redaction/logging, OAuth client_secret, Insecure opt-outs, TOTP docs snippet, other .md).
