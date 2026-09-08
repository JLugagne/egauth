# Input validation & data exposure — audit notes (2026-09-08)

Commit audited: `6f16690` (worktree `wt-input-exposure`). Category: SSRF, XXE,
mass assignment, sensitive-data exposure, IDOR/tenant cross-access, body limits,
TTL/integer overflow, email/phone normalization, enumeration oracles.

## Findings (1)

### IE-01 — Login user-enumeration oracle: disabled/locked accounts answer 429 vs 401 by default
- Severity: Low (CVSS 3.7, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`), confidence: **high** (PoC-verified).
- Files: `identity/handlers.go` (`mapAuthError`), `identity/service.go` (`Authenticate`).
- The service layer equalizes *timing* with decoy hashing, but the default
  client-visible *status/message* still splits: `429 account_locked` for
  locked/disabled accounts vs `401 invalid_credentials` for unknown accounts.
  A disabled account is enumerable with a single request carrying any password.
- PoC: `TestAuditEnumeration_DisabledVsUnknown` in
  `wt-input-exposure/identity/zzauditpoc/zz_audit_poc_test.go`
  (observed `disabled -> 429 "account_locked"`, `unknown -> 401 "invalid_credentials"`).
- Remediation: default to uniform `401 invalid_credentials` (opt-out for
  distinct lockout signaling), or document the oracle and recommend
  `WithUniformAuthErrors` for public-signup / multi-tenant deployments.

## Checked and ruled out (with evidence)

- **SSRF — dynamic (untrusted tenant) path: HARDENED, no bypass found.**
  `adapters/pgx/oauth/store.go` `GetProvider` builds providers with
  `oauth.SafeHTTPClient()` for the token exchange AND the OIDC
  discovery/JWKS fetch, and `UpsertProvider` → `validateProviderURLs` →
  `ValidateExternalURL` (https-only, literal-internal-IP rejection) gates
  registration; JWKS override is deliberately omitted (discovery binds
  `jwks_uri` via exact issuer match). Redirects are disabled
  (`CheckRedirect` → `ErrUseLastResponse`) on both the safe and default
  clients. PoC-verified with localhost-only `httptest` servers:
  `TestAuditSSRF_ValidateExternalURL_BlocksInternalLiterals` (loopback,
  RFC1918, link-local/metadata 169.254.x, 0.0.0.0, IPv6 loopback/unspecified,
  non-https — all `ErrBlockedURL`),
  `TestAuditSSRF_SafeHTTPClient_BlocksLoopbackServer` (loopback fetch refused
  with `ErrBlockedAddress`, server never hit),
  `TestAuditSSRF_SafeHTTPClient_BlocksAbbreviatedLoopback` (`127.1` form fails
  closed at dial time), `TestAuditSSRF_NonCanonicalIPEncodings_FailClosed`
  (decimal `2130706433` / hex `0x7f.0.0.1` pass the coarse registration gate —
  by design, `net.ParseIP` only parses canonical literals — but the dial-time
  `Control` hook on the resolved IP fails the fetch closed; server never hit),
  `TestAuditSSRF_RedirectsDisabled`. File:
  `wt-input-exposure/oauth/zz_audit_ssrf_poc_test.go`.
- **SSRF — static path (`oauth.New` / `providers.OIDC` / `OIDCConfig` defaults
  use a plain 10s client): not a finding.** Source is integrator-supplied
  static config (trusted), not tenant input; discovered endpoints are still
  passed through `validateOIDCEndpointURL` (https gate) inside `oauth.New`.
  Docs direct untrusted-path callers to inject `SafeHTTPClient()`.
- **SSRF — HIBP breach client: not exposed.** `passwords/breach/hibp` fetches
  `baseURL + "/range/" + 5-hex-chars` where `baseURL` is integrator config and
  the path suffix is hex derived from SHA-1 — no tenant-controlled URL.
  Bounded reads (4 MiB cap, truncation → fail-closed error, never a silent
  false negative). No finding.
- **SSRF — `keystore/jwks.go`: no outbound fetch** (local public-key set
  exposure). No finding.
- **XXE: none.** No `encoding/xml` import or XML decoding anywhere in the
  module (grep-verified). Ruled out.
- **Mass assignment / over-binding: ruled out (PoC).** Handlers read explicit
  form fields (`r.PostForm.Get`) — never JSON-decode into `User`/`Identity`
  (both structs have no JSON tags at all). Tenant always comes from the
  server-side resolver/context, never the body. Passkey JSON bodies decode
  into narrow anonymous structs (`credentialId`/`nickname`); ceremony state
  (`ceremonyState.TenantID`) is HMAC-sealed server state, cross-checked in
  `loadSession`. PoC `TestAuditMassAssignment_PrivilegedFieldsIgnored` posts
  hostile `tenant_id/TenantID/roles/scopes/email_verified_at` fields and
  asserts the resolver tenant wins. Authflow flow-tokens are HMAC-signed
  (`authflow/token.go`, constant-time compare + expiry).
- **Sensitive data exposure: ruled out (PoC + grep).**
  `tokens/redact.go` (`TokenPair`, `APIKey`) and `tokens/jwt/redact.go`
  redact `String`/`GoString`/`LogValue`; JSON marshalling is intentionally
  unredacted (legitimate issuance path). PoC asserts secrets never render via
  fmt/slog (`tokens/zz_audit_redact_poc_test.go`). Event envelope
  (`event/event.go`) carries only machine `Reason` codes + IDs by contract;
  no error path interpolates tokens/passwords/hashes or emails (grep for
  `%v/%q` over secrets: no hits). Handlers reply with status codes / codes,
  never credential values. (`APIKey.String`/`LogValue` intentionally keep the
  non-secret prefix/hash for identification — documented, accepted.)
- **IDOR / tenant cross-access at data layer: enforced (PoC + code).**
  Memory stores check `TenantID` on every read/write/consume path
  (`identity/memory/store.go`, `sessions/memory/store.go`,
  `mfa/otp/passkey` memory stores → `ErrTenantMismatch`); pgx stores scope
  every query with `tenant_id = $n` (`adapters/pgx/identity/store.go`,
  incl. `ConsumeVerificationToken` selector+tenant+kind binding); storetest
  contracts assert cross-tenant rejection. Handlers derive tenant from
  resolver/actor context, never request body. PoC
  `TestAuditIDOR_VerificationTokenCrossTenant` (tenant-A token not consumable
  in tenant B; cross-tenant `FindUserByID` fails).
- **Request size/body limits: enforced (PoC).** 4 KiB default caps on
  identity/mfa/otp/authflow handlers via `http.MaxBytesReader` +
  `httputil.ParseLimitedForm` → 413 `request_too_large` before service/KDF;
  64 KiB on passkey ceremonies. PoC `TestAuditBodyLimit_OversizedRegisterRejected`
  asserts 413 with the service never invoked. (`WithMaxBodyBytes(≤0)` disables
  the cap — documented as requiring an upstream limit; operator opt-in.)
- **Integer overflow in TTL/expiry: ruled out.** All TTLs are operator-supplied
  `time.Duration` constants; no user-controlled integer → duration
  multiplication exists on any auth path.
- **Email/phone normalization bypasses: enforced (PoC).** `normalizeEmail`
  (RFC5322 parse, NFC, lowercase, IDN/punycode folding) and `normalizePhone`
  (E.164) applied at every entry point incl. defensive re-normalization of
  token metadata; already-normalized values used for delivery targets. PoC
  `TestAuditNormalization_CaseVariantDuplicate` (case/space variant → 
...[truncated 890 chars]