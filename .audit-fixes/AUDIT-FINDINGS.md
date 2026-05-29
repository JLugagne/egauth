# libauth completeness audit — findings (2026-05-29)

Source of truth for the gap work. Produced by a 17-agent workflow that read the real `.go`
source (not the PRD) and cross-checked against OWASP ASVS / NIST SP 800-63B, with an
adversarial critic pass. The actionable items are tracked as C1–C4 / I1–I19 / N1–N11 in
`01-critical.md`, `02-important.md`, `03-nice-to-have.md`. This file preserves the verdict and
the "what's already solid" inventory (the original workflow output lived only in /tmp).

## Verdict
Strong, security-literate **core**, but NOT a complete auth SDK as shipped, and not
safe-by-default on the most exposed path. Headline missing set at audit time:
1. Pre-auth hashing DoS — unbounded credential input reached argon2id (login/reset), no body
   cap. **[FIXED — C1]**
2. No rate limiting anywhere. **[FIXED — C2: pluggable seam + reference limiter]**
3. No authenticated change-password / change-email; no user-facing account deletion.
   **[C3 change-password FIXED; I5 change-email, I6 deletion remain]**
4. otp module shipped zero HTTP handlers. **[FIXED — I1]**
5. CSRF opt-in only on identity handlers; absent on token Refresh/Logout. **[FIXED — I2]**
6. No HIBP impl (I7), no email/SMS delivery impl (I8), no OIDC id_token/nonce (I9), no JWT key
   rotation (I10), no audit/event hooks (I11), no expiry cleanup (I16), ~no docs (C4).

## Architecture (mature, keep)
database/sql-style "import the modules you need" across 8 modules (identity, tokens, sessions,
passwords, mfa, otp, passkey, oauth), each with a Service interface + Store contract, memory +
pgx backends behind a shared cross-backend conformance suite (pgx against real postgres:16 via
testcontainers), functional-option DI, pervasive multi-tenancy, context everywhere, explicit
Actor principal. Builds clean, `go vet` passes.

## Already solid (verified in source — do NOT "fix")
- Argon2id (PHC, crypto/rand salt, constant-time compare); decoy-hashing + uniform responses
  for enumeration resistance; brute-force lockout enforced in the service.
- Refresh rotation within a family + reuse/theft detection (full-family revoke, grace window);
  JWT alg-pinned to HMAC (rejects none/alg-confusion); logout-everywhere.
- Flows wired end-to-end: register(+auto-login), login, password reset, email verification,
  magic-link, OAuth (Google/GitHub/Discord, PKCE-S256 + state, takeover-safe linking),
  MFA TOTP (RFC 6238, monotonic replay guard, recovery codes), passkey register/authenticate
  (HMAC-signed single-use challenge cookie), remember-me.
- Secret-at-rest: only SHA-256 hashes of refresh/API/session/OTP/recovery secrets persisted;
  plaintext returned once. Secure-by-default cookies. Accurate SECURITY.md.

## Known false-positive guards (from the critic) — keep in mind
- "test file exists" ≠ flow wired; "breach.go exists" ≠ HIBP implemented (it is interface-only).
- Passkey Finish ceremonies have NO end-to-end verification test (I14).
- Tenant enforcement is asymmetric across memory vs pgx and across read/write paths (I19).
