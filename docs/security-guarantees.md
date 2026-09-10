# Per-module security guarantees

This page summarises, module by module, what `egauth` guarantees and what the consumer remains
responsible for. It matches the code in this repository. [SECURITY.md](../SECURITY.md) is the
detailed model and the source of record for the mechanisms behind these statements; where a
module summary needs more detail, it points at the relevant part of SECURITY.md. Cross-cutting
controls are described once in SECURITY.md and referenced, not repeated, below.

Stability classes for these modules (which are proposed for the v1 frozen surface and which are
experimental) are listed in
[ADR 0001](adr/0001-v1-scope-and-stability-classes.md) and the README's Stability section.

## Cross-cutting controls

- **Same-origin gate.** The state-changing handlers of `identity`, `tokens`, `mfa`, `otp`,
  `sessions` and `passkey.RenameCredentialHandler` reject a browser POST whose `Origin`/`Referer`
  host is not the request host (or a `WithTrustedOrigins` entry) with `403 cross_site_blocked` by
  default. The opt-out is the explicit `WithInsecureNoOriginCheck`. See SECURITY.md,
  "CSRF on the form handlers".
- **Rate limiting.** The à-la-carte handlers are policy-free about throttling; the consumer wires
  `ratelimit`. The `webapp` preset applies a per-IP token bucket to every route it mounts unless
  explicitly disabled. See SECURITY.md, "Rate limiting on authentication endpoints".
- **Redaction.** Credential-bearing structs redact their secret fields on `fmt`/`slog`. This is a
  backstop, not a licence to log them. See SECURITY.md, "What the consumer must NOT do".
- **Bounded memory.** The in-memory stores and `ratelimit.TokenBucket` are capped by default and
  evict deterministically; `sessions/memory` refuses to evict live sessions. Callers that opt into
  an unbounded store must schedule `janitor`. See SECURITY.md, "In-memory stores are bounded by
  default".
- **No internal logging.** `egauth` never logs. `event.Sink` carries short machine `Reason`
  codes, never secrets or raw user input.
- **Context cancellation.** `context.Context` flows through every operation and is checked before
  deliberately expensive work (Argon2id, breach lookups, deletion cascades).

## identity

**Guarantees**

- Password verification is constant-time by construction (`crypto/subtle`), and the
  user-enumeration paths run a decoy Argon2id hash so unknown, non-password, locked and disabled
  accounts cost the same as a real verification.
- Brute-force lockout is on by default (5 failures / 15 minutes) and cannot be disabled by a
  zero/negative option; only the explicit `WithNoLockout` opts out.
- Password-reset, email-verification and magic-link tokens use a selector/verifier split: only
  the verifier's SHA-256 is stored, consumption is atomic and single-use, and a mismatch is
  reported exactly like an unknown token.
- A new password that fails policy or hashing is rejected *before* the token is consumed.
- `DeleteUser` invalidates outstanding password-reset/verification/magic-link tokens and blocks
  OAuth re-linking; soft-deleted accounts are re-checked on every consume path.
- Forced-password-change is set only by administrative provisioning and is carried onto every
  renewal of the session family; a flagged user is never locked out.
- A pre-auth body cap bounds password-hashing work.

**Consumer must**

- Rate-limit the `Request*`, login and verify endpoints (per IP and per account/destination).
- Supply `Mailer`/`SMSSender` implementations and deliver off the response path; `egauth` never
  sends anything.
- Register `AccountErasers` for the stores that hold credential state so account deletion and
  password changes revoke live sessions and token families promptly.
- Treat the documented account-existence disclosures (`429`, `409 email_taken`) as a deliberate
  trade-off and override the handlers where the threat model forbids them.

## tokens

**Guarantees**

- JWT verification pins the algorithm and selects the signer by `kid`; `"none"` and algorithm
  confusion are rejected.
- Signing keys are validated at construction: HMAC secrets below 32 bytes, all-zero/repeated-byte
  keys and published example keys are rejected (`InsecureAllowWeakKey` suppresses only the length
  gate).
- Refresh tokens are single-use, chained by family, and stored only as SHA-256 hashes. Replaying
  a consumed token within its validity revokes the whole family; concurrent benign re-use inside
  `ReuseGracePeriod` is rejected without revocation.
- Rotation carries the tenant, the forced-change flag and the original `auth_time` forward; the
  tenant is immutable across a family.
- Multi-tenant verification fails closed: with `Config.MultiTenant` set, the tenant-unaware
  `VerifyAccessToken` refuses and `VerifyAccessTokenForTenant` binds the signed `tenant_id` to
  the request tenant. The `RequireAuth` tenant resolver rejects an unresolved tenant with `401`.
- API keys (PAT and service tokens) are stored hashed, are constrained to the scopes passed at
  issuance, and the opt-in route gates fail closed on kind or scope mismatch.
- Auth cookies default to the host-locked `__Host-` names, and `Cookies.Validate` rejects a
  configuration that violates the prefix requirements.
- Credential-bearing types redact their secret fields on `fmt`/`slog`.

**Consumer must**

- Never log or serialize tokens; store access/refresh tokens in `HttpOnly`/`Secure` cookies and
  transmit only over TLS.
- Set `MultiTenant` and a tenant resolver for multi-tenant deployments.
- Keep signing material in a secret store; use `keystore` when tenants must not share keys.
- Implement `ClaimsProvider` to re-evaluate authority on every refresh, and use the rotation
  context when assurance must be per-session.
- Rate-limit refresh and API-key authentication where the threat model requires it.

## sessions

**Guarantees**

- Only the SHA-256 hash of the opaque session token is stored; the plaintext is returned once.
- An idle timeout plus a 30-day absolute lifetime are enforced by default; `WithNoMaxLifetime` is
  the explicit escape hatch.
- `Rotate` is a compare-and-set on the token hash, so two racing rotations cannot both succeed;
  it defeats session fixation after a privilege change.
- `RequireSession` applies the same-origin gate to cookie-authenticated unsafe methods and
  exempts non-ambient `Authorization: Bearer` requests.

**Consumer must**

- Serve cookies over TLS and rate-limit session creation/login.
- Apply `Touch` on activity if a sliding idle timeout is wanted; revoke sessions through the
  account/tenant revocation hooks on password changes and administrative actions.
- Understand that `WithCookieName` and `WithNoMaxLifetime` forfeit hosting/absolute-lifetime
  hardening.

## passwords

**Guarantees**

- Argon2id hashing with a random salt and a PHC-encoded hash; comparison is constant-time by
  construction and the account-existence paths invoke a decoy hash.
- Hash and compare reject input longer than `MaxPasswordLength` before the KDF runs.
- Stored cost parameters are bounds-checked before `argon2.IDKey` (lower bounds prevent panics,
  `MaxMemoryKiB` prevents an allocation-based denial of service).
- The passphrase policy is length-first (counted in Unicode code points) with no composition
  rules, plus an optional denylist and `BreachChecker` seam.

**Consumer must**

- Own the fail-open vs fail-closed decision for a breach-check outage, wrap the checker in a
  timeout, and alert when it errors.
- Re-hash stored passwords on cost upgrades (or accept the temporary enumeration-timing
  degradation documented in SECURITY.md).
- Treat password lengths/inputs as secrets and never log them.

## mfa

**Guarantees**

- RFC 6238 TOTP with a bounded skew window and replay protection: an accepted time-step can never
  be used twice, including the enrolment code.
- Digits are validated at construction (6–8) so no compliant authenticator receives an
  out-of-range code.
- Recovery codes are single-use and stored only as SHA-256 hashes.
- Failed attempts are counted atomically and locked after the configured budget, with a
  time-based decay or an explicit administrative unlock.

**Consumer must**

- Rate-limit TOTP and recovery-code verification (the module does not throttle).
- Encrypt the TOTP secret at rest at the storage layer: it must be recoverable for code
  computation and is intentionally not hashed.
- Keep the factor lockout configuration appropriate for the deployment and monitor the emitted
  events.

## otp

**Guarantees**

- Only the code's hash is stored; comparison is constant-time and consumption is a single-use
  atomic guarded delete keyed on the compared hash, so a superseded code can neither be accepted
  nor burn a freshly issued replacement.
- Attempt slots are reserved atomically before comparison, so concurrent wrong guesses cannot
  exceed the limit, and codes carry a TTL and a per-subject cooldown.
- Digits are validated at construction (6–10).

**Consumer must**

- Deliver the plaintext code over the intended channel and treat it as a credential.
- Rate-limit issuance per destination — especially SMS, where unthrottled use is a toll-fraud
  vector — and cap provider spend.

## passkey

**Guarantees**

- WebAuthn ceremonies are scoped to the configured Relying Party ID, and the ceremony
  `SessionData` travels in a short-lived HMAC-signed cookie that the client cannot tamper with.
- `Config.CookieKey` and `Config.ChallengeStore` are required (fail-fast at construction);
  challenges are single-use and server-side, and user verification defaults to required.
- A regressed signature counter is rejected as a possible cloned credential.
- `Config.AccountGate` lets the ceremony refuse suspended/deleted accounts.
- `RenameCredentialHandler` enforces the same-origin gate plus `Content-Type: application/json`.

**Consumer must**

- Supply a stable random `CookieKey`, a challenge store, an account gate where accounts can be
  disabled, and serve over HTTPS.
- Rate-limit ceremony attempts; the module deliberately does not throttle them.
- Route the login success callback through the `issuance` pipeline (or the `authflow` engine) so
  the account-state, tenant and forced-change invariants are applied.

## oauth

**Guarantees**

- Authorization-code flow with PKCE S256 by default; the CSRF `state`, PKCE verifier and OIDC
  nonce are carried in a host-locked `__Host-oauth_state` cookie that is HMAC-signed with a
  required key (`WithStateSigningKey`, minimum 32 bytes) and compared in constant time.
- The token exchange and userinfo fetches run server-side with `oauth.SafeHTTPClient` by default:
  the dial-time guard rejects loopback/link-local/private/unique-local/unspecified/multicast
  addresses after DNS resolution (rebinding-safe), does not follow redirects, and ignores
  environment proxies.
- Provider emails reported as unverified are refused unless `WithAllowUnverifiedEmail` is set,
  and an external identity is never auto-linked onto a pre-existing account with the same email.
- The client secret is only used server-side; the provider's access token never leaves the
  server.

**Consumer must**

- Configure a persistent random state-signing key and a pinned `WithRedirectURL` (or
  `WithAllowedHosts`) in production.
- Never log or mirror request cookies: the state cookie contains the PKCE verifier and nonce in
  plaintext even though it is signed.
- Rate-limit begin/callback and use the tenant resolver in dynamic multi-tenant deployments.
- Route the callback's issuance through the pipeline and gate unverified/disabled accounts
  through the supplied linker/account checks.

## oauth/providers

**Guarantees**

- Each constructor is a thin wrapper over `oauth.New`; the guarantees are those of the core
  `oauth` package.

**Consumer must**

- Review the provider's scopes, userinfo fields and email-verification semantics for your
  deployment; provider APIs and policies change independently of this library.

## keystore

**Guarantees**

- Signing material is resolved per tenant; a key presented under the wrong tenant fails closed
  with `ErrTenantMismatch`, and a tenant with no active key fails closed with `ErrNoActiveKey`.
- Stored secrets are sealed with the deployment KEK (envelope encryption); the KEK is required
  and validated at construction.
- Provision, renew, revoke and delete are explicit lifecycle operations with event emission; the
  empty tenant ID is a real single-tenant partition, and the static single-keyset mode remains
  the default elsewhere in the library.

**Consumer must**

- Hold the KEK in a secret store, provision tenants before they issue tokens, schedule renewal
  before `NotAfter`, and run the tenant delete/purge path when a tenant goes away.
- Register tenant erasers so deleting a tenant also clears the downstream module stores.

## issuance

**Guarantees**

- Every interactive issuance re-loads the account from authoritative state and rejects deleted,
  disabled or tenant-mismatched accounts; the forced-change flag is OR-ed with the caller's
  signal, the MFA gate is applied in one place, and one uniform issuance event is emitted.
- Constructing a pipeline with an MFA gate but without an authoritative state source fails
  loudly.

**Consumer must**

- Route every interactive login path (password, magic link, OAuth, passkey, OTP, step-up)
  through this pipeline or through the handlers that use it; do not mint interactive session
  pairs by calling the token issuer directly.

## webapp

**Guarantees**

- The preset mounts the identity and tokens handlers with `__Host-` cookies, the same-origin
  gate for both handler families, and a per-IP rate limit. It refuses to build with an empty
  `Config.TrustedOrigins` unless `Config.InsecureNoOriginCheck` is set, and the opt-out is
  applied consistently to both families.

**Consumer must**

- Supply the signing key from a secret store, list the trusted origins, replace the process-local
  limiter for multi-instance deployments, and serve over HTTPS.

## authflow

**Guarantees**

- The flow state is carried in an HMAC-SHA-256 signed, expiring token; the account validator is
  required whenever the MFA gate is configured; credentials are minted only through the
  `issuance` pipeline.

**Consumer must**

- Treat the engine as an experimental composition layer: keep its secret stable and random, and
  verify that the per-handler gates cover any custom login method added outside the engine.

## adapters

**Guarantees**

- `adapters/pgx` implements the concurrency-critical store methods atomically (single-use refresh
  consumption, strictly increasing TOTP step compare-and-set, atomic failed-attempt increment)
  and runs the core contract suites against a real PostgreSQL instance.
- `adapters/otel` records events as child spans with `egauth.*` attributes; emission is
  synchronous and does not spawn goroutines.

**Consumer must**

- Pin the adapter versions to the core version you deploy, run the `*storetest` contract suites
  against any custom adapter, and treat a custom non-atomic store as breaking the service-layer
  guarantees described in SECURITY.md.
