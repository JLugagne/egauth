# Security model — handling secrets and passwords

This document describes how `egauth` handles sensitive values (passwords, opaque
tokens, hashes) and what the **consumer** of the library is responsible for.

## What egauth guarantees

- **Hashing at rest.** Opaque tokens (refresh tokens, API keys, session tokens) are
  never persisted in clear text. Only their SHA-256 hash is stored (`tokens.HashToken`),
  so a database leak does not expose usable credentials. Lookups are performed on the
  hash, which is what makes a plain index/equality lookup safe for high-entropy tokens.
- **Constant-time password comparison.** Password verification uses
  `crypto/subtle.ConstantTimeCompare` (`passwords/argon2`), so a wrong password cannot
  be recovered byte-by-byte through timing.
- **Constant-time authentication paths.** The password authentication path applies an
  equivalent hashing cost even when the user, identity, or password hash is absent, so
  account existence cannot be inferred from response timing (user-enumeration defence).
- **Brute-force lockout (identity).** After `DefaultLockThreshold` (5) consecutive
  password failures the identity is locked for `DefaultLockDuration` (15 min). Lockout is
  **on by default** and hardened against misconfiguration: `identity.WithLockout(0, 0)` does
  NOT disable it — a non-positive argument falls back to the safe default, matching the
  convention of `mfa.WithMaxAttempts`. To explicitly opt out (e.g. when an external
  WAF or rate-limiter enforces the budget), use `identity.WithNoLockout()`, which makes the
  intent auditable and greppable.
- **Single-use refresh-token rotation with theft detection.** Refresh tokens are
  single-use and chained by `FamilyID`. Each rotation atomically consumes the old token
  and mints a new one in the same family; the access-token lifetime is always
  issuer-controlled on rotation, and the family's tenant is immutable across rotations.
  Replaying a consumed token **that is still within its validity** revokes the **entire
  family** (forcing re-authentication), and a revocation that fails is surfaced rather than
  silently swallowed. (Once a token has expired it can no longer be rotated and may have been
  reaped by the `DeleteExpired` GC, so a *post-expiry* replay reports not-found instead of
  revoking the family — the theft tripwire spans a token's validity, by which point an expired
  token grants no access regardless.) To avoid logging
  users out on ordinary request concurrency (parallel tabs, prefetch, concurrent
  sub-resource loads racing the same cookie), a replay within `ReuseGracePeriod`
  (default 10s) of consumption is treated as benign and rejected *without* revoking the
  family — set a negative `ReuseGracePeriod` for strict mode where any replay revokes.
- **Single-use verification tokens (selector/verifier).** Password-reset and email-verification
  tokens follow a selector/verifier scheme: a 128-bit random `selector` indexes the row, and only
  the SHA-256 of the secret `verifier` half is stored. Consumption compares the verifier in
  constant time, is atomic and single-use (a guarded delete), reports a verifier mismatch
  identically to an unknown token, and mints/consumes only for a **live, same-tenant** user
  (enforced identically by the memory and Postgres stores). A weak new password or a hashing
  failure is rejected *before* the token is consumed, so it is never burned for nothing.
- **OAuth is CSRF- and phishing-hardened.** The authorization-code flow uses **PKCE (S256)** and a
  single-use `state` value bound in an `HttpOnly`/`Secure`/`SameSite=Lax` cookie (compared in
  constant time on callback). By default the callback **refuses to provision or sign in from a
  provider email the provider reports as unverified** (`WithAllowUnverifiedEmail` opts out), and it
  never auto-links an external identity onto a pre-existing account that merely shares the email —
  both are account-squatting / takeover defences. The token exchange runs server-side with the
  client secret; the provider access token never leaves the exchange.
- **NIST-aligned passphrases.** `passwords/policy.PassphrasePolicy` enforces length (counted in
  Unicode code points) with NO composition rules and screens secrets against a denylist plus an
  optional pluggable `passwords.BreachChecker` (e.g. a HIBP k-anonymity client — egauth ships
  the interface only, never the network call).
- **TOTP & recovery codes.** The `mfa` module implements RFC 6238 TOTP (authenticator apps only,
  no SMS) with a ±skew window and **replay protection** via a monotonic last-used time-step (a
  code, including the enrolling one, cannot be reused). Recovery codes are single-use and stored
  only as SHA-256 hashes. `NewService` panics at construction if `WithDigits` is called with a
  value outside the RFC 6238 range **6–8** — values below 6 produce a trivially guessable code
  space and values above 8 cause uint32 truncation in the HOTP truncation step, neither of which
  will be accepted by any compliant authenticator app. **Caveat:** a TOTP shared secret must be stored in recoverable form (the
  server recomputes codes from it), so — unlike passwords/opaque tokens — it is NOT hashed. Per the
  PRD's "no at-rest encryption in v1" non-objective, the `mfa` store persists the secret in clear;
  deployments that need defense against a database leak should encrypt the `secret` column at the
  storage/DB layer (envelope encryption).
  **Failed-attempt lockout is time-bound.** Once `FailedAttempts` exceeds `MaxAttempts` (default 5)
  the factor is locked and `ConfirmTOTP`, `VerifyTOTP`, and `VerifyRecoveryCode` all return
  `ErrTooManyAttempts`. When `ConfirmTOTP` exhausts the budget the pending enrollment is deleted
  so an attacker cannot continue guessing; the user must restart from `EnrollTOTP`.
  The lockout automatically resets after `LockoutDuration` (default 15 min, measured from the last
  failed attempt), giving legitimate users a self-service recovery path without operator action.
  Operators can also unblock a user immediately via `Service.UnlockMFA(ctx, tenantID, userID)`,
  which wraps `Store.ResetTOTPAttempts`. The window is configurable via
  `mfa.WithLockoutDuration(d)`; passing `0` makes the lockout permanent until `UnlockMFA` is
  called or the factor is disabled.
- **Passkeys (WebAuthn).** The `passkey` module wraps go-webauthn. Credentials are scoped to the
  configured Relying Party ID; the ceremony challenge and user-verification requirement
  (`SessionData`) are carried between Begin and Finish in a short-lived, **HMAC-signed**
  `HttpOnly`/`Secure` cookie so the client cannot tamper with the challenge or downgrade user
  verification; the cookie is single-use and the ceremony has a server-enforced expiry. A
  regressed signature counter (possible cloned authenticator) is rejected (`ErrCredentialCloned`).
  The module is **secure by default**: `passkey.NewService` fails fast on a misconfigured
  passwordless/step-up setup rather than degrading silently (mirroring `jwt.New`). See the
  hardening checklist below.

  **Passwordless / step-up hardening checklist** — required configuration for a secure
  deployment (each item is enforced at construction unless noted):
  - **`Config.CookieKey` (required).** A stable, random secret of at least
    `passkey.MinCookieKeyLength` (32) bytes used to HMAC-authenticate the ceremony cookie.
    `NewService` returns `ErrCookieKeyMissing` if it is unset or too short — the key is validated
    at construction, not on the first ceremony, so a misconfiguration fails at startup. (A
    per-handler `passkey.WithCookieKey` override still exists for the rare case of a distinct key,
    and the handlers also fail closed defensively if that override clears the key.)
  - **`Config.ChallengeStore` (required).** Provides single-use, server-side replay protection
    (SEC-05): the challenge is recorded on Begin and atomically consumed on Finish, so a captured
    raw Finish request cannot be replayed within the cookie TTL. `NewService` returns
    `ErrChallengeStoreMissing` unless a store is supplied or the explicit opt-out
    `Config.InsecureNoChallengeStore` is set (cookie-only protection — **do not** use for
    passwordless). The `passkey/memory` and `passkey/pgx` subpackages provide implementations.
  - **`Config.UserVerification` (defaults to required).** The zero value is now
    `protocol.VerificationRequired`: an assertion whose User Verified (UV) flag is unset is
    rejected at Finish across register, login and discoverable login. Leave it at the default for
    passwordless/step-up; set it explicitly to `VerificationPreferred`/`VerificationDiscouraged`
    **only** for a flow where another factor already authenticated the user.
  - **Serve over HTTPS** so the `Secure` ceremony cookie is sent; `passkey.WithInsecureCookies`
    is for local HTTP development only.
  - **Rate-limit ceremony attempts** in front of the handlers (egauth does not throttle them —
    see the next bullet).
- **MFA verification is not rate-limited by egauth.** Per the non-objectives, throttling TOTP /
  recovery-code / passkey attempts is the consumer's responsibility; egauth exposes the errors
  and propagates `context.Context` so an external limiter can be attached in front of the handlers.
- **Step-up / AAL enforcement.** Tokens carry an `AMR` claim (RFC 8176) recording the factors used
  to obtain them. The model has two halves and **both ship in egauth**:
  - *Enforcement.* `tokens.WithRequiredAMR(...)` gates a route on those factors (e.g. require
    `AMRMFA`), returning 403 for an authenticated-but-under-assured subject. It fails **closed**: a
    token that does not carry the required AMR value never passes, so a password-only session can
    never satisfy `WithRequiredAMR(AMRMFA)`.
  - *Production.* `identity.WithMFAGate(mfaSvc)` makes `LoginHandler` check `IsEnrolled` after a
    correct password; an enrolled user receives a **short-lived interim access token**
    (`AMR=[AMRPassword]`, default 5 min, configurable via `WithInterimTokenTTL`) and **no refresh
    cookie**, so the pre-MFA state is not an indefinitely renewable session. The second factor is
    then driven by `mfa.StepUpHandler`, which on a correct TOTP re-issues the **full**
    access+refresh pair with `AMR=[AMRPassword, AMROTP, AMRMFA]` and sets both cookies, replacing the
    interim access cookie. Users with no enrolled factor are unaffected and receive the full pair.

  Without `WithMFAGate`/`StepUpHandler`, AMR production is entirely consumer-implemented: the
  application's `ClaimsBuilder`/`ClaimsProvider` must stamp the AMR values itself when issuing the
  pair after a second factor, and a plain `LoginHandler` issues a full refreshable pair on the
  password alone. On refresh the AMR is re-evaluated by the `ClaimsProvider`, not frozen at login.
  To make that re-evaluation per-session rather than per-user, `Rotate` attaches a
  `tokens.RotationContext` (the rotation family ID and the family's preserved `auth_time`) to the
  context passed to `ClaimsProvider.ClaimsForUser`; recover it with `tokens.RotationContextFromContext`.
  This lets a provider keyed by family ID preserve (or deliberately downgrade) the assurance the
  family originally proved, instead of being forced to either silently decay a legitimately
  MFA-elevated session after one access-token TTL or blanket-elevate every session of an
  MFA-enrolled user — the latter being a step-up bypass where a password-only family would gain
  `AMRMFA` on its first silent refresh.
- **Magic-link login** reuses the single-use selector/verifier verification tokens; the request
  endpoint is uniform (no account enumeration) and delivery is dispatched off the response path,
  exactly like the password-reset request.
- **Independent recovery channels (breaking the single-email takeover chain).** An account can
  enroll a verified phone (`RequestPhoneVerification`) and/or a verified recovery email
  (`RequestRecoveryEmail`) — both proven by a token delivered to that channel before it is trusted,
  and a recovery email may not equal the primary address (`ErrRecoveryEmailIsPrimary`). The
  recovery email is a contact attribute, not a login key (it is not unique, never re-keys an
  identity, and cannot be authenticated against). `RecoveryChannels(...).Any()` is the gate
  primitive: pair it with a freshness/step-up check (`tokens.WithMaxAuthAge`) to require an
  independent verified channel before a sensitive factor-reset. `RequestPasswordResetViaRecovery`
  directs the reset token to a verified recovery channel **instead of** the primary inbox, so a
  compromised primary mailbox cannot drive the reset; it is enumeration-uniform — an unknown
  account, an OAuth-only account, and a known account with no recovery channel all produce the
  same empty, no-error response.
- **Deactivation revokes pending tokens and blocks re-authentication.** Magic-link,
  password-reset and email-verification all reject a token whose account has since been
  soft-deleted (`DeleteUser`): the consume path re-checks `DeletedAt` and returns "not found",
  so deleting an account reliably invalidates its outstanding passwordless logins and reset links.
  `LinkOrCreateIdentity`'s already-linked branch likewise re-checks `DeletedAt` and returns
  "not found", so a deleted account cannot regain a session through its previously-linked OAuth
  identity. To make this gate reachable, `DeleteUser` only anonymizes the `provider_id` of
  **password-provider** identity rows (the `provider_id` for password identities is the user's
  email address, which is PII); non-password (OAuth/OIDC) identity `provider_id` values are
  opaque external subject identifiers and are preserved intact so that `FindIdentityByProvider`
  can still locate the identity after deletion, allowing the `DeletedAt` check to fire.
- **One-time passcodes (email/SMS OTP).** The `otp` module is delivery-agnostic — egauth never
  sends anything; `Issue` returns the plaintext code for the application to deliver, and `Verify`
  is single-use and **attempt-limited** (the code is burned after `MaxAttempts` wrong guesses).
  Both guarantees hold under concurrency: success consumes the code through an atomic guarded
  delete keyed on the exact hash that was compared (only one of N parallel correct-code
  verifications wins), and an attempt slot is reserved atomically *before* the code is compared,
  so concurrent wrong guesses cannot exceed the limit. The hash guard also covers the Issue/Verify
  interleave: if the code is reissued between a verifier's read and its consume, the stored row
  now carries a different hash, so the stale verification deletes nothing and fails — a superseded
  code can neither be accepted nor burn its freshly issued replacement.
  Because numeric OTPs are intentionally low-entropy, the at-rest SHA-256 hash is not a barrier
  against an attacker who already has the database; the real defenses are the short TTL,
  single-use consumption and the attempt limit — and, as always, the consumer's own rate limiting
  on the verify endpoint.
- **No internal logging.** egauth performs no logging of its own ("silent by default").
  It never writes passwords, plaintext tokens, or hashes to stdout/stderr or any logger.
  `context.Context` is propagated so consumers can attach their own tracing.
- **Context cancellation is observed on the expensive paths.** `context.Context` flows through
  every operation. I/O cancellation propagates through the driver (pgx for the Postgres stores;
  `net/http` for the HIBP breach client, which uses `http.NewRequestWithContext`). In addition,
  the deliberately expensive in-process paths check `ctx.Err()` *before* doing the costly work, so
  a client that has already gone away cannot keep burning resources: the Argon2id KDF
  (`passwords/argon2` `Hash`/`Compare`) short-circuits before the hash pass, the offline breach
  lookup fails fast, and `identity.DeleteAccount` aborts its cross-module cascade before running
  another eraser (leaving the account live and the operation cleanly retriable). Argon2id itself is
  not interruptible mid-hash, so the guard is a pre-call check, not a kill switch for an in-flight
  pass; in-memory map lookups in the reference stores are not individually cancellable but complete
  in microseconds.
- **Argon2id cost parameters from stored hashes are bounds-checked on both sides.** `Compare`
  parses the `m`/`t`/`p` cost fields from the stored PHC string and validates them before invoking
  `argon2.IDKey`. Lower bounds (time ≥ 1, threads ≥ 1, memory ≥ 8×threads) prevent library panics.
  An upper bound (`MaxMemoryKiB` = 512 MiB = 524 288 KiB) prevents an OOM DoS: `argon2.IDKey`
  allocates `memory × 1 024` bytes, so a tampered or corrupt stored hash row carrying e.g.
  `m=4000000000` would attempt a multi-TiB allocation on the victim's next login. Any stored hash
  whose memory parameter exceeds `MaxMemoryKiB` is rejected as `ErrInvalidPassword` (same opaque
  mismatch signal as all other validation failures) before the KDF is invoked.
- **Redaction on credential-bearing types (defence in depth).** The structs most likely to be
  logged or printed implement `fmt.Stringer`/`fmt.GoStringer` and `slog.LogValuer` so their
  secret fields render as `REDACTED` on the accidental-leak paths (`%v`/`%s`/`%+v`/`%#v`, `log`,
  `slog`): `tokens.TokenPair` (access + refresh token), `tokens.APIKey` (the clear-text `Token`),
  and — because the HS256 signing key is the most catastrophic secret to leak — `tokens/jwt.Config`,
  `tokens/jwt.SigningKey` and the running `tokens/jwt.Service` (its `SecretKey` / `SigningKeys[].Secret`
  and the resolved key bytes). Non-secret identifiers (key IDs, issuer, expiry) stay visible to aid
  debugging. This is a safety net, **not** a licence to log these values (see below). JSON
  marshalling is intentionally **not** redacted, since returning a freshly issued token to its
  owner in a response body is a legitimate use.
- **Errors do not echo secrets.** Wrapped errors carry the underlying cause
  (`%w`) or non-sensitive metadata (e.g. a JWT `alg` header), never the plaintext
  password or token bytes.

## What the consumer must NOT do

Some values are returned to the caller in **plaintext exactly once** and must be treated
as credentials:

- `tokens.APIKey.Token` — the raw API key (only `APIKey.Hash` is stored).
- `tokens.TokenPair.AccessToken` and `tokens.TokenPair.RefreshToken`.
- Session tokens returned by the `sessions` service (bare `string` return values, **not** a
  struct field — `sessions.Session` persists only `TokenHash`).
- Any password passed into `Register` / `Authenticate`.

The `tokens.*` structs above redact their secret fields on `fmt`/`slog` (see the redaction note
above), but a session token / password is a bare string with **no** such safety net, and the
redaction is in any case only a backstop. Therefore the consumer must:

- **Never log them** (no `log`, `slog`, `fmt.Printf`, request/response dumps, etc.). The
  redaction stops an accidental struct dump; it does not make logging a token's *value* safe.
- **Never serialize them by accident.** The `tokens.*` structs carry no `json` tags and JSON
  marshalling is deliberately *not* redacted, so a consumer that JSON-encodes them will emit the
  plaintext. Send a token to the client deliberately (cookie/body) and nowhere else.
- **Never log the JWT signing key.** Load `tokens/jwt.Config.SecretKey` / `SigningKeys` from a
  secret store; `Config`, `SigningKey` and `Service` redact it on `fmt`/`slog`, but do not
  serialize the config or persist the key in plaintext.
- **Transmit only over TLS** and store client-side tokens in `HttpOnly`, `Secure`
  cookies (the HTTP handlers set these flags by default).
- **Use the `__Host-` cookie name prefix** for session cookies in production.
  Configure `sessions.RequireSession` with `sessions.WithCookieName("__Host-session_token")`
  (or any `__Host-` prefixed name). Browsers enforce that a `__Host-` cookie is host-locked
  (no `Domain` attribute), `Secure`, and `Path=/` — this defeats subdomain/sibling-host
  cookie-tossing session fixation, where an attacker on `evil.example.com` injects a
  `Domain=.example.com session_token` cookie containing the attacker's own valid token and
  the victim transparently operates inside the attacker's session. Without the prefix the
  hardcoded `session_token` name cannot be protected from this attack by the library alone.
  The default remains `"session_token"` for backwards compatibility; deployments should
  migrate to a `__Host-` prefixed name.
- **Session absolute lifetime.** `sessions.NewService` enforces a 30-day absolute session
  lifetime by default (OWASP session guidance: an absolute timeout must complement the idle
  timeout). Regardless of how recently `Touch` was called, a session is rejected once
  `now > CreatedAt + 30d`. Use `sessions.WithMaxLifetime(d)` to shorten or lengthen this
  cap. Use `sessions.WithNoMaxLifetime()` to disable it entirely — this is insecure: an
  attacker who keeps a stolen token warm with periodic requests can extend the session
  forever, and should only be used in explicitly documented, low-risk contexts.
  `WithMaxLifetime(0)` is treated as "keep the default" (not "disable"), so callers that
  pass a configurable duration do not silently opt out of the cap when the user configures
  zero.

## CSRF on the form handlers (consumer responsibility)

`LoginHandler`, `RegisterHandler`, `RefreshHandler` and `LogoutHandler` are
state-changing endpoints driven by the request (form body / cookies). egauth applies two
partial defences but does **not** ship a full CSRF-token system (per the PRD, rate limiting
and general CSRF are left to the application layer):

- **`SameSite=Lax` cookies** (default) stop a cross-site request from *sending* the
  refresh/session cookie, which protects `RefreshHandler`/`LogoutHandler` against classic
  CSRF acting on an existing session.
- **`identity.WithTrustedOrigins(...)`** (opt-in) rejects a login/register POST whose
  `Origin`/`Referer` host is not allow-listed. This closes the **login-CSRF / session
  fixation** gap, where `SameSite` does *not* help because the attack needs no
  pre-existing cookie (it forces the victim's browser to log into the *attacker's*
  account). Enable it, or add your own synchronizer/double-submit CSRF token middleware
  in front of these endpoints.

The **`mfa` handlers** (`EnrollHandler`, `ConfirmHandler`, `VerifyHandler`,
`VerifyRecoveryHandler`, `RegenerateRecoveryCodesHandler`, `DisableHandler`,
`StepUpHandler`) are also state-changing POST endpoints. If the session cookie they rely
on is `SameSite=None` (e.g. in a cross-subdomain or embedded app), a cross-site form POST
could silently strip a victim's second factor (MFA downgrade via `DisableHandler`) or
invalidate their recovery codes (`RegenerateRecoveryCodesHandler`). Use
**`mfa.WithTrustedOrigins(...)`** to apply the same `Origin`/`Referer` host allowlist
check on all MFA handlers. Supply hostnames without scheme, e.g.
`mfa.WithTrustedOrigins("app.example.com")`. When unset (the default), no origin check
is performed — CSRF protection remains the consumer's responsibility.

## Observability and idempotency (consumer responsibility)

egauth ships no first-party metrics, tracing, or request-level idempotency layer.

**Observability** — wire `event.Sink` to your metrics pipeline or audit log. The ready-made
`event.NewSlogSink` covers the "log it with slog" case; for richer consumers (Prometheus
counters, OpenTelemetry spans, SIEM ingestion) implement `event.Sink` directly or use
`event.MultiSink` to fan out. Every operation propagates a `context.Context`, so span
propagation and deadline enforcement are fully under the consumer's control. egauth ships no
first-party OpenTelemetry or Prometheus adapter (a later milestone, if wanted).

**Idempotency** — request-level deduplication (idempotency keys, retry-safe mutations) is the
application layer's responsibility. egauth provides no idempotency-key layer; consuming
applications that need it must implement or proxy one in front of the egauth handlers, mirroring
how rate limiting and CSRF tokens are positioned.

## Evicting in-memory stores in production (consumer responsibility)

The in-memory store backends (`sessions/memory`, `otp/memory`) and the `ratelimit.TokenBucket`
accumulate entries until a caller explicitly invokes `DeleteExpired` / `Cleanup`. This is an
intentional design choice (the in-memory stores are primarily for tests and single-process apps),
but it is an **operational footgun** if overlooked:

- A flood of short-lived sessions, OTP codes, or unique rate-limit keys will grow the internal
  maps indefinitely, exhausting heap memory and creating a denial-of-service vector.
- The per-read opportunistic eviction in `sessions/memory` only evicts the single looked-up entry;
  it is O(1) on the hot path and is **not** a substitute for a full sweep.

**Mitigation (consumer responsibility):** schedule periodic eviction using the optional
`janitor` helper shipped with egauth:

```go
import "github.com/JLugagne/egauth/janitor"

j := janitor.Start(ctx, 5*time.Minute, func() {
    sessStore.DeleteExpired(context.Background(), tenantID)
})
defer j.Stop()
```

The same pattern applies to `otp/memory.Store.DeleteExpired` and `ratelimit.TokenBucket.Cleanup`.
See package `janitor` for multi-tenant and multi-store usage examples. Deployments that need
persistence or horizontal scaling should use the `pgx` backends instead of the in-memory stores.

## Account-existence disclosure (by design)

Three responses intentionally reveal that an account exists; this is an accepted trade-off,
not a bug:

- **`ErrAccountLocked` / `ErrAccountDisabled` → 429** on login: lockout and administrative
  suspension are both meant to be observable (PRD §105–106). Both map to the same 429 response
  so suspended accounts are indistinguishable from locked ones to an external observer.
- **`email_taken` → 409** on registration: standard registration UX. If your threat model
  requires anti-enumeration on sign-up, collapse `mapRegisterError` to a single generic
  `400` (note that `Register` already hashes before the uniqueness check, so the timing
  channel is already closed).
- **`email_taken` → 409** on the authenticated change-email request
  (`RequestEmailChangeHandler`): the caller is told up front when the requested new address
  already belongs to another account, mirroring the registration disclosure. This is gated
  behind authentication (a higher bar than sign-up) and gives the user a clear "pick another
  address" response. If your threat model forbids it, drop the pre-flight `FindUserByEmail`
  conflict in `RequestEmailChange` and rely solely on the store's unique index at confirm
  time (`ConfirmEmailChange` already returns `ErrEmailAlreadyExists` for an address claimed in
  the interim).
- **`no_credentials` → 400** on `BeginLoginHandler`: when the resolved user has no registered
  passkeys, `BeginLogin` returns `ErrNoCredentials`, which `BeginLoginHandler` maps to HTTP 400
  `no_credentials`. A user with at least one passkey receives HTTP 200 plus a challenge. A
  caller that can drive the begin-login endpoint with a chosen/identified userID can therefore
  distinguish "account has passkeys" from "account has none" — a passkey-enrolment enumeration
  oracle. This is an accepted trade-off: WebAuthn UX fundamentally requires the server to
  know whether the account has any credential before issuing a challenge, and a silent generic
  error would break the client flow. **Consumer guidance:** gate `BeginLoginHandler` behind
  per-IP or per-subject rate limiting (egauth does not throttle ceremony attempts — see the
  hardening checklist above). If your threat model forbids passkey-enrolment enumeration,
  change your `UserResolver` to return `ok=false` (→ 401) for unenrolled subjects before the
  handler reaches `BeginLogin`, or handle `ErrNoCredentials` yourself and return a generic 400
  without the `no_credentials` body.

The login path itself is hardened against enumeration (generic `ErrInvalidCredentials` +
decoy hashing); the four disclosures above are the only intentional exceptions.

### Residual enumeration timing after raising Argon2id cost (rehash-on-login)

The decoy-hashing defence is not perfectly uniform across a cost upgrade. The decoy path
(the hash run for an **unknown** account) always uses the hasher's **current** configured
cost — `Hash` bakes in `m`/`t`/`p` from the live `Hasher`. The real verify path (`Compare`)
runs Argon2id at the cost recorded **in the stored hash**, which for a not-yet-rehashed
account is the **old, lower** cost. So immediately after an operator raises the cost
parameters (the documented rehash-on-login upgrade), every existing account whose hash has
not yet been rehashed verifies at the old (faster) cost, while an unknown account is
decoy-hashed at the new (slower) cost. The measurable timing gap is a **partial enumeration
oracle**: it can distinguish "registered account that last logged in before the cost bump"
from "unknown". The gap closes for each account the moment it next authenticates and its hash
is transparently rehashed at the new cost, and it disappears entirely once the population has
refreshed.

**Operator guidance.** When you raise Argon2id cost, treat enumeration-resistance as
**degraded until the fleet is rehashed**. Either proactively re-hash all stored passwords to
the new cost (so no account verifies at the old cost), or accept the degraded
enumeration-resistance during the natural rehash-on-login refresh window. As with all residual
in-process timing in `egauth`, the standing mitigation is the consumer's own rate limiting on
the login endpoint (per the non-objectives), which covers the remainder.

The **password-reset request** endpoint (`RequestPasswordResetHandler`) is, by contrast,
deliberately uniform: it returns the same response for a known account, an unknown account, an
OAuth-only account (no password to reset), and even a backend error — and it dispatches email
delivery off the response path so the Mailer's latency is not a timing oracle. Account existence
must not be inferable from this endpoint. (Residual in-process timing — one extra indexed DB
read for an existing account — is left to the consumer's rate limiting, per the non-objectives.)

## Reporting a vulnerability

Please use **GitHub Private Vulnerability Reporting** — do **not** open a public issue for
security matters.

1. Go to the repository's **Security** tab.
2. Click **"Report a vulnerability"**.
3. Fill in the advisory form and submit.

Direct link: <https://github.com/JLugagne/egauth/security/advisories/new>

> **Note:** GitHub Private Vulnerability Reporting must be enabled in the repository's
> Security settings for the button to appear; this is verified separately.

## Supported versions

Only the latest `0.x` minor release receives security fixes. Older minor series are
unsupported and may be retracted.

| Version | Supported          |
| ------- | ------------------ |
| >= 0.3  | yes                |
| 0.2.x   | no (unsupported)   |
| 0.1.x   | no (retracted)     |

## Acknowledgement window

Security reports are acknowledged on a **good-faith, best-effort** basis:

- **72 hours** — initial acknowledgement (confirm receipt and assign a tracking ID).
- **7 days** — preliminary assessment (severity, reproduction status, and an estimated
  fix timeline).
