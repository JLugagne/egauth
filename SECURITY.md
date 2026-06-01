# Security model — handling secrets and passwords

This document describes how `libauth` handles sensitive values (passwords, opaque
tokens, hashes) and what the **consumer** of the library is responsible for.

## What libauth guarantees

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
  optional pluggable `passwords.BreachChecker` (e.g. a HIBP k-anonymity client — libauth ships
  the interface only, never the network call).
- **TOTP & recovery codes.** The `mfa` module implements RFC 6238 TOTP (authenticator apps only,
  no SMS) with a ±skew window and **replay protection** via a monotonic last-used time-step (a
  code, including the enrolling one, cannot be reused). Recovery codes are single-use and stored
  only as SHA-256 hashes. **Caveat:** a TOTP shared secret must be stored in recoverable form (the
  server recomputes codes from it), so — unlike passwords/opaque tokens — it is NOT hashed. Per the
  PRD's "no at-rest encryption in v1" non-objective, the `mfa` store persists the secret in clear;
  deployments that need defense against a database leak should encrypt the `secret` column at the
  storage/DB layer (envelope encryption).
- **Passkeys (WebAuthn).** The `passkey` module wraps go-webauthn. Credentials are scoped to the
  configured Relying Party ID; the ceremony challenge and user-verification requirement
  (`SessionData`) are carried between Begin and Finish in a short-lived, **HMAC-signed**
  `HttpOnly`/`Secure` cookie (the key is **required** via `passkey.WithCookieKey`; the handlers
  fail closed without it) so the client cannot tamper with the challenge or downgrade user
  verification; the cookie is single-use and the ceremony has a server-enforced expiry. A
  regressed signature counter (possible cloned authenticator) is rejected (`ErrCredentialCloned`).
- **MFA verification is not rate-limited by libauth.** Per the non-objectives, throttling TOTP /
  recovery-code / passkey attempts is the consumer's responsibility; libauth exposes the errors
  and propagates `context.Context` so an external limiter can be attached in front of the handlers.
- **Step-up / AAL enforcement.** Tokens carry an `AMR` claim (RFC 8176) recording the factors used
  to obtain them; `tokens.WithRequiredAMR(...)` gates a route on those factors (e.g. require
  `AMRMFA`), returning 403 for an authenticated-but-under-assured subject. On refresh the AMR is
  re-evaluated by the `ClaimsProvider`, not frozen at login.
- **Magic-link login** reuses the single-use selector/verifier verification tokens; the request
  endpoint is uniform (no account enumeration) and delivery is dispatched off the response path,
  exactly like the password-reset request.
- **Deactivation revokes pending tokens.** Magic-link, password-reset and email-verification all
  reject a token whose account has since been soft-deleted (`DeleteUser`): the consume path
  re-checks `DeletedAt` and returns "not found", so suspending an account reliably invalidates its
  outstanding passwordless logins and reset links (a token minted while live cannot resurrect it).
- **One-time passcodes (email/SMS OTP).** The `otp` module is delivery-agnostic — libauth never
  sends anything; `Issue` returns the plaintext code for the application to deliver, and `Verify`
  is single-use and **attempt-limited** (the code is burned after `MaxAttempts` wrong guesses).
  Both guarantees hold under concurrency: success consumes the code through an atomic guarded
  delete (only one of N parallel correct-code verifications wins), and an attempt slot is reserved
  atomically *before* the code is compared, so concurrent wrong guesses cannot exceed the limit.
  Because numeric OTPs are intentionally low-entropy, the at-rest SHA-256 hash is not a barrier
  against an attacker who already has the database; the real defenses are the short TTL,
  single-use consumption and the attempt limit — and, as always, the consumer's own rate limiting
  on the verify endpoint.
- **No internal logging.** egauth performs no logging of its own ("silent by default").
  It never writes passwords, plaintext tokens, or hashes to stdout/stderr or any logger.
  `context.Context` is propagated so consumers can attach their own tracing.
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

## CSRF on the form handlers (consumer responsibility)

`LoginHandler`, `RegisterHandler`, `RefreshHandler` and `LogoutHandler` are
state-changing endpoints driven by the request (form body / cookies). libauth applies two
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

## Account-existence disclosure (by design)

Three responses intentionally reveal that an account exists; this is an accepted trade-off,
not a bug:

- **`ErrAccountLocked` → 429** on login: lockout is meant to be observable (PRD §105–106).
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

The login path itself is hardened against enumeration (generic `ErrInvalidCredentials` +
decoy hashing); the three disclosures above are the only intentional exceptions.

The **password-reset request** endpoint (`RequestPasswordResetHandler`) is, by contrast,
deliberately uniform: it returns the same response for a known account, an unknown account, an
OAuth-only account (no password to reset), and even a backend error — and it dispatches email
delivery off the response path so the Mailer's latency is not a timing oracle. Account existence
must not be inferable from this endpoint. (Residual in-process timing — one extra indexed DB
read for an existing account — is left to the consumer's rate limiting, per the non-objectives.)

## Reporting a vulnerability

Report security issues privately to the maintainer rather than opening a public issue.
