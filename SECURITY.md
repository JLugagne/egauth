# Security model — handling secrets and passwords

> **Audit status.** egauth's security review to date is an AI-driven audit only; it has not had
> an independent third-party human security audit, and that risk is accepted for v1.0 — pin a
> reviewed commit, commission your own audit, or wait if that trade-off is unacceptable.
> "AI-audited" is **not** a synonym for "audited". See [AUDIT.md](AUDIT.md) for the full review
> scope (what was reviewed and how, what was not, the accepted trade-offs) and the cautious-user
> escape hatch.

This document describes how `egauth` handles sensitive values (passwords, opaque
tokens, hashes) and what the **consumer** of the library is responsible for.

## What egauth guarantees

- **Hashing at rest.** Opaque tokens (refresh tokens, API keys, session tokens) are
  never persisted in clear text. Only their SHA-256 hash is stored (`tokens.HashToken`),
  so a database leak does not expose usable credentials. Lookups are performed on the
  hash, which is what makes a plain index/equality lookup safe for high-entropy tokens.
  The library enforces a minimum token byte length (`jwt.MinTokenLength = 16`) for
  `RefreshLength` and `APIKeyLength`: `Config.Validate` returns an error and `New` panics
  if either is set to a positive value below the minimum, preventing low-entropy tokens
  from being issued accidentally.
- **Constant-time password comparison (by construction).** Password verification compares
  the derived key with `crypto/subtle.ConstantTimeCompare` (`passwords/argon2`), so a wrong
  password cannot be recovered byte-by-byte through timing. The guarantee is *structural*:
  `Compare` never branches on the byte-wise outcome of the secret comparison, and for any
  in-bounds, non-empty candidate against a well-formed stored hash it always reaches the
  constant-time comparison.

  Three kinds of input do return before the KDF, and it is worth being precise about what each
  one discloses:

  1. A *malformed or out-of-range* stored hash (bad PHC shape, wrong algorithm/version, or a
     cost parameter outside `MinMemoryKiB`…`MaxMemoryKiB` / `MaxTime` / `MaxThreads` /
     `MaxKeyLen` / `MaxSaltLen`) is rejected before the KDF. That decision depends only on the
     shape of the untrusted stored hash, never on the candidate, so it leaks nothing about the
     password.
  2. An **empty** candidate returns `ErrInvalidPassword` immediately. This branches on the
     candidate — but `Hash` refuses to hash `""`, so no stored hash can ever correspond to it,
     and the decoy path (`decoyHash` → `Hash("")`) returns just as fast. The fast return is
     what keeps the two paths symmetric; making it slow would create the enumeration oracle,
     not remove one. The attacker learns only that they submitted an empty password.
  3. A candidate longer than `passwords.MaxPasswordLength` returns `ErrInvalidPassword`
     immediately (pre-auth CPU/memory DoS guard). This also branches on the candidate, and
     discloses only the length bound the attacker themselves chose to exceed — a public,
     documented constant, independent of the account and of the stored hash.

  Neither (2) nor (3) is reachable with a candidate that could match, so neither distinguishes a
  correct password from a wrong one, nor one account from another. This is not provable
  by a boolean unit test; the supporting *evidence* is a pair of benchmarks
  (`BenchmarkCompare_CorrectPassword` vs `BenchmarkCompare_WrongPassword` in
  `passwords/argon2`) whose measured per-op timings land within benchmark noise of each other.
- **Constant-time authentication paths (by construction).** The password authentication path
  applies an equivalent hashing cost (a full Argon2id pass via the decoy-hash path) even when
  the user, identity, or password hash is absent, or the provider is non-password, so account
  existence cannot be inferred from response timing (user-enumeration defence). Again the
  guarantee is structural — every enumeration-safe branch in `Authenticate` calls `decoyHash`.
  The supporting evidence is `BenchmarkAuthenticate_ValidUser_WrongPassword` (real `Compare`)
  vs `BenchmarkAuthenticate_UnknownUser` / `BenchmarkAuthenticate_NonPasswordProvider`
  (decoy hash) in `identity`, whose measured deltas are within benchmark noise.

  **Running the timing-evidence benchmarks.** These are evidence to inspect manually, not CI
  pass/fail gates (a wall-clock threshold on a shared runner is too flaky to gate a build):

  ```sh
  go test -run=^$ -bench=BenchmarkCompare      -benchmem ./passwords/argon2
  go test -run=^$ -bench=BenchmarkAuthenticate -benchmem ./identity
  # For a noise-aware comparison across a change, capture multiple runs and use benchstat:
  go test -run=^$ -bench=BenchmarkAuthenticate -benchmem -count=10 ./identity | tee old.txt
  # ...make the change...
  go test -run=^$ -bench=BenchmarkAuthenticate -benchmem -count=10 ./identity | tee new.txt
  benchstat old.txt new.txt   # go install golang.org/x/perf/cmd/benchstat@latest
  ```

  A benchstat-significant gap between the correct/valid and wrong/unknown variants would signal
  a regression in the constant-time guarantee (e.g. a path that skips the decoy or short-circuits
  the comparison) and should be investigated. Note the benchmark fixture disables lockout
  (`WithNoLockout`) so the valid-user path keeps exercising `Compare` every iteration instead of
  short-circuiting on `ErrAccountLocked`; lockout remains on by default in production.
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
  (default 10s) of consumption — and the lost-race case where two requests rotate the
  *same not-yet-consumed* token in parallel — is treated as benign and rejected *without*
  revoking the family. These benign cases surface the distinct `tokens.ErrRefreshConcurrent`
  sentinel (which wraps `ErrRefreshTokenReused` for compatibility), so the cookie-clearing
  callers (`RequireAuth` auto-refresh and `RefreshHandler`) clear **only the stale access
  cookie** and leave the refresh cookie intact: the winning request already minted a fresh,
  valid refresh cookie for this client, and clearing it would wipe that and force a full
  re-login — the very lockout the grace window exists to prevent. After-grace reuse, expiry
  and not-found still clear all cookies. Set a negative `ReuseGracePeriod` for strict mode
  where any replay revokes.

  **Clock discipline.** The age of a consumption is measured with the Service's injected clock
  (`Config.Clock`, default `time.Now`), the same source that stamps `iat`/`exp` — never a
  second, implicit wall-clock read. `consumed_at` itself is written by whichever clock the Store
  runs on, which for a SQL backend is the **database server's**. Skew between the two is handled
  explicitly in one direction: a `consumed_at` *ahead* of clock-now yields a negative age that is
  clamped to zero, so store-clock skew reads as "just consumed" (benign concurrency) instead of
  tripping theft detection on a token consumed a moment ago. Skew the other way can only shorten
  the grace window, never widen it, which fails closed. Operators must still keep the application
  and database clocks in sync (NTP): a skew larger than `ReuseGracePeriod` degrades the
  concurrency allowance and no clamp can recover it.
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
  will be accepted by any compliant authenticator app. The shared secret is 160 bits of
  `crypto/rand`, and a secret below `mfa.MinSecretBytes` (128 bits, the RFC 4226 §4 minimum) is
  rejected with `mfa.ErrWeakSecret` at enrollment **and** at verification — an empty or truncated
  secret would key the HMAC with (nearly) no entropy, making every code it produces computable by
  anyone, so a row damaged by a bad import or a hand edit fails closed instead of accepting an
  attacker-derived code. `mfa.ValidateSecret` is exported for callers importing enrollments minted
  elsewhere. **Caveat:** a TOTP shared secret must be stored in recoverable form (the server
  recomputes codes from it), so — unlike passwords/opaque tokens — it is NOT hashed. The in-memory
  reference store keeps it as-is; the shipped Postgres backend
  (`adapters/pgx/mfa`) **requires** a KEK and envelope-encrypts the `secret` column (see
  *Envelope encryption of recoverable secrets* below). A custom store must provide equivalent
  at-rest protection.
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
  - *Production.* `identity.WithMFAGate(mfaSvc)` makes **`LoginHandler` and
    `MagicLinkLoginHandler`** check `IsEnrolled` after a successful FIRST factor, and
    `oauth.WithMFAGate(mfaSvc)` does the same in the OAuth/OIDC callback — so a password, a mailbox
    and a federated IdP account are all gated, not just the password form. An enrolled user receives
    a **short-lived interim credential** (`tokens.Claims.Interim`, `AMR=[AMRPassword]` with every
    step-up marker stripped, default 5 min, configurable via `WithInterimTokenTTL`) and **no refresh
    cookie** — any refresh cookie an earlier full session left in the browser is actively CLEARED, and
    when the issuer implements `tokens.AccessTokenIssuer` (as `jwt.Service` does) no refresh-token
    family is persisted at all. The second factor is then driven by
    `mfa.StepUpHandler`, which on a correct TOTP re-issues the **full** access+refresh pair with
    `AMR=[AMRPassword, AMROTP, AMRMFA]` and sets both cookies, replacing the interim access cookie.
    Users with no enrolled factor are unaffected and receive the full pair.
  - *The interim credential is not a session, and that is **enforced**, not documented.*
    `tokens.RequireAuth` / `tokens.ContextMiddleware` refuse an interim credential with 403
    `step_up_required` on **every** route unless the route opts in with
    `tokens.WithInterimAllowed()` — mount that on the step-up endpoint **only**. Independently of the
    routing layer, the handlers that could otherwise be abused refuse it themselves:
    `mfa.DisableHandler` and `mfa.RegenerateRecoveryCodesHandler` (which additionally require a
    credential that *carries* a step-up factor, so a stolen password-only session cannot strip MFA),
    `identity.ChangePasswordWithReissueHandler` (which would otherwise upgrade the interim credential
    into a full renewable pair) and `identity.DeleteAccountHandler` (irreversible). Those checks fail
    **closed**: a request whose assurance cannot be resolved is refused. They read the assurance from
    `tokens.AssuranceResolverFromContext` by default, so mounting the handler behind
    `tokens.ContextMiddleware` is the only wiring required; `WithAssuranceResolver` supplies it from a
    custom middleware and `WithInsecureNoStepUpCheck` is the loud opt-out.
  - *An MFA-gated login is distinguishable on the wire.* The pre-step-up reply is **not** the 204 (or
    `successURL` redirect) of a full login: it carries the `X-Egauth-MFA-Required: 1` header plus
    either `200 {"mfa_required":true}` or a 303 to `identity.WithMFARequiredRedirect` /
    `oauth.WithMFARequiredRedirect`. A client must treat that response as "second factor required",
    POST the code to the step-up endpoint, and only then consider itself logged in — the interim
    credential will be refused everywhere else, and expires within minutes.
  - *`WithMaxAuthAge` alone does NOT gate a sensitive route.* An interim credential is freshly
    issued, so its `auth_time` freshness window passes trivially. Use
    `WithRequiredAMR(AMRMFA)` — optionally *alongside* `WithMaxAuthAge` for a sudo-mode window.

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
- **Forced-password-change for temporary credentials (soft gate).** egauth forces a password
  change only for **admin-provisioned credentials** — `identity.AdminCreateUser` (admin-created
  account) and `identity.SetTemporaryPassword` (admin-issued one-time password) set the
  `MustChangePassword` flag on the identity explicitly, so the user must choose their own password
  before the app is usable. egauth deliberately does **not** offer periodic, age-based password
  rotation: forcing expiry on a fixed interval is discouraged by NIST SP 800-63B (it drives weaker,
  predictably-incremented passwords) and is intentionally not implemented.

  The soft-gate contract: **a flagged credential still authenticates — the user is never locked
  out.** At next login the handler detects the flag (via `identity.PasswordChangeRequired`) and
  issues a **full, renewable token pair** whose access token carries
  `tokens.Claims.MustChangePassword=true`. Crucially the flag is recorded on the refresh-token
  **family**, and `Rotate` replays it verbatim onto every silent refresh (overriding whatever the
  `ClaimsProvider` returns), so the renewed token is flagged **if and only if** the family it
  descends from was flagged. A user therefore **cannot escape the gate by waiting for the access
  token to expire and refreshing** — the carry-forward is enforced in the token layer, not the
  handler. The flag clears only when a fresh family is minted (a new login after the password is
  changed). To force a change on a user's *existing* active sessions, an administrator revokes their
  families — `SetTemporaryPassword` does this via the registered `AccountErasers`.

  The `tokens.WithPasswordChangeGate` `AuthOption` enforces the gate generically in the
  `RequireAuth` middleware: after successful token verification, if `Claims.MustChangePassword`
  is true the wrapped handler is bypassed and the request is redirected (`303`) to the configured
  reset URL (or `403 password_change_required` if none). The change-password and logout routes
  should be excluded from this middleware.

  egauth never proactively re-queries the credential's state on refresh and never auto-revokes
  sessions to force a change: the flag is set at login and carried forward, and forcing a change on
  live sessions is an explicit administrative action (family revocation). A flagged-but-not-yet-
  logged-in user is unaffected until their next login attempt.

  On a successful `ChangePassword` / `ResetPassword`, `UpdateIdentityPassword` atomically stamps
  `PasswordChangedAt` and clears `MustChangePassword`; `ChangePasswordWithReissueHandler` then
  re-issues a full access+refresh pair so the user is immediately authenticated and the
  change-password redirect loop stops.

  `PasswordChangedAt` (added by migration `008_add_password_change_columns.sql`) is **informational
  audit metadata** — "when the password hash was last set" — stamped on every password write. It
  does **not** drive any forced-change decision (there is no age-based policy); a zero value on a
  legacy row is simply an unknown last-changed time and is harmless.

- **API keys: PAT and service tokens.** egauth issues two kinds of long-lived key via `IssueAPIKey`.
  A **PAT (Personal Access Token)** acts on behalf of a human: `Actor.Kind == egauth.PAT`,
  `IsHuman()` returns `true`, and `Actor.UserID` is the owning user's UUID. A **Service token** is a
  machine identity decoupled from any human: `Actor.Kind == egauth.Service`, `IsMachine()` returns
  `true`, and the token's subject is the key's own ID (recorded in `Actor.KeyID`); the human who
  created it is tracked separately in the key's `CreatedBy` field and emitted on the
  `api_key.created` audit event.

  **A key's authority is only the scopes you pass at issuance. `IssueAPIKey` does not copy, inherit,
  or mirror the creating user's live roles.** Passing `Scopes: ["repo:read"]` at issuance constrains
  the key to that capability regardless of the issuing user's full privilege set. This is the safe
  default — a leaked PAT is bounded to the scopes it was issued with. If a broader scope is
  appropriate, pass it explicitly; egauth never widens it silently.

  Both key types are stored as SHA-256 hashes only — the clear-text token is returned exactly once
  at issuance and is never persisted. Audit events for the key lifecycle never carry the token,
  its hash, or any raw user input; they carry only short machine `Reason` codes and safe metadata:
  - `api_key.created` — fired on issuance; `Attrs` carry `"key_type"` (pat/service) and `"created_by"`.
  - `api_key.auth.succeeded` — fired on a successful verify; `Attrs` carry `"key_type"`, and optionally
    `"ip"` / `"user_agent"` when a `event.RequestContext` is threaded in by the handler.
  - `api_key.auth.failed` — fired on a failed verify; `Event.Reason` is one of: `not_found`,
    `expired`, `tenant_mismatch`, `wrong_type`. No token or hash is included.
  - `api_key.purged` — fired by the `DeleteExpired` GC sweep; `Attrs` carry `"count"`.

  **Opt-in route gates** (`WithRequiredKind`, `WithRequiredScopes`, `RequireMachine`, `RequireHuman`)
  are `AuthOption`s on `RequireAuth`. They are entirely opt-in: the library imposes no default
  authority policy. A request carrying a PAT when the route requires a Service token (or vice versa)
  receives `403 wrong_principal_kind`; a request missing a required scope receives `403 insufficient_scope`.
  The `egauth.Actor` injected into every handler always carries `Kind`, `KeyID`, and `Scopes`, so
  application code can also enforce policy directly without relying on middleware gates.

- **Magic-link login** reuses the single-use selector/verifier verification tokens; the request
  endpoint is uniform (no account enumeration) and delivery is dispatched off the response path,
  exactly like the password-reset request.
- **Independent recovery channels (breaking the single-email takeover chain).** An account can
  enroll a verified phone (`RequestPhoneVerification`) and/or a verified recovery email
  (`RequestRecoveryEmail`) — both proven by a token delivered to that channel before it is trusted,
  and a recovery email may not equal the primary address (`ErrRecoveryEmailIsPrimary`). The
  recovery email is a contact attribute, not a login key (it is not unique, never re-keys an
  identity, and cannot be authenticated against). `RecoveryChannels(...).Any()` is the gate
  primitive: pair it with a step-up check (`tokens.WithRequiredAMR(tokens.AMRMFA)`, optionally with
  `tokens.WithMaxAuthAge` for a freshness window — freshness alone is satisfied by a freshly minted
  pre-MFA interim credential) to require an independent verified channel before a sensitive
  factor-reset. `RequestPasswordResetViaRecovery`
  directs the reset token to a verified recovery channel **instead of** the primary inbox, so a
  compromised primary mailbox cannot drive the reset; it is enumeration-uniform — an unknown
  account, an OAuth-only account, and a known account with no recovery channel all produce the
  same empty, no-error response.
- **A credential rotation kills the account's pending token-borne credentials.** A password reset is
  the canonical response to "I think I am compromised", so it must end the takeover on *every* axis —
  not just the session axis. `ResetPassword`, `ChangePassword`, `SetTemporaryPassword` and
  `DisableUser` therefore call `Store.DeleteVerificationTokensForUser` for every
  **credential-bearing** kind: `KindPasswordReset`, `KindMagicLink`, `KindEmailChange`,
  `KindPhoneVerification`, `KindRecoveryEmailVerification`. Each of those is redeemable *later* by
  whoever received it: a reset token re-sets the password, a magic link logs in outright, an
  email-change token moves the login identifier, and a recovery-email or phone-verification token
  installs an attacker-controlled recovery channel that then drives
  `RequestPasswordResetViaRecovery`. Without the purge, an attacker riding a hijacked session could
  request a recovery-email token to their own address, lose their session to the victim's reset, and
  still confirm the token afterwards — the reset would have handed the account back. Expiry-based GC
  is not a substitute: those tokens live for an hour to a day, which is exactly the window the evicted
  attacker needs.

  `KindEmailVerification` is deliberately **kept**: it only marks the account's *current* address as
  verified — an address the account already owns — so confirming it grants an attacker nothing, while
  purging it would strand a legitimate user who reset their password before clicking the welcome link.

  The purge runs **after** the new hash (or `DisabledAt`) is committed, so the account is
  authoritatively re-keyed even if the purge fails, and its error is joined into the returned error —
  a failed purge is never a silent success, so the (idempotent) call can be retried. For `DisableUser`
  deletion is what makes the revocation permanent: `consumeForLiveUser` only refuses tokens *while*
  `DisabledAt` is set, so a surviving token would come back to life on `EnableUser`.
- **Changing the login identifier or the recovery channel takes more than a session.** Confirming an
  email change proves control of the *new* address; it does not prove the requester owns the account.
  So `RequestEmailChangeHandler` and `RequestRecoveryEmailHandler` enforce the same step-up bar as
  `DeleteAccountHandler`: a pre-step-up interim credential — and any request whose assurance cannot be
  resolved (fail closed) — is refused with `403 step_up_required`, and with `WithMFAGate` configured an
  MFA-enrolled user must present a credential carrying a step-up factor. Otherwise a hijacked
  password-only session could move the account to `attacker@evil` (locking the victim out of their own
  login address) or install an attacker-controlled recovery address. Mount both behind
  `tokens.ContextMiddleware` (or supply `WithAssuranceResolver`); `WithInsecureNoStepUpCheck` is the
  deliberate, loudly-named opt-out. A caller invoking `Service.RequestEmailChange` /
  `Service.RequestRecoveryEmail` directly MUST apply an equivalent bar.
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
- **Deactivation ends access — but only when both halves are wired.** `DisableUser` /
  `DeleteAccount` stamp the account and refuse every fresh authentication, yet an already-issued
  refresh token lives in the `tokens` store, which the `identity` service cannot reach by design.
  Ending access therefore takes two hooks, and **either one alone leaves a hole**:
  1. **Revoke the stored credentials.** Register `tokens.NewAccountRevoker(store)` with
     `identity.WithDisableRevokers` (and `WithAccountErasers` for deletion), plus
     `sessions.Service.RevokeAllForUser` when you use the `sessions` module. Without it the user's
     refresh families stay live and rotatable.
  2. **Re-check status on refresh-token rotation.** `Rotate` resolves fresh claims through the
     `ClaimsProvider`, and that provider is the **only** place a rotation can be refused. Wrap it
     with `identity.ActiveClaimsProvider(svc, provider)` (it calls `identity.Service.EnsureActive`,
     returning `ErrAccountDisabled` / `ErrUserNotFound`, which aborts `Rotate`; `RefreshHandler`
     answers `401` and clears the cookies). A provider that always succeeds lets a suspended user
     refresh **forever** — each rotation pushes the refresh expiry out to `now+RefreshTTL`, so
     access is not merely retained, it is renewed.

  `webapp.NewWebApp` wires both halves for you: it registers the account revoker on the
  `identity.Service` it is handed (via `identity.RevocationRegistry`, since the service arrives
  already constructed) and wraps its `ClaimsProvider` in `ActiveClaimsProvider`. It **refuses to
  build** (`webapp.ErrIdentityNotRegisterable`) rather than mount a preset that cannot revoke.
  What survives a fully wired deactivation: an **already-issued access token**, until it expires —
  it is a stateless JWT and nothing consults a store to verify it, so keep `AccessTTL` short (the
  preset defaults to 15 minutes). There is no way to retract an access token in flight.
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
  `NewService` panics at construction if `WithDigits` is called with a value outside **[6, 10]**:
  values below 6 produce a trivially guessable code space (a 5-digit code has only 100 000
  candidates, giving a 50 % win rate with 5 attempts); values above 10 cause big.Int allocations
  with no security benefit. Most authenticator apps support only 6 and 8 digits.
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
  `argon2.IDKey`. Lower bounds (time ≥ 1, threads ≥ 1, memory ≥ 8×threads, non-empty derived key)
  prevent library panics. Upper bounds cap the work a single row can demand, because *every*
  parameter on the verify path comes out of storage and is therefore attacker-influenced (a
  tampered row, a hostile import, a corrupt migration):

  | parameter | ceiling | what it bounds |
  |---|---|---|
  | `m` | `MaxMemoryKiB` = 512 MiB (524 288 KiB) | `argon2.IDKey` allocates `memory × 1 024` bytes, so `m=4000000000` would attempt a multi-TiB allocation on the victim's next login |
  | `t` | `MaxTime` = 32 | iterations multiply CPU time linearly and `t` is a `uint32` (~4 billion passes), so one row could pin a core for hours on every login attempt |
  | `p` | `MaxThreads` = 64 | shape sanity: a parallelism far above any real core count marks a row this library never wrote |
  | derived key length | `MaxKeyLen` = 1 024 B | the final PHC segment sizes the KDF's output and extract cost (this library emits 32 B) |
  | salt length | `MaxSaltLen` = 1 024 B | the salt is absorbed by the KDF, so its length is work too (this library emits 16 B) |

  Any stored hash outside these bounds is rejected as `ErrInvalidPassword` (the same opaque
  mismatch signal as all other validation failures) *before* the KDF is invoked. Every ceiling is
  an order of magnitude or more above the largest published recommendation, so no legitimately
  produced hash is refused. The checks read only the stored hash, never the candidate password, so
  the constant-time property above is unaffected.
- **Envelope encryption of recoverable secrets (context-bound).** Some secrets cannot be hashed
  because the server has to recover them: per-tenant JWT signing keys (`keystore`), TOTP shared
  secrets (`mfa`), and OIDC `client_secret`s (`oauth`). Every one of them is sealed with a
  deployment KEK (`keystore.KEK`, AES-256-GCM) before it reaches a Store, so a database dump alone
  yields nothing usable — the attacker also needs the KEK, which belongs in the deployment's secret
  manager, not the database. The KEK is **mandatory**: `keystore.NewKEK` rejects any key that is not
  exactly 32 bytes, and `NewManager` / the pgx `mfa` and `oauth` stores refuse to construct without
  one. There is no "no encryption" mode.

  `Seal` binds a `keystore.SecretContext` — tenant, purpose, and the row's own identity — into the
  AEAD as **associated data**. Authenticating the bytes is not enough on its own: without a binding,
  a ciphertext is *portable*, so anyone who can write a row (a SQL injection, a restored foreign
  dump, a misrouted migration) can paste another tenant's sealed signing key into their own row and
  have the application decrypt and sign with it, or interchange a signing key and a TOTP secret
  between subsystems. With the binding, a blob only opens in the place it was sealed for; anywhere
  else it fails the tag and returns `keystore.ErrCiphertextCorrupt`. The contexts in use are:

  | secret | context (tenant, purpose, row) | helper |
  |---|---|---|
  | tenant signing key | tenant, `keystore/signing-key`, key id | `keystore.SigningKeyContext` |
  | TOTP shared secret | tenant, `mfa/totp-secret`, user id | `adapters/pgx/mfa.TOTPSecretContext` |
  | OIDC `client_secret` | tenant, `oauth/client-secret`, provider name | `adapters/pgx/oauth.ClientSecretContext` |

  The tenant in the context is the one the **operation** is scoped to, not the one recorded on the
  row, which is what makes a relocated row fail rather than resolve.

  Nonce discipline: a fresh 12-byte `crypto/rand` nonce per `Seal`, prefixed to the blob, never
  reused.

  **Sealed format and migration.** `Seal` writes a versioned blob,
  `0x01 || nonce(12) || ciphertext || tag`, with the context as associated data. `Open` accepts that
  **and** the legacy pre-binding format (`nonce(12) || ciphertext || tag`, no associated data) that
  earlier releases wrote, so upgrading needs no data migration to keep working — a legacy blob
  carries no binding, so it opens under any context. To finish the transition, re-seal each row:
  read it (the legacy blob still opens), `Seal` the plaintext under the row's context (see the table
  above), write it back. Once every row has been re-sealed, construct the KEK with
  `keystore.WithoutLegacySealedFormat()` so the unbound format is refused from then on — until then
  that option locks out every secret written by an earlier release.
- **Key provisioning is a signing-path privilege, never a verify-path side effect.** With
  `keystore.WithLazyProvisioning` an unknown tenant is provisioned (and a key minted) on first
  keyset resolution. That resolution happens only on the **signing** path, which runs for an
  authenticated, authorized issuance. The **verification** path — reachable by anyone presenting a
  token, or hitting a JWKS endpoint, for any tenant id they choose — resolves verification keys
  only and never the active signing key, so it cannot provision: an unauthenticated request for an
  unknown tenant fails closed with `keystore.ErrTenantNotFound` and writes nothing. This holds
  through the `tokens/jwt.CachingKeyStore` decorator, whose two cache halves are filled (and aged)
  independently precisely so a verify-path miss does not reach `ActiveSigningKey`.
- **Redaction on credential-bearing types (defence in depth).** The structs most likely to be
  logged or printed implement `fmt.Stringer`/`fmt.GoStringer` and `slog.LogValuer` so their
  secret fields render as `REDACTED` on the accidental-leak paths (`%v`/`%s`/`%+v`/`%#v`, `log`,
  `slog`): `tokens.TokenPair` (access + refresh token), `tokens.APIKey` (the clear-text `Token`),
  and — because the HS256 signing key is the most catastrophic secret to leak — `tokens/jwt.Config`,
  `tokens/jwt.SigningKey` and the running `tokens/jwt.Service` (its `SecretKey` / `SigningKeys[].Secret`
  and the resolved key bytes). The same treatment covers the two other recoverable secrets the
  library holds in memory: `keystore.SigningKey` (its `Secret` is the OPENED per-tenant HMAC secret
  or PKCS#8 private key, and a `%+v` would otherwise dump it as a byte slice) and, in `mfa`, both
  `TOTPEnrollment` and the freshly minted `Enrollment` — for the latter the provisioning `URI` is
  redacted alongside the secret, because `otpauth://…?secret=…` embeds it. Non-secret identifiers
  (key IDs, tenant, alg, issuer, expiry) stay visible to aid debugging. This is a safety net,
  **not** a licence to log these values (see below). JSON marshalling is intentionally **not**
  redacted, since returning a freshly issued token — or a freshly minted TOTP secret and its QR
  URI — to its owner in a response body is a legitimate use.
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
- **Access-token tenant binding (fail-closed when multi-tenant).** When one `tokens/jwt.Service`
  signs for every tenant under a shared key, a token minted for tenant A is cryptographically
  valid in tenant B's context. The tenant-unaware `VerifyAccessToken` performs **no** tenant
  comparison and is **deprecated**. Set `tokens/jwt.Config.MultiTenant = true` so that
  `VerifyAccessToken` fails closed with `tokens.ErrTenantBindingRequired`, and call
  `Service.VerifyAccessTokenForTenant(ctx, tenantID, token)` — it binds the signed `tenant_id`
  claim to the request tenant and rejects a mismatch with `tokens.ErrTenantMismatch`. The HTTP
  middleware exposes the same guarantee: `tokens.RequireAuth` with `tokens.WithAuthTenantResolver`
  resolves the request's tenant and verifies through `VerifyAccessTokenForTenant`. The resolver is
  fail-closed — returning `""` (tenant could not be resolved) rejects the request with `401` and
  never falls back to the tenant-unaware path, so a multi-tenant verifier is never reached
  unbound. Genuinely single-tenant deployments leave `MultiTenant` false (every token is issued
  under the empty tenant), configure no resolver, and may keep using `VerifyAccessToken` or the
  `SingleTenant` wrapper.
- **Tenant resolution is fail-closed on every HTTP surface.** Every `WithTenantResolver` /
  `WithAuthTenantResolver` option in the library (`identity`, `tokens`, `otp`, `oauth`, `sessions`)
  obeys one contract: a **configured** resolver MUST return a non-empty tenant ID for any request
  it can map, and a `""` return means "the tenant could not be resolved" (an unmapped `Host`, a
  missing path segment, an absent claim). The handler then REFUSES the request — `401
  tenant_unresolved` on the `identity`, `tokens` and `otp` surfaces, `403 tenant_unresolved` on
  `oauth`, `401` in `sessions.RequireSession` and `tokens.RequireAuth` — instead of falling back to
  the empty tenant. That fallback is what makes it a security property and not a nicety: `""` is a
  real partition, and in a single-tenant/bootstrap deployment it is where the operator accounts
  live, so failing open would let an unmapped host authenticate, register, reset a password or link
  an OAuth identity there. The `""` partition is used only when **no** resolver is configured at
  all (single-tenant mode), so single-tenant deployments are unaffected.
  Consequently: resolve the tenant through an **explicit allowlist / canonical mapping** (a
  host→tenant table, a validated path segment), never by returning the raw `Host` header — it is
  attacker-controlled and not canonical (case, port, trailing dot, IDN).
- **One tenant resolution per request.** Each handler resolves the tenant ONCE and pins that single
  value for every store operation it performs (authentication, the forced-password-change check,
  the MFA-enrollment gate, delivery events, the OAuth state binding and identity link). An impure
  resolver — an expiring cache entry, a transient store error returning `""` — therefore cannot
  make two steps of the same request operate on different partitions. That mattered: a per-step
  re-resolution let `identity.LoginHandler` consult the MFA gate in the wrong partition, find no
  enrollment, and issue a full renewable session on the password alone.
- **`__Host-` cookie name prefix** — the tokens package defaults to `__Host-access_token`
  and `__Host-refresh_token` (`DefaultAccessCookieName` / `DefaultRefreshCookieName`).
  Browsers enforce that a `__Host-` cookie is host-locked: `Secure`, no `Domain` attribute,
  and `Path=/`. This defeats subdomain/sibling-host cookie-tossing / refresh-token fixation,
  where an attacker on `evil.example.com` plants a `Domain=.example.com refresh_token` cookie
  containing the attacker's own token — the victim's auto-refresh then rotates the attacker's
  family and silently signs the victim into the attacker's session. `tokens.Cookies.Validate()`
  rejects any configuration that pairs a `__Host-` cookie name with `Domain != ""`, `Path != "/"`,
  or `Insecure == true` (and a `__Secure-` name with `Insecure == true`). That check runs at
  CONSTRUCTION: every handler and middleware constructor that takes a `Cookies` calls
  `MustValidate` (a startup panic), and `webapp.NewWebApp` returns it as an error. Writing or
  reading a cookie never panics at request time.
  Opting out is explicit and self-consistent rather than fatal: `WithCookieDomain`,
  `WithCookiePath`, `WithRefreshCookiePath` and `WithInsecureCookies` (and the underlying
  `Cookies.WithDomain` / `WithPath` / `WithRefreshPath` / `WithInsecure`) **demote** a `__Host-`
  name to `__Secure-` when the cookie is still `Secure` with `Path="/"`, and to the bare name
  otherwise. Demotion forfeits the host-lock hardening above — that is the price of the Domain,
  path scope or plain-HTTP development the option asked for, so reach for them deliberately.
  For the `sessions` package: `sessions.RequireSession` now reads the session token from
  `sessions.DefaultSessionCookieName` (`"__Host-session_token"`) **by default** — the hardened
  host-locked name is automatic and you no longer opt in. `sessions.WithCookieName` is an escape
  hatch for deployments that genuinely cannot satisfy the `__Host-` requirements (e.g. a
  path-scoped cookie or local plain-HTTP development); overriding to a name without the prefix
  forfeits the host-lock hardening and is the consumer's explicit choice.
- **OAuth state cookie carries secrets in plaintext.** The short-lived OAuth `state` cookie
  (default name `oauth_state`) is a plain concatenation of the CSRF state, the **PKCE code
  verifier**, the **OIDC nonce**, the provider name and the tenant — it is *not* signed or
  encrypted. Its integrity model is "the attacker cannot read or write the cookie," resting on
  `HttpOnly` + `Secure` + `SameSite=Lax` (set automatically) plus a constant-time `state`
  comparison on callback — **not** on the cookie being tamper-evident. Two consequences for the
  consumer:
  - **Never log or mirror request cookies.** The verifier and nonce sit in the cookie in
    plaintext; any infra that logs cookies, ships them to an observability backend, or proxies
    them through something that persists headers is recording sensitive material.
  - **Do not move `state` out of the cookie without re-deriving the guarantee.** If you refactor
    it to a server-side handle, a header, or a differently-prefixed cookie, you can silently
    lose the read/write protection the current scheme depends on.
  Unlike the `tokens`/`sessions` cookies, the state cookie name is **not** `__Host-` prefixed by
  default (it must survive the provider's top-level redirect, which `SameSite=Lax` already
  handles; `__Host-` is independently compatible). For defence against subdomain cookie-tossing,
  set a `__Host-`-prefixed name via `oauth.WithStateCookieName("__Host-oauth_state")` **when your
  deployment serves OAuth over HTTPS with no cookie `Domain`** (the `__Host-` prefix requires
  `Secure`, `Path=/`, and no `Domain`).
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

## CSRF on the form handlers (strict same-origin by default)

`LoginHandler`, `RegisterHandler`, the authenticated identity mutations
(`ChangePasswordHandler`, change-email, delete-account, recovery, phone/email
verification), `RefreshHandler`, `LogoutHandler`, the `mfa` handlers and the `otp`
handlers are all state-changing endpoints driven by the request (form body / cookies).
egauth does **not** ship a full CSRF-token system (per the PRD, that is left to the
application layer), but it now applies a **strict same-origin check on every one of these
handler families by default**:

- **Same-origin is enforced even with no configuration.** A state-changing POST is allowed
  only when its `Origin` (or `Referer` fallback) host equals the request's own `Host` or an
  explicitly allow-listed host. A browser-driven POST carrying **neither** `Origin` nor
  `Referer` is treated as untrusted and rejected with `403 cross_site_blocked`. This closes
  the **login-CSRF / session-fixation** gap (where `SameSite` does *not* help, because the
  attack needs no pre-existing cookie) and the MFA/OTP downgrade gaps (a cross-site POST to
  `DisableHandler`/`RegenerateRecoveryCodesHandler` stripping a victim's second factor)
  *out of the box* — the previous behavior, where an empty allowlist disabled the check, is
  gone.
- **`SameSite=Lax` cookies** (default) remain a second layer: they stop a cross-site request
  from *sending* the refresh/session cookie, protecting `RefreshHandler`/`LogoutHandler`
  against classic CSRF on an existing session.
- **`WithTrustedOrigins(...)`** (on `identity`, `tokens`, `mfa`, `otp`) **widens** the
  same-origin allowlist to additional hosts — e.g. a front-end served from another subdomain.
  Supply hostnames without scheme, e.g. `identity.WithTrustedOrigins("app.example.com")`.
- **`WithInsecureNoOriginCheck()`** (on `identity`, `tokens`, `mfa`, `otp`) is the explicit,
  loudly-named opt-out: it disables the same-origin check entirely, restoring the pre-v1
  accept-all behavior. Only reach for it when CSRF is handled by a separate layer (e.g. a
  synchronizer/double-submit token middleware) or in trusted test setups.

The **`webapp` v1 preset** (`webapp.NewWebApp`) carries this guarantee across both handler
families it mounts: it **refuses to build** when `Config.TrustedOrigins` is empty unless you
explicitly set `Config.InsecureNoOriginCheck`, in which case the opt-out is wired into *both*
the identity and tokens handlers so the preset is consistently insecure rather than protecting
only one half. This makes "CSRF-by-default" mean the same thing across every endpoint the
preset exposes.

The **`mfa` handlers** (`EnrollHandler`, `ConfirmHandler`, `VerifyHandler`,
`VerifyRecoveryHandler`, `RegenerateRecoveryCodesHandler`, `DisableHandler`,
`StepUpHandler`) are also state-changing POST endpoints, and — like the identity and token
handler families — they enforce the strict same-origin check **by default**. Even with no
configuration, a cross-site form POST that would otherwise silently strip a victim's second
factor (MFA downgrade via `DisableHandler`) or invalidate their recovery codes
(`RegenerateRecoveryCodesHandler`) is rejected with `403 cross_site_blocked`. Use
**`mfa.WithTrustedOrigins(...)`** to *widen* the `Origin`/`Referer` host allowlist to additional
hosts when the MFA endpoints are reachable from a browser session on another origin (e.g. a
cross-subdomain or embedded app); supply hostnames without scheme, e.g.
`mfa.WithTrustedOrigins("app.example.com")`. The check is turned off only via the explicit
`mfa.WithInsecureNoOriginCheck()` opt-out.

## Observability and idempotency (consumer responsibility)

**Observability** — wire `event.Sink` to your metrics pipeline or audit log. The ready-made
`event.NewSlogSink` covers the "log it with slog" case. For OpenTelemetry tracing, egauth ships
a reference adapter at `github.com/JLugagne/egauth/adapters/otel`:

```go
import (
    "go.opentelemetry.io/otel"
    egauthotel "github.com/JLugagne/egauth/adapters/otel"
    "github.com/JLugagne/egauth/event"
)

tracer := otel.Tracer("egauth")
sink   := egauthotel.NewSpanSink(tracer)

// Fan out to both slog and spans:
combined := event.MultiSink(event.NewSlogSink(nil), sink)
```

`NewSpanSink` creates one child span per security event (auth success/failure, MFA, refresh
rotation, token-family revocation, insecure-cookie misuse, etc.) with `egauth.*` attributes and
records errors via `span.RecordError`. For Prometheus counters or SIEM ingestion, implement
`event.Sink` directly or use `event.MultiSink` to fan out. Every operation propagates a
`context.Context`, so span propagation and deadline enforcement are fully under the consumer's
control.

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

## Breach-check fail-open vs fail-closed (consumer responsibility)

`passwords.BreachChecker` is a **hook** — egauth ships the interface and makes no network calls
itself. When you wire a HIBP (or other) client into the password policy and that client errors
(service down, timeout, rate-limited), the policy propagates the **raw error unchanged**. How
your handler reacts to that error is an explicit security-posture decision with no safe default,
and it is invisible unless you look for it:

- **Reject on any policy error → fail-closed.** A breach-service outage blocks every registration
  and password change (an availability hit), but no unscreened password is ever accepted.
- **Special-case only `ErrPasswordBreached` and let other errors pass → fail-open.** An outage
  silently disables breach screening and weak/known-breached passwords sail through — and because
  nothing fails loudly, a fail-open can go unnoticed for months.

Neither is wrong; the choice depends on whether you value availability or screening guarantees
more. **Consumer guidance:** decide deliberately, wrap your `IsBreached` implementation in a
**timeout** so a hung upstream cannot stall the auth path, and **log/alert when it errors** so a
silent fail-open is observable. Treat the breach check as advisory defence-in-depth on top of the
length/denylist policy, not as the primary control.

## Custom store adapters: atomicity is on you (consumer responsibility)

The library's most important runtime guarantees — refresh-token single-use (replay detection),
TOTP single-use, and failed-attempt lockout — are *enforced in the service layer but depend on
the store implementing specific methods atomically*. The bundled `pgx` adapters do this correctly
(`ConsumeRefreshToken` is an `UPDATE … WHERE consumed_at IS NULL`; `MarkTOTPUsed` is a
compare-and-set on a strictly increasing step; `IncrementFailedAttempts` is a single atomic
`UPDATE` whose post-increment result drives the lock decision and the `account.locked` event).

These contracts are documented in the store **interface comments**, not enforced by the compiler.
If you write your own adapter (or modify the bundled one) and implement any of these as a
non-atomic read-then-write, you **silently break the guarantee** — replay detection stops working,
a TOTP code becomes reusable, or the lockout audit event mis-fires — and nothing fails loudly.

**Consumer guidance:** treat those methods as concurrency-critical and test them under parallel
load. The repo ships contract test suites for exactly this — run `identity/storetest`,
`tokens/storetest`, `mfa/storetest`, and the equivalent per-module suites against your adapter;
they assert the atomic behaviours (including that `IncrementFailedAttempts` reports the locking
transition exactly once) that the service layer relies on.

## Account-existence disclosure (by design)

Three responses intentionally reveal that an account exists; this is an accepted trade-off,
not a bug:

- **`ErrAccountLocked` / `ErrAccountDisabled` → 429** on login: lockout and administrative
  suspension are both meant to be observable (PRD §105–106). Both map to the same 429 response
  so suspended accounts are indistinguishable from locked ones to an external observer.
  Note this disclosure is at the **status-code** level by design. The login path additionally
  spends a decoy Argon2id hash on the locked and disabled rejection branches (matching the
  unknown-user / wrong-password paths) so the *response time* of those branches does not become
  a second, redundant enumeration oracle — keeping all in-process timing uniform and robust
  against a future refactor that collapses the 429 back to a generic 401.
- **`email_taken` → 409** on registration: standard registration UX. If your threat model
  requires anti-enumeration on sign-up, collapse `mapRegisterError` to a single generic
  `400` (note that `Register` already hashes before the uniqueness check, so the timing
  channel is already closed).
- **`email_taken` → 409** on the authenticated change-email request
  (`RequestEmailChangeHandler`): the caller is told up front when the requested new address
  already belongs to another account, mirroring the registration disclosure. This is gated
  behind authentication *and* the handler's step-up bar (a higher bar than sign-up) and gives the
  user a clear "pick another address" response. If your threat model forbids it, drop the pre-flight `FindUserByEmail`
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
