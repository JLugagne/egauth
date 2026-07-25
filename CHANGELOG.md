# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### BREAKING

- **The `passkey` HTTP handlers now enforce a strict same-origin CSRF check, and the ceremony cookie
  is `__Host-` prefixed (`mfa/SF-9`, `http/SF-9`, `http/HTTP-7`, `http/HTTP-10`).** The passkey
  handler family was the only one with no origin check at all, so `RenameCredentialHandler` and every
  ceremony endpoint were CSRF-reachable. Every state-changing passkey handler now refuses a POST
  whose `Origin` (or `Referer` fallback) host is neither the request `Host` nor an allowlisted one
  with `403 cross_site_blocked`, and a POST carrying neither header counts as untrusted — matching
  identity/tokens/mfa/otp exactly. Widen with `passkey.WithTrustedOrigins("app.example.com")`; the
  loud opt-out is `passkey.WithInsecureNoOriginCheck()`. Browser clients are unaffected (browsers
  send `Origin` on form/fetch POSTs); non-browser callers and tests must send `Origin` or opt out.
  `passkey.DefaultSessionCookieName` changed from `passkey_ceremony` to `__Host-passkey_ceremony`;
  `WithCookieDomain` / `WithInsecureCookies` DEMOTE the name (`__Secure-` or bare) instead of
  emitting a cookie browsers reject, and Begin/Finish always derive the same name. In-flight
  ceremonies at deploy time fail once and are retried by the client.

- **`passkey.NewService` rejects an entropy-free ceremony-cookie key (`crypto/CRY-8`, `EX-2`).**
  `MinCookieKeyLength` only checked length, so the `make([]byte, 32)` placeholder — which the shipped
  `examples/fullstack` reference application actually used — sailed through and every ceremony cookie
  it sealed was forgeable. A key whose bytes are all identical is now refused with the new sentinel
  `passkey.ErrCookieKeyWeak`, at construction and on the per-handler / per-tenant key paths (which
  fail the request closed with 500). The example now generates its key with `crypto/rand`.

- **`mfa.StepUpHandler` no longer asserts a password factor that was never presented (`mfa/SF-10`).**
  It stamped `AMR=[pwd, otp, mfa]` unconditionally, claiming a password for a subject who may have
  signed in with a magic link or a federated IdP — a false security assertion consumed by
  `tokens.WithRequiredAMR`. The re-issued AMR is now `[otp, mfa]` (the factors the ceremony actually
  verified), prefixed with the interim credential's own factors when the new
  `mfa.WithPriorAMR(tokens.PriorAMRResolverFromContext[C])` seam is wired — which restores the exact
  previous value for a password login. Deployments that gate on `AMRPassword` being present after a
  step-up must wire `WithPriorAMR`.

- **`tokens.RefreshToken` gained `Kind` and `FamilyCreatedAt`, and the token layer now enforces an
  absolute refresh-FAMILY lifetime by default (`lifecycle/LIFE-2`, `lifecycle/KIND-2`).** The struct
  change is additive (existing code compiles), but a custom `tokens.Store` MUST round-trip both
  fields or the absolute cap loses its anchor and the principal kind is dropped on every refresh —
  run `tokens/storetest`, whose refresh-token contract case now asserts both. Postgres users must
  apply the new migration `adapters/pgx/tokens/migrations/008_add_refresh_family_lifetime_and_kind.sql`
  (two nullable columns, `family_created_at` and `kind`); legacy rows keep working, falling back to
  the row's own `created_at` as the cap anchor.
  Behaviourally, a family now dies 30 days (`jwt.DefaultMaxRefreshFamilyLifetime`) after its
  creation however often it is rotated. Deployments relying on indefinitely renewable refresh
  families must set `jwt.Config.MaxRefreshFamilyLifetime` to a longer value, or opt out explicitly
  with `DisableMaxRefreshFamilyLifetime` (insecure).

- **`identity.Store` gained `MarkEmailVerified`, and `DeleteUser` now releases the account's provider
  identities (`identity/TEN-5`, `identity/TEN-6`).** Both change the backend contract, so a custom
  `identity.Store` implementation must be updated (the shipped memory and pgx backends already are;
  run `identity/storetest` against yours).
  - New method
    `MarkEmailVerified(ctx, tenantID string, userID uuid.UUID, verifiedAt time.Time) error` writes
    ONLY `email_verified_at` on a live user (`ErrUserNotFound` otherwise) and is what `VerifyEmail`
    now uses. New contract case: `storetest.StoreMarkEmailVerifiedContract`.
  - `DeleteUser` must now anonymize the `provider_id` of **every** identity row of the account, not
    just the password one, and must derive the anonymized value **per row** so an account holding
    several identities of one provider still deletes cleanly.
    `storetest.StoreDeleteAuthGateContract` was inverted accordingly: it used to require the OAuth
    `provider_id` to be preserved and now requires it to be released.
  - `UpdateIdentityPassword` must now refuse a SOFT-DELETED owner with `ErrUserNotFound` (it kept
    returning success and re-armed the credential). New contract case:
    `storetest.StorePasswordRotationLivenessContract`.

- **KEK-sealed secrets are now bound to WHERE they belong (`crypto/CRY-1`).** `keystore.KEK.Seal` /
  `Open` took no context and passed `nil` GCM associated data, so a sealed blob authenticated its
  bytes but not its position: a ciphertext was **portable** between rows, tenants and subsystems. A
  signing-key ciphertext and a TOTP-secret ciphertext were interchangeable at the storage layer, and
  anyone able to write a row (a SQL injection, a restored foreign dump, a misrouted migration) could
  paste another tenant's sealed signing key into their own row and have the application decrypt and
  sign with it — a confused deputy. Both cases are now regression-tested end to end.

  - New type `keystore.SecretContext{TenantID, Purpose, RowID}` is bound into the AEAD as associated
    data. `Purpose` is required (`keystore.ErrSecretContextIncomplete` otherwise); the shipped labels
    are `keystore.PurposeSigningKey`, `PurposeTOTPSecret` and `PurposeOAuthClientSecret`. Helpers
    build the context for each call site: `keystore.SigningKeyContext(tenantID, keyID)`,
    `adapters/pgx/mfa.TOTPSecretContext(tenantID, userID)`,
    `adapters/pgx/oauth.ClientSecretContext(tenantID, providerName)`. On the open path the tenant is
    the one the **operation** is scoped to, not the one recorded on the row, so a relocated row fails
    instead of resolving.
  - **Signature changes.** `KEK.Seal(sc, plaintext)`, `KEK.Open(sc, sealed)` and
    `keystore.Manager.SealSecret(sc, plaintext)` gained a leading `SecretContext`. The pgx `KEK`
    interfaces changed to match: `adapters/pgx/mfa.KEK` is now
    `Seal(keystore.SecretContext, []byte)` / `Open(keystore.SecretContext, []byte)`, and
    `adapters/pgx/oauth.KEK` is `Seal(ctx, keystore.SecretContext, []byte)` /
    `Open(ctx, keystore.SecretContext, []byte)`. `*keystore.KEK` satisfies the former directly.
    **Action required** only for code that calls `Seal`/`Open`/`SealSecret` itself or supplies its own
    KEK implementation (e.g. a KMS-backed one): thread the context through. Nothing else changes —
    `NewKEK` is now variadic and existing calls compile unchanged.
  - **Sealed format, and NO data migration to keep working.** `Seal` writes
    `0x01 || nonce(12) || ciphertext || tag` with the context as associated data. `Open` accepts that
    **and** the legacy pre-binding format (`nonce(12) || ciphertext || tag`, no associated data), so
    every secret already at rest keeps opening across the upgrade while everything newly written is
    bound. A legacy blob carries no binding, so it opens under any context — that is the compatibility
    this buys, and the reason to finish the transition. To finish it, re-seal each row (read it, `Seal`
    the plaintext under the row's context, write it back) and then build the KEK with the new
    `keystore.WithoutLegacySealedFormat()`, which refuses the unbound format from then on. Nonce
    discipline is unchanged: a fresh 12-byte `crypto/rand` nonce per `Seal`, prefixed, never reused.
    Documented in SECURITY.md (*Envelope encryption of recoverable secrets*) and `.llms/storage-pgx.md`.

- **An out-of-range Argon2id parameter in a STORED hash is now rejected (`crypto/CRY-3`).**
  `argon2.Hasher.Compare` capped the memory parameter read out of a stored PHC string but not the
  iteration count, so one tampered row — or a hostile import — drove unbounded CPU on the login path
  (`t` is a `uint32`: ~4 billion passes). New exported ceilings `MaxTime` (32), `MaxThreads` (64),
  `MaxKeyLen` (1024 B) and `MaxSaltLen` (1024 B) join the existing `MaxMemoryKiB`; a stored hash
  outside any of them is rejected as `passwords.ErrInvalidPassword` *before* the KDF runs. Every
  ceiling is an order of magnitude or more above the largest published recommendation, so no
  legitimately produced hash is refused — but a deployment that hand-wrote hashes with absurd
  parameters will now see those rows fail to verify. The checks read only the stored hash's shape,
  never the candidate password, so the documented constant-time property is preserved.

- **A TOTP shared secret below 128 bits is now refused (`crypto/CRY-9`).** `mfa` accepted an empty or
  truncated secret, keying the HMAC with (nearly) no entropy and making every code it produced
  computable by anyone — a second factor that verified an attacker-derived code. Secrets decoding to
  fewer than the new `mfa.MinSecretBytes` (16) are rejected with the new `mfa.ErrWeakSecret` at
  enrollment **and** at verification (`EnrollTOTP`, `ConfirmTOTP`, `VerifyTOTP`, `GenerateCode`), and
  `mfa.ValidateSecret` is exported for callers importing enrollments minted elsewhere. A row damaged
  by a bad import now surfaces `ErrWeakSecret` instead of `ErrInvalidCode`: that is a broken record,
  not a wrong code.

- **`identity.Store` gained `DeleteVerificationTokensForUser`, and a password reset now purges the
  account's pending token-borne credentials.** A password reset is the canonical response to "I think
  I am compromised", but nothing invalidated the *verification tokens* minted while the attacker held
  the account, and the `Store` exposed no per-user purge seam, so a consumer could not fix it either.

  - New method on the `identity.VerificationTokenStore` capability (and therefore `identity.Store`):
    `DeleteVerificationTokensForUser(ctx, tenantID string, userID uuid.UUID, kinds ...string) error`.
    An empty `kinds` list purges every kind. It is idempotent (an unknown user or nothing pending is a
    success) but MUST report a genuine backend failure — a silent success would leave the attacker's
    token redeemable. **Action required** for external `identity.Store` implementers: add the method
    and run `identity/storetest` (`StoreVerificationTokenPurgeContract` and, for multi-tenant
    backends, `StoreVerificationTokenPurgeTenantScopeContract`) to verify conformance. The in-memory
    and pgx backends implement it; the pgx `DELETE` is served by the existing
    `idx_verification_tokens_user` index, so **no new migration** is required.
    `identity/storetest.MockStore` gained the matching `DeleteVerificationTokensForUserFunc` — an
    unset func is a no-op success there, so existing tests built on the mock keep compiling.
  - `identity.Service.ResetPassword`, `ChangePassword`, `SetTemporaryPassword` and `DisableUser` now
    call it for every credential-bearing kind: `KindPasswordReset`, `KindMagicLink`, `KindEmailChange`,
    `KindPhoneVerification`, `KindRecoveryEmailVerification`. `KindEmailVerification` is deliberately
    kept (it only verifies the address the account already owns). The purge runs after the new hash /
    `DisabledAt` is committed and its error is joined into the returned error, so the account is
    authoritatively re-keyed and the idempotent call can be retried.
  - For `DisableUser` this makes the documented revocation of pending token-gated actions
    **permanent**: previously `consumeForLiveUser` only refused them *while* `DisabledAt` was set, so a
    magic-link or email-change token minted before the suspension became usable again the moment
    `EnableUser` cleared it.

- **`identity.RequestEmailChangeHandler` and `identity.RequestRecoveryEmailHandler` now enforce a
  step-up bar.** Both refuse a pre-step-up interim credential — and, failing closed, any request whose
  assurance cannot be resolved — with `403 step_up_required`; with `identity.WithMFAGate` configured an
  MFA-enrolled user must additionally present a credential carrying a step-up factor. A session alone
  could previously move the account's login address to `attacker@evil` (locking the victim out of their
  own address) or install an attacker-controlled recovery channel that then drives
  `RequestPasswordResetViaRecovery`. **Action required:** mount both handlers behind
  `tokens.ContextMiddleware`, or supply `identity.WithAssuranceResolver`; opt out deliberately with
  `identity.WithInsecureNoStepUpCheck()`.

- **MFA is now an ENFORCED control, not advisory.** The pre-step-up credential minted by an MFA-gated
  login is stamped `tokens.Claims.Interim` (new field, JWT claim `interim`, omitted for ordinary
  sessions) and is no longer accepted as a session:

  - `tokens.RequireAuth` / `tokens.ContextMiddleware` refuse an interim credential with
    `403 step_up_required` on **every** route unless the route opts in with the new
    `tokens.WithInterimAllowed[C]()`. **Action required:** add that option to the route hosting
    `mfa.StepUpHandler` (and any other endpoint that must be reachable before the second factor);
    without it the step-up flow cannot complete.
  - `mfa.DisableHandler` and `mfa.RegenerateRecoveryCodesHandler` now refuse any request whose
    credential does not prove a second factor (`Claims.SatisfiesStepUp()`: AMR carries `mfa`, `otp`
    or `hwk` and the credential is not interim) with `403 step_up_required`. A password-only session
    can no longer strip MFA or invalidate the victim's recovery codes.
  - `identity.ChangePasswordWithReissueHandler` (which mints a full renewable pair) and
    `identity.DeleteAccountHandler` (irreversible) now refuse an interim credential with
    `403 step_up_required`. With `identity.WithMFAGate` also passed, `DeleteAccountHandler`
    additionally requires an MFA-enrolled user to present a step-up factor.
  - All four checks **fail closed**: a request whose assurance cannot be resolved is refused. The
    assurance is read from the new `tokens.AssuranceResolverFromContext` by default, so mounting the
    handler behind `tokens.ContextMiddleware` is the only wiring needed. **Action required** for a
    deployment whose access token is verified by a middleware of its own: supply
    `mfa.WithAssuranceResolver` / `identity.WithAssuranceResolver`, or opt out explicitly with
    `mfa.WithInsecureNoStepUpCheck()` / `identity.WithInsecureNoStepUpCheck()`.

- **An MFA-gated login now CLEARS any existing refresh cookie.** The pre-step-up state claims not to
  be renewable, so it no longer leaves a refresh cookie from an earlier session in the browser. A
  client that observes a refresh cookie must therefore treat its disappearance after a login as
  "second factor required", not as a bug.

- **An MFA-gated login no longer replies `204`/`successURL`.** It was previously byte-identical to a
  full login, leaving the client no signal to drive the second factor. The pre-step-up reply now
  carries the `X-Egauth-MFA-Required: 1` header (`identity.MFARequiredHeader`) plus either
  `200 {"mfa_required":true}` or, when the new `identity.WithMFARequiredRedirect(url)` /
  `oauth.WithMFARequiredRedirect(url)` is set, a `303` to that URL. The full-login response is
  unchanged. **Action required** for browser-driven deployments using `WithSuccessRedirect`:
  configure the matching MFA-required redirect.

- **`tokens.WithMaxAuthAge` is no longer documented as sufficient** to gate a factor-mutating or
  destructive route: a freshly minted interim credential passes an `auth_time` freshness window
  trivially. Use `tokens.WithRequiredAMR(tokens.AMRMFA)`, optionally alongside `WithMaxAuthAge` for a
  sudo-mode window. The guidance in `mfa.Service.DisableTOTP`, `identity.Service.DeleteAccount`,
  `identity.Service.RecoveryChannels`, `SECURITY.md` and `.llms/mfa.md` has been corrected.

- **A configured tenant resolver that returns `""` now refuses the request** (`identity`, `tokens`,
  `otp`, `oauth`). Behavioural, not an API change: no signature moved. Previously `""` was passed
  through verbatim and the request operated on the empty tenant partition. A deployment that
  configured a resolver and relied on its `""` return to mean "the default partition" now receives
  `401 tenant_unresolved` (`403` on `oauth`) and must either map those requests explicitly or
  configure no resolver at all (single-tenant mode, where `""` remains the legitimate partition).

- **`identity.Service` gained `EnsureActive`, and `webapp.Config.Identity` must now implement
  `identity.RevocationRegistry`.** Both changes serve one guarantee: account deactivation ends
  access.

  - `EnsureActive(ctx, tenantID, userID) error` is a new method on the `identity.Service`
    **interface** (and on `identity.SingleTenant`). **Action required** only for code that
    implements `identity.Service` itself — add the method (or embed the real Service);
    `identity.servicetest.MockService` already has it, defaulting to "active" when its
    `EnsureActiveFunc` is unset.
  - `webapp.NewWebApp` now returns `webapp.ErrIdentityNotRegisterable` when `Config.Identity` does
    not implement the new `identity.RevocationRegistry` seam. The `Service` returned by
    `identity.NewService` does, so ordinary wiring is unaffected; a hand-written `identity.Service`
    passed to the preset must implement it (or embed the real Service). Failing construction is
    deliberate: without that seam the preset cannot revoke the refresh families it issues.
  - `webapp.NewWebApp` now MUTATES the service it is handed, registering an account revoker on it.
    Wire the preset once, at startup, before serving traffic.

- **Key revocation now holds on the pgx keystore backend (new migration required).**
  `adapters/pgx/keystore` derived tenant existence from the presence of key rows, so
  `RevokeTenantKeys` — which deletes every key row — made the tenant look *unknown*. A
  `keystore.Manager` built with `WithLazyProvisioning` answers `ErrTenantNotFound` by minting a fresh
  key, so an emergency revocation was silently reversed on the next keyset resolution (fail-open),
  and `VerificationKeys` / `Manager.JWKS` returned `ErrTenantNotFound` instead of an empty key set,
  erroring a `/.well-known/jwks.json` handler after a revoke.

  - **New migration `003_create_keystore_tenants_table.sql`** — run `keystore.Migrate` on upgrade. It
    creates `keystore_tenants`, backfills it from existing `keystore_keys` rows (no tenant is lost),
    and makes `keystore_keys.tenant_id` a foreign key onto it with `ON DELETE CASCADE`. Code that
    inserts `keystore_keys` rows directly must insert the tenant row first.
  - `RevokeTenantKeys` now deletes key rows only; the tenant record survives until `DeleteTenant`.
    `ActiveSigningKey` returns `ErrNoActiveKey` (not `ErrTenantNotFound`) for a revoked tenant, and
    `VerificationKeys` returns an empty map with a nil error.
  - The `keystore.Store` doc comment now states this sentinel contract explicitly. **Action required**
    for external `keystore.Store` implementers: keep a tenant record independent of key rows and run
    `keystore/keystoretest.StoreContractTesting`, which gained `RevokeKeys` store-level sentinel
    assertions and a new `RevokeSurvivesLazyProvisioning` case.
  - `adapters/pgx/keystore.NewStore` is now variadic (`NewStore(db, opts ...Option)`) and accepts
    `WithClock`; the pgx backend evaluates key activity/expiry with the **application** clock instead
    of SQL `now()`, so it agrees with the `Manager` that stamped `NotAfter`. Existing calls compile
    unchanged. The pgx backend is now wired into the shared conformance suite
    (`TestPgxKeystore_StoreContract`), which previously skipped it for want of an injectable clock.

### Added

- **`identity/storetest` and `tokens/storetest` gained parallel-load contract cases
  (`claims/DOC-5`).** SECURITY.md tells custom-adapter authors to run these suites because they
  "assert the atomic behaviours ... under parallel load", but until now only `mfa/storetest` had a
  genuine concurrency case — the identity/tokens suites were purely sequential, so a deliberately
  non-atomic `ConsumeVerificationToken`, `IncrementFailedAttempts`, or `ConsumeRefreshToken` passed
  them clean. Each now fires 64 concurrent callers at the same record and asserts exactly one
  winner (single-use consumption, or the locking transition reported exactly once), run with
  `-race` against the memory backend. A custom adapter that was silently non-atomic will now fail
  these suites.

- **`internal/doctest` now catches a fabricated struct field or method, not just a fabricated
  top-level symbol, and scans `SECURITY.md` and every `.llms/*.md` file (`claims/DOC-1`).**
  Previously it only resolved bare `pkg.Symbol` references via `go doc`, so a doc example using
  `Config{MultiTenant: true}` or `svc.VerifyAccessToken(...)` — fields/methods that never existed —
  passed silently; this is exactly how `tokens/jwt.Config.MultiTenant` and
  `jwt.Service.VerifyAccessToken` shipped in the docs. It now additionally parses each fenced Go
  block's AST for `pkg.Type{Field: ...}` composite literals and `x := pkg.Func(...); x.Method(...)`
  chains and checks each against the real API, conservatively skipping anything ambiguous. It also
  now runs as `go test ./internal/doctest/...`, so a doc-vs-code drift fails `go test ./...`, not
  only the separate CI step.

- **`adapters/pgx/passkey.NewChallengeStore` — the SHARED, Postgres-backed passkey
  `ChallengeStore` (`mfa/SF-4`).** `Config.ChallengeStore` is required, but the only implementation
  that ever shipped was the per-process in-memory one, so a multi-replica deployment rejected roughly
  `(N-1)/N` of its ceremonies as replays and the pressure-relief valve an operator found was
  `InsecureNoChallengeStore` — silently removing the SEC-05 replay defence. `Consume` is a single
  `DELETE ... RETURNING`, so exactly one of N racing Finish requests wins across processes; `Put`
  upserts; `DeleteExpired(ctx)` is the pruning path for ceremonies that are never finished. Ships with
  migration `adapters/pgx/passkey/migrations/003_create_passkey_challenges.sql`. Both backends are now
  pinned by the new shared contract suite `passkey/storetest.ChallengeStoreContractTesting`.
  SECURITY.md pointed at a `passkey/pgx` package that never existed; it and the `passkey/memory` doc
  comment now name the real one.

- **`mfa.StepUpRecoveryHandler` — recovery-code self-service (`mfa/SF-6`).** No shipped handler
  converted a recovery code into a session (`StepUpHandler` is TOTP-only and `VerifyRecoveryHandler`
  mints nothing), so a user who lost their authenticator had no way back in. The new handler redeems a
  single-use recovery code and re-issues the same full access+refresh pair, stamped
  `AMR=[tokens.AMRRecoveryCode, tokens.AMRMFA]`, with the same single-use semantics, shared
  failed-attempt budget and CSRF guard as the rest of the family.

- **`tokens.AMRRecoveryCode` (`"rc"`) and `tokens.PriorAMRResolverFromContext[C]`.** The former records
  a redeemed recovery code (RFC 8176 registers no value for it; `"otp"` means HOTP/TOTP) and counts as
  a step-up factor in `HasStepUpFactor` / `SatisfiesStepUp`, and is stripped by `AsInterim` like the
  other step-up markers. The latter surfaces the interim credential's proven factors to
  `mfa.WithPriorAMR`.

- **`passkey.WithTrustedOrigins` / `passkey.WithInsecureNoOriginCheck`** — the CSRF allowlist seam and
  its loud opt-out for the passkey handler family (see BREAKING).

- **`passkey/memory.WithMaxEntries` and `memory.DefaultMaxChallengeEntries` (100k).** The in-memory
  `ChallengeStore` is now hard-capped, evicting oldest-first.

- **`jwt.Config.MaxRefreshFamilyLifetime` / `DisableMaxRefreshFamilyLifetime` /
  `jwt.DefaultMaxRefreshFamilyLifetime` (30 days)** cap the ABSOLUTE lifetime of a refresh-token
  family, anchored on the family's creation, mirroring `sessions.WithMaxLifetime`. Every rotation is
  clamped to `min(now+RefreshTTL, familyCreatedAt+cap)` — never extended — and `Rotate` reports
  `tokens.ErrTokenExpired` past the deadline. The cap is on by DEFAULT: an unset value selects
  `max(DefaultMaxRefreshFamilyLifetime, RefreshTTL)` so it never shortens a single configured token,
  a NEGATIVE value is a `Validate` error normalised to the default (never a silent opt-out), and
  combining an explicit cap with the disable flag keeps the CAP (fail secure) while `Validate`
  reports the contradiction.
- **`jwt.Config.SupersededRefreshRetention`** (opt-in, default off) shortens how long a
  rotated-away refresh row is retained so the reaper can collect it, bounding the
  `RefreshTTL / rotation-interval` row growth of a long-lived session. It is an explicit trade-off —
  it narrows the window in which a replay of that token still revokes the family — and a value below
  `ReuseGracePeriod` is raised to it so benign-concurrency detection is never blinded.
- **`tokens.PrincipalKindForKeyType(KeyType)`** exposes the single key-type → `egauth.PrincipalKind`
  mapping shared by `ActorFromAPIKey` and the issuer (which now stamps it on every minted key).
- **`identity.WithRevocationTimeout(d)` / `identity.DefaultRevocationTimeout`** bound the detached
  revocation cascade of the credential-rotating flows (30s by default; a non-positive value keeps
  the default, the cascade is never unbounded).
- **`identity.MaxEmailLength` (254) and `identity.ErrEmailTooLong`** cap the canonicalized address
  in every flow that validates one (`identity/TEN-16`). The enumeration-safe `Request*` flows keep
  treating an oversized address exactly like a malformed one; the handlers map it to the existing
  `400 invalid_email`.
- **`identity.ErrDeliveryPanic`** is joined into the `Err` of the `DeliveryFailed` event emitted when
  a consumer delivery callback panics (see Fixed).
- **Documented: a tenant holds at most ONE email-less account** (refuter-found). A provider account
  that supplies no usable email is provisioned with an EMPTY email, and the email slot is unique per
  tenant, so the second such provisioning returns `ErrEmailAlreadyExists` rather than collapsing two
  provider accounts into one. `LinkOrCreateIdentity`'s contract now says so explicitly and a test
  pins it; deployments needing several must supply a synthetic unique address.

- **The MFA login gate now covers every login path.** `identity.WithMFAGate` applies to
  `MagicLinkLoginHandler` as well as `LoginHandler` (a magic link is a first factor: a compromised
  mailbox no longer bypasses the second factor), and the new `oauth.WithMFAGate(checker)` +
  `oauth.WithInterimTokenTTL(d)` bring the same gate to `CallbackHandler` /
  `DynamicCallbackHandler`, so an IdP-account compromise no longer yields a full renewable local
  session. An enrollment-check error fails closed on every path.

- **`tokens.AccessTokenIssuer[C]`**, an optional extension of `tokens.Issuer` minting a standalone
  access token with no refresh token and no persisted refresh-token family
  (`IssueAccessToken(ctx, claims) (string, time.Time, error)`). `jwt.Service` and `jwt.SingleTenant`
  implement it, and the MFA-gated login paths use it for the interim credential — which previously
  minted a full pair and discarded its refresh token, leaving a full-`RefreshTTL` refresh row behind
  for a session that was never granted. Implementing it in a custom issuer is optional: egauth
  type-asserts and falls back to `IssueTokenPair`.

- **Assurance helpers** for enforcing step-up outside the middleware: `tokens.Claims.SatisfiesStepUp()`,
  `tokens.HasStepUpFactor(amr)`, `tokens.Claims.AsInterim(ttl)` (stamps `Interim`, strips every
  step-up AMR marker, sets the short expiry), plus the non-generic context bridge
  `tokens.Assurance`, `tokens.AssuranceResolver`, `tokens.AssuranceFromContext` and
  `tokens.AssuranceResolverFromContext`.

- **Forced-password-change for temporary credentials** (M7). Lets an admin provision a credential
  that requires the user to choose a new password at next login, without ever locking the user out:

  - `identity.AdminCreateUser(ctx, tenantID, email, tempPwd)` creates an account with a temporary
    password, and `identity.SetTemporaryPassword(ctx, tenantID, userID, tempPwd)` replaces an
    existing credential with one — both flag the identity so the user must set their own password
    before the app is usable.

  egauth deliberately does **not** offer periodic, age-based password rotation: fixed-interval
  expiry is discouraged by NIST SP 800-63B.

  At next login, when a credential is flagged, `LoginHandler` / `MagicLinkLoginHandler` issue a
  full, **renewable** pair whose access token carries `tokens.Claims.MustChangePassword=true` (JSON
  claim `must_change_password`). The flag is recorded on the refresh-token family and `Rotate`
  replays it onto every silent refresh (overriding the `ClaimsProvider`), so the renewed token is
  flagged iff the family was — a silent refresh cannot drop the flag and a user cannot escape the
  gate by waiting for the access token to expire. To force a change on a user's existing sessions,
  an admin revokes their token families (`SetTemporaryPassword` does this via its erasers).

  `tokens.WithPasswordChangeGate[C](resetURL)` enforces the gate generically in the `RequireAuth`
  middleware: after successful token verification, if `Claims.MustChangePassword` is true, the
  wrapped handler is bypassed and the request is redirected `303` to `resetURL` (or `403
  password_change_required` if `resetURL` is empty). The change-password and logout routes must
  be excluded from this middleware.

  On a successful `ChangePassword` / `ResetPassword`, `UpdateIdentityPassword` atomically stamps
  `PasswordChangedAt` and clears the flag; `ChangePasswordWithReissueHandler` re-issues a full
  access+refresh pair so the user is immediately authenticated.

  New `identity.Store` method: `UpdateIdentityPassword(ctx, tenantID, userID, passwordHash,
  changedAt time.Time, mustChange bool)` (stamps timestamp and flag in one atomic write). External
  store implementers must add this method; run `identity/storetest` to verify conformance.

  New `tokens.RefreshToken.MustChangePassword` field records the gate on the rotation family; the
  `tokens.Store` (`SaveRefreshToken` / `FindRefreshToken`) must persist and return it. External
  token-store implementers must carry this field; run `tokens/storetest` to verify conformance.

  New pgx migrations: `adapters/pgx/identity` migration `008_add_password_change_columns.sql` adds
  `password_changed_at` (nullable, informational "last changed" audit metadata — drives no behavior)
  and `must_change_password` (boolean, default false) to the `identities` table;
  `adapters/pgx/tokens` migration `005_add_refresh_token_must_change_password.sql` adds
  `must_change_password` (boolean, default false) to the `tokens` table so the gate survives refresh.

  Zero behavior change unless a credential is explicitly flagged via admin provisioning.

- **`identity.ActiveClaimsProvider` + `identity.Service.EnsureActive`: the account-status re-check
  refresh rotation needs.** `Rotate` resolves fresh claims through the issuer's `ClaimsProvider`,
  which is the only place a rotation can be refused. Wrapping your provider —
  `identity.ActiveClaimsProvider(svc, provider)` — aborts the refresh of a disabled or soft-deleted
  account with `ErrAccountDisabled` / `ErrUserNotFound` (the presented token stays unconsumed;
  `RefreshHandler` answers `401` and clears the cookies). `EnsureActive` is the underlying gate and
  is also the cheap status check for API-key and background-job paths that never re-run
  `Authenticate`. New narrow interface `identity.ActiveChecker` for wiring it from less than the
  whole Service.

- **`identity.RevocationRegistry`: post-construction registration of the revocation hooks.**
  `RegisterAccountErasers` / `RegisterDisableRevokers` do at wiring time what `WithAccountErasers` /
  `WithDisableRevokers` do at construction, for a composition root that only receives an
  already-built `Service` (a DI container, or the `webapp` preset). Hook lists are copied on write,
  so registration is safe alongside in-flight operations.

### Fixed

- **`WithTrustedOrigins` now supports scheme-qualified origins across `identity`, `tokens`, `mfa`,
  `otp` and `passkey` (`http/HTTP-3`).** A scheme-qualified entry, e.g.
  `identity.WithTrustedOrigins("https://app.example.com")`, previously never matched anything: the
  allowlist stored the literal string while the request-side lookup always compared a bare host, so
  the pattern the `webapp` preset's own doc comment recommended silently failed closed. Entries may
  now be a bare host (matched on host only, unchanged) or a scheme-qualified origin (matched on
  scheme AND host — the stricter form). Purely additive: existing bare-host entries are unaffected.

- **`webapp.NewWebApp` now wires `Config.EventSink` into the `tokens` handlers, not just `identity`
  (`http/HTTP-6`).** The preset's own doc says `EventSink` receives "login, registration and logout"
  events, but `LogoutHandler`'s `event.Logout` emission was never reaching it (no
  `tokens.WithEventSink` was ever passed) — a configured sink silently never saw a logout. Fixed.

- **The in-memory passkey `ChallengeStore` no longer sweeps its whole map on every `Put`
  (`conc/AVAIL-1`, `tenant/TEN-7`, `mfa/SF-5`).** `Put` — reachable from the UNAUTHENTICATED
  `BeginRegistration` / `BeginLogin` endpoints — pruned by iterating every entry under one global
  mutex, so insertion was linear in the live set (quadratic overall) and the sweep tracked the map's
  PEAK size, letting a single traffic burst degrade it permanently. Expiry reclamation is now
  amortised over an insertion-ordered queue with a bounded number of steps per `Put` (measured: 2.0M
  scan steps for 100 inserts against a 20k live set, now ≤ 800), the queue is compacted so it tracks
  the live set rather than the peak, and the store is hard-capped with a documented oldest-first
  eviction policy so an anonymous caller cannot grow it without bound.

- **A refresh-token family can no longer be kept alive forever by rotating it
  (`lifecycle/LIFE-2`).** Every rotation reset the full `RefreshTTL`, so a family kept warm by a
  stolen token never expired — unlike `sessions`, which has had an absolute cap. Rotation is now
  clamped to the family's absolute deadline (see Added) and the anchor is persisted on every refresh
  row.
- **Rotation no longer drops the principal kind (`lifecycle/KIND-2`, `lifecycle/KIND-1`).** `Rotate`
  pinned the tenant, `auth_time` and `must_change_password` but not `Claims.Kind`, so a
  `Service`/`PAT` credential silently became a human one after a single refresh and a
  `WithRequiredKind`/`RequireMachine`/`RequireHuman` gate flipped. The kind is now recorded on the
  family and replayed onto every descendant. Relatedly, `IssueAPIKey` never stamped `Claims.Kind` at
  all — contradicting the `WithRequiredKind` documentation and leaving the gate useless for
  key-backed credentials — so it now stamps it from the key type.
- **Rotation can no longer be re-pointed at another user (refuter-found).** A `ClaimsProvider`
  returning a different `Subject` silently re-issued the family's tokens for that other user while
  the stored family still named the original one; `Rotate` now pins the subject to the family record.
- **`WithGate` now really runs after the principal-kind gate (`lifecycle/GATE-1`).** Its
  documentation promised the built-in gates ran first, but the kind gate ran AFTER the
  application predicate, so app policy code observed credentials the route was configured to
  reject outright. All built-in gates (kind → step-up → scopes → password-change) now run before
  `WithGate` on both the direct-token and the auto-refresh paths.
- **An explicit `Authorization: Bearer` token now beats the ambient access cookie
  (`lifecycle/HDR-1`).** The cookie always shadowed a deliberately presented header token, so a
  client acting as another principal was silently served the cookie's identity. A
  presented-but-invalid bearer token is now rejected rather than downgraded to the cookie, while a
  non-bearer scheme (e.g. `Basic`) leaves the cookie in charge. Bearer parsing also tolerates extra
  whitespace after the scheme instead of rejecting the header.
- **A client abort no longer leaves a rotated password with every old session alive
  (`identity/TEN-3`, `http/HTTP-2`).** `ResetPassword`, `ChangePassword` and `SetTemporaryPassword`
  commit the new hash first and then revoke the account's pending token-borne credentials, sessions
  and refresh families — but that cascade ran on the CLIENT-CANCELLABLE request context and even
  checked `ctx.Err()` between erasers. A client that aborted mid-request (closed tab, proxy timeout)
  therefore left the NEW password active and EVERY OLD session and refresh family alive: the exact
  inverse of the intended outcome on the compromise-recovery path. The cascade now runs on
  `context.WithoutCancel(ctx)` bounded by `DefaultRevocationTimeout` (`WithRevocationTimeout`), and
  every failure is still joined and returned so a revocation outage is visible and retriable.
  `DeleteAccount` keeps honouring cancellation by design (its erasers run before the soft delete).
- **`VerifyEmail` no longer clobbers a concurrent email change (`identity/TEN-5`).** It
  read-modify-wrote the whole user row through `UpdateUser`, so a `ConfirmEmailChange` landing
  between the read and the write was silently LOST — the login address reverted although its
  change token had already been consumed. It now writes through the narrow
  `Store.MarkEmailVerified`, pinned in the shared store contract for both backends.
- **A deleted account can sign up again through the same social login (`identity/TEN-6`).**
  `DeleteUser` preserved external (OAuth/OIDC) `provider_id` values, so after a user-facing account
  deletion every later login OR signup with that provider account was refused **forever** — a user
  who deleted their account could never come back. Deletion now releases the provider identity (as
  it already did for the password identity's email key) and the same provider account provisions a
  NEW account; the service-layer `DeletedAt` gate remains, so a deleted user is still never handed
  back. Covered end to end and in both backends' contract suite.
- **A panicking Mailer/SMSSender no longer kills the process (`identity/TEN-7`).** The
  off-response-path delivery goroutine in the `identity` and `otp` handlers invoked consumer
  callbacks with no `recover()`; because the request has already returned, no `http.Server`
  recovery covered it, so any panic in consumer code was a whole-process crash reachable from a
  mostly unauthenticated endpoint. Both goroutines now recover. The `identity` handlers report the
  recovered value as a `DeliveryFailed` event (`Reason: "delivery_panic"`, `Err` joined with
  `ErrDeliveryPanic`); the request still returns its uniform `204`.
- **A failed social-login provisioning no longer burns the email address (`identity/TEN-8`).**
  When the `emailVerified` write failed, `LinkOrCreateIdentity` left the just-created user as an
  ORPHAN with no identity, and the live-row email index kept matching it — that address became
  permanently unusable for both a retried social login and an ordinary registration. The failure
  now compensates by soft-deleting the orphan, exactly as the `AddIdentity` failure path already did.
- **A password rotation can no longer re-arm a soft-deleted account (refuter-found).**
  `UpdateIdentityPassword` was not gated on the owner being live in either backend, so
  `ChangePassword` / `SetTemporaryPassword` could write a usable hash onto a deleted account's
  identity. Both backends now return `ErrUserNotFound`, pinned by
  `storetest.StorePasswordRotationLivenessContract`.
- **An oversized email address is rejected by validation (`identity/TEN-16`).** `normalizeEmail`
  enforced no maximum, so an address far beyond the RFC 5321 limit passed validation and failed late
  in the store with an opaque error. It now returns `ErrEmailTooLong` above `MaxEmailLength` (254),
  checked both before the IDN fold and after canonicalization.

- **An unauthenticated verify no longer provisions a tenant and mints a key (`crypto/CRY-4`,
  `tenant/TEN-4`).** `tokens/jwt.CachingKeyStore.VerificationKeys` resolved the delegate's
  `ActiveSigningKey` on a verification-path cache miss to fill both halves of its cache entry. With
  `keystore.WithLazyProvisioning` wired, that resolution PROVISIONS the tenant: an anonymous request
  presenting any token (or a JWKS lookup) for an attacker-chosen tenant id created a tenant and wrote a
  fresh signing key to the database — attacker-driven key creation from an unauthenticated endpoint.
  The verification path now resolves verification keys ONLY and never touches `ActiveSigningKey`, so an
  unknown tenant fails closed with `keystore.ErrTenantNotFound` and writes nothing. The cache's two
  halves are filled and aged independently to make that possible (the signing path still fills both in
  one pass, so it costs no extra reads); staleness is still bounded by the same TTL per half and by the
  same event-driven invalidation. Lazy provisioning on the signing path is unchanged.

- **A validly signed access token missing `iat` or `exp` no longer panics (`crypto/CRY-2`).** Both
  claims are OPTIONAL in RFC 7519, so golang-jwt leaves the corresponding `*NumericDate` nil rather
  than rejecting the token, and `verifyAccessToken` dereferenced them unguarded — a nil-pointer panic
  on the verify path, reachable by anyone who can get a token signed (or hand one to a service using a
  leaked key). Both are now nil-guarded and the token is rejected with `tokens.ErrInvalidClaims`;
  egauth stamps both on every token it issues, so a token missing either is not one of ours.

- **The refresh reuse-grace decision now uses the injected clock (`lifecycle/CLOCK-1`,
  `crypto/CRY-10`).** `Rotate` compared `consumed_at` — written by the STORE's clock, which for a SQL
  backend is the database server's — against a direct `time.Since` wall-clock read, bypassing the
  `Config.Clock` seam the rest of the package (issuance, `exp`/`nbf` validation) runs on. App/DB skew
  therefore either falsely tripped theft detection (revoking a whole family on ordinary concurrency)
  or silently widened the reuse window, and a test clock could not pin the behaviour. The age is now
  measured with the injected clock, and skew handling is explicit: a `consumed_at` ahead of clock-now
  yields a negative age that is clamped to zero, so store-clock skew reads as benign concurrency
  instead of theft; skew the other way can only shorten the window, never widen it. Documented in
  SECURITY.md (*Clock discipline*).

- **The per-tenant signing key and the TOTP secret are now redacted in log/print output
  (`crypto/CRY-6`).** Redaction coverage stopped at `tokens/` and `tokens/jwt/`, so a `%+v` of a struct
  holding a `keystore.SigningKey` dumped the OPENED signing material (as a byte slice), and a `%+v` of
  an `mfa.TOTPEnrollment` or a freshly minted `mfa.Enrollment` printed the shared secret verbatim —
  the `Enrollment.URI` too, since `otpauth://…?secret=…` embeds it. All three now implement
  `fmt.Stringer`, `fmt.GoStringer` and `slog.LogValuer` mirroring the `tokens/redact.go` pattern:
  secrets render as `REDACTED` on `%v`/`%+v`/`%s`/`%#v` and through `slog`, while non-secret
  identifiers (key id, tenant, alg, timestamps) stay visible. JSON marshalling is deliberately left
  alone — returning a freshly minted TOTP secret and QR URI to the enrolling user is the point.

- **SECURITY.md overstated the constant-time `Compare` guarantee (`claims/DOC-12`).** Two pre-KDF
  early returns branch on the CANDIDATE password (an empty candidate, and one over
  `passwords.MaxPasswordLength`), not only on the shape of the stored hash. Both are legitimate — the
  empty-candidate return is what keeps `Compare` timing-symmetric with the decoy path, and the
  oversized-candidate return is a pre-auth DoS guard — so the document now states precisely what each
  one discloses (nothing that distinguishes a correct password from a wrong one, or one account from
  another) instead of claiming they do not exist. No code change.

- **One unreadable keystore row no longer takes a tenant's whole verification set offline.**
  `keystore.Manager.VerificationKeys` (and therefore `JWKS`) failed the entire call when a single key
  row could not be opened with the deployment KEK (corrupt at rest, or sealed under a KEK that is no
  longer configured). It now skips that row and emits the new `keystore.EventKeyUnreadable`
  (`Reason: keystore.ReasonKeyUnsealFailed`, `Attrs["key_id"]`, `Err` set) so the degradation stays
  observable. The signing path is unchanged and still strict: `ActiveSigningKey` returns the open
  error rather than silently signing with something else.

- **A password reset did not end an account takeover (HIGH, `identity/TEN-1`).** Reproduced end to
  end: an attacker holding a live session on the victim's account `POST`s
  `RequestRecoveryEmailHandler` with `recovery_email=attacker@evil` (only an address equal to the
  primary was rejected), which mails a `KindRecoveryEmailVerification` token with a 24h TTL to the
  attacker. The victim then performs the canonical recovery — `ResetPassword` re-keys the password and
  the `AccountErasers` revoke every session and refresh family, so the attacker loses their session.
  But nothing deleted the pending verification-token rows, and `ConfirmRecoveryEmailHandler` is
  authenticated by the token alone (no session), re-checking only `DeletedAt`/`DisabledAt`. The
  attacker could therefore confirm the token *after* the reset and end up with an
  attacker-controlled verified recovery channel — which then drives
  `RequestPasswordResetViaRecovery` and hands the account straight back. The same held for a pending
  email-change token (which moves the login identifier), a pending magic link (a full login
  credential), a pending phone verification and a second pending reset token. The four
  credential-rotating flows now purge those kinds through the new
  `Store.DeleteVerificationTokensForUser` seam (see BREAKING).

- **`RequestEmailChange`'s doc overclaimed (`identity/TEN-2`).** It said the confirm-to-new-address
  step meant "a hijacked session cannot silently move the account to an attacker-controlled address".
  Reproduced: a session-only email change to `attacker@evil.test` succeeded and the victim could no
  longer log in with their own address — confirming to the new address proves control of *that
  address*, not ownership of the account. The bar is now enforced by
  `RequestEmailChangeHandler` (see BREAKING) and the godoc states the real guarantee.

- **`ChangePassword`'s interface doc said cross-module revocation was "left to the consumer"** while
  the implementation has been running the registered `AccountErasers` all along. The godoc,
  `.llms/identity.md` and `SECURITY.md` now describe what the code actually does (and now also
  document the token purge).

- **Account deactivation did not end access in the shipped `webapp` preset (HIGH).** The only
  `ClaimsProvider` egauth shipped never looked at the account: it took `_ context.Context`, could
  not fail, and the preset registered no disable revoker (it could not — `Config.Identity` arrives
  already constructed). So after `identity.DisableUser`, every `POST /auth/refresh` still returned
  `204` and each rotation reset the refresh expiry to `now+RefreshTTL` — access was not merely
  retained, it was renewed indefinitely, defeating offboarding, GDPR erasure and compromise
  response for anyone using the preset or the README quickstart. `NewWebApp` now wires both halves
  (revoker registration + `ActiveClaimsProvider`) and refuses to build when it cannot. Every shipped
  example, the README quickstart, `.llms/*`, `llms.txt` and the docs site taught the same broken
  provider and were corrected.

- **`identity/memory`'s `UpdateUser` blind-wrote the whole user row, clearing `DisabledAt`.** A
  stale `*User` copy — e.g. the one a concurrent `VerifyEmail` holds — replayed its old values over
  an administrative change, so a suspended account could be re-activated (and `Phone`,
  `PhoneVerifiedAt`, `RecoveryEmail`, `RecoveryEmailVerifiedAt` reverted) and log in again. The
  memory backend now persists only `Email`/`EmailVerifiedAt`, matching the pgx backend's narrow
  `UPDATE`; the field scope is now part of the documented `Store` contract and pinned for BOTH
  backends by `storetest.StoreUpdateUserFieldScopeContract`.

- **`tokens.NewAccountRevoker`'s doc claimed more than it does.** It said it invalidates "EVERY
  token a user holds" and kills "every active session". It revokes stored refresh tokens and API
  keys; an already-issued stateless access token survives until `AccessTTL` expires and the
  `sessions` module is untouched. The godoc, `SECURITY.md`, `.llms/tokens.md`, `.llms/identity.md`,
  `.llms/architecture.md` and the docs site now state exactly what is revoked, what survives and
  for how long. The `identity.Service.DisableUser` doc no longer claims that refresh tokens are not
  revoked by the call (they are, through the registered revokers).

- **HTTP handlers now fail CLOSED on an unresolved tenant** (`identity`, `tokens`, `otp`, `oauth`).
  A configured tenant resolver that could not map a request (the natural result of a map or DB
  lookup for an unknown `Host`) returned `""`, and that `""` was passed through verbatim: the
  request then authenticated, registered, reset a password, verified an OTP, rotated/revoked a
  refresh family or linked an OAuth identity **in the empty tenant partition** — which in a
  single-tenant/bootstrap deployment is exactly where the operator accounts live. `identity.LoginHandler`
  returned `204` against `""` and `identity.RegisterHandler` created an account there.

  Every handler now distinguishes "no resolver configured" (single-tenant mode: `""` is the
  legitimate default partition, unchanged) from "a resolver was configured and could not resolve"
  (refused). The refusal is `401 tenant_unresolved` on the `identity` and `tokens` handlers, `401`
  with the family's uniform code on `otp` (`unauthorized` for `IssueHandler`, `invalid_code` for
  `VerifyHandler`, so no new account-existence oracle is introduced) and `403 tenant_unresolved` on
  the `oauth` begin/callback handlers (matching the existing `tenant_mismatch` refusal).
  `sessions.RequireSession` and `tokens.RequireAuth` already behaved this way; the handler families
  now mirror them. The `WithTenantResolver` doc comments, `SECURITY.md` and the `.llms/*.md` guides
  document the contract, and the guides no longer teach `func(r *http.Request) string { return
  r.Host }` — resolvers must map the request through an explicit allowlist / canonical table.

- **Handlers resolve the tenant exactly once per request** (`identity`, `tokens`, `otp`, `oauth`).
  `identity.LoginHandler` resolved it three separate times (authentication, the
  forced-password-change check, the MFA-enrollment gate), so an impure resolver — an expiring cache
  entry, a transient store error returning `""` — made `MFAEnrollmentChecker.IsEnrolled` look for
  the second factor in the wrong partition, find none, and skip the MFA branch entirely, issuing a
  full renewable session on the password alone. Each handler now pins the single resolved value and
  reuses it for every store operation (`oauth.DynamicCallbackHandler` already did this).

- **A negative lockout argument no longer silently disables brute-force protection**
  (`identity`, `mfa`). `identity.WithLockout` and `mfa.WithMaxAttempts` were documented (and, for
  `WithLockout`, doc-commented) to treat any non-positive argument as "use the safe default" —
  only `WithNoLockout` / `WithNoAttemptLimit` are meant to disable the gate. In both services,
  `NewService`'s normalization mapped a NEGATIVE threshold/limit to the same internal value as
  the explicit opt-out, so e.g. `identity.WithLockout(-1, ...)` or `mfa.WithMaxAttempts(-1)`
  silently disabled lockout/attempt-limiting instead of falling back to the default. Both options
  now clamp any non-positive value (zero or negative) to the documented default, and the disabled
  state is reachable ONLY through `WithNoLockout` / `WithNoAttemptLimit` (now tracked via an
  explicit boolean field rather than overloading the threshold/limit itself).

- **`mfa.WithLockoutDuration(0)` now actually produces a permanent lockout, as documented**
  (`mfa`). The option's godoc, its field doc and SECURITY.md all state that `0` disables
  time-based lockout decay (permanent until `UnlockMFA` or `DisableTOTP`), but `NewService`
  could not distinguish a deliberate `WithLockoutDuration(0)` from an untouched field and always
  overwrote it with `DefaultLockoutDuration` — making the documented permanent-lockout setting
  unreachable. `WithLockoutDuration` now records that it was explicitly called, so `0` (or any
  negative value) is honored as "no decay".

- **Cookie configuration no longer panics at request time** (`tokens`, `identity`, `oauth`, `mfa`,
  `webapp`). `tokens.Cookies.withDefaults` panicked whenever a `__Host-` cookie name was paired with
  a `Domain`, a `Path != "/"` or `Insecure`, and it ran on the request path — including inside the
  pure read helpers `Cookies.Access` / `Cookies.Refresh`. Consequences: `webapp.Config.CookieDomain`
  broke every cookie-writing endpoint while `NewWebApp` reported no error; `WithCookieDomain`,
  `WithCookiePath`, `WithRefreshCookiePath` and `WithInsecureCookies` each produced an unusable
  handler; and `tokens.RequireAuth` with domain-scoped cookies panicked on EVERY request to a
  protected route, even an unauthenticated `GET` carrying no cookie at all.

  Those options are now self-consistent: they DEMOTE a cookie name that still carries the `__Host-`
  prefix to `__Secure-` (while the cookie stays `Secure` with `Path="/"`) or to its bare form,
  because setting a `Domain`, a path scope or `Insecure` is already an opt-out of host-lock
  semantics. New demoting derivations on `tokens.Cookies` — `WithDomain`, `WithPath`,
  `WithRefreshPath`, `WithInsecure` — plus `MustValidate`, expose the same behavior for hand-built
  values. `Validate` additionally rejects a `__Secure-` name on a non-`Secure` cookie.

  Validation moved to CONSTRUCTION: `tokens`/`identity`/`oauth`/`mfa` handler constructors and
  `tokens.RequireAuth` / `tokens.ContextMiddleware` call `MustValidate` (a startup panic on a
  genuinely invalid hand-built value), and `webapp.NewWebApp` returns it as an error. `DefaultCookies`
  is unchanged — `__Host-` remains the default.

- **Concurrent `Migrate` calls no longer race each other (`pgx/PG-1`).** Every pgx-backed store's
  `Migrate` now takes a Postgres advisory lock (keyed per module namespace, e.g. `"identity"`,
  `"tokens"`) for the whole migration run and releases it on every path, including error. Without
  it, N replicas of one service starting together during a rolling deploy could all observe a
  migration file as "not yet applied" and race its DDL — even fully idempotent `IF NOT EXISTS`
  statements are not safe against a concurrent identical DDL statement in Postgres (a known
  catalog race) — so N-1 of N replicas could fail startup. Different modules never contend with
  each other. `internal/pgxmigrate.Run` gained a required `namespace string` parameter (internal
  package, not part of the public API).
- **`adapters/pgx/identity`'s migration 001 violated the runner's own idempotency contract
  (refuter-found).** `idx_users_email_tenant` and `idx_identities_provider_tenant` were created with
  plain `CREATE UNIQUE INDEX` (no `IF NOT EXISTS`), so re-issuing 001's DDL against a database where
  it already ran — e.g. after the exact crash-before-the-version-row-committed scenario the runner's
  package doc describes — failed with "relation already exists" instead of completing cleanly.
  Every other `.sql` file across every `adapters/pgx` subpackage (`identity`, `keystore`, `mfa`,
  `oauth`, `otp`, `passkey`, `sessions`, `tokens`) was audited against the same contract and found
  compliant.
- **`.llms/storage-pgx.md` overclaimed migration safety.** It said re-running `Migrate` is "always
  safe" and told every instance to call it at startup with no caveat. It now states the actual
  contract (idempotent files + the advisory lock make concurrent `Migrate` calls safe) and
  recommends a dedicated migration job/init container as the primary operational pattern, with
  per-instance `Migrate` at startup documented as the (now-safe) convenience path.
- **The `identities` table had no index covering its per-login lookup (`pgx/PG-2`).**
  `FindIdentitiesByUserID` filters on `(tenant_id, user_id)`, which no existing index covered (only
  the unique `(tenant_id, provider, provider_id)` index existed), so the query sequential-scanned
  the table. New migration `adapters/pgx/identity/migrations/009_add_identities_user_index.sql`
  adds `idx_identities_user_tenant`.
- **The `tokens` table had no index on `id` or `created_by` (`pgx/PG-3`, `lifecycle/IDX-1`).**
  `RevokeAPIKey` (`WHERE id = ...`), `ListAPIKeysByCreator` and `RevokeAllAPIKeysForUser` (`WHERE
  created_by = ...`) sequential-scanned the highest-churn table; the existing indexes
  (`idx_tokens_user_id`, `idx_tokens_family_id`, `idx_tokens_tenant_expires`) and the
  `(tenant_id, token_hash)` primary key cover neither column. New migration
  `adapters/pgx/tokens/migrations/009_add_api_key_lookup_indexes.sql` adds `idx_tokens_id` and
  `idx_tokens_created_by`, both scoped to API-key rows (`WHERE claims IS NOT NULL`). Every query in
  every other `adapters/pgx` store was reviewed against its available indexes; no other unindexed
  hot path was found (`sessions`, `mfa`, `passkey`, `otp`, `oauth` and `keystore` all filter on a
  primary-key or existing-index prefix).
- **An unclassified API key could be silently issued or stored as a machine identity
  (`lifecycle/APIKEY-1`).** `tokens.PrincipalKindForKeyType` documents the fail-safe direction for
  an unclassified (empty) `Type` as `egauth.User` (a plain human principal) — never a machine
  identity — but `jwt.Service.IssueAPIKey` accepted an empty/unknown `keyType` outright, and
  `adapters/pgx/tokens`'s `SaveAPIKey` separately defaulted an empty `Type` to `KeyTypeService`
  before persisting, while the in-memory store stored it verbatim: the SAME key classified as a
  machine principal on Postgres and a human principal in memory.
  - **`IssueAPIKey` now validates `keyType`** and returns the new sentinel
    `jwt.ErrInvalidKeyType` for anything other than `tokens.KeyTypePAT` / `tokens.KeyTypeService`,
    including the zero value.
  - **`adapters/pgx/tokens.Store.SaveAPIKey` no longer defaults an empty `Type` to
    `KeyTypeService`**; it now stores `Type` verbatim, matching the in-memory store and the
    documented fail-safe. A pre-existing pgx test asserting the old defaulting behavior was wrong
    and has been corrected; a new case in `tokens/storetest` pins the correct round-trip behavior
    for both backends.
- **`mfa.IncrementTOTPAttempts` had a lost-update race in its non-transactional path
  (`pgx/PG-5`).** The prior implementation issued a `SELECT ... FOR UPDATE` and a separate `UPDATE`;
  on a bare pool (autocommit per statement) the row lock is released between the two statements, so
  two concurrent attempts could both read the same pre-increment count and lose an increment — a
  second-factor brute-force budget that does not actually decrement correctly under load. It is now
  a single `UPDATE ... FROM (... SELECT ... FOR UPDATE ...)` statement, atomic even without an
  explicit transaction.
- **`passkey.Store.UpdateCredential` allowed a lost-update race on `sign_count`
  (`pgx/PG-6`).** It was a plain full-record `UPDATE` with no guard, so a stale write (e.g. a
  slower concurrent request whose write commits after a faster one already advanced the counter)
  could silently roll `sign_count` backward — the exact signal `FinishLogin` uses to detect a
  cloned credential. The write is now a compare-and-swap (`AND sign_count <= $5`): a write that
  would regress the stored counter is a silent no-op instead of overwriting it.
- **gofmt / `errors.Join` cleanup in `adapters/pgx/tokens`.** `adapters/pgx/tokens/store.go`'s two
  `fmt.Errorf(...%w...)` call sites were converted to `errors.Join`, matching house style. (The
  `pgx/PG-4` stray-blank-line gofmt violation and the `sf-11` `fmt.Errorf` usage reported for
  `adapters/pgx/mfa` were both NOT reproduced against this branch — `gofmt -l` was already clean and
  `adapters/pgx/mfa` already used `errors.Join` throughout before this change.)

### Security / disclosure (v1.0.0)

- **Audit-status disclosure.** egauth's security review to date is an AI-driven audit only; it
  has not had an independent third-party human security audit, and that risk is accepted for
  v1.0 — pin a reviewed commit, commission your own audit, or wait if that trade-off is
  unacceptable. "AI-audited" is **not** a synonym for "audited". The full review scope (what was
  reviewed and how, what was not, the accepted trade-offs) and the cautious-user escape hatch
  live in the new [`AUDIT.md`](AUDIT.md) ledger. The canonical sentence above is reused verbatim
  across the README, root package godoc (`doc.go`), `llms.txt`, and `SECURITY.md`, and its
  presence on those surfaces is enforced by a build-failing test (`disclosure_test.go`).
  Post-v1, any security-relevant change re-discloses its review status here (see AUDIT.md's
  re-disclosure policy). (#19)

### Tooling / CI

- **Added a strict `golangci-lint` configuration (`.golangci.yml`).** With no config file, CI and
  `make lint` silently ran only the five linters golangci-lint enables by default. The new config
  adds `revive`, `errorlint`, `errname`, `godot`, `misspell`, `dupword`, `perfsprint`, `intrange`,
  `usestdlibvars`, `unconvert`, `bodyclose`, `contextcheck`, `nilerr`, `copyloopvar` and `gocritic`,
  and all three modules (core, `adapters/pgx`, `adapters/otel`) now pass it with zero issues.
  `errorlint`'s "use `%w`" check is deliberately disabled repo-wide (`errorf: false`): the house
  convention is `errors.Join`, not `fmt.Errorf("%w", ...)`, and converting the ~258 existing
  `fmt.Errorf` call sites is tracked separately as a mechanical follow-up, not part of this change.
  A handful of other rules are excluded with a one-line justification each (documented inline in
  `.golangci.yml`) for verified, systemic false-positive patterns: the three deliberate
  enumeration-uniform `nilerr` hits in `identity/service.go`, `bodyclose`'s inability to see a
  `t.Cleanup`-deferred close or recognize `httptest.NewRecorder().Result()` as leak-free, and
  `contextcheck` on test helpers that legitimately construct a detached `context.Background()`.
  Real diagnostics the new linters found (not excluded) were fixed: `errors.Is`/`!errors.Is`
  instead of `==`/`!=` sentinel-error comparisons, `http.MethodGet`/`http.MethodPost` instead of
  string literals, `for range n` instead of `for i := 0; i < n; i++`, missing doc-comment periods,
  a redundant `fmt.Errorf` with no format arguments replaced by `errors.New`, and a deprecated
  `trace.NewNoopTracerProvider` replaced by `trace/noop.NewTracerProvider` in `adapters/otel`.
- **Added SAST: CodeQL and gosec.** A new `.github/workflows/codeql.yml` runs GitHub's CodeQL Go
  analysis on push, PR, and a weekly schedule. A new `sast-gosec` job in `ci.yml` runs `gosec`
  across all three modules. `gosec`'s findings were triaged, not blanket-silenced: `G114` (the
  `examples/fullstack` reference server using bare `http.ListenAndServe`, with no timeouts, a real
  connection-exhaustion DoS risk) is fixed with a properly configured `http.Server`; `G101`,
  `G124`, `G401` and `G505` are excluded repo-wide as verified systemic false positives (see the
  rationale comment in `ci.yml`); a handful of isolated integer-length-as-prefix conversions and
  one nonce-fill idiom `gosec` misreads are suppressed with a per-line `#nosec <ruleID>` and an
  explanation; `internal/doctest`'s dev-only `go doc` subprocess/file access is excluded by path.
- **`govulncheck` bumped from v1.1.4 to v1.6.0**, in the Makefile and `ci.yml`, both of which
  document that the pin must stay in sync. `golangci-lint`'s v2.12.2 pin was checked against the
  latest release and is already current.
- **`govulncheck` and `golangci-lint` CI jobs now actually cover all three modules.** Both were
  misleadingly named "(both modules)" while only ever running against core and `adapters/pgx` —
  `adapters/otel` had no vulnerability or lint coverage at all. Renamed to "(all modules)" and
  extended to include `adapters/otel`; the Makefile's `lint`/`vulncheck`/`vet`/`verify`/`test-unit`
  targets were extended the same way.
- **`.github/dependabot.yml` now covers every module.** It only declared `directory: "/"` for the
  `gomod` ecosystem, so `adapters/pgx` and `adapters/otel` — each with their own `go.mod` — never
  got automated dependency-update PRs. Added a `gomod` entry for each.
- **`adapters/otel`'s core pin was three releases stale (v0.3.0) and it was absent from
  `RELEASING.md`.** Bumped the pin to v0.7.0 (matching `adapters/pgx`) and added it to the
  release dance, the vulnerability-gate checklist, and the release-checklist summary.
  `adapters/otel`'s tests already exercise the current, in-tree core via the committed `go.work`
  (unaffected by whatever the pin says); `internal/doctest` already validates its package doc
  comment against current core too, confirmed by a clean `go run ./internal/doctest`.
- **Corrected `RELEASING.md` and `adapters/pgx/go.mod`'s stale description of a `replace`
  directive that no longer exists.** Both said the adapter's go.mod carries a dev
  `replace github.com/JLugagne/egauth => ../..`, dropped only at release time — but a prior
  release-prep commit already dropped it in favor of a `require` pinned directly at the latest
  published core tag. (An earlier claim that this causes untested divergence between the pin and
  HEAD core was investigated and refuted: no CI job builds `adapters/pgx` with `GOWORK=off`, so
  every CI run already compiles it against HEAD core via the committed `go.work` regardless of
  the pin.) Both files now describe what actually happens; `adapters/otel`, which still carries
  the `replace`, is documented as the adapter currently mid-transition.
- **`examples/fullstack`'s `main()` now uses a configured `http.Server`** (`ReadHeaderTimeout`,
  `ReadTimeout`, `WriteTimeout`, `IdleTimeout`) instead of bare `http.ListenAndServe`, which never
  times out a slow or stalled client (`gosec` G114). Every other development-only shortcut in the
  example (in-memory backends, `WithInsecureNoOriginCheck`, `WithInsecureCookies`, the hardcoded
  JWT signing key) was already called out in a comment.
- **Applied the real `go fix -diff` modernizer suggestions**: `Actor.HasScope`/`HasAnyScope`
  (`actor.go`) and `tokens/middleware.go`'s `isAllowedKind` now use `slices.Contains`/
  `slices.ContainsFunc` instead of a hand-rolled loop; `internal/doctest`'s `funcSignatureLine`
  uses `strings.SplitSeq`; `passkey/storetest/challengestore.go`'s racer goroutines use
  `sync.WaitGroup.Go` instead of manual `Add`/`go func`/`defer Done`.

## [0.7.0] - 2026-07-21

Security-hardening batch: CSRF coverage is completed across the state-changing handler families,
audit coverage is broadened to the OAuth and admin paths, and a set of concurrency/correctness
bugs are fixed.

### BREAKING

- **tokens/jwt (PAT subject):** `IssueAPIKey` for `KeyTypePAT` now pins the token's `Claims.Subject`
  to `createdBy`. A caller-supplied `Subject` naming a different user is rejected with the new
  `ErrPATSubjectMismatch` (previously it was honored verbatim). This guarantees a PAT is severed by
  `DisableUser` → `RevokeAllAPIKeysForUser`, which is scoped by `CreatedBy`. Leave `Subject` unset to
  default it.

### Added

- New audit events on previously SIEM-dark paths: OAuth login (`login.succeeded` /
  `login.failed{account_disabled}` with `method=oauth`), JIT provisioning
  (`user.registered{oauth_provision}`), and admin credential operations
  (`password.changed{admin_temporary_password}`, `user.registered{admin_created}`), mirroring the
  password path.
- New `event.Type` values: `mfa.verified`, `mfa.unlocked`, `credential.added`, `credential.removed`.
- CI coverage for the `adapters/otel` module (`go vet` + `go test -race`).

### Changed

- **CSRF secure-by-default documentation.** `tokens.WithTrustedOrigins` and `mfa.WithTrustedOrigins`
  are documented as *wideners* of an on-by-default strict same-origin check; disabling requires the
  explicit `WithInsecureNoOriginCheck` opt-out. `SECURITY.md` updated to match.

### Fixed

- **identity (CSRF gap):** `VerifyEmailHandler` and `RequestEmailVerificationHandler` now enforce the
  strict same-origin check their siblings apply; a cross-origin POST is rejected with `403
  cross_site_blocked` (previously processed).
- **internal/httputil:** an opaque `"null"` `Origin` is treated as untrusted rather than falling back
  to the weaker, more-spoofable `Referer`.
- **tokens/jwt (key cache):** an `Invalidate`/`InvalidateAll` racing an in-flight cache fill is no
  longer lost; the stale pre-rotation keyset is dropped instead of being re-cached for a full TTL.
- **oauth:** `DynamicBeginHandler` / `DynamicCallbackHandler` no longer mutate the shared
  closure-captured `opts` slice, so concurrent requests for different tenants can no longer alias one
  another's resolver.
- **mfa:** `NewService` rejects a sub-second `WithPeriod` at construction (previously a divide-by-zero
  panic on first use); `ConfirmTOTP` resets the failed-attempt budget on success so failed
  confirmations are not carried into the user's first-login budget.
- **passkey:** a per-handler `WithCookieKey` override shorter than `MinCookieKeyLength` now fails
  closed with `500 server_misconfigured`.
- **event:** a panicking `Sink` is contained (and logged) so a misbehaving audit sink cannot change a
  handler's client-visible behavior; `MultiSink` continues its fan-out past a panicking member.
- **adapters/pgx:** `AddIdentity` gates the insert on a live, same-tenant user (`ErrUserNotFound`
  otherwise), matching the memory store and closing a cross-tenant / soft-deleted linkage hole.
- **adapters/pgx (keystore):** `CreateTenant` is now atomic per tenant. Its check-then-insert ran
  unserialized, so concurrent calls for the same new tenant (with distinct key ids) could all win
  and insert multiple active signing keys; it now runs inside a transaction guarded by a per-tenant
  `pg_advisory_xact_lock`, so exactly one call wins and the rest get `ErrTenantExists`.

## [0.3.0] - 2026-06-06

Public-release hardening: secure-by-default behavior changes, a PostgreSQL storage-adapter
module split, plus documentation/naming/packaging cleanup and pre-1.0 API-stability changes,
in preparation for an open public release. Under v0.x SemVer the breaking changes below are a
minor bump. The pre-hardening tags `v0.1.0`–`v0.2.1` are retracted in `go.mod`.

### BREAKING

- **passkey (secure-by-default):** `passkey.NewService` now fails fast on insecure
  configuration. WebAuthn user verification is **required by default** (set
  `Config.UserVerification` explicitly to opt out); a `ChallengeStore` is **required**
  (`Config.ChallengeStore`) unless `Config.InsecureNoChallengeStore` is set; and the HMAC
  cookie key is supplied and validated at construction (`Config.CookieKey`, min length
  `MinCookieKeyLength`). New sentinels `ErrCookieKeyMissing` and `ErrChallengeStoreMissing`.
  Existing callers must add `CookieKey` + `ChallengeStore` (or the explicit opt-outs).
- **mfa (secure-by-default):** the second factor is now attempt-limited. `VerifyTOTP` and the
  recovery-code path reserve a slot via the new `mfa.Store.IncrementTOTPAttempts` atomically
  *before* the constant-time compare and lock the factor after `DefaultMaxAttempts` (5) failures
  (`ErrTooManyAttempts`, HTTP 429); a successful verification resets the counter. Limiting is ON
  by default — tune it with `mfa.WithMaxAttempts` or disable it explicitly with
  `mfa.WithNoAttemptLimit`. Adds `failed_attempts` to `mfa_totp` (pgx migration
  `002_add_totp_failed_attempts.sql`). External `mfa.Store` implementers must add
  `IncrementTOTPAttempts` and reset `failed_attempts` on a successful `MarkTOTPUsed` /
  `ConsumeRecoveryCode`.
- **tokens/jwt:** `jwt.VerifyRefreshToken` and `jwt.VerifyAPIKey` now take a `tenantID string`
  parameter (after `ctx`) so multi-tenant callers can verify tokens saved under a real tenant —
  the lookup was previously hard-wired to the empty tenant and reported not-found for any token
  saved under a real one. Single-tenant callers pass `""` (or use the `SingleTenant` facade,
  whose signature is unchanged).
- **pgx storage moved to a nested module:** the PostgreSQL stores + migration runner now live in
  the separate module `github.com/JLugagne/egauth/adapters/pgx` (packages `adapters/pgx/identity`,
  `adapters/pgx/tokens`, …) instead of `egauth/<domain>/pgx`. Core consumers no longer pull the
  `pgx` driver or the testcontainers/Docker dependency chain. Update imports to
  `github.com/JLugagne/egauth/adapters/pgx/<domain>` and add
  `go get github.com/JLugagne/egauth/adapters/pgx`. The `Store` interfaces and the exported
  `*storetest` conformance suites stay in core as the documented backend-extension seam.

### Added

- `tokens/basic`: a non-generic convenience layer over the generic token API, specialized to
  no-custom-claims, so the common login/refresh/protect path can be wired without writing
  `[struct{}]`. The generic `tokens` / `tokens/jwt` API is unchanged and remains the path for
  custom claims.
- Four OAuth providers since v0.2.0 — **Amazon Cognito, Discord, GitLab, and Keycloak** —
  bringing `oauth/providers` to **12** (Apple, Auth0, Cognito, Discord, Facebook, GitHub, GitLab,
  Google, Keycloak, LinkedIn, Microsoft, Okta).
- This `CHANGELOG.md`, backfilled from git history.

### Changed

- Documentation, naming, and packaging consistency improvements across the repository
  (module/name consistency, README, package docs, pinned CI linter, relaxed `go` directive).
- Documented that `identity.Store` / `tokens.Store` are cohesive, pre-1.0-evolving persistence
  contracts (new methods may be added in minor releases); they are intentionally not split into
  optional capability interfaces.

### Fixed

- Documentation drift and packaging rough edges surfaced during the public-release audit
  (non-compiling package example, duplicated doc comments, dangling references, stale provider
  list, tracked coverage artifact).

## [0.2.1] - 2026-06-04

### Changed

- Synchronized the `oauth/providers` documentation with the actual code and
  added a CI check that validates the provider docs to prevent future drift.

## [0.2.0] - 2026-06-04

### Added

- Extracted the OAuth providers into a dedicated `oauth/providers` package and
  added support for 8 identity providers.

### Changed

- OAuth provider documentation kept in sync with the code and checked in CI.

## [0.1.0] - 2026-06-03

Initial public release.

### Added

- Composable, multi-tenant authentication library with an explicit, mandatory
  `tenantID` argument across stores.
- OAuth/OIDC support, including a `ProviderStore` and dynamic handlers for
  multi-tenant provider configuration.
- Configurable Argon2 cost parameters with `NeedsRehash` for transparent
  rehash-on-login.
- Session management with an absolute maximum lifetime and a
  revoke-all-sessions-for-user capability.
- Independent recovery channel and a phone/SMS verification flow.
- Context-cancellation support on expensive code paths.
- Store `Ping` health-check seam.
- Comprehensive developer manual and documentation, including a quickstart,
  runnable examples, and package-level docs, with a CI doc-symbol check to
  guard the docs against API drift.
- MIT License, `CONTRIBUTING.md`, a Makefile, a GitHub Actions
  security/testing pipeline, and a GitHub Pages workflow for the Hugo docs.

### Changed

- HS256 JWT signing keys are redacted in log and print output.

### Security

- Enforced WebAuthn user verification (SEC-01).
- SSRF-hardened server-side OIDC fetches (SEC-02).
- Verified `iss` and `aud` on the access-token path (SEC-03).
- Reject malformed Argon2 PHC parameters instead of panicking (SEC-04).
- Single-use passkey challenge consumption to block login replay (SEC-05).
- Required HTTPS and bound JWKS to the issuer via OIDC discovery.
- Bounded the JWKS key count and RSA modulus/exponent size (SEC-11).
- Bound the OAuth state cookie to the provider and tenant (SEC-12).
- Capped the passkey `Finish` ceremony request-body size (DOS-01).
- Memory session store: O(1) hash lookup and eviction of expired sessions to
  prevent unbounded growth (DoS hardening).
- Deferred OIDC configuration errors instead of panicking per request.
- Completed and documented a panic/DoS sweep (3 confirmed issues fixed,
  4 refuted).
