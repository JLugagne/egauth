# Security Review — Findings Tracker

Source: deep adversarial security review (2026-06-02). 44 raw findings → 13 confirmed after
two-lens adversarial verification against the real code + pinned dependency sources
(golang-jwt v5.3.1, go-webauthn v0.17.4, x/crypto v0.52.0). Severities below are
**post-verification** (several were down-ranked from the finder's original claim).

**Process per finding:** write a failing unit test that reproduces the issue → implement the fix →
confirm the test passes (and full suite is green) → check the box. Use go-surgeon for all `*.go` edits.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

---

## HIGH

- [x] **SEC-01 — Passkey User Verification is never enforced**
  - File: `passkey/service.go:43-57`
  - Problem: `webauthn.New` omits `AuthenticatorSelection.UserVerification`, so go-webauthn's
    `shouldVerifyUser` is always false and the UV bit is never checked (register, login,
    discoverable). No option exposed to require it. Defeats passkey-as-step-up / passwordless.
  - Fix: set `AuthenticatorSelection.UserVerification = protocol.VerificationRequired`; expose a
    `Config`/option to control it; enforce the UV flag at Finish for step-up/passwordless.
  - Resolution: added `Config.UserVerification protocol.UserVerificationRequirement` (zero value =
    backward-compatible "preferred"); wired into `webauthn.Config.AuthenticatorSelection.UserVerification`
    in `NewService`. In go-webauthn v0.17.4 this single field drives `SessionData.UserVerification` and
    `shouldVerifyUser`, so UV is enforced automatically at Finish across register/login/discoverable —
    no explicit per-method flag check needed.
  - [x] Test: a UV=0 assertion is rejected when UV is required (`passkey/userverification_test.go`)
  - [x] Fix implemented
  - [x] Suite green + box checked

- [x] **SEC-02 — SSRF in the dynamic multi-tenant OIDC ProviderStore**
  - Files: `oauth/pgx/store.go:47-80`, `oauth/oidc.go:259-286`, `oauth/provider.go:198-210`
  - Problem: tenant-stored `jwks_url`/`token_url`/`issuer` fetched server-side via a bare
    default-transport client — no scheme/host/IP validation. `token_url` POST leaks `client_secret`.
    Bites when an integrator exposes provider registration to an untrusted tenant (BYO-SSO model).
  - Fix: validate provider URLs at registration AND at dial time (require https; reject
    loopback/link-local/RFC1918 via a `net.Dialer.Control` hook to defeat DNS-rebinding); optional
    operator issuer allowlist; ship an SSRF-hardened default `*http.Client`.
  - Resolution: new `oauth/ssrf.go` — `ValidateExternalURL` (https + non-internal-literal-host gate),
    `SafeHTTPClient()` (transport with a `net.Dialer.Control` hook), and `isBlockedIP` covering
    loopback, link-local/metadata (169.254/16, fe80::/10), unique-local (fc00::/7), RFC1918, CGNAT
    (100.64/10), unspecified, multicast — validated at dial time (post-DNS) so it is rebinding-proof.
    `oauth/pgx/UpsertProvider` now validates all four URLs before any DB write; `GetProvider` wires the
    hardened client into both `OIDCConfig.HTTPClient` (JWKS fetch) and the Provider via `WithHTTPClient`
    (token POST). Hardening is opt-in only on the untrusted dynamic-store path; static built-ins
    (Google/GitHub/Discord) keep their default client. Operator issuer allowlist deliberately deferred
    (additive policy layer, no rework needed) — the dial guard + https-at-registration is the core fix.
  - [x] Test: registering/using a loopback or http URL is rejected (`oauth/ssrf_test.go`,
    `oauth/pgx/validate_internal_test.go`)
  - [x] Fix implemented
  - [x] Suite green + box checked

## MEDIUM

- [x] **SEC-03 — `VerifyAccessToken` validates neither `iss` nor `aud`**
  - File: `tokens/jwt/issuer.go:413`
  - Problem: parse passes only `WithTimeFunc`; `iss` is stamped + required at issuance but never
    verified, `aud` is inert. Confused-deputy when one HS256 key is shared across services/audiences.
  - Fix: pass `jwt.WithIssuer(s.issuer)`; add expected-audience to `Config` + pass `jwt.WithAudience`.
  - Resolution: added `Config.ExpectedAudience []string` (any-of semantics) threaded onto `Service`.
    `VerifyAccessToken` now appends `jwt.WithIssuer(s.issuer)` (only when issuer is set, preserving
    issuer-less backward compat) and `jwt.WithAudience(s.expectedAudiences...)`. Confirmed against
    golang-jwt v5.3.1: `WithAudience` is variadic and validates with `expectAllAud=false`, so a single
    call gives ANY-of matching; iss/aud failures map to `tokens.ErrInvalidToken`, not `ErrTokenExpired`.
    Refresh/API-key paths are opaque store lookups (no JWT) so need no change; singletenant forwards.
  - [x] Test: token minted for issuer/aud A is rejected by a service expecting B (shared key)
    (`tokens/jwt/audience_test.go`)
  - [x] Fix implemented
  - [x] Suite green + box checked

- [x] **SEC-04 — `argon2.Compare` panics on malformed stored parameters**
  - File: `passwords/argon2/hasher.go:99-120`
  - Problem: `time`/`threads`/`keyLen` fed to `argon2.IDKey` with no lower-bound check; `t=0`,
    `p=0`, or empty hash segment → panic, and there is no `recover()` → process crash. Reachable via
    consumer-populated `Identity.PasswordHash` (import/migration/DB).
  - Fix: reject `time<1 || threads<1 || keyLen==0` (and clamp/limit `memory`) before `IDKey`.
  - Resolution: `Compare` now rejects (→ `passwords.ErrInvalidPassword`, the same opaque mismatch
    error, so a corrupt hash leaks no distinct signal) when `time<1 || threads<1 || keyLen==0 ||
    memory < 8*threads`, inserted after PHC parsing and before `argon2.IDKey`. Confirmed against
    x/crypto v0.52.0 source: `deriveKey` panics on `time<1` and `threads<1`; `keyLen==0` nil-derefs in
    `extractKey`; `memory` below the per-thread floor (`8*threads` KiB) means the stored digest could
    not have been self-produced (corrupt). Input validation makes every panic path unreachable — no
    blanket `recover()` added (root-cause fix).
  - [x] Test (write first): PHC with `t=0`, `p=0`, and empty-hash each return error, not panic
    (`passwords/argon2/hasher_test.go` — `TestArgon2Hasher_MalformedParamsDoNotPanic`)
  - [x] Fix implemented
  - [x] Suite green + box checked

- [x] **SEC-05 — Passkey login replay for sign-count-0 authenticators**
  - File: `passkey/handlers.go:235-253`
  - Problem: challenge only in the HMAC cookie; no server-side single-use consume. Clone counter is a
    no-op at 0/0 (typical platform passkeys), so a verbatim Finish-request replay within 5 min
    re-authenticates. Requires capturing raw request bytes.
  - Fix: persist the issued challenge (or hash) with a short TTL; atomically consume it at Finish;
    reject an already-consumed challenge.
  - Resolution: new optional `passkey.ChallengeStore` interface (`Put(ctx,tenant,challenge,expiresAt)`
    / atomic single-use `Consume(ctx,tenant,challenge) (bool,error)`) wired via `WithChallengeStore`.
    Begin handlers (login + registration) `Put` the issued `SessionData.Challenge` (TTL from
    `SessionData.Expires`); Finish handlers `Consume` it immediately after `loadSession` and before the
    verifier, so a byte-identical replay gets `(false,nil)` and is rejected (`ErrSessionInvalid`, 400)
    — even for a 0/0 authenticator whose clone counter never advances. Opt-in: handlers without a store
    behave as before. In-memory impl in `passkey/memory` (`NewChallengeStore`); pgx-backed impl
    deferred (noted in the memory package doc). Discoverable login has no HTTP handler (service-layer
    only), so nothing to wire there.
  - [x] Test: replaying a completed Finish request fails (`passkey/replay_test.go` —
    `TestFinishLogin_Replay_BlockedWithChallengeStore`; store unit tests in `passkey/memory`)
  - [x] Fix implemented
  - [x] Suite green + box checked

- [x] **SEC-06 — OIDC token/JWKS URLs not required to be HTTPS**
  - File: `oauth/provider.go:90-105` (also `oauth/oidc.go:84-122`)
  - Problem: any scheme accepted; `http://` token endpoint sends `client_secret` cleartext, `http://`
    JWKS allows MITM key substitution. Doc claims HTTPS but nothing enforces it.
  - Fix: reject non-https URLs in `New`/`newOIDCVerifier`, with an explicit dev-only opt-out.
  - Resolution: https enforced by default (reusing `ValidateExternalURL`/`ErrBlockedURL`) in
    `newOIDCVerifier` (issuer + JWKS/discovery URL) and `oauth.New` (auth/token URL, surfaced at
    `Exchange` via a deferred `configErr`). Loud, greppable dev-only opt-in added: `WithInsecureURLs()`
    ProviderOption + `OIDCConfig.AllowInsecureURLs`, mirroring `WithInsecureCookies`. On the insecure
    path the verifier falls back to a plain client (the SSRF-safe client blocks loopback). Static
    Google/GitHub/Discord providers are unaffected (already https).
  - [x] Test: non-https token/auth/JWKS URL rejected (`oauth/oidc_discovery_test.go`)
  - [x] Fix implemented
  - [x] Suite green + box checked

- [x] **SEC-07 — JWKS host not bound to the issuer; no discovery**
  - File: `oauth/oidc.go:51-69` (also `oauth/pgx/store.go:73-78`)
  - Problem: `Issuer` and `JWKSURL` are independent free-form fields with no relationship enforced; in
    the dynamic store a tenant can bind a trusted issuer string to attacker-controlled keys.
  - Fix: derive `jwks_uri` from the issuer via OIDC discovery, or require JWKS host == issuer host;
    allowlist issuers for the dynamic store. (Coordinate with SEC-02/SEC-06 as one OIDC pass.)
  - Resolution: full OIDC discovery (`oauth/oidc_discovery.go`) — the verifier fetches
    `<issuer>/.well-known/openid-configuration` over the configured (SSRF-safe on the dynamic path)
    client, requires the doc's `issuer` to equal the configured issuer exactly, validates `jwks_uri`
    and binds its host to the issuer host. `JWKSURL` is now an optional same-host override only (a
    mismatched host is rejected at construction with `ErrJWKSHostMismatch`). Discovery is lazy and
    cached under the existing jwks-cache mutex. The pgx store now omits the tenant JWKSURL entirely to
    force discovery, and gained an opt-in operator issuer allowlist (`WithIssuerAllowlist`, empty =
    allow-all default) enforced in both `GetProvider` and `UpsertProvider`. Existing fixtures that
    relied on the old http/host-mismatch behavior were updated to self-consistent issuer/discovery —
    that is the closed vulnerability.
  - [x] Test: issuer/JWKS host mismatch (or non-discovered jwks) rejected
    (`oauth/oidc_discovery_test.go`, `oauth/pgx/allowlist_internal_test.go`)
  - [x] Fix implemented
  - [x] Suite green + box checked

## LOW

- [x] **SEC-08 — No absolute session lifetime**
  - File: `sessions/service.go:117`
  - Problem: `Touch` slides `ExpiresAt` to `now+duration` forever; `CreatedAt` never compared. Idle
    timeout is the only timeout; a kept-warm stolen token lives indefinitely.
  - Fix: add `WithMaxLifetime`; in Validate/Touch/Rotate reject when `now > CreatedAt + maxLifetime`.
  - Resolution: `WithMaxLifetime` ServiceOption; `ValidateSession` rejects (→ `ErrSessionNotFound`) once
    `now > CreatedAt+maxLifetime`, and `Touch`/`Rotate` clamp the new `ExpiresAt` to that deadline. Zero
    value disables the cap. (`sessions/lifetime_test.go`)
  - [x] Test · [x] Fix · [x] Green

- [x] **SEC-09 — No revoke-all / "log out everywhere"**
  - File: `sessions/service.go:15`
  - Problem: `Store` has `DeleteSessionsByUserID` but `Service` only exposes single-token
    `RevokeSession`; can't kill an attacker's other sessions after reset/compromise.
  - Fix: add `RevokeAllForUser(ctx, tenantID, userID)` to `Service` + `SingleTenant` forwarder.
  - Resolution: `Service.RevokeAllForUser` (+ `SingleTenant` forwarder) over the existing
    `Store.DeleteSessionsByUserID`; no other `Service` implementer/mock existed. (`sessions/lifetime_test.go`)
  - [x] Test · [x] Fix · [x] Green

- [x] **SEC-10 — argon2: no minimum-cost floor, no rehash-on-login**
  - File: `passwords/argon2/hasher.go:96-120`
  - Problem: verification trusts the stored params; weak imported hashes verify cheaply forever and a
    defaults bump never upgrades existing users.
  - Fix: enforce a configurable strength floor; add `NeedsRehash`; re-hash on successful login when
    stored params are below target. (Combine with SEC-04.)
  - Resolution: `NewHasher` gains `WithTime`/`WithMemory`/`WithThreads` options (zero-arg defaults
    byte-for-byte unchanged) and a concrete `NeedsRehash(hash) bool` that flags a stored hash below the
    hasher's current target params (or malformed/foreign) for rehash-on-login. Kept off the shared
    `passwords.Hasher` interface to avoid breaking other implementers (consumers type-assert).
    (`passwords/argon2/hasher_test.go`)
  - [x] Test · [x] Fix · [x] Green

- [x] **SEC-11 — JWKS parsing unbounded (key count / RSA modulus size)**
  - File: `oauth/oidc.go:320-360,418-427`
  - Problem: no cap on number of keys or modulus size (within the 1 MiB body); hostile JWKS amplifies
    CPU/memory on cache-miss.
  - Fix: cap key count (e.g. ≤16); bound RSA modulus to [2048, 8192] bits and exponent range;
    coalesce/rate-limit refreshes per issuer.
  - Resolution: `parseJWKS` hard-rejects a document declaring more than `maxJWKSKeys` (16) before the
    per-key loop; `jwk.publicKey` rejects RSA keys outside [2048,8192] bits or with an out-of-range
    exponent (skipped per-key, so an all-bad JWKS trips the existing no-usable-keys error). Per-issuer
    refresh rate-limiting deferred (the cache already has a TTL). (`oauth/oidc_test.go`)
  - [x] Test · [x] Fix · [x] Green

- [x] **SEC-12 — OAuth state cookie not bound to provider/tenant**
  - Files: `oauth/handlers.go:163,172-211,245-264,349-376`, `oauth/state.go:52-68`
  - Problem: single shared cookie name carries only state/verifier/nonce; multiple providers/tenants
    on one host enable provider confusion.
  - Fix: bind provider+tenant into the signed/packed state and verify on callback; and/or namespace
    the cookie per provider/tenant.
  - Resolution: `packState`/`unpackState` now carry the provider name and tenant (base64url-encoded so
    the separator stays unambiguous, fixed 5-field format that fails closed on any legacy/forged value);
    `CallbackHandler` rejects a mismatched packed provider/tenant (`provider_mismatch`/`tenant_mismatch`,
    403). Dynamic handlers inherit it via delegation. Cookie-namespacing deferred (packed-state binding
    already closes the vuln). (`oauth/state_binding_test.go`)
  - [x] Test · [x] Fix · [x] Green

## INFO

- [ ] **SEC-13 — `Request*` endpoints have no built-in rate limiting (mail/SMS bombing, SMS toll-fraud)**
  - Files: `identity/handlers.go:405,534,891`, `identity/service.go:851`
  - Problem: unauthenticated reset/magic-link take a victim email; phone-verification takes an
    attacker-chosen number into a paid SMS sender. The `ratelimit` package ships but is unwired.
  - Fix: document a required wiring recipe; provide a ready helper that wraps reset/magic-link/refresh
    with a per-IP + per-account `Limiter`; cap outstanding tokens per (user, kind); rate-limit phone
    verification per destination number; prominently warn about SMS toll-fraud.
  - [ ] Docs/recipe · [ ] Optional helper · [ ] Box checked

---

## Reviewed and NOT actioned (refuted or accepted design)

Captured so they aren't re-triaged. Revisit only if you disagree with the verifiers' call.

- `VerifyAPIKey`/`VerifyRefreshToken` hardcode empty tenant — fails **closed** (correctness, not a
  leak); revisit if multi-tenant API-key verification is a supported path. `tokens/jwt/issuer.go:456,480`
- CSRF origin check opt-in on refresh/logout — SameSite=Lax + opt-in allowlist judged adequate.
  `tokens/handlers.go:189-190`
- MFA handlers expose no CSRF/Origin option — consider adding `WithTrustedOrigins` parity with OTP
  handlers if SameSite isn't guaranteed by integrators. `mfa/handlers.go:148`
- `Request*` response-latency timing oracle — delivery is async; synchronous delta judged too noisy
  to be a reliable oracle. `identity/service.go:454,785,996`
- `CreateSession ON CONFLICT` overwrite — not reachable given hashed-token uniqueness.
  `sessions/pgx/store.go:53`
- argon2 unbounded `memory` (separate from SEC-04 crash) — fold the clamp into SEC-04/SEC-10.
- `DefaultPolicy` 72-char cap + composition rules — consider steering the quickstart to
  `PassphrasePolicy` + breach screening. `passwords/policy/default.go:23-32`
- Session IP/User-Agent captured but not enforced — informational/by-design. `sessions/service.go:101`
- `RequireSession` accepts Bearer == cookie — by design for API clients. `sessions/middleware.go:32`
- HIBP `WithBaseURL` no scheme validation — low risk (k-anonymity). `passwords/breach/hibp/hibp.go:64`
- Passkey credential-existence oracle (400 vs 200); MFA form size limit; TOTP digit overflow;
  RequestEmailChange 409 enumeration; VerifyEmailHandler CSRF; AccountLocked event race; reset
  doesn't invalidate other tokens; refresh rotation not transactional; sign-count blind overwrite;
  MinSecretKeyLength = length-not-entropy; ceremony-cookie MaxAge knob; non-constant-time hash
  lookups in memory stores — all reviewed, judged low/non-exploitable or by-design.
