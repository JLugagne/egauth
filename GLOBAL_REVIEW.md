# egauth — Global Deep Review & Security Audit

> **Verdict: DO NOT SHIP AS-IS for a multi-tenant SaaS.** The cryptographic core is genuinely
> strong — 150 separate attack hypotheses about randomness, AEAD, JWT algorithm confusion, kid
> handling, constant-time comparison and SQL injection were tested and **held**. What does not hold
> is the layer above it: **MFA is not actually enforced on any non-password login path**, the
> shipped `webapp` preset lets a **disabled account refresh forever**, tenant resolution **fails
> open into the `""` partition**, and several documented options **silently disable the control they
> claim to harden** or **panic at request time**. Nine HIGH findings are confirmed with reproducible
> failing tests. None is a remote-unauthenticated crypto break; most require a stolen password, a
> hijacked session, or one line of documented-but-broken configuration — which is exactly the threat
> model a commercial SaaS must survive.

Whole-project review (not a diff) of module `github.com/JLugagne/egauth` at `HEAD = ce6aeef`
(Go 1.26.5, ~55k LOC, 3 modules: core, `adapters/pgx`, `adapters/otel`).

**Totals:** 132 distinct findings · **9 confirmed HIGH** · **35 confirmed MEDIUM** · 23 confirmed
LOW · 2 refuted · 2 plausible-but-unproven · 61 advisory (low/info, not sent to refutation) ·
150 attack hypotheses tested and cleared.

---

## Method

Eleven independent adversarial lenses, three running in parallel, model-tiered by task
(Opus/xhigh for tenant isolation, cryptography and the identity state machine; Opus/high for the
HTTP boundary, token lifecycle, second factors and doc-vs-code; Sonnet/high for the pgx adapter,
concurrency, and idiom/supply-chain). Deterministic tooling was run centrally once.

Every lens that produced a medium-or-worse finding was then handed to a **separate Opus refuter in
its own isolated git worktree**, instructed to *disprove* the claim and told that reasoning alone is
insufficient. A finding is **CONFIRMED** only if the refuter produced a reproducible failure — a
failing assertion, a panic, a compile error, or verbatim command output. Otherwise it is
**PLAUSIBLE** or **REFUTED**. The refuters also reported defects the finders had missed; those are
marked *(refuter-found)* and carry the same evidence, but were not themselves independently
re-refuted.

Two finder claims were **refuted** and are documented in §6 rather than quietly dropped.

### Deterministic baseline

| Check | Core | `adapters/pgx` | `adapters/otel` |
|---|---|---|---|
| `go build ./...` | clean | clean | clean |
| `go vet ./...` | clean | clean | clean |
| `go test ./...` | **1396 pass / 44 pkgs** | pass (`-short`) | pass |
| `gofmt -l` | clean | **1 file dirty** (`tokens/store.go`) | clean |
| `golangci-lint v2.12.2` | 0 issues | — | — |
| `govulncheck v1.1.4` | 0 reachable | 0 reachable | not run in CI |

Two caveats on that green baseline, both findings in their own right:

- **There is no `.golangci.yml`.** `make lint` and the CI lint job therefore run only golangci-lint's
  five *default* linters (`errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`). The strict
  suite the project's own docs assume (`revive`, `errorlint`, `wrapcheck`, `err113`, `errname`,
  `godot`, `misspell`, `dupword`, `perfsprint`, `intrange`) never runs. A `--default=all` run
  surfaces 3000+ additional diagnostics.
- **A green test suite is not evidence of these guarantees.** Every one of the nine HIGH findings
  below reproduces on a tree where all 1396 tests pass.

---

## 1. What to fix before you put this in front of paying tenants

Ordered by what I would actually block a launch on.

1. **Enforce MFA on every login path, or document loudly that it isn't.** `WithMFAGate` currently
   guards exactly one handler. (§2.A)
2. **Make the shipped `webapp` preset re-check account status**, or stop shipping a `ClaimsProvider`
   that can't. Right now `DisableUser` does not end access. (§2.B)
3. **Fail closed on an unresolved tenant** in the identity/oauth/otp/tokens handler families, the
   way `sessions` and `tokens` middleware already do. (§2.C)
4. **Fix the `__Host-` cookie panic** — validate `Cookies` at construction instead of panicking on
   the request path, including the read path. One documented config line takes down every protected
   route. (§2.E)
5. **Fix `WithLockout(negative, …)`** — it disables brute-force lockout while both the godoc and
   `SECURITY.md` promise the opposite. (§2.E)
6. **Give the identity Store a per-user verification-token purge seam** so a password reset can
   actually end an account takeover. There is currently no consumer-side mitigation. (§2.B)
7. **Add an advisory lock to the pgx migration runner** before your first rolling deploy. (§3)
8. **Add the `(tenant_id, user_id)` index on `identities`** before your first thousand tenants. (§3)
9. **Wire `adapters/pgx/keystore` into `keystore/keystoretest`.** It currently *fails* the core
   conformance suite, and `RevokeTenantKeys` is silently reversible on Postgres. (§2.D)
10. **Do not use `passkey` in a multi-pod deployment yet** — the only shipped `ChallengeStore` is
    per-process, and `SECURITY.md` names a `passkey/pgx` package that does not exist. (§3)

---

## 2. Confirmed HIGH findings

### A. MFA is not an enforced control — it is advisory

Four confirmed defects. A consumer who wires `identity.WithMFAGate(mfaSvc)` exactly as
`SECURITY.md:170-177` prescribes does **not** get an enforced second factor. This is the single
most consequential cluster in the review: it makes the MFA feature approximately decorative against
a stolen password.

#### A1 · [HIGH] `MagicLinkLoginHandler` and the OAuth callback ignore the MFA gate entirely

`identity/handlers.go:753` · `oauth/handlers.go:255` · category `auth-bypass`

`LoginHandler` has an `if cfg.mfaGate != nil { … IsEnrolled … }` branch at
`identity/handlers.go:345-359`. `MagicLinkLoginHandler` (`identity/handlers.go:718-758`) has **no
such block** — it runs `svc.LoginWithMagicLink`, then `PasswordChangeRequired`, then goes straight
to `issuePairAndSetCookies` at line 753. The OAuth callback has the same gap, and the `oauth`
package exposes no MFA-gate option at all.

The refute test constructed the handler *with* the gate configured and the user *enrolled*:

```
$ GOWORK=off go test ./identity/ -run TestRefute -v
=== RUN   TestRefuteSF3_MagicLinkIgnoresMFAGate
    magic-link login for an MFA-ENROLLED user: refresh cookie=true AMR=[]
    Error: Expected nil, but got: &http.Cookie{Name:"__Host-refresh_token", ...}
    Messages: MagicLinkLoginHandler must not hand an MFA-enrolled user a renewable refresh cookie
--- FAIL: TestRefuteSF3_MagicLinkIgnoresMFAGate
```

**Impact.** Mailbox compromise (magic link) or IdP-account compromise (OAuth) yields a
full-privilege, indefinitely renewable session with no second factor. Nothing in `SECURITY.md`,
`README.md` or `.llms/` discloses this.

**Fix.** Apply the same `mfaGate` branch in `MagicLinkLoginHandler`, and add an MFA-gate option to
the oauth callback. Until then, document that `WithMFAGate` only covers password login.

#### A2 · [HIGH] A pre-MFA interim token can strip the victim's second factor — through the gate the docs recommend

`mfa/service.go:40` · category `auth-bypass`

The interim token minted at `identity/handlers.go:1374` carries `AMR=[pwd]`, and because
`claims.AuthTime` is left unset the issuer stamps `auth_time = now`
(`tokens/jwt/issuer.go:415-418`). So `tokens.WithMaxAuthAge` — the gate `mfa/service.go:40-41` and
`.llms/mfa.md:171` recommend for `DisableHandler` — passes trivially. `mfa/handlers.go:220-244`
(`guarded`) checks only method, same-origin and `cfg.resolve(r)`, so `DisableTOTP` runs and deletes
the enrollment **and every recovery code**.

```
$ GOWORK=off go test ./mfa/ -run TestRefute -v
=== RUN   TestRefuteSF1_InterimTokenStripsMFAThroughRecommendedMaxAuthAgeGate
    DisableHandler behind WithMaxAuthAge, driven by the pre-MFA interim token: status=204
    IsEnrolled after the interim-token disable call = false
--- FAIL
=== RUN   TestRefuteSF1_AMRGateDoesBlock
    same call behind WithRequiredAMR(AMRMFA): status=403 body="step_up_required"
--- PASS
```

The correct gate exists — `WithRequiredAMR(AMRMFA)` blocks it with 403. The documentation points at
the wrong one.

**Fix.** Change the recommendation in `mfa/service.go:40-41`, `.llms/mfa.md:171` and
`identity/service.go:196-207` from `WithMaxAuthAge` to `WithRequiredAMR(tokens.AMRMFA)`. Better:
have `DisableHandler` reject an `AMR` lacking an MFA factor on its own, so the gate is not the
consumer's to remember.

*Related (refuter-found, MEDIUM):* the same interim token can **irreversibly delete the account**
through the same recommended gate — `identity/service.go:206`, `DeleteAccountHandler` reached with
status 204. Note `identity/handlers.go:983-985` *does* additionally recommend
`WithRequiredAMR(AMRMFA)`, so the two doc surfaces disagree and only one is sufficient.

#### A3 · [HIGH] `ChangePasswordWithReissueHandler` upgrades an interim token into a full renewable pair

`identity/handlers.go:873` · category `auth-bypass`

`cfg.userResolver(r)` resolves the user from the interim access token; nothing inspects the
request's `AMR`. Line 873 then calls `issuePairAndSetCookies`, which builds claims from
`claimsOf(user)` — **the user, not the request** — and writes both cookies. This directly violates
`SECURITY.md:170-176` ("not an indefinitely renewable session").

```
$ GOWORK=off go test ./identity/ -run TestRefute -v
=== RUN   TestRefuteSF2_ChangePasswordWithReissueUpgradesInterimSession
    reissue from an interim (pre-MFA) session: access=true refresh=true AMR=[]
    Error: Expected nil, but got: &http.Cookie{Name:"__Host-refresh_token", ...}
--- FAIL
```

The handler was built *with* `WithMFAGate(enrolled: true)` wired — it is accepted and ignored.

**Fix.** Carry the interim marker in the claims and refuse to reissue a full pair from a request
whose `AMR` lacks an MFA factor.

#### A4 · (refuter-found, MEDIUM) An MFA-gated login is indistinguishable on the wire from a full login

`identity/handlers.go:356` · category `api-footgun`

Both the interim branch (line 356) and the full-pair branch (line 369) end with the identical
`httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)`. Two logins over the same
handler produce byte-identical status, body and non-`Set-Cookie` headers; the only difference is an
`HttpOnly` cookie browser JS cannot observe.

**Impact.** A consumer has no reliable signal to drive `mfa.StepUpHandler`. Either the SPA treats
204 as "logged in" and the user is silently ejected when the 5-minute interim token expires, or the
integrator keeps the user on the interim token — which, per A2/A3, is over-privileged.

**Fix.** Add a distinguishing signal (a `mfa_required` body field, a distinct status, or a separate
`mfaSuccessURL` option).

---

### B. Account-status and revocation controls do not hold

#### B1 · [HIGH] The only `ClaimsProvider` egauth ships never re-checks account status — a disabled user refreshes forever

`webapp/webapp.go:154` · category `auth-bypass`

The batteries-included preset installs its own provider at `webapp/webapp.go:154-156`:

```go
func(_ context.Context, userID uuid.UUID, tenantID string) (basic.Claims, error) {
    return basic.Claims{Subject: userID, TenantID: tenantID}, nil
}
```

It takes `_ context.Context`, never touches `cfg.Identity`, and **cannot return an error**. The
preset also never registers `tokens.NewAccountRevoker(cfg.TokenStore)` — and it cannot, because
`cfg.Identity` is already constructed by the caller — so the `s.disableRevokers` loop at
`identity/service.go:1316` is empty and the user's refresh rows survive `DisableUser`.

```
$ GOWORK=off go test ./webapp/ -run TestRefute -v
=== RUN   TestRefuteLIFE1_DisabledUserCanRefreshForever
    refresh #1 after disable => 204   (Error: must not obtain a fresh token pair)
    refresh #2 after disable => 204
    refresh #3 after disable => 204
    refresh #4 after disable => 204
    refresh #5 after disable => 204
--- FAIL
```

Each rotation also resets the refresh expiry to `now + RefreshTTL` (`tokens/jwt/issuer.go:468`), so
access is not merely retained — it is renewed indefinitely.

**Impact.** Complete loss of account deactivation for anyone using the shipped preset or the README
quickstart without hand-wiring `identity.WithDisableRevokers`. Offboarded employees, banned tenants
and self-service deletions keep working. This defeats termination, GDPR erasure and compromise
response simultaneously.

**Fix.** Have the preset's `ClaimsProvider` load the user and return an error when
`DisabledAt`/`DeletedAt` is set, and register the account revoker inside the preset (accept a
constructor callback rather than a built `Identity` if necessary).

#### B2 · [HIGH] Password reset never invalidates outstanding verification tokens — takeover survives the documented remediation

`identity/service.go:714` · category `auth-bypass`

1. Attacker holds a live session on the victim's account — the exact scenario `ResetPassword` is
   documented to remediate.
2. Attacker POSTs `RequestRecoveryEmailHandler` with `recovery_email=attacker@evil`
   (`identity/handlers.go:1223` → `service.go:1176`). Only rejected if it equals the primary
   (`service.go:1201`). A `KindRecoveryEmailVerification` token with a **24h TTL** is mailed to the
   attacker.
3. Victim performs the canonical recovery: `ResetPassword` (`service.go:693`) rewrites the hash and
   the `AccountErasers` revoke every session and refresh family (`service.go:723-733`). The attacker
   loses their session.
4. **Nothing deletes the pending verification-token rows.** The Store exposes only
   `CreateVerificationToken` / `ConsumeVerificationToken` / `DeleteExpiredVerificationTokens`
   (`identity/store.go:110-127`) — there is **no per-user purge seam**, so the consumer cannot fix
   this either.
5. Attacker POSTs `ConfirmRecoveryEmailHandler` — token-authenticated, no session needed.
   `consumeForLiveUser` re-checks only `DeletedAt`/`DisabledAt` (`service.go:677-686`), so it
   succeeds. The account now has an attacker-controlled verified recovery channel, which drives
   `RequestPasswordResetViaRecovery`.

```
$ GOWORK=off go test ./identity/ -run TestRefute -v
=== RUN   TestRefuteTEN1_ResetPasswordLeavesAttackerTokensLive
    Error: An error is expected but got nil.
    Messages: recovery-email token minted before the reset must not still be usable
    recovery email now on the account: attacker@evil.test
    attacker-controlled recovery channel now drives resets: recovery=attacker@evil.test
    Error: An error is expected but got nil.
    Messages: attacker must not be able to authenticate after the victim's recovery
    Error: An error is expected but got nil.
    Messages: email-change token minted before the reset must not still be usable
--- FAIL
```

**Impact.** Full account takeover that **survives the library's own documented remediation**. For a
SaaS this defeats incident response: "force a password reset" does not recover the account, and
there is no supported mitigation short of raw SQL against `verification_tokens`.

**Fix.** Add `DeleteVerificationTokensForUser(ctx, tenant, userID, kinds...)` to the Store contract
(both backends) and call it from `ResetPassword`, `ChangePassword` and `SetTemporaryPassword`.

*Related (refuter-found, MEDIUM):* the memory store's `UpdateUser` blind-writes the whole row
(`identity/memory/store.go:117-120`), so a stale `VerifyEmail` copy **silently clears `DisabledAt`**
— an administratively suspended account can log in again. The pgx backend is immune (it writes only
`email`/`email_verified_at`).

---

### C. Tenant resolution fails open

#### C1 · [HIGH] identity / oauth / otp / tokens handlers fall into the `""` partition when the resolver cannot resolve

`identity/handlers.go:431` · `tokens/handlers.go:273` · category `cross-tenant-leak`

A resolver returning `""` for an unknown `Host` — the natural implementation of a map or DB lookup —
is passed through verbatim. There is no unresolved-tenant rejection, so the request authenticates
against the **empty tenant partition**, which in single-tenant/bootstrap deployments is exactly
where operator accounts live.

```
$ GOWORK=off go test ./identity/ -run TestRefute -v
=== RUN   TestRefuteTEN1_UnresolvedTenantFallsIntoEmptyPartition
    status for unmapped Host with resolver configured: 204
    FAIL-OPEN: login against the "" partition succeeded from an unmapped Host
--- FAIL
=== RUN   TestRefuteTEN1_RegisterLandsInEmptyPartition
    FAIL-OPEN: account 019f95de-… created in the "" partition from an unmapped Host (status 204)
--- FAIL
```

Same fall-through in `RegisterHandler` (:395), `RequestPasswordResetHandler` (:570),
`ResetPasswordHandler` (:601), `VerifyEmail` (:672), magic link (:703/:737), `DeleteAccount`
(:1008), `oauth.CallbackHandler` (`oauth/handlers.go:248`), `otp.VerifyHandler`
(`otp/handlers.go:244`), `tokens` Refresh/Logout (`tokens/handlers.go:161`/`:213`).

**The library already knows this is wrong.** `sessions/middleware.go:70-73` explains that failing
open into `""` would let such requests reach bootstrap/admin sessions, and
`sessions/middleware.go:77-80` plus `tokens/middleware.go:205-208` **do** reject with 401. The four
handler families do not.

Compounding it, `.llms/sessions.md:222` teaches consumers (and LLM agents) to use the raw `Host`
header as the tenant id with no allowlist or canonicalisation — confirmed MEDIUM
(`tenant/TEN-6`).

**Fix.** Add an explicit unresolved-tenant rejection to the four handler families, mirroring
`tokens/middleware.go:205-208`. Correct `.llms/sessions.md` to require an allowlist.

*Related (refuter-found, MEDIUM):* `identity.LoginHandler` resolves the tenant **three separate
times** (`:322` for `Authenticate`, `:334` for `PasswordChangeRequired`, `:346` for
`mfaGate.IsEnrolled`). An impure resolver — an expiring cache entry, a transient DB error — makes
`IsEnrolled(ctx, "", …)` return false and the MFA branch is skipped entirely:

```
    status=204 authTenant="acme" gateTenants=[""] refreshCookieIssued=true
    MFA BYPASS: authenticated in "acme" but the MFA gate was consulted in ""
```

The authors already know the hazard — `oauth/handlers.go:379` pins the tenant once precisely so
behaviour is "consistent even if the supplied resolver is not perfectly pure". `LoginHandler`
should do the same.

---

### D. Keystore revocation is reversible on Postgres

#### D1 · [HIGH] `RevokeTenantKeys` is silently undone by lazy provisioning on the pgx backend

`adapters/pgx/keystore/store.go:109` · category `crypto`

`keystore/resolve.go:17` auto-provisions on **exactly one sentinel**:
`if m.lazy && errors.Is(err, ErrTenantNotFound) { m.ProvisionTenant(…) }`. Which sentinel the store
returns after a revoke is therefore security-relevant.

- pgx: `RevokeTenantKeys` runs `DELETE FROM keystore_keys WHERE tenant_id = $1` (`store.go:218`),
  leaving zero rows. `TenantExists` is `SELECT 1 FROM keystore_keys …` (`store.go:80`), so it now
  returns **false**, and `ActiveSigningKey` returns **`ErrTenantNotFound`** (`store.go:109-115`) —
  the lazy branch fires and mints a brand-new active key.
- memory: `RevokeTenantKeys` keeps an empty per-tenant map (`keystore/memory/store.go:203`), so
  `TenantExists` stays true, `ActiveSigningKey` returns `ErrNoActiveKey`, and the revocation holds.

Reproduced against real Postgres:

```
$ cd adapters/pgx && go test ./keystore/ -run TestRefuteTEN2 -v
    pgx ActiveSigningKey after revoke -> keystore: tenant not found
    pgx TenantExists after revoke -> false
    lazy Manager ActiveSigningKey after revoke -> keyID="oKklQnD3af8PRnxxxKpeYQ" err=<nil>
    REVOCATION REVERSED: lazy provisioning re-minted signing key for a tenant whose keys
    were revoked (old key "1EzewNH2Z3v73S3UjySWxw")
```

**Impact.** After the documented emergency response to a suspected key compromise, the tenant
silently regains the ability to mint tokens on the very next request. Same operator action, same
library version, **opposite security outcome depending on which store is wired**. Previously-issued
tokens do stay dead and `EventTenantProvisioned` is emitted, which is the only reason this is not
critical.

#### D2 · (refuter-found, MEDIUM) The pgx keystore store *fails* the core conformance suite

`adapters/pgx/keystore/store.go:143`

`keystore/keystoretest/contract.go:222-225` pins the contract: after `RevokeTenantKeys`,
`VerificationKeys` **must succeed and return an empty set**. The pgx store cannot satisfy it —
`store.go:138-144` returns `ErrTenantNotFound`. Proven by running the core suite against a store
faithfully mirroring the pgx semantics:

```
$ GOWORK=off go test ./keystore/ -run TestRefute -v
=== RUN   TestRefutePgxSemanticsPassesCoreContract/RevokeKeys
    contract.go:224: VerificationKeys after revoke: keystore: tenant not found
--- FAIL
```

`Manager.JWKS` (`keystore/jwks.go:57-59`) propagates it, so a `/.well-known/jwks.json` handler
errors out after an emergency revoke instead of publishing an empty key set.

**This is not caught today because `adapters/pgx` never imports `keystoretest`** — confirmed
separately as `tenant/TEN-3` (MEDIUM): `AUDIT.md:28` and the README claim cross-backend conformance
coverage that the keystore does not have. `adapters/pgx/keystore/store_test.go:62-65` documents a
*deliberate* reason (the suite needs an injectable clock the pgx store does not expose), so the fix
is to make the clock injectable or to split the clock-dependent cases out — not to silently skip
the suite while advertising it.

---

### E. Documented options that silently disable a control, or panic

#### E1 · [HIGH] The `__Host-` cookie panic — one documented config line takes down every protected route

`tokens/cookies.go:135` (write path) and `tokens/cookies.go:220` (read path) · category `api-footgun`

`DefaultCookies()` sets `__Host-` names (`tokens/cookies.go:61-70`). `Validate()` rejects a
`__Host-` name paired with a non-empty `Domain`, a `Path != "/"`, or `Insecure == true`
(`:80-113`). `withDefaults()` **panics** on any such error (`:135`) — and it is called by every
`Set*`/`Clear*`/`Access`/`Refresh` method.

The convenience options mutate one field and leave the `__Host-` names in place:
`tokens.WithCookieDomain` (`tokens/handlers.go:52`), `WithCookiePath` (:62),
`WithRefreshCookiePath` (:70), `WithInsecureCookies` (:85), the four identical `identity.*`
(`identity/handlers.go:136,146,154,159`), `oauth.*`, and the SemVer-frozen
`webapp.Config.CookieDomain` (`webapp/webapp.go:165-168`). `Cookies.Validate()` is **never called at
construction**, even though `tokens/cookies.go:76-79` documents it as exported precisely so callers
can catch this at startup. `NewWebApp` returns a nil error.

```
$ GOWORK=off go test ./webapp/ -run TestRefute -v
    NewWebApp returned no error with CookieDomain=example.com
    CONFIRMED: register panicked: tokens.Cookies: invalid __Host- cookie configuration:
      cookie "__Host-access_token": __Host- prefix requires Domain to be empty, got "example.com"
--- FAIL
```

The refuter then escalated this: **`Cookies.Access` and `Cookies.Refresh` are pure read helpers that
call `withDefaults()` as their first statement, before `r.Cookie` is even consulted.** So
`tokens.RequireAuth` with a domain-scoped `Cookies` panics on **every request to every protected
route, including an unauthenticated GET with no cookie**:

```
$ GOWORK=off go test ./tokens/ -run TestRefuteRequireAuthSurvivesCookieDomain -v
    CONFIRMED: an unauthenticated GET to a protected route panicked: tokens.Cookies:
      invalid __Host- cookie configuration: … requires Domain to be empty, got "example.com"
```

`WithInsecureCookies()` — the documented *local HTTP development* option — is broken the same way
(refuter-found, MEDIUM, `tokens/handlers.go:85`), and its existing test suite is blind to it.

**Impact.** Total, deterministic outage of every authenticated route, triggered by a one-line
documented option, with a clean build, clean vet, and nil error from the constructor. Fails closed,
so not a bypass — but on a SaaS it is a full outage with no HTTP status to diagnose it by. The login
path also panics *after* `IssueTokenPair` has persisted a refresh row, leaking an orphaned family
per attempt.

**Fix.** Call `Validate()` in every handler constructor and return an error (or panic *there*, at
startup, not per-request). Better: have `WithCookieDomain`/`WithCookiePath`/`WithInsecureCookies`
drop the `__Host-` prefix automatically, since a caller passing them has already opted out of it.

#### E2 · [HIGH] `WithLockout(negative, …)` silently disables brute-force lockout — docs promise the opposite

`identity/service.go:412` · category `silent-control-loss`

`SECURITY.md:62-66` claims lockout is "hardened against misconfiguration: `identity.WithLockout(0,
0)` does NOT disable it — a non-positive argument falls back to the safe default". `WithLockout`'s
godoc (`identity/service.go:280-284`) repeats it verbatim.

`NewService` normalises (`identity/service.go:409-414`):

```go
case s.lockThreshold == 0:  s.lockThreshold = DefaultLockThreshold
case s.lockThreshold < 0:   s.lockThreshold = 0 // explicitly disabled via WithNoLockout
```

So `0` does fall back — but any **negative** threshold, which is equally "non-positive", maps to the
internal *off* value.

```
$ GOWORK=off go test ./identity/ -run TestRefute -v
=== RUN   TestRefuteIdentityWithLockoutNegativeThreshold
    expected: "identity: account locked"  in chain: "identity: invalid credentials"
    Messages: WithLockout(-1, 15m) is documented as falling back to DefaultLockThreshold (5),
              but 16 failed logins never locked the account
--- FAIL
```

`mfa.WithMaxAttempts(negative)` — the convention `SECURITY.md` cites as the model — has the same
defect.

**Fix.** Clamp negative to the default (as documented) and keep `WithNoLockout` as the only way to
disable. Or, if the current behaviour is intended, say "zero" rather than "non-positive" in all
three places.

*Sibling (MEDIUM, confirmed):* `mfa.WithLockoutDuration(0)` is documented in **three** places
(`SECURITY.md:125-127`, `mfa/service.go:63-65`, `mfa/service.go:100-104`) to make the MFA lockout
permanent until `UnlockMFA`. `NewService` overwrites the deliberate `0` with the 15-minute default
(`mfa/service.go:166-168`); the factor self-unlocked after 24h with no `UnlockMFA` call. The
"permanent" semantics exist in the store but are unreachable through the public option.

---

## 3. Confirmed MEDIUM findings

Grouped by theme. All reproduced.

### Crypto and secret handling

| ID | Location | Finding |
|---|---|---|
| `crypto/CRY-1` | `keystore/kek.go:60` | **KEK `Seal`/`Open` pass nil GCM associated data**, so a sealed blob is portable between rows, tenants and subsystems — a signing key ciphertext and a TOTP-secret ciphertext are interchangeable at the storage layer. Bind tenant + key id + column as AAD. |
| `crypto/CRY-3` | `passwords/argon2/hasher.go:282` | **Argon2id verify caps the memory parameter from a stored hash but not the iteration count.** One tampered stored hash (or a hostile import) drives unbounded CPU on the login path. Cap `t` as well as `m`. |
| `crypto/CRY-4`, `tenant/TEN-4` | `tokens/jwt/keycache.go:165` | `CachingKeyStore.VerificationKeys` calls the delegate's `ActiveSigningKey` on a **verification-path** miss. With `keystore.WithLazyProvisioning` an unauthenticated verify request provisions a tenant and mints a key — attacker-driven key creation and DB writes from an unauthenticated endpoint. |

### Identity lifecycle and atomicity

| ID | Location | Finding |
|---|---|---|
| `identity/TEN-3`, `http/HTTP-2` | `identity/service.go:727`, `:791` | **The new password hash is written before sessions are revoked, on the client-cancellable request context.** A client that aborts mid-request leaves the new password active and every old session alive. Use `context.WithoutCancel` for the revocation cascade, or revoke first. |
| `identity/TEN-5` | `identity/service.go:935` | `VerifyEmail` read-modify-writes the whole user row; a concurrent `ConfirmEmailChange` is partially lost. |
| `identity/TEN-6` | `identity/service.go:198` | After `DeleteAccount` an **OAuth identity is permanently unusable** — every re-login/re-signup with the same provider account fails. |
| `identity/TEN-7` | `identity/handlers.go:475` | The off-response-path delivery goroutine runs consumer `Mailer`/`SMSSender` callbacks with **no `recover()`** — a panic in consumer code takes down the process. |
| `identity/TEN-8` | `identity/service.go:1005` | `LinkOrCreateIdentity` leaks an orphan user when the `emailVerified` `UpdateUser` fails, permanently blocking that email. |

### Tokens and sessions

| ID | Location | Finding |
|---|---|---|
| `lifecycle/LIFE-2` | `tokens/jwt/issuer.go:468` | **Refresh families have no absolute lifetime cap** — every rotation resets the full `RefreshTTL`, so a family lives forever under a kept-warm stolen token. Contrast `sessions`, which does have an absolute cap. |
| `lifecycle/KIND-2` | `tokens/jwt/issuer.go:811` | **`Claims.Kind` is silently dropped on refresh rotation**, so a `WithRequiredKind` / `RequireHuman` gate flips after one rotation. |
| `lifecycle/REV-1` | `tokens/revoke.go:10` | `NewAccountRevoker`'s godoc claims it "invalidates EVERY token a user holds" and kills "every active session"; it does neither in full. |

### Postgres adapter

| ID | Location | Finding |
|---|---|---|
| `pgx/PG-1` | `adapters/pgx/internal/pgxmigrate/pgxmigrate.go:47` | **Migrations take no lock.** Reproduced: on every schema-changing rolling deploy, N-1 of N replicas fail startup. `.llms/storage-pgx.md:266` tells every instance to call `Migrate` at startup and says it is "always safe". Add a `pg_advisory_lock`. |
| `pgx/PG-2` | `adapters/pgx/identity/store.go:279` | **`identities` has no `(tenant_id, user_id)` index** — the per-login lookup degenerates to a full parallel Seq Scan. |

### Availability

| ID | Location | Finding |
|---|---|---|
| `conc/AVAIL-1`, `tenant/TEN-7` | `passkey/memory/challengestore.go:34` | The only shipped `ChallengeStore` runs a **full O(n) map sweep under one global mutex on every `Put`**, driven by unauthenticated `BeginRegistration`/`BeginLogin`. Quadratic under load; `pruneLocked` cost tracks peak map size, not live entries, so one burst degrades it permanently. |
| `mfa/SF-4` | `SECURITY.md:151` | **`SECURITY.md` claims a `passkey/pgx` ChallengeStore exists. It does not** (`go list …/passkey/pgx` → *no required module provides package*). `NewService` hard-requires a `ChallengeStore`, so every deployment runs the per-process memory one; passkey login therefore breaks on any multi-pod deployment, and the pressure-relief valve a rushed operator finds is `InsecureNoChallengeStore` — silently removing SEC-05 replay protection. |

### Documentation that misstates the security model

| ID | Location | Finding |
|---|---|---|
| `claims/DOC-1`, `tenant/TEN-5` | `SECURITY.md:370` | **The central multi-tenant hardening instruction names three APIs that do not exist**: `jwt.Config.MultiTenant`, `tokens.ErrTenantBindingRequired`, and `VerifyAccessToken` (only `VerifyAccessTokenForTenant` exists). The `docs/` code block does not compile — proven by transcribing it verbatim: `unknown field MultiTenant`, `svc.VerifyAccessToken undefined`, `undefined: tokens.ErrTenantBindingRequired`. |
| `claims/DOC-6`, `http/HTTP-4` | `llms.txt:52` | **`llms.txt` and four `.llms/*.md` files state the CSRF same-origin check is opt-in / the consumer's responsibility.** It is ON by default in all four handler families; a handler built with zero options returned `403 cross_site_blocked`. `SECURITY.md:427-475` is correct; the LLM-facing surfaces contradict it — including `llms.txt`, a build-enforced disclosure surface. |
| `claims/DOC-5` | `SECURITY.md:571` | **`SECURITY.md` tells custom-store authors the shipped contract suites "assert the atomic behaviours … under parallel load".** Only `mfa/storetest` has a concurrency test; `identity/storetest` and `tokens/storetest` are purely sequential — a deliberately non-atomic adapter passes them clean. |
| `http/HTTP-3` | `webapp/webapp.go:70` | `webapp.Config.TrustedOrigins` godoc says to supply scheme-qualified origins; the check compares hosts. |
| `ops/REL-3` | `adapters/otel/go.mod:8` | `adapters/otel` pins core `v0.3.0` (vs `v0.7.0` for pgx), is absent from `RELEASING.md` entirely, and is never covered by the CI `govulncheck`/lint jobs despite those jobs being named "both modules". |

---

## 4. Confirmed LOW (23)

Full table in the appendix. The ones worth acting on:

- `crypto/CRY-2` — `tokens/jwt/issuer.go:680`: `verifyAccessToken` dereferences the **optional**
  `iat`/`exp` `NumericDate` pointers unguarded; a validly-signed token missing either panics.
- `lifecycle/KIND-1` — `tokens/token.go:39`: `Claims.Kind` is **never stamped by any egauth issuer**,
  contradicting the godoc that `WithRequiredKind` relies on.
- `lifecycle/CLOCK-1` — `tokens/jwt/issuer.go:755`: the refresh reuse-grace window compares the **app
  wall clock** against a `consumed_at` written by the **database** clock; skew either falsely trips
  theft detection or widens the reuse window. Also bypasses the injected clock seam used elsewhere.
- `mfa/SF-6` — `mfa/handlers.go:336`: no shipped handler converts a recovery code into a session
  (`StepUpHandler` is TOTP-only), so recovery-code self-service is unreachable — users who lose their
  authenticator have no path back in.
- `identity/TEN-2` — `identity/service.go:141`: `RequestEmailChange`'s godoc overclaims; a
  session-only email change to an attacker-controlled address is possible (no re-auth, no step-up).
- `ops/REL-2` — `RELEASING.md:166` and `adapters/pgx/go.mod:5-15`: both describe a `replace`
  directive that `adapters/pgx/go.mod` **does not contain** (`grep -c '^replace'` → 0).
- `ops/SUPPLY-1` — `.github/dependabot.yml:3`: only `directory: "/"` is declared, so
  `adapters/pgx` and `adapters/otel` get no automated dependency bumps.
- *(refuter-found)* `adapters/pgx/identity/migrations/001_create_tables.sql:11` violates the
  migration runner's documented idempotency contract.

---

## 5. Plausible but not proven (2)

Both need a live Postgres to settle; every *code* fact was verified, only the runtime effect was not.

- `lifecycle/APIKEY-1` — `adapters/pgx/tokens/store.go:192`: pgx rewrites an empty API-key `Type` to
  `KeyTypeService` before INSERT; memory copies it unchanged. `tokens/actor.go:37-48` then classifies
  the same key as a **machine principal on Postgres and a user principal in memory**, against the
  stated "never as a machine" fail-safe. The memory half was proven; the pgx half needs Docker.
- `lifecycle/IDX-1` — `adapters/pgx/tokens/store.go:304`: no index on `tokens.id` or
  `tokens.created_by`, so `RevokeAPIKey`, `ListAPIKeysByCreator` and the account-disable cascade
  sequential-scan the highest-churn table. Schema facts confirmed; the plan was not measured.

---

## 6. Refuted claims (recorded, not hidden)

Two finder claims did not survive refutation. Both are recorded because a review that only reports
hits is not calibrated.

**`identity/TEN-4` — REFUTED.** Claimed the godoc unconditionally promises that reset/change-password
revokes sessions. The *behaviour* is real (with no erasers registered, nothing is revoked), but the
godoc says "runs **the registered** AccountErasers" (`identity/service.go:97-99`) and
`DeleteAccount` says "every **registered** AccountEraser" (`:195-197`). The docs are accurate; the
opt-in design is a documented choice, not a doc mismatch.

**`ops/REL-1` — REFUTED.** Claimed the missing `replace` in `adapters/pgx/go.mod` means the adapter
ships bound to core behaviour predating the keystore fix, and that neither test mode covers it. The
refuter disproved the mechanism:

- **No CI job runs pgx under `GOWORK=off`.** The `test-adapters-pgx` job sets no `GOWORK`
  (`ci.yml:55-85`), and in `test-short` the `GOWORK: "off"` env is scoped to the **core** step only
  (`ci.yml:152-155`) while the pgx step deliberately omits it (`:156-159`). Every CI pgx run compiles
  against HEAD core; the stale-core resolution is a local-developer condition only.
- The bug commit `616f300` fixed requires a store whose tenant record *survives* revocation — that is
  the **memory** store. On pgx, `TenantExists` is false after a revoke, so even the old
  `ProvisionTenant` took the `CreateTenant` branch and restored signing.
- `RELEASING.md:186-198` step 2 mandates `go mod edit -require=…@vX.Y.Z` before tagging, so the
  "tagged with a stale require" scenario contradicts the runbook.
- Not using `keystoretest` is documented as deliberate at `adapters/pgx/keystore/store_test.go:62-65`
  (the suite needs an injectable clock the pgx store does not expose).

**I stated the weaker version of this claim earlier in the session and it was wrong.** The residue
that *is* real: the stale comment (`ops/REL-2`, LOW) — and, far more seriously, the reason the suite
is skipped turned out to matter, because the pgx keystore store **actually fails that conformance
suite** (§2.D2).

---

## 7. Prior review: 8 of 8 fixed

The `GLOBAL_REVIEW.md` in `HEAD` claimed 8 confirmed findings. All eight are fixed at `ce6aeef`,
each with a named regression test, and every fix commit verified as an ancestor of HEAD.

| # | Area | Fix | Regression test |
|---|---|---|---|
| C1 | oauth cross-host JWKS (was HIGH) | `bcfd1b2` | `oidc_test.go` "jwks override on a different host accepted" + `oidc_crosshost_internal_test.go` |
| C2 | `actorFromClaims` KeyID/UserID | `9e1c788` | `TestActorFromClaims_PrincipalMapping` |
| C3 | re-lockout `AccountLocked` event | `7efa0e0` | `storetest/contract.go` (shared memory+pgx) |
| C4 | session absolute-lifetime option order | `ccc6b3f` | `sessions/lifetime_test.go:190-248` (both orderings) |
| C5 | OTP issue timing oracle | `033efea` | `TestIssueHandler_MintOffResponsePath`, `…UniformResponse…` |
| C6 | keystore re-provision after revoke | `616f300` | `keystoretest/contract.go` (shared memory+pgx) |
| C7 | pgx provider cache before decrypt | `23f6780` | `TestGetProviderCacheHitSkipsDecrypt`, `…SurvivesKEKFailure` |
| C8 | passkey attestation 403 | `8e1fd3b` | `TestFinishRegistrationHandler_AttestationRejectedIs403` |

Note C6's fix is what makes §2.D1 exploitable: it added a lazy-provisioning path keyed on
`ErrTenantNotFound`, and the pgx store returns exactly that sentinel after a revoke. The fix is
correct for memory and turns a fail-closed outage into a fail-open revocation bypass on Postgres.

---

## 8. What held up under attack (150 cleared hypotheses)

This matters as much as the findings. The following were specifically attacked and **did not
break**. Highlights:

**Randomness and entropy** — `grep -rn "math/rand"` returns **zero hits across all three modules,
including tests**. Every generator uses `crypto/rand`, every read's error is checked. Measured
entropy: session token 32B, refresh token 32B (with `MinTokenLength=16` enforced in both `Validate`
and `New`), API key 32B, OAuth state 16B, PKCE verifier, TOTP secret, recovery codes. No modulo
bias: `otp/code.go:15-21` uses `rand.Int(rand.Reader, 10^digits)` (big.Int rejection sampling);
recovery codes base32-encode raw bytes.

**JWT algorithm confusion** — both keyfuncs resolve the `Signer` **first** by `kid`, then compare
`token.Method.Alg()` against that signer's pinned alg (`tokens/jwt/issuer.go:589-598`,
`tokens/jwt/keystore.go:59-65`). A token claiming HS256 against an RSA kid is rejected. `"none"` is
unreachable. `grep` for `ParseUnverified` / `SkipClaimsValidation` finds nothing — no claim is ever
read before signature verification. `kid` is only ever a Go map index, never a path, URL or SQL
fragment.

**AEAD nonce handling** — `keystore/kek.go:54-61` generates a fresh 12-byte nonce from `crypto/rand`
per `Seal`, prefixes it, never derives/increments/reuses. `Open` length-checks before slicing. (The
*missing AAD* is a real finding — `crypto/CRY-1` — but nonce discipline is correct.)

**SQL injection** — no query in `adapters/pgx` interpolates a caller-controlled value; all user data
goes through `$N` placeholders.

**Constant-time comparison** — the password path reaches `subtle.ConstantTimeCompare` structurally,
and the `decoyHash` enumeration defence is present on every enumeration-safe branch of
`Authenticate`. (One nuance: `claims/DOC-12`, LOW — two pre-KDF early returns branch on the
*candidate* rather than only on the stored hash's shape, so the guarantee is very slightly
overstated in `SECURITY.md:27`.)

Full per-lens list in the appendix.

---

## 9. Go idiom, supply chain, CI posture

**Idiom (advisory).** `go fix -diff` flags 4 real modernizer gaps (e.g. `actor.go:66` hand-rolled
loop → `slices.Contains`). The house rule "`errors.Join(errors.New(…), err)`, never
`fmt.Errorf("%w")`" is violated in **258 places** across the codebase — including
`adapters/pgx/mfa` throughout — so either the rule or the code should change. Several exported
constructors return ad-hoc `errors.New(…)` at the return site instead of a declared sentinel
(`tokens/jwt/issuer.go:155` and others), which callers cannot match with `errors.Is`.

**CI gaps for a security library.** No `.golangci.yml` (see baseline). No SAST — no `gosec`, no
CodeQL, no semgrep. No fuzzing, and **no `Fuzz*` targets exist at all**, which is notable for code
that parses JWTs, CBOR attestation objects, encoded Argon2 hashes and cookies from untrusted input.
`govulncheck` is pinned to `v1.1.4` while `v1.5.0` is current. `adapters/otel` is excluded from the
`govulncheck` and lint jobs even though both are labelled "both modules". Dependabot covers only the
root module.

**Dependencies.** All direct dependencies are current at review time. `govulncheck` reports one
vulnerability in a required-but-uncalled module — not reachable, worth tracking.

**`examples/fullstack`** would not be safe to copy: `main()` uses `http.ListenAndServe` with no
read/write/idle timeouts (`:406`), and the passkey ceremony `CookieKey` is an **all-zero 32-byte
slice** (`:157`) that passes the library's length check while providing no integrity at all —
`MinCookieKeyLength` validates length but not entropy.

---

## 10. Bottom line for SaaS use

The primitives are sound and the enumeration/timing work is unusually careful. The risk is
concentrated in three places, all above the crypto layer:

1. **Composition.** Controls exist but are not wired together. `WithMFAGate` guards one handler of
   several. `WithDisableRevokers` must be remembered or deactivation silently does nothing. The
   shipped preset cannot wire either correctly.
2. **Configuration.** Documented options disable the control they claim to harden
   (`WithLockout(-1, …)`, `WithLockoutDuration(0)`) or panic at request time
   (`WithCookieDomain`, `WithInsecureCookies`). Nothing validates at construction.
3. **Documentation drift.** `SECURITY.md`'s central multi-tenant instruction names APIs that do not
   exist; `llms.txt` and the `.llms/` guides state the CSRF default backwards; `SECURITY.md` claims
   a `passkey/pgx` store and parallel-load contract suites that do not exist. For a library whose
   security story *is* its documentation, and one increasingly consumed by LLM agents reading
   `llms.txt`, this is a first-class defect class — six confirmed findings.

None of that is unfixable, and most of it is a day or two of work. But "no surprises" is not the
current state: a competent integrator following the shipped documentation ends up with unenforced
MFA, ineffective account deactivation, and a tenant resolver that fails open.

---

## Appendix

### Advisory findings (low / info tier, not sent to refutation)

Status `—` means the finding was not routed to the refutation pass (only medium-and-above were).
Locations and code facts were established by the finder but not independently reproduced.

### LOW tier (62)

| ID | Status | Category | Location | Finding | Fix |
|---|---|---|---|---|---|
| `claims/DOC-10` | — | dos | `SECURITY.md:511` | The documented eviction/GC checklist is incomplete: tokens/memory and the verification-token table (memory AND Postgres) grow without bound and are named nowhere | Extend the SECURITY.md eviction section, janitor's package doc and llms.txt:50 to the full set: add `tokens/memory.Store.DeleteExpired` and — in its own subsection, because it is backend-independent — |
| `claims/DOC-11` | — | doc-mismatch | `AUDIT.md:9` | AUDIT.md claims the audit-status sentence's presence is build-enforced on the CHANGELOG entry; disclosure_test.go never reads CHANGELOG.md, and the test's own comment falsely says it is "checked separately" | Either add CHANGELOG.md to the enforced set (a `TestDisclosureChangelogPresent` mirroring `TestDisclosureLedgerPresent`) or correct AUDIT.md:8-10 and the disclosure_test.go:24-25 comment to state that |
| `claims/DOC-12` | — | doc-mismatch | `SECURITY.md:27` | The structural constant-time Compare guarantee is stated too strongly: two pre-KDF early returns branch on the CANDIDATE PASSWORD, not only on the shape of the stored hash | Restate the guarantee accurately: Compare reaches the constant-time comparison for any well-formed stored hash AND any in-bounds non-empty candidate; the empty-candidate and oversized-candidate reject |
| `claims/DOC-7` | — | race | `tokens/jwt/issuer.go:755` | Refresh-reuse grace window compares a DB-written consumed_at against the app's wall clock via time.Since, bypassing the injectable Clock — DB/app clock skew silently widens or collapses the documented theft tripwire | Replace `time.Since(*rt.ConsumedAt)` with `s.now().Sub(*rt.ConsumedAt)` so the reuse-grace decision uses the same clock as every other time decision in the service, and either (a) have the store retur |
| `claims/DOC-8` | — | doc-mismatch | `SECURITY.md:306` | "No internal logging — egauth performs no logging of its own (silent by default)" is false for the webapp v1 preset, which defaults to slog.Default() and writes user IDs, tenant IDs, client IPs and User-Agents to stderr | Qualify SECURITY.md:306-308: the core packages are silent by default, but `webapp.NewWebApp` deliberately defaults to `event.NewSlogSink(nil)` ("silent auth is un-auditable auth") and therefore writes |
| `claims/DOC-9` | — | doc-mismatch | `identity/handlers.go:1134` | The "Account-existence disclosure (by design)" section claims to be exhaustive but omits the phone_taken 409 enumeration oracle, and its own count is internally inconsistent ("Three responses" / four bullets / "the four disclosures") | Add a fifth bullet to SECURITY.md's disclosure section for `phone_taken` → 409 on `RequestPhoneVerificationHandler` (and its `ConfirmPhoneVerification` counterpart), with the same shape as the accepte |
| `conc/AVAIL-2` | — | dos | `sessions/memory/store.go:220` | sessions/memory.DeleteSessionsByUserID scans the entire store (every tenant's sessions), not just the calling tenant's — an authenticated 'logout everywhere' call costs O(total sessions across all tenants) and holds the single mutex for the | Maintain a secondary (tenantID,userID) -> []sessionID index (mirroring the existing byHash index) so DeleteSessionsByUserID is O(sessions for that user) instead of O(total store size). This is a refer |
| `crypto/CRY-10` | — | go-idiom | `tokens/jwt/issuer.go:755` | Refresh-reuse grace window and step-up freshness use the wall clock, bypassing the injected clock seam used by every other time decision | Replace issuer.go:755 with `s.now().Sub(*rt.ConsumedAt) > s.reuseGrace`. For FreshAuth, add a clock-taking variant (e.g. `FreshAuthAt(now time.Time, maxAge time.Duration) bool`) and have the middlewar |
| `crypto/CRY-2` | CONFIRMED | error-handling | `tokens/jwt/issuer.go:680` | verifyAccessToken dereferences the optional iat/exp NumericDate pointers unguarded: a validly-signed token missing either claim panics with a nil dereference instead of returning ErrInvalidToken | Add `jwt.WithExpirationRequired()` to the opts slice at issuer.go:630 and nil-guard both dereferences (e.g. `if wrapper.ExpiresAt != nil { claims.ExpiresAt = wrapper.ExpiresAt.Time }`, same for Issued |
| `crypto/CRY-5` | — | doc-mismatch | `oauth/oidc.go:76` | OIDCConfig.AllowedAlgs documents that "none" and HMAC are always rejected regardless of the list, but the caller's list is passed through verbatim | In newOIDCVerifier, filter the caller's list against an explicit denylist (`none`, `HS256`, `HS384`, `HS512`, case-insensitively) and return a configuration error rather than silently dropping — so a  |
| `crypto/CRY-6` | — | secret-exposure | `keystore/keystore.go:66` | Redaction coverage stops at tokens/ and tokens/jwt/: the per-tenant PLAINTEXT signing key, TOTP enrollment secret and OTP code have no String/GoString/LogValue | Add a keystore/redact.go giving `SigningKey`, `Keyset` and the `Manager` the same String/GoString/LogValue treatment as tokens/jwt/redact.go (print KeyID/TenantID/Alg/NotAfter/RetiredAt, render Secret |
| `crypto/CRY-7` | — | doc-mismatch | `SECURITY.md:631` | SECURITY.md claims the Argon2 cost-upgrade enumeration gap self-heals through transparent rehash-on-login, but nothing in egauth ever calls NeedsRehash | Pick one and make everything agree. Preferred: wire it in — after a successful Compare in identity Authenticate, type-assert the hasher to an interface { NeedsRehash(string) bool } and, when true, re- |
| `crypto/CRY-8` | — | crypto | `examples/fullstack/main.go:157` | Shipped reference application uses an all-zero passkey ceremony-cookie HMAC key, and MinCookieKeyLength only validates length so it is accepted | In the example, generate the key with crypto/rand at startup (or read it from an env var and fail fast when unset) rather than shipping a zero buffer. In the library, harden the guard so a degenerate  |
| `crypto/CRY-9` | — | crypto | `mfa/totp.go:58` | TOTP verification accepts an empty or truncated shared secret; an empty secret yields a zero-length HMAC key and a publicly computable code | Add a `MinTOTPSecretBytes` constant (16, or 20 to match secretBytes) and make decodeSecret return an error when the decoded key is shorter, so validateTOTP/GenerateCode fail closed on a blank or trunc |
| `http/HTTP-10` | — | dos | `passkey/handlers.go:274` | The passkey ceremony cookie is not __Host- prefixed and accepts a Domain, so a sibling subdomain can toss a same-named cookie and wedge every passkey ceremony — undocumented, unlike the equivalent oauth-state case | Default passkey.DefaultSessionCookieName to "__Host-passkey_ceremony" (the cookie is already Secure + Path=/ + Domain-less by default, so it satisfies the prefix rules out of the box) and validate tha |
| `http/HTTP-4` | CONFIRMED | doc-mismatch | `llms.txt:52` | llms.txt and four .llms/*.md lines still describe the CSRF origin check as opt-in / the consumer's responsibility, contradicting the code and SECURITY.md | Update llms.txt:52 and the four .llms/*.md lines to "strict same-origin check ON by default; WithTrustedOrigins WIDENS the allowlist; WithInsecureNoOriginCheck is the explicit opt-out", matching SECUR |
| `http/HTTP-5` | — | api-footgun | `identity/handlers.go:504` | The same-origin gate rejects every origin-less POST, so non-browser clients cannot use any identity/tokens/mfa/otp endpoint, and the only escape hatch disables CSRF protection for browsers too | Add a scoped escape hatch rather than an all-or-nothing one — e.g. an option that exempts requests carrying a required custom header (the standard 'this cannot be sent by a cross-site HTML form' proof |
| `http/HTTP-6` | — | error-handling | `webapp/webapp.go:78` | webapp.Config.EventSink is documented as receiving login, registration and logout events, but the preset never wires it into the tokens handlers — no event.Logout is ever emitted, so the v1 preset's sign-out is un-auditable | Add `tkOpts = append(tkOpts, tokens.WithEventSink(sink))` next to the identity wiring at webapp/webapp.go:163, and correct the Config.EventSink godoc to state precisely which events flow through it (l |
| `http/HTTP-7` | — | auth-bypass | `passkey/handlers.go:531` | passkey handlers have no same-origin/CSRF check at all and no WithTrustedOrigins option; RenameCredentialHandler is an authenticated state-changing POST with no Content-Type enforcement, so a cross-site text/plain form renames a victim's pa | Add the same originAllowed gate plus WithTrustedOrigins/WithInsecureNoOriginCheck to the passkey package (at minimum to RenameCredentialHandler and the Begin* handlers), and enforce Content-Type: appl |
| `http/HTTP-8` | — | crypto | `internal/httputil/httputil.go:13` | No Cache-Control: no-store / Pragma / X-Content-Type-Options on responses that carry TOTP secrets, recovery codes, WebAuthn challenges or freshly minted auth cookies | Set `Cache-Control: no-store` (and `Pragma: no-cache` for HTTP/1.0 intermediaries) plus `X-Content-Type-Options: nosniff` inside httputil.WriteJSON, and add the same two headers on the cookie-writing  |
| `http/HTTP-9` | — | api-footgun | `oauth/handlers.go:313` | oauth requestScheme trusts X-Forwarded-Proto with no proxy opt-in and no scheme validation, and resolveRedirectURL derives the redirect_uri from the raw Host header | Require WithRedirectURL for BeginHandler (return a construction error, or fail the request closed, when it is unset) instead of silently deriving it from request headers. Gate the X-Forwarded-Proto re |
| `identity/TEN-10` | — | auth-bypass | `identity/service.go:538` | Authenticate never asserts that the identity it verifies belongs to the user it returns, so any store-side keying bug becomes direct cross-account authentication | After the identity lookup, add `if ident.UserID != user.ID { s.decoyHash(ctx, password); loginFailed(user.ID.String(), "invalid_credentials", "password"); return nil, ErrInvalidCredentials }` (keeping |
| `identity/TEN-11` | — | doc-mismatch | `identity/handlers.go:1133` | 409 phone_taken is a fifth account-existence oracle (tenant-wide phone-number enumeration) while SECURITY.md states the four listed disclosures are the only intentional exceptions | Add a fifth bullet to the SECURITY.md disclosure ledger for `phone_taken` (with the same 'drop the pre-flight FindUserByPhone and rely on the unique index at confirm time' escape hatch already offered |
| `identity/TEN-12` | — | dos | `identity/service.go:549` | Account lockout is per-identity and keyed on a public identifier, giving anyone a trivial repeatable DoS against a chosen victim account — an availability trade-off absent from SECURITY.md's otherwise exhaustive ledger | Disclose the targeted-DoS trade-off in SECURITY.md alongside the lockout bullet, and offer the mitigations the mfa module already has: an administrative `UnlockAccount` (wrapping Store.ResetFailedAtte |
| `identity/TEN-13` | — | doc-mismatch | `SECURITY.md:645` | SECURITY.md understates the password-reset-request work asymmetry: the known-account path costs two extra reads plus an INSERT, and there are three distinguishable timing classes, not two | Restate the residual accurately: 'two extra indexed reads and one durable INSERT for a known password account; two extra reads for a known OAuth-only account; one read for an unknown account'. Same co |
| `identity/TEN-14` | — | doc-mismatch | `.llms/identity.md:377` | .llms/identity.md tells consumers (and LLM agents) that the CSRF origin check is off by default and that Store is a monolithic interface — both contradict the code | Update .llms/identity.md:240 and :377 to 'the same-origin check is ON by default; WithTrustedOrigins WIDENS the allowlist; WithInsecureNoOriginCheck turns it off', fix the same sentence in architectur |
| `identity/TEN-15` | — | api-footgun | `identity/handlers.go:1322` | RequestPasswordResetViaRecoveryHandler delivers a password-reset credential through the SMSSender.PhoneVerification callback, so the victim receives a 'verify your phone' message that actually carries a reset token | Add a dedicated `SMSSender.PasswordReset func(ctx, PasswordResetSMS) error` callback (with its own struct) and use it here; keep PhoneVerification strictly for the enrollment flow. If the extra seam i |
| `identity/TEN-16` | — | error-handling | `identity/service.go:26` | normalizeEmail enforces no maximum address length, so an oversized address passes validation and fails deep in Postgres as an opaque error — including a 500 that burns a change-email token | Bound the address in normalizeEmail (RFC 5321: 64-octet local part, 255-octet domain, 254 total) and return ErrInvalidEmail — one check that fixes Register, RequestEmailChange, RequestRecoveryEmail an |
| `identity/TEN-2` | CONFIRMED | api-footgun | `identity/service.go:141` | RequestEmailChange godoc overclaims: a session-only email change to an attacker-controlled address is possible, and the route carries none of the step-up guidance DeleteAccount gives | Either (a) require proof of the current credential in RequestEmailChange (re-verify currentPassword like ChangePassword does, and/or require the confirmation to be co-signed by a token sent to the OLD |
| `identity/TEN-9` | — | error-handling | `adapters/pgx/identity/store.go:351` | UpdateIdentityPassword is not gated on the user being live in either backend, so ChangePassword and SetTemporaryPassword succeed on a soft-deleted (erased) account | Add the liveness gate to UpdateIdentityPassword in both backends (pgx: `AND EXISTS (SELECT 1 FROM users WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL)`; memory: check the users map) and exte |
| `lifecycle/APIKEY-1` | PLAUSIBLE | cross-backend-divergence | `adapters/pgx/tokens/store.go:192` | pgx and memory token stores classify an unclassified API key oppositely (service vs user), violating the stated 'never as a machine' fail-safe, and the shared contract suite does not catch it | Make `IssueAPIKey` reject a keyType that is not exactly KeyTypePAT or KeyTypeService (fail fast at the boundary), align the pgx default with `ActorFromAPIKey`'s documented 'never as a machine' fail-sa |
| `lifecycle/APIKEY-2` | — | cross-tenant-leak | `tokens/memory/store.go:165` | APIKey.Claims.TenantID is never validated or normalised against the row's tenant, and VerifyAPIKey returns it to the caller | In both stores, either reject a non-empty `key.Claims.TenantID` that differs from the tenantID argument (same ErrTenantMismatch treatment as the outer field) or overwrite it, and do the same in `SaveR |
| `lifecycle/CLOCK-1` | CONFIRMED | race | `tokens/jwt/issuer.go:755` | Refresh reuse-grace comparison uses real wall clock against a consumed_at written by the database clock, so app/DB skew silently disables theft detection | Replace `time.Since(*rt.ConsumedAt)` with `s.now().Sub(*rt.ConsumedAt)` so the grace window honours the injected clock, and have the store stamp consumed_at from the application clock (pass it in, as  |
| `lifecycle/GATE-1` | — | doc-mismatch | `tokens/middleware.go:481` | WithGate's godoc promises it runs after the principal-kind gate; it actually runs before it | Move the `kindSatisfied` check into `serveAuthenticated` ahead of the other gates (it needs only `actorFromClaims(claims)`, which is already computed there for the gate call) so one fail-closed orderi |
| `lifecycle/GROW-1` | — | dos | `tokens/jwt/issuer.go:468` | Every rotation inserts a new refresh row that lives a full RefreshTTL, so an active session retains RefreshTTL/AccessTTL rows (2880 at the webapp defaults) | Document the retained-row formula (RefreshTTL/AccessTTL per active session) in the TokenReaper godoc and SECURITY.md's capacity notes, and consider capping consumed-row retention to a short detection  |
| `lifecycle/IDX-1` | PLAUSIBLE | dos | `adapters/pgx/tokens/store.go:304` | The Postgres tokens table has no index on id or created_by, so API-key revoke/list and the account-disable cascade sequential-scan the largest table in the schema | Add a migration creating `CREATE INDEX ... ON tokens (tenant_id, id) WHERE claims IS NOT NULL` and `CREATE INDEX ... ON tokens (tenant_id, created_by) WHERE claims IS NOT NULL` (partial on claims IS N |
| `lifecycle/KIND-1` | CONFIRMED | doc-mismatch | `tokens/token.go:39` | Claims.Kind is never stamped by any egauth issuer, contradicting the godoc that the WithRequiredKind gate relies on | Either make `IssueAPIKey` stamp `claims.Kind` from `keyType` (and add a jwt-level test asserting it survives to the Actor), or correct both godocs to state plainly that Claims.Kind is caller-supplied  |
| `lifecycle/TEN-1` | — | cross-tenant-leak | `tokens/handlers.go:273` | RefreshHandler/LogoutHandler fall back to the "" tenant partition when a configured tenant resolver cannot map the request, while the middleware deliberately 401s | Make `tenant` distinguish 'no resolver' from 'resolver returned empty' (e.g. return (string, bool)) and have RefreshHandler/LogoutHandler reject with 401 unresolved_tenant when a configured resolver y |
| `mfa/SF-10` | — | crypto | `mfa/handlers.go:343` | StepUpHandler unconditionally asserts AMR=[pwd, otp, mfa], claiming a password factor that may never have been used | Derive the base AMR from the verified incoming token (union it with AMROTP/AMRMFA) rather than hard-coding AMRPassword, or add the TOTP factors to whatever the StepUpClaimsBuilder returns and document |
| `mfa/SF-5` | CONFIRMED | dos | `passkey/memory/challengestore.go:34` | memory.ChallengeStore does a full-map prune on every Put, so insertion cost is linear in the live set (quadratic total) behind an unauthenticated endpoint | Add a bounded constructor (NewBoundedChallengeStore(max int)) that rejects/evicts on overflow, replace the per-Put full scan with amortized pruning (a min-heap by expiry, or prune at most k entries pe |
| `mfa/SF-6` | CONFIRMED | api-footgun | `mfa/handlers.go:336` | No shipped handler converts a recovery code into a session (StepUpHandler is TOTP-only), so recovery-code self-service must be hand-rolled | Ship a StepUpRecoveryHandler (or a WithRecoveryFallback option on StepUpHandler) that calls VerifyRecoveryCode and, on success, re-issues the full pair with AMR=[AMRPassword, AMRMFA] exactly like Step |
| `mfa/SF-7` | — | enumeration | `otp/handlers.go:240` | otp.VerifyHandler leaks account existence through response timing, contradicting WithSubjectResolver's documented 'no account-existence signal' guarantee | Either equalize the work (on ok=false, hash the submitted code against a dummy value and, if cheap, issue a same-shaped no-op store read) or narrow the documented guarantee in otp/handlers.go:74-79 to |
| `mfa/SF-8` | — | doc-mismatch | `SECURITY.md:117` | SECURITY.md states the mfa store persists the TOTP secret in clear; the pgx store envelope-encrypts it and its constructor panics without a KEK | Update SECURITY.md:111-117 and .llms/mfa.md's Gotchas to state that adapters/pgx/mfa seals the secret with a caller-supplied KEK (constructor-enforced), that the in-memory store keeps it in process me |
| `mfa/SF-9` | — | csrf | `passkey/handlers.go:244` | The passkey handler family has no same-origin/CSRF check, unlike every other handler family | Add the same WithTrustedOrigins / originAllowed / WithInsecureNoOriginCheck triple to the passkey handlers (at minimum to RenameCredentialHandler and the Begin* handlers), and either way state explici |
| `ops/CI-1` | — | error-handling | `.github/workflows/ci.yml:284` | No .golangci.yml means CI's lint job only runs the 5 default linters; a --default=all run surfaces 3000+ additional findings across 20+ linters the strict Go community config expects, including a real (if low-severity) gosec hit in shipped  | If the maintainer wants a stricter bar, add a committed .golangci.yml enabling errorlint, gosec, revive, and err113 at minimum (the ones with clear security/correctness value), leaving the purely styl |
| `ops/EX-1` | — | api-footgun | `examples/fullstack/main.go:406` | examples/fullstack's main() starts the HTTP server with http.ListenAndServe (no read/write/idle timeouts), the one insecure-for-production shortcut in that file NOT called out in a comment | Use an &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: ..., ReadTimeout: ..., WriteTimeout: ..., IdleTimeout: ...} and add the same '// In production, tune these for your workload' style |
| `ops/EX-2` | — | api-footgun | `examples/fullstack/main.go:157` | examples/fullstack's passkey CookieKey is an all-zero 32-byte slice -- it passes the library's length check but is a fully predictable HMAC key | Generate the demo key with crypto/rand even in the example (it costs nothing and removes the footgun entirely), or have passkey.NewService additionally reject an all-zero key as a cheap defense-in-dep |
| `ops/REL-1` | REFUTED | supply-chain | `adapters/pgx/go.mod:5` | adapters/pgx/go.mod's header comment describes a replace directive the file does not have; the reprovision-after-revoke coverage gap it is blamed for is inert on Postgres (that bug was memory-store-only) | Either add the replace directive the comment claims exists (matching what RELEASING.md describes), or fix the comment to say the replace lives only in the workspace go.work; either way, add a pgx-spec |
| `ops/REL-2` | CONFIRMED | doc-mismatch | `RELEASING.md:166` | RELEASING.md:166-172 and adapters/pgx/go.mod:5-15 both describe a replace directive adapters/pgx/go.mod does not have, so GOWORK=off commands there silently test against cached core v0.7.0 instead of the local tree | Correct RELEASING.md (and the adapters/pgx/go.mod header comment) to state plainly that the replace lives only in the root go.work for local dev/CI, and that adapters/pgx/go.mod's own require is the o |
| `ops/REL-4` | — | supply-chain | `.github/workflows/ci.yml:260` | CI pins govulncheck to a stale version (v1.1.4) while the current release is v1.5.0 | Bump the pinned govulncheck version in ci.yml (both occurrences) to a current release, and consider Dependabot-tracking it too (it's a plain go run version string, invisible to gomod-ecosystem Dependa |
| `ops/SUPPLY-1` | CONFIRMED | supply-chain | `.github/dependabot.yml:3` | dependabot.yml declares only directory "/", so adapters/pgx and adapters/otel get no automated dependency-bump PRs (CI govulncheck still covers pgx, not otel) | Add gomod entries with directory: "/adapters/pgx" and "/adapters/otel" to dependabot.yml. |
| `pgx/PG-3` | — | availability-dos | `adapters/pgx/tokens/store.go:317` | No index on tokens.created_by backs API-key-by-creator queries against a high-churn table | Add a migration creating a partial index, e.g. CREATE INDEX IF NOT EXISTS idx_tokens_tenant_created_by ON tokens (tenant_id, created_by) WHERE claims IS NOT NULL; which serves both ListAPIKeysByCreato |
| `pgx/PG-5` | — | race | `adapters/pgx/mfa/store.go:182` | SELECT ... FOR UPDATE provides no real serialization in the non-transactional fallback path (mfa.IncrementTOTPAttempts) | Either require DBQuerier to embed the Beginner capability (making the fallback unrepresentable), or make increment() explicitly begin its own transaction when q is not already inside one (rather than  |
| `pgx/PG-6` | — | race | `adapters/pgx/passkey/store.go:98` | passkey.UpdateCredential is a non-CAS full-record replace, allowing a lost-update race on sign_count | Add a monotonic guard to the UPDATE, e.g. 'AND ($5 = 0 OR sign_count < $5)' (sign_count 0 is the valid 'authenticator does not support counters' case per WebAuthn spec) and treat 0 rows affected as a  |
| `tenant/TEN-10` | — | doc-mismatch | `SECURITY.md:115` | SECURITY.md states the mfa store persists the TOTP secret in clear and tells operators to add envelope encryption, but the shipped pgx mfa store already mandates a KEK and seals it | Rewrite the caveat per backend: adapters/pgx/mfa requires a KEK and stores the secret KEK-sealed (AES-256-GCM); mfa/memory holds it in process memory in clear and is for tests / single-process use; a  |
| `tenant/TEN-11` | — | doc-mismatch | `tokens/middleware.go:159` | tokens.RequireAuth always binds the token to a tenant ("" when no resolver) but its godoc says it verifies without tenant binding, so webapp.Config.Tenant plus RequireAuth 401s every request | Correct the godoc: with no resolver, RequireAuth binds to the empty tenant and therefore REQUIRES tokens issued under ""; fix the option name to WithAuthTenantResolver. Add a note on webapp.Config.Ten |
| `tenant/TEN-12` | — | cross-tenant-leak | `adapters/pgx/tokens/store.go:179` | tokens.Store SaveAPIKey validates the record's TenantID but ignores the embedded Claims.TenantID that VerifyAPIKey returns to callers | Extend the guard in both backends to reject key.Claims.TenantID != "" && key.Claims.TenantID != tenantID, and pin key.Claims.TenantID = tenantID on save. On read, overwrite key.Claims.TenantID from th |
| `tenant/TEN-13` | — | dos | `identity/handlers.go:460` | The identity Request* delivery semaphore is shared across all tenants, so one tenant's reset/magic-link volume silently drops other tenants' mail while still returning success | The drop-on-full policy itself is a deliberate, documented backpressure choice; the missing piece is per-tenant fairness. Add a per-tenant sub-cap (e.g. a small per-tenant counter under the global sem |
| `tenant/TEN-14` | — | doc-mismatch | `ratelimit/tokenbucket.go:134` | TokenBucket.WithMaxKeys documents that fully-refilled buckets are always preferred for eviction, but evictOne samples only 5 random buckets and can evict a bucket still under brute-force pressure | Soften the godoc to say a small random sample (5) is inspected and the most-refilled of the sample is evicted, so eviction is best-effort and a pressured bucket can be reclaimed under sustained key ch |
| `tenant/TEN-5` | CONFIRMED | doc-mismatch | `SECURITY.md:370` | SECURITY.md AND the published docs site document the multi-tenant token-binding control via three identifiers that do not exist (Config.MultiTenant, VerifyAccessToken, ErrTenantBindingRequired) | Rewrite the SECURITY.md bullet to describe the API as shipped: VerifyAccessTokenForTenant is the ONLY access-token entry point, it always compares the signed tenant_id claim against the supplied tenan |
| `tenant/TEN-8` | — | dos | `sessions/memory/store.go:249` | Bounded in-memory sessions and OTP stores evict across tenant boundaries, so one tenant's insert pressure logs out / breaks OTP for other tenants | Either document explicitly that NewBoundedStore is single-tenant-only (and have the multi-tenant guidance point at a per-tenant cap or the pgx backend), or add a per-tenant quota so eviction can only  |
| `tenant/TEN-9` | — | crypto | `keystore/kek.go:60` | KEK envelope encryption uses no additional authenticated data, so a sealed signing key or TOTP secret can be moved between tenant rows without the KEK | Bind the AAD to the record identity: KEK.Seal(plaintext, aad []byte) / Open(sealed, aad []byte), with aad = tenantID // 0x00 // keyID for keystore rows and tenantID // 0x00 // userID for mfa rows. Kee |

### INFO tier (10)

| ID | Status | Category | Location | Finding | Fix |
|---|---|---|---|---|---|
| `claims/DOC-13` | — | doc-mismatch | `SECURITY.md:251` | SECURITY.md states the api_key.auth.failed reason set exhaustively ("is one of") but omits `revoked`, and its api-key event list omits api_key.revoked entirely | Add `revoked` to the SECURITY.md:251-252 reason list and add an `api_key.revoked` bullet (Attrs: key_id) so SECURITY.md matches README.md:250-257 and the code. Consider a small table-driven test that  |
| `claims/DOC-14` | — | doc-mismatch | `llms.txt:51` | llms.txt's "Handlers are POST-only with a pre-auth body cap" is false for the oauth handlers, and doc.go's quickstart omits the ClaimsProvider that Rotate requires, so the copied example can never refresh | Scope llms.txt:51 to the form/JSON handler families (identity, tokens, mfa, otp, passkey Finish) and note that the oauth Begin/Callback handlers are GET redirect endpoints with no method gate or body  |
| `http/HTTP-11` | — | api-footgun | `internal/httputil/httputil.go:60` | internal/httputil.OriginAllowed is a permissive-by-default origin helper that no production code uses, kept alive by a test that pins the permissive semantics | Delete OriginAllowed (and its test), or invert it to the strict policy and have identity/tokens/mfa/otp share it — replacing four duplicated implementations with one, so there is exactly one origin de |
| `identity/TEN-4` | REFUTED | error-handling | `identity/service.go:103` | Session/token revocation on reset, change-password and delete is entirely opt-in with no startup validation, so the documented "attacker holding a live session is evicted immediately" is silently false in the default configuration | Make the absence of erasers loud: log a startup warning (or expose identity.WithNoAccountErasers() as an explicit, greppable opt-out, mirroring the WithNoLockout convention already used for lockout at |
| `lifecycle/HDR-1` | — | api-footgun | `tokens/middleware.go:305` | A cookie always shadows an explicitly presented Authorization: Bearer token, and the header parse rejects any non-single-space form | Prefer the Authorization header over the cookie (an explicit credential should win over an ambient one), or at least document the precedence on `WithCookieAuth`. Use `strings.Fields`/`strings.Cut` wit |
| `mfa/SF-11` | — | go-idiom | `adapters/pgx/mfa/store.go:86` | adapters/pgx/mfa wraps errors with fmt.Errorf("%w") against the project's errors.Join standard | Replace with errors.Join(errors.New("mfa pgx: sealing secret"), err) etc., per the house standard. |
| `ops/IDIOM-1` | — | go-idiom | `actor.go:66` | go fix -diff (Go 1.26 modernizers) flags 4 real idiom gaps across the repo | Run go fix ./... (both modules) and commit; add modernize to the default lint set if the maintainer wants this enforced going forward (it is NOT in golangci-lint's default set, see CI-1). |
| `ops/IDIOM-2` | — | error-handling | `oauth/oidc.go:114` | House rule 'errors.Join(errors.New(...), err) not fmt.Errorf %w' is violated everywhere in the codebase -- 258 fmt.Errorf(...%w...) call sites across ~29 files, zero errors.Join(errors.New(...),...) call sites anywhere | Either update the stated house rule to match the codebase's actual (and arguably more standard) fmt.Errorf(%w) convention, or, if errors.Join is genuinely preferred going forward, treat it as a delibe |
| `ops/IDIOM-3` | — | error-handling | `tokens/jwt/issuer.go:155` | Several exported constructors return ad hoc errors.New(...) at the return site rather than a declared sentinel, so callers cannot errors.Is-match a specific validation failure | No action needed unless the maintainer wants uniform sentinel errors even for constructor validation; if so, a shared configError helper type per package would avoid the current one-off strings. |
| `pgx/PG-4` | — | style | `adapters/pgx/tokens/store.go:216` | gofmt formatting violation: stray blank line in tokens/store.go | Run gofmt -w adapters/pgx/tokens/store.go to delete the extra blank line at line 216-217. |


---

### Attack hypotheses tested and cleared (150)

**crypto** (24)

- math/rand used anywhere for security material — `grep -rn "math/rand" --include=*.go .` over all three modules returns zero hits, including tests. Every generator uses crypto/rand.
- Unchecked or short crypto/rand reads yielding a partly-zero secret — Enumerated every crypto/rand call site in non-test code (identity/verification.go:78,82; sessions/service.go:93; mfa/totp.go:25; mfa/recovery.go:43; passwords/argon2/hasher.go:203; oauth/state.go:32,41; tokens/jwt/issuer.go:463,520; keystor
- Insufficient entropy in any generated credential — Measured in bytes: session token 32 (sessions/service.go:92), refresh token 32 default with MinTokenLength=16 enforced in both Validate and New (tokens/jwt/issuer.go:143,352-365), API key 32 same enforcement, OAuth state 16 / PKCE verifier 
- Modulo bias in digit or charset generation — otp/code.go:15-21 uses `rand.Int(rand.Reader, 10^digits)` — big.Int rejection sampling, uniform by construction, no modulo. Recovery codes (mfa/recovery.go:46) base32-encode raw random bytes, so no reduction occurs. The only modulo is RFC 4
- AES-GCM nonce reuse, derivation, counters or zero nonces in the KEK — keystore/kek.go:54-61 generates a fresh NonceSize() (12-byte) nonce from crypto/rand for every Seal, prefixes it to the blob, and never derives/increments/reuses it. Open (:65-75) length-checks before slicing and collapses any authenticatio
- JWT algorithm confusion: alg taken from the header, "none", HS-vs-RS substitution — Both keyfuncs resolve the Signer FIRST (by kid) and only then compare `token.Method.Alg()` to the resolved signer's own pinned alg — tokens/jwt/issuer.go:589-598 and tokens/jwt/keystore.go:59-65. A token claiming HS256 against an RSA kid is
- kid used as an unsafe lookup key (injection, path traversal, unbounded key fetch) — kid is only ever a plain Go map index into an in-memory set built at construction or from the tenant's resolved keyset (tokens/jwt/issuer.go:609, tokens/jwt/keystore.go:59) — never a filesystem path, URL or SQL fragment. A present-but-non-s
- Claims read before signature verification, or an unverified parse anywhere — `grep -rn "ParseUnverified|SkipClaimsValidation|WithoutClaimsValidation|UnsafeAllowNone"` finds hits only in _test.go files (tokens/jwt/keyset_test.go:38, asymmetric_test.go:72, algconfusion_test.go:81, oauth/oidc_test.go:245). Production c
- Cross-tenant token acceptance under a shared signing key — Two independent layers. With a KeyStore, tenantKeyFunc consults only tenantID's keys (tokens/jwt/keystore.go:47), so another tenant's token cannot resolve a key. Without one, VerifyAccessTokenForTenant compares the SIGNED tenant_id claim ag
- OIDC id_token validation: iss/aud/exp/iat, azp confused deputy, nonce replay, JWKS poisoning/size — oauth/oidc.go:184-191 passes WithValidMethods, WithIssuer, WithAudience, WithExpirationRequired, WithIssuedAt and a bounded leeway (1 min default). azp is enforced per OIDC Core 3.1.3.7 including the subtle multi-audience-without-azp reject
- A revoked or stale JWKS/keyset validating a forged token — jwksCache.refresh replaces the whole key map (oauth/oidc.go:343-346), so a revoked kid disappears on the next refresh; staleness is bounded by the 1 h TTL and cached() refuses to serve past c.exp (:307). A failed refresh leaves publicKey re
- Timing side channels in secret comparison — Every secret comparison is either subtle.ConstantTimeCompare / hmac.Equal or a SHA-256-then-indexed-equality lookup: derived password key (passwords/argon2/hasher.go:309), OTP code (otp/code.go:37), TOTP code (mfa/totp.go:119), verification
- Symmetric (HS256) secret accidentally published in a JWKS — Both JWKS builders special-case symmetric keys to metadata only, never emitting "k": keystore/jwks.go:67-70 (`JWK{Kty: "oct", Use: "sig", Alg: "HS256", Kid: kid}`) and tokens/jwt/jwks.go:92-95 (default branch for []byte and any unknown key 
- Weak or wrong-type key material accepted on the keystore path — keystore/jwtadapter.go:64-114 routes HS256 through jwt.NewHMACSigner, which enforces MinSecretKeyLength=32 (tokens/jwt/signer.go:89-94) with no allowWeak escape on that path; asymmetric algs enforce RSA>=2048 bits (signer.go:107), a named s
- TOTP replay within the skew window; concurrent brute force exceeding the attempt budget — validateTOTP returns the ACCEPTED step (mfa/totp.go:120) and MarkTOTPUsed applies only when `last_used_step < $3` (adapters/pgx/mfa/store.go:136-144), so no step is ever accepted twice — including the enrollment-confirming code, which is re
- Recovery codes: entropy, hashed at rest, single-use, count — 10 codes by default, each 80 bits of crypto/rand base32-encoded (mfa/recovery.go:13,41-46). Only the SHA-256 hash of the normalised code is stored (:18-21) and normalisation is applied identically on generation and verification, so the dash
- Argon2id parameters below current OWASP guidance, or tunable downward — Defaults are m=65536 KiB (64 MiB), t=1, p=4, keyLen=32, saltLen=16 (passwords/argon2/hasher.go:28-32) — at or above the OWASP 2021 Argon2id guidance for concurrent workloads. Crucially the WithMemory/WithTime/WithThreads options clamp UP, n
- Malformed stored PHC hash causing a panic in the KDF — Compare explicitly guards the three known panic sources in x/crypto argon2 before calling IDKey — time<1 and threads<1 (deriveKey panics) and keyLen==0 (nil-deref in extractKey/blake2bHash) — plus the memory<8*threads clamp mismatch, all ma
- Decoy-hash cost equivalence and the empty-password timing oracle — Both halves short-circuit symmetrically on the degenerate inputs: Hash returns immediately for password=="" (passwords/argon2/hasher.go:188) and for oversized input (:192), and Compare mirrors both (:227, :234) with the reasoning documented
- OAuth state cookie is not integrity-protected, so a tampered cookie could downgrade PKCE or the nonce — The cookie is plaintext HMAC-less (oauth/handlers.go:269-280) but every consumer of its fields fails closed rather than skipping a check. A blanked nonce hits oauth/oidc.go:215 `expectedNonce == ""` → ErrNonceMismatch, so nonce verification
- Passkey ceremony cookie forgery or cross-tenant replay — The cookie is HMAC-SHA256 sealed and verified with hmac.Equal in constant time, with a length precondition before slicing (passkey/handlers.go:309-329). The key is required at construction (>=32 bytes, ErrCookieKeyMissing at passkey/service
- JWKS response content-type not validated — Not a control here. The response is size-capped at 1 MiB (oauth/oidc.go:335), the status must be exactly 200 (:332), and json.Unmarshal is type-strict — a non-JSON or wrong-shaped body simply fails to decode into the jwk struct and yields '
- jwt.Config redaction leaving the newer pluggable Signers field exposed — Config.String()/LogValue() omit the Signers slice entirely rather than printing it (tokens/jwt/redact.go:52-59, :75-82), and Config implements Stringer so fmt uses the redacting method for %v/%+v/%#v. SecretKey is rendered as REDACTED while
- Refresh-token rotation allowing replay or family-revocation bypass — Only the hash is stored (tokens/jwt/issuer.go:467 via tokens.HashToken), consumption is atomic through the store with the losing racer mapped to the distinct ErrRefreshConcurrent so a benign parallel-tab race does not revoke the family (:79

**identity** (16)

- Verification-token cross-purpose replay: can a password-reset token be presented as an email-verification/magic-link token (or vice versa)? — The kind is part of the atomic consume predicate in BOTH backends — memory store checks `vt.Kind != kind` inside the same mutex (identity/memory/store.go:335) and pgx puts `AND kind = $3` in the lookup (adapters/pgx/identity/store.go:406). 
- Double-spend of a single-use token under concurrency (two simultaneous confirms). — Memory: lookup, verify, expiry check and delete all happen under one held s.mu.Lock (identity/memory/store.go:324-346). pgx: the SELECT is followed by a guarded DELETE whose RowsAffected()==0 is mapped to ErrVerificationTokenNotFound (adapt
- Token brute-force / hashing at rest / timing on the verifier. — Selector is 128 bits and verifier 256 bits from crypto/rand (identity/verification.go:76-89); only the hex SHA-256 of the verifier is persisted and it is compared with subtle.ConstantTimeCompare (verification.go:110-113). Unsalted SHA-256 i
- Email-verification tokens carry no email binding, so consuming an old one could mark a NEW (unproven) address verified. — Examined and not exploitable in the shipped flows: the only paths that change users.email are ConfirmEmailChange and UpdateUserEmail, and both already require confirming a token delivered to the new address and mark it verified in the same 
- Pre-registration takeover / squatting via an email that is pending an email-change for someone else. — Both directions are closed by the live-row unique index, not just by the advisory pre-flight. If the victim registers first, the attacker's ConfirmEmailChange fails with ErrEmailAlreadyExists at UpdateUserEmail (adapters/pgx/identity/store.
- OAuth identity silently auto-linked onto a pre-existing local account that shares the email (classic takeover vector). — Explicitly refused: LinkOrCreateIdentity returns ErrEmailAlreadyExists when the provider email matches any live account and the provider identity is not already linked (identity/service.go:986-995), and the shipped callback additionally ref
- Email case/Unicode normalization used to create a duplicate account or hijack a victim's address (homoglyphs, NFC/NFD, IDN U-label vs punycode, whitespace). — normalizeEmail trims, NFC-normalizes and lowercases the local part and folds the domain to its IDN A-label via idna.Lookup.ToASCII (identity/service.go:26-55), so case variants, NFC/NFD pairs and Unicode/punycode domain pairs collapse to on
- Lockout bypass by varying the email casing, or via a parallel login flow that shares no counter (magic link, OTP, passkey). — Casing cannot bypass it: Authenticate normalizes providerID before the lookup (identity/service.go:519-527), so all variants hit the same identity row and the same counter. Magic link and the token-gated paths do ignore LockedUntil, but the
- IncrementFailedAttempts atomicity and the account.locked event firing more than once under concurrent failed logins. — Both backends derive justLocked inside the single atomic operation — pgx via `RETURNING $3 > 0 AND failed_attempts >= $3 AND failed_attempts - 1 < $3` on the post-update row (adapters/pgx/identity/store.go:489), memory via `before < lockThr
- Soft-deleted account still able to authenticate, be reset, receive a magic link, or be re-registered inheriting old data. — DeleteUser anonymizes users.email and the password identity's provider_id and purges pending tokens atomically (adapters/pgx/identity/store.go:200-218), so FindUserByEmail misses (`deleted_at IS NULL`), Authenticate cannot resolve either th
- Disabled (suspended) accounts still able to consume pending magic-link/email-change tokens. — consumeForLiveUser rejects DisabledAt with ErrUserNotFound (identity/service.go:684-686), which reliably revokes pending token-gated actions while the suspension holds, and LinkOrCreateIdentity's already-linked branch refuses disabled accou
- Non-password provider passed to the credential login form (passwordless bypass on identifier alone). — Authenticate hard-rejects any provider other than "password" after a decoy hash (identity/service.go:602-613), so WithProvider("google") cannot turn LoginHandler into an identifier-only bypass, and the rejection is timing-equalized with the
- Pre-authentication argon2 CPU amplification via an unbounded password field, and unbounded delivery goroutine fan-out / mail-toll fraud on the unauthenticated Request* endpoints. — Every form handler bounds the body at DefaultMaxBodyBytes = 4 KiB before parsing (identity/handlers.go:28, :293-295), and dispatchDelivery caps in-flight deliveries with a per-handler-instance buffered semaphore acquired non-blocking, dropp
- Enumeration via the authenticated Request* endpoints leaking whether an arbitrary userID is a live same-tenant account. — RequestEmailVerification deliberately swallows ErrUserNotFound and returns an empty token so a bogus userID produces the same 204 as a real one (identity/service.go:915-923, tested at identity/service_test.go:54), and the handler only dispa
- WithClock skew affecting the lockout window (service clock gates the lock, DB clock stamps it). — Acknowledged in the option's godoc (identity/service.go:358-362: 'Note the lockout STAMP ... is computed by the Store, not the service, so it is not affected by this clock'). Worst case the effective lock duration is off by the app/DB clock
- SingleTenant wrapper leaking across tenants. — Every method hard-wires tenantID="" (identity/singletenant.go:36-157) and the type doc states the single-tenant-only contract and the mixing hazard explicitly (singletenant.go:15-21). It cannot reach another partition.

**tenant** (14)

- Every method on every Store interface (identity, sessions, tokens, mfa, otp, passkey, oauth, keystore, passkey.ChallengeStore) takes a tenant parameter — Verified mechanically: awk over all nine interface files for 'ctx context.Context' lines lacking tenantID/tenant returned zero results. There is no tenant-less lookup anywhere in the persistence contract.
- pgx SQL might look up by an opaque id/hash alone (token hash, session hash, credential id, selector, provider name, API key id) — Read every statement in all eight adapters/pgx/*/store.go files. Every SELECT/INSERT/UPDATE/DELETE carries tenant_id in its WHERE clause or key tuple, including the multi-CTE statements (identity UpdateUserEmail lines 156-169 and DeleteUser
- verification_tokens has 'selector VARCHAR PRIMARY KEY' (global, not per-tenant), and the memory store keys its map on the selector alone — Not exploitable: the selector is a server-generated 128-bit random value the client cannot choose, and every read/consume/delete is still scoped - identity/store.go:406 'WHERE selector = $1 AND tenant_id = $2 AND kind = $3', identity/store.
- JWT signed with tenant A's key validating for tenant B (kid handling / JWKS selection / shared static key) — Two independent defences and both hold. With a KeyStore, tokens/jwt/keystore.go:45-67 tenantKeyFunc resolves kid ONLY from that tenant's VerificationKeys and then pins token.Method.Alg() to the signer's alg. With the shared static keyset, t
- Per-tenant caches poisoning or leaking across tenants (jwt key cache, keystore JWKS, pgx oauth provider cache, passkey challenge store, sessions byHash index) — All correctly composite-keyed: tokens/jwt/keycache.go entries map is keyed by tenantID and Invalidate/InvalidateAll bump a generation counter so an invalidation racing an in-flight fill is not lost (lines 128-135); adapters/pgx/oauth/store.
- The singletenant.go facades could be mixed with a multi-tenant store and collapse tenants — All five facades (identity, sessions, mfa, otp, passkey, tokens/jwt) hard-wire the literal "" at every call site - verified line by line in identity/singletenant.go:37-157 and tokens/jwt/singletenant.go:39-100. They cannot reach a non-empty
- Service-layer code dropping the tenant on the way to the store — Enumerated every store call in the five services: identity/service.go (48 call sites), sessions/service.go (8), mfa/service.go (16), otp/service.go (8), passkey/service.go (7). Every single one passes tenantID through. In jwt Rotate the ten
- Passkey discoverable (usernameless) login resolves the account from a client-supplied user handle, which could cross tenants — The handle only selects a user id; the credential lookup that actually authenticates stays tenant-scoped. passkey/service.go:309 calls s.loadUser(ctx, tenantID, uid, ...) -> store.GetCredentials(ctx, tenantID, userID), so presenting tenant 
- OAuth callback state replay across tenants / providers in the bring-your-own-SSO model — oauth/handlers.go:206-213 constant-time-compares both the cookie's provider name and the cookie's tenant against the request's, rejecting with provider_mismatch / tenant_mismatch. DynamicBegin/DynamicCallbackHandler resolve the tenant exact
- List*/Count*/prune/janitor operations spanning tenants — None do. Every reaper takes a tenantID and filters on it: DeleteExpired in sessions/tokens/otp/identity (both backends), identity DeleteExpiredVerificationTokens, keystore RetireExpiredKeys. ListAPIKeysByCreator is scoped 'WHERE tenant_id =
- Unique indexes not scoped to the tenant, letting one tenant block another's registration or collide on a key — Every uniqueness constraint is tenant-first: users (tenant_id, email) partial-unique on deleted_at IS NULL, users (tenant_id, phone) partial-unique, identities (tenant_id, provider, provider_id), sessions (tenant_id, token_hash), tokens PK 
- sessions.BindUser accepts any userID with no check that the user belongs to the tenant — Structurally unavoidable and not a library defect: the sessions module has no users table and no dependency on identity, so it cannot verify the binding. The identity module does add the equivalent guard where it can (identity pgx AddIdenti
- The pgx cross-tenant conformance tests may never actually execute (they need Docker, which is unavailable here) — CI does run them. .github/workflows/ci.yml:84 runs the full untagged adapters/pgx suite on ubuntu-latest where testcontainers works, and a dedicated job (lines 86-132) runs the integration-tagged suite against a real Postgres service via TE
- otel adapter putting the attacker-controlled tenant id into telemetry (metric-cardinality blowup) — adapters/otel/sink.go:60-61 sets egauth.tenant_id as a SPAN attribute, not a metric label or dimension. Span attributes carry no cardinality cost in the metrics pipeline, and the adapter registers no metric instruments at all.

**http** (16)

- SSRF guard bypass via IPv6, alternate IPv4 notations, cloud metadata, CGNAT, DNS rebinding, HTTP redirect chains, or env proxies (oauth/ssrf.go) — I tried each vector against oauth/ssrf.go:113-165 and could not break it. isBlockedIP covers loopback (all of 127/8, plus ::1 and ::ffff:127.0.0.1 because To4() normalises the mapped form), 0.0.0.0/:: (IsUnspecified), 169.254.0.0/16 incl. 1
- SSRF guard not applied to every outbound call on the bring-your-own-SSO path (token exchange, userinfo, JWKS, OIDC discovery, HIBP) — adapters/pgx/oauth/store.go:212 builds one SafeHTTPClient and injects it into BOTH the provider (oauth.WithHTTPClient(safeClient), line 227) and the OIDC verifier (OIDCConfig.HTTPClient, line 216), so token exchange, discovery and JWKS all 
- Unbounded outbound response bodies or leaked response bodies on the server-side fetch paths — Every outbound read is size-capped and every body is closed: oauth/provider.go:243-244 and 286-287 (maxResponseBytes), oauth/providers/oidc.go:130-131 (discoveryMaxBytes), oauth/oidc.go:331/335 (maxJWKSBytes), oauth/oidc_discovery.go:76/80 
- Host-header poisoning into emailed password-reset / magic-link URLs (the classic identity/delivery.go vector) — identity/delivery.go builds no URLs at all. PasswordResetMail, EmailVerificationMail, MagicLinkMail, EmailChangeMail, RecoveryEmailMail and PhoneVerificationSMS carry only *User, the plaintext token, and (for change/recovery flows) the norm
- Query-string parameter injection into credential fields (email/password/token/code) via r.ParseForm merging query and body — r.ParseForm merges the query string into r.Form but keeps body-only values in r.PostForm. Every handler reads r.PostForm.Get exclusively — identity/handlers.go:318-320, 391-393, 599-600, 671, 734, 796-797, 914, 966, 1127, 1222, 1270, 1303; 
- Origin/Referer parsing failing open on null origin, unparseable headers, or a relative Referer — httputil.RequestOriginHost (internal/httputil/httputil.go:35-55) fails closed on all three: Origin "null" returns "" and explicitly does NOT fall back to the weaker Referer (line 41-43); an unparseable Origin returns "" rather than falling 
- The origin check running after body parsing, letting a cross-site POST burn argon2 cycles pre-auth — Ordering is correct everywhere: method check, then originAllowed, then parseLimitedForm, then the service call — identity/handlers.go:305-322, tokens/handlers.go:144-154, mfa/handlers.go:222-242, otp/handlers.go:177-192. A rejected cross-si
- tokens.ContextMiddleware silently skipping the gates that RequireAuth enforces (WithRequiredKind in particular), i.e. a security control lost on the context bridge — Both entry points share serveAuthenticated (tokens/middleware.go:193), which applies the step-up/AMR, max-auth-age, scope, password-change and application-gate checks on both the verified-token path (lines 222-239) and the auto-refresh path
- HTTP method not enforced, allowing GET-triggered state changes (link prefetchers, email scanners) — Every state-changing handler is POST-only with a correct Allow header: all 14 identity handlers, tokens Refresh/Logout (tokens/handlers.go:144-148, 202-206), the shared mfa guarded() preamble (mfa/handlers.go:222-226), both otp handlers, an
- Open redirect via a user-controlled redirect target (return_to / next / failure URL / state) — No handler derives a redirect target from request data. httputil.Fail and RedirectOrStatus (internal/httputil/httputil.go:73-108) redirect only to cfg.failureURL / cfg.successURL, which are operator-supplied at handler construction via With
- __Host- prefix guarantees being cosmetic rather than enforced for the auth and session cookies — The prefix defaults are real and enforced. tokens.DefaultCookies uses __Host-access_token / __Host-refresh_token (tokens/cookies.go:18-19, 61-70) and sessions.RequireSession defaults to __Host-session_token (sessions/middleware.go:16, 36-38
- OAuth state cookie being unsigned, and cross-provider / cross-tenant state replay — The cookie is a plain concatenation (oauth/state.go:55-63) with no MAC, but the integrity model is sound for what it defends and is fully disclosed at SECURITY.md:398-414, including the plaintext PKCE verifier and nonce and the recommendati
- health package exposing an unauthenticated HTTP endpoint that leaks backend detail — health/health.go is 19 lines containing only the Pinger interface — no HTTP handler, no mux registration, no response writing anywhere in the package. There is no attack surface, and the probe wiring is left entirely to the consumer.
- Error bodies leaking internal detail (SQL text, wrapped store errors, provider errors, stack traces) to clients — Every client-visible body is a fixed literal code, never a formatted error. identity mapAuthError/mapVerificationError/mapRegisterError (identity/handlers.go:520-536, 1026-1057, 1073-1081), oauth mapLinkError (oauth/handlers.go:332-346), mf
- Off-response-path mail/SMS goroutine fan-out as an unauthenticated DoS / toll-fraud amplifier — Both dispatchers are bounded correctly. identity/handlers.go:456-491 and otp/handlers.go:273-298 acquire from a semaphore created ONCE per handler instance in newHandlerConfig (identity/handlers.go:113-115, otp/handlers.go:68-70) — not per 
- Enumeration oracles in the uniform-response Request* handlers — The uniform-response shape is genuinely uniform: RequestPasswordResetHandler, RequestMagicLinkHandler and RequestPasswordResetViaRecoveryHandler discard the service error entirely (identity/handlers.go:570, 703, 1308) with an in-code ration

**lifecycle** (14)

- Refresh rotation atomicity and the two-concurrent-refresh race — is the consume a compare-and-swap in BOTH backends, or a read-then-write? — Both are genuine CAS. pgx: `UPDATE tokens SET consumed_at = now() WHERE tenant_id=$1 AND token_hash=$2 AND claims IS NULL AND consumed_at IS NULL` and it branches on RowsAffected (adapters/pgx/tokens/store.go:104-132), so exactly one of N r
- Can step-up (WithRequiredAMR / WithMaxAuthAge) be evaded by refreshing, and is AuthTime forged or made unsatisfiable? — AuthTime is defaulted to the issue time ONLY when `initial` is true (issuer.go:415-418), and Rotate calls issuePair with initial=false after pinning `claims.AuthTime = rt.AuthTime` (issuer.go:816, 830), so a rotation can never manufacture f
- Is the WithRequiredKind gate silently skipped on the ContextMiddleware path (it lives in RequireAuth's closure, not in shared code)? — No — ContextMiddleware performs the identical check in its own onAuth closure before injecting the Actor (tokens/context.go:60-65), mirroring RequireAuth (middleware.go:178-182). Both paths enforce it; only the ORDER relative to WithGate is
- Auto-refresh writes both cookies before the step-up/scope/password-change/gate checks run — does that leak a credential to an unauthorized request? — This is correct and necessary. The rotation has already atomically consumed the old refresh token by the time the cookies are written (middleware.go:254 → issuer.go:794), so withholding the freshly minted refresh cookie would strand the cli
- Scope/authorization helper semantics — substring/prefix matching, case-insensitivity, wildcards, or an empty-scope-means-all footgun? — All exact string equality with no wildcard or hierarchy: `Actor.HasScope` is a linear `sc == s` (actor.go:65-72); `HasAllScopes` is vacuously true only for a ZERO-argument call and false on any missing scope (actor.go:77-84); `HasAnyScope` 
- Session fixation: is the session identifier rotated on privilege change (anonymous→authenticated via BindUser, and on step-up), and is pre-auth data carried over? — Yes. `BindUser` mints a brand-new token, re-binds UserID and writes both through `BindSession` as a compare-and-set on the OLD token hash (sessions/service.go:190-212), so the pre-auth token stops validating atomically with the promotion; `
- Session expiry: idle vs absolute, and whether an expired-but-unpruned row can ever be treated as valid — Enforced twice, independently, on every read. The store contract requires expired rows to read as not-found and both backends honour it (memory evicts the matched row opportunistically at sessions/memory/store.go:39-43; pgx adds `expires_at
- Actor mapping consistency between ActorFromAPIKey and actorFromClaims — Consistent for the classified kinds. For Service, `IssueAPIKey` sets `claims.Subject = keyID` (issuer.go:538-539), so ActorFromAPIKey's `KeyID = key.ID` (tokens/actor.go:33) and actorFromClaims' `KeyID = claims.Subject` (middleware.go:338-3
- API key storage and verify path: hash-only at rest, revocation and expiry enforcement, and whether a revoked key can slip through any verify entry point — Only the SHA-256 hex hash is persisted; the memory store explicitly blanks `Token` before storing (tokens/memory/store.go:170) and the pgx INSERT never includes a token column (adapters/pgx/tokens/store.go:202-208). Revocation is a single c
- Refresh-token reuse grace window as a theft-detection hole, and lockout of a legitimate double-submitting client — Documented and accepted in SECURITY.md:71-88 with the reasoning spelled out, and the implementation matches the disclosure: within the grace window the replay is still REJECTED (only the family survives), so the replayer gains nothing; ErrR
- Does the JWT verify path allow alg confusion, 'none', a kid-less token forged past a keyset, or cross-tenant replay under a shared signing key? — The signer is resolved from the kid FIRST and the token's alg is then pinned to that signer's alg (issuer.go:589-618 and the per-tenant twin at keystore.go:45-68), so alg:HS256 against an RSA kid and alg:none both fail. A present-but-malfor
- CachingKeyStore serving a revoked tenant keyset after a keystore key revocation — Bounded two ways as documented: entries expire after the TTL (keycache.go:109-112) and `EmitEvent` invalidates the tenant immediately on tenant.keys_renewed/keys_revoked/tenant.deleted when wired as a Manager sink (keycache.go:197-202). The
- LogoutHandler idempotency and whether a store error can leave a family un-revoked while reporting success — Correct. A missing token is an idempotent 204 with no spurious logout event emitted (which would otherwise let a client manufacture audit records by replaying the call); a RevokeFamily failure or any other store error clears the cookies but
- Session/token stores using time.Now() instead of the injected clock (sessions/memory FindSessionByHash, DeleteExpired; tokens/memory ConsumeRefreshToken; pgx expires_at >= NOW()) — Not a production defect for these paths. The reference stores are documented as clock-less and the service re-checks expiry with the injected clock on top of the store's filter, so the stricter of the two wins and the result is always fail-

**mfa** (15)

- TOTP replay of the SAME code inside the ±skew window, and reuse of the enrolling code for a login — Correct. mfa/service.go:288-297 accepts only a step strictly newer than LastUsedStep, and both stores implement the monotonic guard atomically: mfa/memory/store.go:74-76 (`if step <= e.LastUsedStep { return false, nil }`) and adapters/pgx/m
- Is a TOTP secret usable before the enrollment is confirmed? — No. mfa/service.go:258-260 rejects with ErrNotConfirmed, and Confirmed() requires a non-nil ConfirmedAt (mfa/mfa.go:66). EnrollTOTP also refuses to overwrite a CONFIRMED factor (service.go:179-181), so a momentary session cannot silently sw
- Concurrent brute force of TOTP / recovery codes exceeding MaxAttempts (TOCTOU on the stale GetTOTP read) — Correctly handled. The attempt slot is reserved atomically BEFORE the constant-time compare in all three verify paths (ConfirmTOTP service.go:215-222, VerifyTOTP service.go:266-273, VerifyRecoveryCode service.go:312-320), and the reservatio
- Lockout used as a perpetual-DoS loop (an attacker keeps bumping LastAttemptAt so the 15-minute decay never fires) — Explicitly defended. When the factor is already locked and has not decayed, both stores return an over-limit count WITHOUT incrementing or bumping LastAttemptAt: mfa/memory/store.go:97-100 and adapters/pgx/mfa/store.go:167-171. So the decay
- Recovery-code entropy, at-rest form, single-use atomicity, and whether regeneration invalidates the old set — All sound. 80 bits from crypto/rand per code (mfa/recovery.go:13, 42-46), stored only as hex SHA-256 of the normalized value (recovery.go:18-21), 10 per set by default. Consumption is a guarded single-use UPDATE (`... AND used_at IS NULL` +
- OTP single-use under concurrency and the Issue/Verify TOCTOU (a stale verify burning a freshly reissued code) — Correct and well-reasoned. ConsumeOTP is guarded on the exact hash the verifier compared against (otp/service.go:157, otp/memory/store.go:109-115), so only one of N parallel correct-code verifications wins AND a superseded code neither auth
- OTP code entropy / charset bias and a misconfigured digit count — No modulo bias: crypto/rand.Int over exactly 10^digits (otp/code.go:15-22), zero-padded. NewService panics for digits outside [6,10] (otp/service.go:75-77) and floors non-positive TTL / MaxAttempts to the defaults (service.go:78-83). Expire
- WebAuthn credential-ID to user binding — can credential X be claimed by user Y, or a username-bound ceremony cookie be replayed at the discoverable endpoint? — No. go-webauthn enforces the bindings egauth relies on: session.UserID must equal user.WebAuthnID() (webauthn/login.go:217, registration.go:141), a supplied userHandle must equal the user ID (login.go:311), the asserted RawID must be presen
- Passkey user-verification default and whether it is actually enforced (UV downgrade by the client) — Enforced end to end. Config zero value is normalized to protocol.VerificationRequired at construction (passkey/service.go:138-141), wired into AuthenticatorSelection.UserVerification (service.go:151-153), copied by go-webauthn into SessionD
- Ceremony expiry and challenge single-use / guessability — Both hold. Timeouts are Enforce:true with a 5-minute bound (passkey/service.go:154-157), so SessionData.Expires is populated and re-checked server-side at Finish (go-webauthn login.go:221, login.go:258, registration.go:145). Single-use is s
- Sign-count regression / cloned-authenticator detection, and metadata clobbering on the full-record UpdateCredential — Handled in both login paths: cred.Authenticator.CloneWarning is checked and the login rejected with ErrCredentialCloned plus an AccountBlocked event (passkey/service.go:255-258, 316-319). applyLoginMetadata (service.go:474-484) deliberately
- passkey BeginLogin's no_credentials response as a passkey-enrolment enumeration oracle — Already identified, documented and accepted, with a build-enforcing test: passkey/no_credentials_oracle_test.go records the accepted remediation (disclose in SECURITY.md + rate-limit BeginLoginHandler) and asserts the SECURITY.md text is pr
- Absence of per-IP rate limiting on the mfa / passkey verify endpoints — A disclosed, accepted non-objective, not a silent omission: SECURITY.md ('MFA verification is not rate-limited by egauth' and the passkey checklist's 'Rate-limit ceremony attempts in front of the handlers'), mfa/handlers.go:163-167 and pass
- CSRF on the state-changing mfa/otp endpoints (a cross-site POST stripping MFA or invalidating recovery codes) — Closed by default. Both families enforce a strict same-origin check even with an empty allowlist, rejecting a POST whose Origin/Referer host is neither the request Host nor allow-listed, and treating a POST with neither header as untrusted:
- mfa.NewService misconfiguration producing unverifiable or trivially guessable codes, or silently disabling the attempt limit — Fail-fast and secure-by-default: NewService panics on a nil store, digits outside RFC 6238's 6-8, a sub-second period, negative skew, non-positive recovery count and a nil clock (mfa/service.go:124-154); WithMaxAttempts(0) falls back to the

**pgx** (8)

- oauth Store.GetProvider decrypting client_secret via KEK.Open on every call, including cache hits (a prior finding, commit 23f6780) — Verified fixed: the cache lookup (store.go lines 167-172) happens BEFORE the base64-decode/KEK.Open block (lines 174-185), so a cache hit returns without touching the KEK. This is explicitly covered by adapters/pgx/oauth/cache_internal_test
- pgxmigrate.Run building the applied-migration INSERT via string concatenation ('...+strings.ReplaceAll(version, "'", "''")+...') instead of a bound parameter — looks like classic SQL injecti — The interpolated value is the embedded migration filename from go:embed migrations/*.sql — a build-time, source-controlled value, never derived from any runtime/caller/tenant input. Quotes are defensively escaped anyway. This is correctly d
- identity.Store.ConsumeVerificationToken and CreateVerificationToken keying verification_tokens by a global (non-tenant-scoped) PRIMARY KEY 'selector' — looks like a cross-tenant unique-index — selector is a server-generated, high-entropy random value (identity.GenerateVerificationToken), never caller-controlled, so a global PK does not create a functional cross-tenant collision risk the way a global email/username unique index wo
- identity.Store.IncrementFailedAttempts' single UPDATE with nested CASE expressions in both SET and RETURNING clauses — looked suspicious for getting the pre/post-increment semantics wrong (c — Traced the CASE logic by hand: RETURNING sees the POST-update failed_attempts (Postgres UPDATE...RETURNING always reflects the row's final state), so 'failed_attempts >= $3 AND failed_attempts - 1 < $3' correctly reduces to 'the pre-increme
- keystore.Store.CreateTenant's fallback path (createTenantChecked called directly on s.db when s.db is not a txBeginner) doing TenantExists-then-PutSigningKey with no lock — looks like a TOCT — Real but same-class issue as PG-5 (mfa fallback): in every shipped wiring s.db is *pgxpool.Pool or pgx.Tx, both of which implement Begin and take the pg_advisory_xact_lock(hashtext($1)) branch (lines 58-73), so the unguarded fallback is not
- All rows.Next() loops (identity.FindIdentitiesByUserID, passkey.GetCredentials, tokens.ListAPIKeysByCreator, keystore.VerificationKeys) — checked whether rows.Err() is verified after the loo — Every loop in the adapter correctly defers rows.Close() immediately after the Query call and checks rows.Err() after the for loop before returning success (e.g. identity/store.go:285,305-307; tokens/store.go:324,344-346; keystore/store.go:1
- Nullable timestamp/string columns (consumed_at, revoked_at, email_verified_at, phone, recovery_email, disabled_at, deleted_at, auth_time, last_attempt_at, retired_at, not_after) scanned dire — Checked every struct definition backing these columns (tokens.RefreshToken.ConsumedAt, tokens.APIKey.RevokedAt, identity.User.{EmailVerifiedAt,PhoneVerifiedAt,RecoveryEmailVerifiedAt,DeletedAt,DisabledAt,Phone,RecoveryEmail}, keystore.Signi
- Unmapped driver errors (mapError's default branch, and every store method that returns 'return err' or 'return nil, err' verbatim on a non-constraint pgconn.PgError) propagating a raw *pgcon — Within the pgx adapter itself this is a standard Go store-layer pattern (return the underlying error for the caller to log/wrap) and every constraint violation that maps to a user-facing outcome IS translated to a domain sentinel (23505 -> 

**concurrency** (8)

- ratelimit.TokenBucket unbounded map growth when WithMaxKeys is not used and Cleanup is not scheduled — Explicitly documented in the package doc (ratelimit/tokenbucket.go:14-28) with two concrete, correctly-implemented mitigations: WithMaxKeys (verified: floors n at 1, evicts the least-pressured of a random 5-sample in O(1), correctly compare
- keystore/memory.Store and CachingKeyStore (tokens/jwt/keycache.go) unbounded per-tenant map growth — Both are keyed by real tenantID, and the write paths that populate them (Manager.CreateTenant/PutSigningKey for the store; CachingKeyStore.store, only reached after a successful delegate.ActiveSigningKey+VerificationKeys round trip) are gat
- CachingKeyStore.store/Invalidate generation-counter race (a fill racing an Invalidate could cache a pre-rotation keyset) — Correctly handled: generation() is captured before the delegate read, and store() only writes if c.gen is unchanged (tokens/jwt/keycache.go:118-135), so an Invalidate that lands mid-fill causes the stale result to be discarded rather than c
- event.Emit/safeEmit and MultiSink — could a slow or panicking Sink block or crash the auth path? — safeEmit (event/event.go:119-126) wraps every EmitEvent call in a defer/recover and logs the recovered panic via slog rather than swallowing it silently; MultiSink (event/event.go:133-141) wraps each fan-out member individually so one sink'
- janitor.Start/Stop goroutine lifecycle: leaks, double-Stop, Stop-while-running, panic in fn — Start correctly floors a non-positive interval to 1ns (avoiding a busy spin turning into an error case; it still ticks, just fast, which is intended), derives a child context via context.WithCancel so either the parent ctx or Stop() termina
- passkey/memory.Store and mfa/memory.Store copy-on-return / lock discipline for every getter (GetCredentials, GetTOTP, etc.) — Every read path takes RLock/Lock as appropriate and returns a deep-cloned value (clone() in passkey/memory/store.go:30-46 explicitly deep-copies ID/PublicKey/Data/Transports/LastUsedAt; mfa/memory/store.go's GetTOTP does `cpy := *e; return 
- identity/memory, passkey/memory and mfa/memory doing O(n) linear scans for non-ID lookups (FindUserByEmail, FindIdentityByProvider, credential-ID uniqueness check in SaveCredential, etc.) — These packages are consistently and explicitly documented as 'primarily for tests and single-process use' with production guidance pointing to the indexed pgx backends (identity/memory/store.go, passkey/memory/store.go, mfa/memory/store.go 
- ratelimit's own documented limitation that Cleanup() only reaps fully-refilled buckets, so a sustained slow-drip flood (never letting any bucket fully refill) defeats janitor-scheduled Clean — This exact behavior and its implication are explicitly called out in the TokenBucket package doc (ratelimit/tokenbucket.go:19-26): 'Cleanup drops only fully-refilled buckets, so it does not reset any key that is still under pressure' with W

**ops** (10)

- gosec G124 on passkey/handlers.go:274 and :332 (http.Cookie missing/insecure Secure, HttpOnly, SameSite attribute) — Read both http.SetCookie calls directly: both set HttpOnly:true, Secure:!cfg.insecureCookies (defaults to true), and SameSite:cfg.cookieSameSite (defaults Lax) explicitly. gosec's static analyzer cannot verify a variable-driven Secure/SameS
- gosec G401/G505 sha1 usage in passwords/breach/hibp/hibp.go and passwords/breach/offline/offline.go — SHA-1 here is the mandated hash for the HIBP k-anonymity breach-check API protocol (first 5 hex chars of SHA-1(password) sent to the API) -- required by the third-party wire format, not a cryptographic choice made by this library, and not u
- gosec G115 integer overflow conversions in mfa/totp.go:53 (int64->uint64) and passwords/argon2/hasher.go:151,157,270 (int->uint32) — totp.go converts a Unix-time-derived time-step counter (always non-negative in practice) to uint64 for HOTP; the argon2 conversions are uint32(len(...)) on decoded salt/hash byte slices, which are bounded by realistic password-hash sizes (f
- govulncheck's single reported vulnerability (GO-2026-5932, golang.org/x/crypto/openpgp, 'unmaintained, unsafe by design') — Verified via go mod why -m golang.org/x/crypto: the only import path is passwords/argon2 -> golang.org/x/crypto/argon2. libauth never imports the openpgp subpackage; govulncheck itself confirms '0 vulnerabilities in packages you import' and
- testcontainers-go (and its large transitive graph: docker/moby/containerd, grpc, protobuf) is a direct, non-indirect require in adapters/pgx/go.mod — Confirmed via grep that every import of 'testcontainers' in adapters/pgx is confined to _test.go files (identity, sessions, mfa, oauth, tokens, keystore, otp, passkey store_test.go plus pgxmigrate_test.go and the integration test). None of 
- CI's -race, fuzz, and Docker-suite coverage — -race is actually run comprehensively: test-core (3-OS matrix), test-adapters-pgx, test-adapters-pgx-integration, and adapters/otel's test job all pass -race. 6 Fuzz* targets exist and each gets a 30s pass on every push (passwords/argon2, o
- GitHub Actions pinning and job permissions in ci.yml/pages.yml — Every actions/* step is pinned to a full commit SHA with a version comment (e.g. actions/checkout@9c091bb...# v7.0.0); the workflow-level permissions block is contents:read only, and pages.yml's broader pages:write/id-token:write is correct
- Typos in comments and string literals (JSON fields, HTTP headers/params, error strings) across all three modules — Ran go run github.com/client9/misspell/cmd/misspell@latest . against the core module, adapters/pgx, and adapters/otel independently; zero hits in all three. Also grepped for a broad list of common English misspellings across all *.go files;
- Direct dependency staleness across all three go.mod files — GOWORK=off go list -m -u -mod=mod all in each module (network reachable in this session) shows every DIRECT dependency at its latest available version with no update bracket (cbor v2.9.2, go-webauthn v0.17.4, jwt/v5 v5.3.1, uuid v1.6.0, tes
- interface{} usage (vs any) anywhere in non-test code — Searched the whole repo (grep -rn 'interface{}' excluding _test.go); zero hits. The codebase already uses any uniformly.

**claims** (25)

- SECURITY.md: "The library enforces a minimum token byte length (jwt.MinTokenLength = 16) for RefreshLength and APIKeyLength: Config.Validate returns an error and New panics if either is set  — Exactly true. `MinTokenLength = 16` (tokens/jwt/issuer.go:143); `Validate` errors on a non-zero sub-minimum value (issuer.go:233-238); `New` substitutes the 32-byte default for zero FIRST and only then panics (issuer.go:352-365), so 0 means
- SECURITY.md: "every enumeration-safe branch in Authenticate calls decoyHash" — Verified branch-by-branch in identity/service.go:518-613. All seven failure paths spend a decoy Argon2id pass: malformed email (:523), unknown user (:533), missing identity (:540), locked account (:550), disabled account (:559), nil Passwor
- SECURITY.md names four timing-evidence benchmarks; do they exist and still pass, and are the deltas within noise? — All exist and pass. passwords/argon2/timing_bench_test.go:52 BenchmarkCompare_CorrectPassword, :72 BenchmarkCompare_WrongPassword; identity/authenticate_bench_test.go:71 ValidUser_WrongPassword, :86 UnknownUser, :100 NonPasswordProvider. Ra
- Brute-force lockout defaults and the WithLockout(0,0) hardening claim — DefaultLockThreshold=5, DefaultLockDuration=15m (identity/service.go:59-60). `WithLockout(0, 0)` genuinely keeps the defaults (identity/service.go:409-419) and `WithNoLockout()` is the explicit, greppable opt-out (:296-300). Covered by iden
- Alg pinning, iss/aud verification, and alg:none / alg-confusion rejection — Correct and well-ordered: `verificationKey` resolves the Signer from the kid (or the kid-less legacy signer) BEFORE consulting the alg, then requires `token.Method.Alg() == signer.Method().Alg()` (tokens/jwt/issuer.go:589-598), so HS256-aga
- Refresh rotation: single-use, family theft detection, issuer-controlled access TTL, immutable tenant, preserved auth_time, MustChangePassword carry-forward — All implemented as documented in tokens/jwt/issuer.go:734-831: consumed-token replay outside the grace revokes the family and a failed revocation is surfaced rather than swallowed (:754-758); consume is atomic and losing the race yields the
- Secure-by-default cookies and the __Host- claim — `DefaultCookies()` yields __Host- names, Path=/, SameSite=Lax, HttpOnly always, and Secure via the zero value of an opt-OUT `Insecure` bool (tokens/cookies.go:61-70) — so a partially-initialized or zero-value Cookies is still secure. `Valid
- Pre-auth body caps against hashing DoS — Present on every form/JSON handler family: identity (handlers.go:102 default, :293-295 via httputil.ParseLimitedForm), mfa (handlers.go:51, :249-263), otp (handlers.go:58, :317), passkey Finish handlers (handlers.go:71, :171, :228, :505, :5
- OAuth PKCE-S256 + single-use state cookie + constant-time state comparison + provider/tenant binding + unverified-email refusal + no silent account linking — All hold. PKCE is on by default (`usePKCE: true`, oauth/handlers.go:50) with S256 (state.go:39-48); the state cookie is HttpOnly/Secure/SameSite=Lax with a TTL (handlers.go:269-280) and is cleared unconditionally before any validation (:182
- OAuth SSRF guard on tenant-supplied URLs (bring-your-own-SSO) — Two genuine layers, correctly ordered. Registration-time `ValidateExternalURL` requires https and rejects literal internal IPs (oauth/ssrf.go:47-69), and `SafeHTTPClient` enforces the authoritative dial-time check against the RESOLVED addre
- WebAuthn user-verification default and ceremony-cookie integrity — `NewService` maps the zero-value `UserVerification` to `protocol.VerificationRequired` (passkey/service.go:136-141) and wires it into `AuthenticatorSelection`, which go-webauthn copies into SessionData and enforces at Finish across register
- Strict same-origin CSRF check really applied to every handler SECURITY.md names — Verified call-site by call-site. identity: 20 `originAllowed` gates covering login, register and every authenticated mutation (identity/handlers.go:310,383,557,591,621,663,694,726,779,837,897,958,994,1110,1172,1205,1262,1295). tokens: Refre
- passkey handlers have no same-origin CSRF check although every other handler family does — Correct by construction rather than an omission: a WebAuthn Finish request cannot be forged cross-site because the authenticator signs the caller's origin into clientDataJSON and go-webauthn validates it against `Config.RPOrigins` (passkey/
- passkey/memory ChallengeStore could accumulate abandoned ceremony challenges (unbounded growth), like sessions/memory and otp/memory — It self-evicts: `Put` runs a full `pruneLocked(time.Now())` sweep on every insert (passkey/memory/challengestore.go:36-39, :61-68) and `Consume` deletes the entry regardless of expiry (:50-53). No janitor scheduling is required, so its abse
- Argon2id cost-parameter bounds-checking on the verify path (OOM DoS from a tampered stored hash) — Implemented exactly as documented. `Compare` parses m/t/p from the stored PHC string and rejects time<1, threads<1, keyLen==0 (passwords/argon2/hasher.go:282-284), memory < 8*threads (:289-291) and memory > MaxMemoryKiB (:297-299) — all as 
- Single-use verification tokens: selector/verifier, atomic consumption, live/same-tenant gate, and "never burned for nothing" — Confirmed. `ResetPassword` validates the policy and hashes BEFORE consuming, so a weak password or hashing failure cannot burn the token (identity/service.go:696-712). `consumeForLiveUser` re-checks liveness as belt-and-suspenders (:668-669
- tokens.RequireAuth could fall open to the tenant-unaware verify path when no tenant resolver is configured — It cannot. `serveAuthenticated` always calls `VerifyAccessTokenForTenant` — with the resolved tenant when a resolver is set, and with "" otherwise (tokens/middleware.go:216-220); there is no tenant-unaware method to fall back to. A configur
- Step-up / AAL: WithRequiredAMR fails closed with 403, and the MFA gate really withholds a renewable session — `amrSatisfied` requires every configured AMR value to be present in the token, so a password-only session can never satisfy WithRequiredAMR(AMRMFA) (tokens/middleware.go:355-369), and the rejection is 403 step_up_required (:418-420) — as do
- OTP single-use and attempt-limiting "hold under concurrency" as claimed — The service-layer logic matches the claim precisely: the attempt slot is reserved via the atomic `IncrementOTPAttempts` BEFORE the code is compared, so the gate is the counter and not the stale read (otp/service.go:127-139); success consume
- MFA construction-time validation and the documented RFC 6238 digit range — `NewService` panics for digits outside 6-8, sub-second period, negative skew, non-positive recovery-code count and a nil clock (mfa/service.go:140-154), exactly as SECURITY.md:110-112 and the godoc claim, with coverage in mfa/newservice_tes
- "No internal logging" for the core packages (passwords/tokens/hashes never written anywhere) — Holds for every core package. `grep -rn 'fmt\.Print|println\(|log\.|os\.Stderr|os\.Stdout'` over non-test, non-example code returns only the redaction helpers in tokens/redact.go and tokens/jwt/redact.go (which render secrets as a placehold
- AUDIT.md's claim of "cross-backend conformance suites exercising the in-memory and PostgreSQL (pgx) stores against the same contract" — Genuinely wired into CI, not aspirational: .github/workflows/ci.yml has a `test-adapters-pgx` job running the Docker/testcontainers conformance suites (lines 55-84) plus a separate `test-adapters-pgx-integration` job against a real Postgres
- Session absolute-lifetime cap semantics (WithMaxLifetime(0) vs WithNoMaxLifetime, and option ordering) — Matches SECURITY.md:416-425 exactly, and is unusually well tested. `WithMaxLifetime(0)` keeps the 30-day default rather than disabling the cap (sessions/service.go:241-249 godoc; sessions/lifetime_test.go:155 TestWithMaxLifetime_ZeroKeepsDe
- Token/session/API-key hashing at rest — `tokens.HashToken` is SHA-256 hex (tokens/hashing.go:8-12) and is what is persisted for refresh tokens (issuer.go:467-471) and API keys; `sessions` hashes its token the same way (sessions/service.go:235-239) and `sessions.Session` stores on
- go.mod retract block's stated reasons ("insecure-by-default passkey, stale go directive, no tokens/basic") — All three are now true of the shipped code: passkey is secure-by-default (UV required, CookieKey and ChallengeStore mandatory at construction — passkey/service.go:123-141), the go directive is `go 1.26.5`, and `tokens/basic` exists and is t

