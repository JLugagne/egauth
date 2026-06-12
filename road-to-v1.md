# Road to v1

The contract this document sets: **v1.0.0 means the public API is frozen under SemVer, the
security posture and its current limitations are disclosed clearly and prominently, and a real
consumer can wire any supported stack without writing security-critical glue the library should
have provided.**

> **Maintainer decision (recorded):** v1 will ship **without** an independent third-party human
> security audit. This is a conscious, accepted risk. The library is engineered carefully and
> secure-by-default, but its security review to date is AI-driven only. The bar that *replaces* the
> audit as a hard v1 gate is **honest, unmissable disclosure** of that fact (§0) — the maintainer
> prefers transparency over a false impression of assurance. An external audit remains strongly
> encouraged and welcome post-v1, but does not block the tag.

Status today: **v0.3.0** (public-release hardening done; API still settling; AI-driven audit only).
This file is the gap list between here and that contract. It is organized by theme, each item
tagged with a rough size (`S`/`M`/`L`) and whether it is **blocking** v1 or **nice-to-have**.

> Legend — **[BLOCK]** must ship (or be explicitly, permanently waived) before tagging v1.
> **[WANT]** strongly desired but a documented deferral to v1.x is acceptable.
> Sizes are engineering effort, not calendar time.

---

## 0. The one hard gate — honest disclosure of the un-audited status

**Decision:** v1 ships without an external human audit; that risk is accepted. The audit is therefore
*not* the gate. **The gate is that no user can adopt egauth without understanding, clearly and up
front, that its security review is AI-driven only.** Honesty is the deliverable. A user who ships
egauth and is later surprised that it was never human-audited is a documentation failure, not a
security one — and that failure is what blocks v1.

- [ ] **[BLOCK]** **Prominent audit-status disclosure at every first point of contact.** The same
  short, plain statement must appear — not buried — in: `M`
  - the **README**, in the first screen (it already has a good "About this project" note — keep it,
    make sure it stays above the fold and survives future edits);
  - the **root package godoc** (`doc.go`), so it shows on pkg.go.dev and in editors/`go doc`;
  - `llms.txt` (so agents and tools relay it), and the top of `SECURITY.md`;
  - the **CHANGELOG entry for v1.0.0** itself.
  - One canonical wording, reused verbatim, e.g.: *"Security review to date is AI-driven only; egauth
    has not had an independent third-party human security audit. It is secure-by-default and carefully
    engineered, but weigh this status before using it for anything sensitive. Independent audits are
    welcome — see SECURITY.md."*
- [ ] **[BLOCK]** **A machine-checkable disclosure test** so the statement can't silently rot. A small
  test that greps README / `doc.go` / `llms.txt` / `SECURITY.md` for the canonical audit-status
  sentence and **fails the build if it goes missing or is edited away**. The whole point of this gate
  is that the disclosure is durable, not a one-time note someone later "cleans up". `S`
- [ ] **[BLOCK]** **State the scope of the AI review honestly** in `SECURITY.md` / `AUDIT.md`: what was
  reviewed (and how — adversarial AI pass, no high/critical found), what was *not*, and the explicit
  accepted trade-offs already listed there. "AI-audited" must not read as a euphemism for "audited".
  Describe the method plainly so the reader can judge the assurance level themselves. `S`
- [ ] **[BLOCK]** **A clearly-labeled escape hatch for the cautious user.** Document, in one place, the
  concrete options for someone who needs more assurance: pin a reviewed commit, run their own audit,
  fund/commission an external one, or wait. Turning "we're not audited" into "here's how to de-risk
  it" is the difference between a scary footnote and a usable honest disclosure. `S`
- [ ] **[WANT]** **`AUDIT.md` as a living ledger.** Record the AI-review passes (date, scope, tooling,
  findings, fixes) and leave a clearly marked, empty **"Independent human audits"** section so that
  when one happens it has a home — and so the *absence* of entries there is itself an honest signal. `S`
- [ ] **[WANT]** **Re-disclose on security-relevant change.** Any post-v1 change touching a crypto/
  protocol path re-asserts the un-audited status in its CHANGELOG entry (or notes the delta was
  reviewed and how). Keeps the disclosure current instead of frozen at v1.0.0. `S`

> Net effect: the audit moves from a **blocking gate** to a **strongly-encouraged post-v1 follow-up**,
> and **transparent, durable, build-enforced disclosure takes its place as the non-negotiable v1
> requirement.** This is a defensible posture for an honestly-marketed pre-audit auth library — but
> *only* if the disclosure is genuinely unmissable and machine-protected against erosion. That is the
> bar §0 now sets.

---

## 1. API stability (the SemVer promise)

v1 means *no breaking change without a v2*. Today the docs say "API may change between minor
versions" and Store interfaces "may gain methods in minor releases". That has to stop.

- [ ] **[BLOCK]** **Freeze every exported symbol** across all modules. Do a full `go doc -all` sweep
  per module and decide, for each exported type/func/field, whether it is part of the v1 contract.
  Anything not meant to be stable moves to an `internal/` package or gets an `// Experimental:` doc
  marker (see §1.3). `M`
- [ ] **[BLOCK]** **Segment the monolithic `Store` interfaces by capability before freezing them.**
  Right now an external `Store` implementer breaks on every minor because methods get added to one
  big interface. Split each module's `Store` into a stable core + optional capability interfaces
  (e.g. `identity.Store` core vs `identity.RecoveryStore`, `identity.PhoneStore`), so adding a
  feature in v1.x adds a *new optional* interface rather than a method to an existing one. This is
  the structural prerequisite that makes "no breaking change in v1.x" actually achievable. `L`
  - Conformance suites (`*/storetest`) stay, but split to match: a core suite + per-capability suites.
- [ ] **[BLOCK]** **Decide the multi-key-arg ergonomics now.** The `tenantID string` everywhere is a
  deliberate v1 choice — fine, but lock it. If a `context`-carried tenant or an opaque `Tenant` type
  is ever wanted, it must land *before* v1, not after. Document the decision in `architecture.md`. `S`
- [ ] **[WANT]** Add an `// Experimental:` convention + a documented list so a feature can ship in
  v1.x without being frozen. Without this, every new idea waits for v2. `S`
- [ ] **[WANT]** Wire **`apidiff` (golang.org/x/exp/cmd/apidiff)** into CI to fail any PR that breaks
  the v1 exported surface. The machine enforces the promise; humans forget it. `S`

---

## 1b. Per-tenant cryptographic isolation (maintainer v1 requirement)

> **Maintainer requirement (recorded):** in a multi-tenant deployment, **no two tenants may share
> cryptographic material.** Each tenant gets its own JWT signing keyset (its own JWKS), and — over time —
> its own of every other secret/cert/key the library uses. There must be a first-class, tenant-scoped
> **key store** that resolves this material per `tenantID`, plus explicit **provision-tenant** and
> **delete-tenant** workflows (creating a tenant must establish its keys; deleting one must purge them).
> This is a hard v1 requirement, not a nice-to-have.
>
> **Scope decision (recorded):** v1 ships the **contract + per-tenant JWT keyset + JWKS + tenant
> lifecycle + isolation tests** as `[BLOCK]`. Generalizing the store to *every* remaining secret (passkey
> cookie key, OAuth secrets, hashing peppers) is `[WANT-v1.x]` — **but the `KeyStore` contract must be
> designed on day one to absorb that tail without a breaking change** (this is exactly what §1's
> interface-segmentation discipline buys). And: if a deployment is **not multi-tenant, the zero-config
> single-keyset path is the better choice** and none of this applies — it stays the default.

**Why it's a real gap today:** all key material is currently **process-global**, not tenant-scoped.
`jwt.Config.SecretKey` / `SigningKeys` / `ActiveKeyID` are one keyset for the whole `Service[C]`, shared
across every tenant; `passkey.Config.CookieKey` is a single HMAC key for all tenants; OAuth client
secrets are per-provider, not isolated per tenant. So today a token minted for tenant A is signed with
the *same* key as tenant B's — a key compromise or a misconfigured verifier is a cross-tenant blast
radius, exactly the IDOR boundary the explicit `tenantID` philosophy exists to defend. Per-tenant keys
close that gap and make "rotate/revoke one tenant's keys" possible without touching the others.

This is an architectural addition that touches interfaces, so it **must land before the §1 freeze.**

### Core: a tenant-scoped key store
- [ ] **[BLOCK]** Define a `KeyStore` (working name) contract that resolves cryptographic material by
  `tenantID`, following the same `Service`/`Store` split as every other module. Minimum surface: `L`
  - `ActiveSigningKey(ctx, tenantID) (SigningKey, error)` — the current signing key (kid + secret) for minting.
  - `VerificationKeys(ctx, tenantID) ([]SigningKey, error)` — all currently-valid keys for verifying
    (active + overlapping-rotation keys), i.e. the inputs to that tenant's JWKS.
  - `RotateSigningKey(ctx, tenantID) (SigningKey, error)` — mint+activate a new key, keep the old as
    verify-only until its longest-lived token expires (the rotation model `jwt` already has, but per tenant).
  - `RetireExpiredKeys(ctx, tenantID) (int, error)` — GC reaper for keys past their verification window.
  - Tenant-scoped, like every other store: `""` is the single-tenant partition; `ErrTenantMismatch`
    guards record/argument mismatch.
- [ ] **[BLOCK]** **`jwt.Service[C]` resolves its keyset per request via the `KeyStore`** instead of the
  static `Config.SecretKey`/`SigningKeys`. `IssueTokenPair`/`Rotate`/`VerifyAccessToken` already carry
  enough context to know the tenant (claims/tenantID); the signer/verifier must select that tenant's
  keys. Keep the static single-keyset `Config` path as the **single-tenant / zero-config** mode (a
  trivial `KeyStore` backed by the configured key), so simple apps don't pay for the machinery. `L`
- [ ] **[BLOCK]** **Per-tenant JWKS.** Expose each tenant's public verification set so an external
  verifier (or another service) can validate that tenant's tokens. Two sub-decisions to make explicit: `M`
  - The JWKS is **per tenant** — the endpoint/route is tenant-scoped (`/.well-known/jwks.json` under the
    tenant, or a `JWKS(ctx, tenantID)` accessor the consumer mounts however they route tenants).
  - This is the point at which **asymmetric signing (RS256/EdDSA) likely becomes necessary** — a JWKS of
    *symmetric* HS256 keys would publish the signing secret, which is nonsensical. So §4's "asymmetric
    signing" item is **promoted from [WANT] to a dependency of this requirement**: a meaningful public
    per-tenant JWKS implies public-key crypto. Decide HS256-per-tenant (no public JWKS, keys never leave
    the server) vs asymmetric-per-tenant (publishable JWKS) — the maintainer requirement as stated
    ("dedicated JWKS per tenant") points at the asymmetric path.

### Core backends & at-rest protection (BLOCK)
- [ ] **[BLOCK]** **Backends, matching the rest of the library:** an in-memory `KeyStore` (core module,
  for tests/single-process) and an `adapters/pgx` `KeyStore` with `Migrate`. Secrets at rest in the pgx
  store must be **encrypted with a deployment-level KEK** (envelope encryption), not stored plaintext —
  otherwise per-tenant keys in one DB are no better than one shared key. Make the KEK a required config
  with the same fail-fast validation as `CookieKey`/`SecretKey`. `L`
- [ ] **[BLOCK]** **Per-tenant rotation & revocation that doesn't touch other tenants.** Rotating or
  revoking tenant A's keyset (e.g. on suspected compromise) invalidates only A's tokens. Add a
  `RevokeTenantKeys(ctx, tenantID)` path that composes with the existing refresh-family revocation. This
  is the operational *payoff* of per-tenant keys — a compromised tenant becomes a scoped incident, not a
  platform-wide logout. First-class and tested. `M`
- [ ] **[BLOCK]** **Conformance suite + cross-tenant isolation tests.** A `keystoretest` suite both
  backends run, plus an explicit adversarial test: a token minted under tenant A's key **must fail
  verification** when presented as tenant B (and vice-versa), and rotating A must not affect B. This is
  the test that proves the requirement actually holds. `M`

### Tenant lifecycle workflows (BLOCK)
Creating a tenant is implicit today (a row appears the first time you pass a new `tenantID`). With
per-tenant crypto that no longer works — a tenant with no keyset can't issue or verify anything, a
tenant whose keys/certs silently expire is a midnight outage, and a deleted tenant that leaves keys
behind is a security and compliance liability. So the full tenant lifecycle — **provision**, **renew**,
and **delete** — becomes a set of explicit, first-class, tested operations.

- [ ] **[BLOCK]** **Provision-tenant workflow.** A single entry point —
  `ProvisionTenant(ctx, tenantID, opts...)` — that generates and stores the tenant's initial signing
  keyset (and, as the [WANT-v1.x] tail lands, its other crypto material) under the KEK, idempotently
  (re-provisioning an existing tenant is a no-op, not a duplicate or an overwrite). Decide the trigger: `M`
  - **Explicit** (operator calls it at tenant creation) as the default, plus
  - **[WANT]** opt-in **lazy auto-provision** on first use, for apps that create tenants on the fly —
    gated behind a flag because silent key generation isn't always wanted.
  - Emit a `tenant.provisioned` `event.Sink` event; never log the key material.
- [ ] **[BLOCK]** **Delete-tenant workflow that purges everything.** A `DeleteTenant(ctx, tenantID)` (or
  `PurgeTenant`) that, in one auditable operation, removes **all** of that tenant's cryptographic
  material *and* all tenant-scoped records across every wired module — identity accounts/identities,
  tokens (refresh families + API keys), sessions, mfa enrollments + recovery codes, passkey credentials,
  otp challenges, verification tokens, **and the keyset itself**. Requirements: `L`
  - **Fan-out, like `identity.WithAccountErasers` but at tenant granularity:** a `TenantEraser` seam each
    module registers, so deleting a tenant cascades to every store without the core knowing about them all.
    Reuse the existing eraser pattern — don't invent a second one.
  - **Keys actually destroyed**, not soft-deleted: after delete, no token/cookie ever minted for that
    tenant can verify (the key is gone), which is the strongest possible revocation. Document whether a
    soft-delete/tombstone grace window is offered (for "undo"/compliance hold) vs immediate hard purge.
  - **Idempotent and resumable:** a delete interrupted halfway can be re-run to completion; partial state
    is never left verifiable. Order the cascade so the keyset goes last (or is tombstoned first) so a crash
    can't leave live data under a destroyed key in a confusing state.
  - Emit `tenant.deleted` with a summary count per module; this is the audit trail for a destructive op.
- [ ] **[BLOCK]** **Renew / refresh-tenant workflow.** Provision and delete are the bookends; **renew is
  the operation you run repeatedly over a tenant's life** — to roll a signing key on schedule, replace a
  cert before it expires, or re-key after a suspected exposure, *without* downtime and *without* touching
  other tenants. `RenewTenantKeys(ctx, tenantID, opts...)` (or per-material `RenewSigningKey` / `RenewCert`)
  that: `M`
  - mints a **new** active key/cert, marks it active for *new* issuance, and **keeps the previous one as
    verify-only** until the longest-lived token/credential signed by it expires — the overlapping-validity
    rotation `jwt` already models (kid-tagged), but driven as an explicit tenant operation rather than a
    static `Config` change. No valid in-flight token is invalidated by a renew (that's the difference from
    *revoke*, which is deliberate immediate invalidation).
  - **Renew vs rotate vs revoke — name and document the distinction**, because conflating them is how
    people cause outages: *renew/rotate* = add a new key, retire the old gracefully (no user impact);
    *revoke* = destroy a key now, invalidate everything signed by it (incident response). Expose both;
    don't make one masquerade as the other.
  - covers **certificates and expiring material**, not just symmetric keys — when the asymmetric/JWKS path
    (§4 / §1b) lands, renew rolls the keypair and the published JWKS reflects both old (verify) and new
    (active) until the overlap window closes, so external verifiers never see a gap.
  - **schedulable & driftable:** expose each key/cert's `NotAfter` (or a "needs renewal within N days"
    query) so an operator (or a `janitor`-style loop) can renew *before* expiry. A v1 must make "renew on
    a schedule" easy, because the failure mode of forgetting is a tenant-wide auth outage at midnight.
  - idempotent and event-emitting (`tenant.keys_renewed` with the old/new kid), never logging key material.
- [ ] **[BLOCK]** **Renewal isolation + continuity test:** renew tenant A's keyset; prove (a) tokens issued
  *before* the renew still verify during the overlap window, (b) new tokens use the new key, (c) after the
  overlap + retire, the old key is gone, and (d) tenant B is untouched throughout. This proves renew is
  zero-downtime and scoped.
- [ ] **[BLOCK]** **Lifecycle isolation test:** provision A and B, prove they have distinct keysets;
  delete A and prove (a) all of A's records and keys are gone, (b) **B is completely unaffected** — B's
  tokens still verify, B's data intact. This is the test that proves delete is scoped and complete.

### Generalize to all remaining crypto material (WANT — v1.x, but contract-compatible now)
Deferred past v1.0 **provided the `KeyStore` contract is shaped to absorb these without a break.** Each
is the same pattern as the JWT keyset, applied to another secret:
- [ ] **[WANT-v1.x]** **Passkey ceremony cookie key per tenant.** `passkey.Config.CookieKey` becomes a
  per-tenant lookup through the `KeyStore` (or a passkey-specific sibling). A ceremony cookie signed for
  tenant A must not validate under tenant B. `M`
- [ ] **[WANT-v1.x]** **Route every other long-lived secret through the tenant key store** (or document
  why it's legitimately global). Candidates: OAuth client secrets (per tenant + per provider for
  multi-tenant SSO — align with the existing `oauth.ProviderStore`), OTP/verification-token hashing
  peppers, any API-key/session HMAC pepper. Deliverable: a **complete inventory** of cryptographic
  material, each item marked *tenant-scoped* or *intentionally global*. Do the **inventory now** (cheap,
  informs the contract shape); defer the *migration* of each item to v1.x. `M`
- [ ] **[WANT]** **Caching with bounded TTL** in `jwt.Service` so per-request key resolution doesn't hit
  the store on every verify (ties into §8 performance). Invalidate on rotation/revocation. `M`

> Scope note: even split, this is the single largest *feature* on the road to v1 and it cuts across
> `tokens`, the new key store, `adapters/pgx`, and every module's tenant-erase seam. Because it changes
> interfaces (the `KeyStore` contract, the `jwt.Service` key-resolution path, the per-module `TenantEraser`)
> the **contract + lifecycle is a §1-freeze prerequisite** — get the *shape* in before locking the API or
> it forces a v2, even if the [WANT-v1.x] generalization lands later. The single-keyset `Config` path stays
> as the zero-config single-tenant mode so the common (non-multi-tenant) case isn't burdened at all.

---

## 2. The Actor ↔ context seam (highest-impact ergonomic gap)

This is the one place the library forced *me* to write security-critical glue it should own.

- [ ] **[BLOCK]** Ship an official **Actor/claims-in-context bridge** in `tokens`. Today
  `RequireAuth[C]` passes `Actor`+claims as *function arguments* and there is **no
  `tokens.ClaimsFromContext`** — yet `mfa`, `passkey`, and `otp` handlers all need a
  `WithUserResolver(func(*http.Request) -> (uuid, tenant, ok))`. Every consumer that combines
  tokens with a second module must hand-roll the same `RequireAuth -> r.Context() -> resolver`
  adapter. That is exactly the kind of code a security library should not make people reinvent. `M`
  - Add `tokens.ContextMiddleware[C]` (verifies, injects `Actor`+`Claims[C]` into `r.Context()`,
    chains a standard `http.Handler`) plus `tokens.ActorFromContext(ctx)` / `ClaimsFromContext[C](ctx)`.
  - Provide a ready-made `tokens.UserResolverFromContext` matching the `mfa`/`passkey`/`otp`
    `WithUserResolver` signature, so the cross-module wiring is a one-liner.
- [ ] **[BLOCK]** **Fix `recipes.md`** — the MFA recipe currently calls
  `tokens.ClaimsFromContext(r.Context())`, **a function that does not exist**. Either the helper
  above makes it real, or the recipe is corrected. A copy-paste recipe that references a phantom
  function is a documentation bug in the most-copied file. `S`

---

## 3. Secure-by-default for the remaining consumer-responsibility seams

v0.3.0 made passkey and mfa secure-by-default. The same principle should reach the seams a consumer
can still silently get wrong, each with a security consequence. The rule: **dangerous seams are
secure-by-default with a loud opt-out, not safe-only-if-you-remember-to-opt-in.**

- [ ] **[BLOCK]** **CSRF origin check on by default for cookie-bearing POST handlers.** Today
  `WithTrustedOrigins` is opt-in and disabled by default, so `RefreshHandler`/`LogoutHandler` mounted
  on cookies ship with **no CSRF protection unless the caller remembers**. Options (pick one and
  document it): (a) enable same-origin check by default when cookie auth is configured, with an
  explicit `WithInsecureNoOriginCheck()` opt-out; or (b) fail-fast at handler construction if a
  cookie handler is built without trusted origins. `M`
- [ ] **[BLOCK]** **Guard `Insecure` cookies against production misuse.** `WithInsecureCookies()` is
  required for local http dev but nothing stops it reaching prod. Emit a startup `event.Sink` warning
  (or refuse) when `Insecure=true` and the host is not `localhost`/loopback. `S`
- [ ] **[WANT]** Make the **in-memory store unbounded-growth** footgun harder to hit. `sessions/memory`,
  `otp/memory`, `ratelimit.TokenBucket` grow without bound unless the consumer schedules `janitor`
  eviction (documented, but easy to forget). Ship a bounded variant or have the memory stores
  self-evict on a configurable cap by default. `M`

---

## 4. Module completeness & feature gaps

Per-module review of what a "complete" v1 needs. Most modules are feature-complete; these are the
holes I'd want closed (or explicitly declared out-of-scope) before freezing the API.

### tokens
- [ ] **[BLOCK-if-public-JWKS]** First-class **asymmetric signing (RS256/EdDSA)** alongside HS256.
  Today it's HS256-only (alg-pinned, which is correct), fine for server-side verify. **But the §1b
  per-tenant JWKS requirement promotes this from optional to a dependency:** a *publishable* per-tenant
  JWKS implies public-key crypto (you cannot publish a symmetric secret). So this is `[BLOCK]` **iff**
  §1b's JWKS is meant to be externally consumable; it stays `[WANT]` only if §1b chooses the
  HS256-per-tenant / keys-never-leave-the-server path. Resolve this alongside §1b, not separately. `L`
- [ ] **[WANT→tied-to-§1b]** A documented **per-tenant JWKS endpoint helper** (`JWKS(ctx, tenantID)` +
  a mountable `/.well-known/jwks.json` handler scoped to the tenant). Lands with §1b. `M`

### sessions
- [ ] **[WANT]** Confirm the `sessions` ↔ `identity.WithAccountErasers` revocation fan-out is wired and
  tested end-to-end (disable/delete must kill live sessions). Add an integration test proving it. `S`

### oauth
- [ ] **[BLOCK-IF-SHIPPED]** The 12 built-in providers are a large public surface. Either (a) commit
  to keeping them in core and freeze their constructors for v1, or (b) move `oauth/providers` to its
  own module so provider churn doesn't force core minor bumps. Decide before freeze. `M`

### passkey
- [ ] **[WANT]** Export a **test software-authenticator** (`passkeytest.NewSoftAuthenticator`). The
  ES256 "none"-attestation soft authenticator already exists in the internal test suite
  (`passkey/authenticator_test.go`); consumers integration-testing their passkey wiring currently
  have to re-vendor ~200 lines of it. Exporting it would save every integrator hours and is the
  single biggest passkey ergonomics win. `S`
- [ ] **[WANT]** A runnable **end-to-end HTTP example** of the full begin→`navigator.credentials`→
  finish flow for both registration and login. Signatures alone are not enough for WebAuthn. `M`

### otp / identity
- [ ] **[WANT]** None blocking — these are feature-complete. Confirm the enumeration-safe invariants
  (uniform 204 on `Request*`, 401-collapse on verify) are covered by tests that would fail if a
  future change leaked existence. `S`

---

## 5. Documentation & onboarding

The `.llms/` docs are the project's best asset and are excellent — keep them. The gaps are around
*getting started* and *examples that actually run*.

- [ ] **[BLOCK]** **A clean, verified `go get` story.** Today `go.mod` references a retracted
  lineage (`v0.1–v0.2.1` retracted) and the pgx adapter is consumed as a pseudo-version. Publish
  aligned, non-retracted tags for **core and the pgx adapter together** (same version), and put the
  exact, tested `go get` commands in `llms.txt` and the README. A new user (or agent) must not get a
  retracted version from a copy-pasted install line. `S`
- [ ] **[BLOCK]** **One runnable reference application** in `examples/` (or linked) that wires a real
  multi-module stack — identity + tokens(custom claims) + mfa + passkey + admin + audit — over HTTP,
  building from the proxy with no local workspace. Proves the recipes compose and gives integrators
  a copy-paste starting point. (This very demo repo is a candidate seed.) `M`
- [ ] **[WANT]** Per-module **runnable `Example` tests** (`go test ./... -run Example`) for the
  login-critical paths, so the docs' snippets are compiler-verified, not prose. `M`
- [ ] **[WANT]** A **migration guide** section in the CHANGELOG for every breaking change, in the
  style of the v0.3.0 entry (which is good). Make it the required format. `S`

---

## 6. Observability, operations, supply chain

- [ ] **[BLOCK]** **Reference metrics/tracing adapter.** SECURITY.md states no first-party metrics or
  tracing ship today (wire your own to `event.Sink`). For v1, ship at least one reference adapter
  (Prometheus counters or OpenTelemetry spans over the existing `event.Sink`/`context`) so production
  observability isn't a from-scratch task. The seam exists; the reference impl doesn't. `M`
- [ ] **[BLOCK]** **Request-level idempotency guidance** (or a helper). Declared a consumer
  responsibility today; for v1 at least document the recommended pattern for the mutating handlers,
  ideally with a small optional middleware. `S`
- [ ] **[WANT]** **Supply-chain hardening for release:** signed tags, `go.sum`/`vuln` gating
  (`govulncheck` in CI), SBOM, and a documented release checklist (RELEASING.md exists — fold these
  in). `M`
- [ ] **[WANT]** **Fuzzing in CI** for the parsers on the attack surface (JWT decode, WebAuthn
  attestation/assertion decode, OTP/verification-token parsing). A `passkey/fuzz_test.go` already
  exists — extend the pattern and run it in CI with a corpus. `M`

---

## 7. Go-version policy decision

- [ ] **[BLOCK]** **Lock the Go-support policy for v1.** Today the floor tracks the newest major Go
  release and is bumped deliberately (`go 1.26`), which is greenfield-only by design. That is a
  legitimate choice — but for a v1 with a stability promise, decide and document whether the floor
  can move *within* v1.x (a `go.mod` `go` bump is arguably a breaking change for some consumers) or
  is pinned for the life of v1. Either answer is fine; the ambiguity is not. `S`

---

## 8. Performance & efficiency

None of these block v1, but a v1 is the right moment to bake in measurement and shed avoidable cost.
The theme: **auth sits on the hot path of every request — its overhead and its DoS resistance are
features.**

- [ ] **[WANT]** **Publish a benchmark suite + numbers.** Add `Benchmark*` for the per-request hot
  paths (access-token verify, cookie parse, `RequireAuth` middleware, session `Touch`) and the
  expensive-by-design paths (Argon2id hash, refresh rotation incl. store round-trips). Track them in
  CI to catch regressions and give consumers a latency budget. You can't tune what you don't measure. `M`
- [ ] **[WANT]** **Make Argon2id cost tunable and documented, with a calibration helper.** Hashing is
  intentionally expensive; the right cost depends on the deployment's CPU. Expose the params (time,
  memory, parallelism) as first-class `argon2` options (if not already) and ship a
  `argon2.Calibrate(targetDuration)` helper so operators pick a cost matched to their hardware instead
  of guessing. Pair it with the pre-auth body cap (already present) as the documented anti-hashing-DoS
  story. `M`
- [ ] **[WANT]** **Access-token verify allocation audit.** The JWT verify path runs on every
  authenticated request; profile it for needless allocations (claims structs, signature buffers,
  base64 decodes) and pool/​reuse where safe. A few hundred ns and zero-alloc verify is achievable and
  worth it at scale. `S`
- [ ] **[WANT]** **Batch / single-round-trip store methods where the protocol allows.** Rotation today
  is find→consume→save; check whether the pgx store can collapse these into one statement (CTE /
  `UPDATE ... RETURNING`) to halve the DB round-trips on the refresh hot path. Add the method to the
  capability interface, not the core, so it stays optional. `M`
- [ ] **[WANT]** **Constant-time everywhere it matters, asserted by test.** The compares on the
  security path (verifier hashes, recovery codes, API keys, OTP) should all be constant-time
  (`subtle.ConstantTimeCompare`); add a lint/grep test that fails if a `==` or `bytes.Equal` sneaks
  into a secret-comparison path. Cheap insurance against a timing-leak regression. `S`
- [ ] **[WANT]** **Bounded, sharded in-memory stores.** Beyond the unbounded-growth footgun (§3), the
  memory stores use coarse locking; for the single-process deployments they target, a sharded map (or
  `sync.Map` where appropriate) removes a contention point under load. Only worth it once the
  benchmarks justify it. `M`

---

## 9. Opinionated choices you *could* make (flagged, with the trade-off)

You want egauth non-opinionated — that is a legitimate, deliberate stance. But "non-opinionated" should
be a **choice per seam**, not a blanket default that quietly leaves the consumer holding a security-
critical decision. This section is a catalogue of opinions you *could* adopt to make the library safer
and easier, **each one optional**. For every item the pattern is the same and is the key idea of this
whole file:

> **Be opinionated about the secure default; stay non-opinionated about the override.**
> i.e. pick the safe behavior by default, and expose a *loud, greppable, explicit* opt-out
> (`WithInsecureX()`, `InsecureNoY: true`) for the consumer who genuinely needs the other path.
> v0.3.0 already did exactly this for passkey UV + challenge store + cookie key — extend the pattern.

Each item below is a **stance you can take**, not a mandate. Adopt, defer, or reject — but decide
consciously and record the decision (a short ADR or a line in `architecture.md`), so "non-opinionated"
is documented intent rather than an unfilled gap.

### Safety defaults you could flip to secure-by-default
- [ ] **CSRF origin check ON by default** for cookie-bearing handlers (also in §3). *Opinion:* a cookie
  auth handler with no CSRF protection is almost never what someone wants. *Opt-out:*
  `WithInsecureNoOriginCheck()`. *Trade-off:* breaks pure-API callers who set `Origin` oddly — hence
  the explicit opt-out. **Recommended.**
- [ ] **Refuse `Insecure` cookies on non-loopback hosts** unless `WithInsecureCookies()` is paired with
  an explicit `WithInsecureCookiesOnPublicHost()` acknowledgement. *Opinion:* shipping `Secure`-off to
  prod is a bug, not a config. *Trade-off:* a tiny bit more friction for reverse-proxy-terminated TLS
  setups where the app sees http — document that case. **Recommended.**
- [ ] **MFA/step-up required for sensitive self-service actions by default** (disable-MFA, change-email,
  delete-account, regenerate-recovery-codes). *Opinion:* a hijacked session shouldn't be able to strip
  the second factor. The pieces exist (`WithMaxAuthAge`, `FreshAuth`, AMR) — make the *handlers* gate
  these actions by default rather than relying on the consumer to remember. *Opt-out:* an explicit
  `WithoutStepUp()`. *Trade-off:* more re-auth prompts; some apps won't want it — opt-out covers them.
  **Strongly recommended — this is a real account-takeover hole if forgotten.**
- [ ] **Breach check (HIBP/offline) wired into the default password policy.** *Opinion:* rejecting known-
  breached passwords is table stakes in 2026. *Current:* it's an optional seam the consumer must wire.
  *Opt-out:* `WithoutBreachCheck()` (offline list as the zero-dependency default; HIBP as an upgrade).
  *Trade-off:* offline list size, or an outbound call for HIBP (k-anonymity, already SSRF-guarded).
  **Recommended (offline default).**
- [ ] **Generic-failure login responses by default** (already enumeration-safe) — keep, and add a test
  that *fails the build* if any handler ever returns a status/body that distinguishes "no such user"
  from "wrong password". *Opinion:* this invariant is too important to leave to code review. **Recommended.**

### Sensible defaults you could *pick* (instead of forcing the consumer to choose)
- [ ] **Ship a "batteries-included" preset constructor** — e.g. `egauth.NewWebApp(cfg)` that wires
  identity + tokens(+claims) + the secure-cookie/CSRF/step-up defaults above into a mounted `http.Handler`,
  for the 80% web-app case. *Opinion:* the à-la-carte model is great for power users and a cliff for
  newcomers; a blessed preset that *uses the same public API underneath* gives both. *Trade-off:* a
  second, higher-level surface to maintain and freeze. Keep it thin — it should be a documented
  composition of the existing pieces, nothing private. **Recommended, clearly labeled as a convenience layer.**
- [ ] **Default token TTLs** (e.g. access 15m / refresh 30d) as the zero-value, overridable. *Opinion:*
  most people want sane defaults, not a required decision. *Trade-off:* none real — it's just a default.
  **Recommended.**
- [ ] **Default `ReuseGracePeriod`** is already 10s — good; document *why* and when to set it negative
  (strict). Keep the default, make the reasoning prominent. **Keep.**
- [ ] **A recommended `event.Sink` wiring** (the slog sink) mounted by the preset, so security events go
  *somewhere* by default instead of silently to nil. *Opinion:* silent auth is un-auditable auth.
  **Recommended within the preset.**

### Opinions to *resist* (flagging them so the non-opinionated stance is deliberate, not accidental)
- [ ] **Do NOT** bundle a router, a mailer/SMS transport, an ORM, or a config framework. These are the
  right things to stay non-opinionated about — they're where consumers have strong, legitimate, varied
  preferences, and coupling to them is what makes auth libraries painful. Keep these as seams forever.
  *Record this as an explicit, permanent design boundary in `architecture.md`* so it reads as a decision,
  not an omission.
- [ ] **Do NOT** hide `tenantID` behind the context by default. It's verbose on purpose — that visibility
  *is* the IDOR defense. Keep it explicit. (Offer a context helper as opt-in only, never the default.)

The meta-point: a v1 should be able to say, for every security-relevant default, **"we chose this
default deliberately, here's the opt-out, here's why."** Right now several defaults (CSRF, insecure
cookies, step-up on sensitive actions) are *absent* rather than *chosen* — turning them into conscious,
documented opinions (secure default + loud opt-out) is the single biggest safety upgrade available
without abandoning the à-la-carte philosophy.

---

## Cut-line summary

**v1 is blocked until:** the un-audited status is disclosed prominently and build-enforced against
erosion (§0 — the audit itself is an accepted-risk deferral, the *disclosure* is the gate);
**per-tenant cryptographic isolation lands — a tenant-scoped key store so no two tenants share a JWKS
or signing keyset, the full tenant lifecycle (provision / renew / delete) with graceful key rotation and
complete purge-on-delete, and cross-tenant isolation + continuity tests (§1b core; generalizing to every
remaining secret is a contract-compatible v1.x tail)** — and because it changes interfaces it must
precede the freeze; the exported API + Store interfaces are
frozen and apidiff-gated (§1); the Actor↔context seam ships and the phantom-function recipe is fixed
(§2); CSRF/insecure-cookie defaults are made safe-by-default (§3); the `go get` story is clean and one
runnable reference app exists (§5); a reference observability adapter ships (§6); and the Go-version
policy is locked (§7).

**Everything tagged [WANT]** — including all of §8 (performance) and §9 (opinionated defaults) — can
ship in v1.1+ *provided* it doesn't require a breaking change. That proviso is why §1 (interface
segmentation + experimental markers) must come first: get the surface right, and every safety default
in §9 can be added later as a *default change behind an explicit opt-out* rather than a v2 break.

**On the non-opinionated philosophy (§9):** keep it — but make each default a *decision*. Before v1,
walk the §9 list and, for every security-relevant seam, either adopt the secure-by-default + loud-opt-out
pattern or record an explicit "intentionally left to the consumer" note. The three I would not ship v1
without consciously deciding: **CSRF-on-by-default, insecure-cookie guard, and step-up on sensitive
self-service actions** — absent today, and each one a real account-takeover footgun if a consumer forgets.

The honest one-liner: egauth is **exceptionally well-designed and documented for its age** — the work
left is not redesign, it's **freeze the surface, disclose the un-audited status honestly and durably,
own the two or three security-critical seams currently left to the consumer, and turn the remaining
absent-by-default safety behaviors into deliberate secure-by-default choices with explicit opt-outs.**
The engineering is there; v1 is about contract, conscious defaults, and earned trust through honesty —
not features. Shipping pre-audit is a legitimate choice; shipping it *quietly* would not be — so the
disclosure carries the weight the audit otherwise would.
