# architecture — design model & conventions

module: `github.com/JLugagne/egauth` (Go 1.26+)
root package exports only `Actor` (see [infra.md](infra.md)). All behavior lives in sub-packages.

## Go version support policy

- **For v1.x and later**: The `go.mod` `go` directive is **pinned for the life of the major version**.
  v1.0 through v1.x will all use `go 1.26` as the minimum toolchain. Bumping to a newer major Go
  release is deferred to v2, ensuring maximum build compatibility within v1. This is a stability
  guarantee for consumers building against v1.x.
  
- **Pre-v1 releases**: egauth targets the newest major Go release as its minimum toolchain and bumps
  deliberately with each new major Go version. This allows pre-v1 development to track the cutting
  edge. If you need support for an older Go version, pin an earlier egauth release.

## Model: à-la-carte, not a framework

egauth is a set of independent modules in the style of `database/sql`: import the ones you need,
wire them with dependency injection. egauth NEVER owns your HTTP router, DB access, mail/SMS
transport, or conventions. There is no top-level constructor that bundles everything — that is
deliberate. You compose exactly the stack you need.

## The Service / Store split (every module)

Each module follows the same shape:

- **`Service` interface** — the business logic (e.g. `identity.Service`, `sessions.Service`).
  Constructed with `NewService(store, deps..., opts...)`. Functional-options DI (`WithX(...)`).
- **`Store` contract** — persistence interface the Service depends on. Two interchangeable impls:
  - `<module>/memory` — zero-dependency, in core module, for tests / single-process apps.
  - `adapters/pgx/<module>` — PostgreSQL via jackc/pgx, in a **separate module** (see [storage-pgx.md](storage-pgx.md)).
- **`SingleTenant` facade** — `NewSingleTenant(svc)` wraps a Service and hard-wires `tenantID=""`,
  dropping the tenant argument from every call. Exists on identity, sessions, mfa, otp, passkey,
  tokens/jwt. `.Service()` is the escape hatch back to the multi-tenant Service.
- **HTTP handlers** — à-la-carte `http.HandlerFunc` factories (e.g. `identity.LoginHandler(...)`)
  you mount on your own mux. egauth imposes no router. Form-encoded bodies, configurable via
  `HandlerOption`s. Most are POST-only (405 otherwise) with a pre-auth body cap (default 4 KiB).

`tokens` is generic over a custom-claims type `C` (`Issuer[C]`, `Claims[C]`, ...). The `tokens/basic`
facade specializes everything to `C=struct{}` so the common no-custom-claims case never spells the
type argument. See [tokens.md](tokens.md).

## Multi-tenancy (explicit & pervasive)

Every tenant-scoped Store and Service method takes an explicit `tenantID string`. Empty string `""`
is the valid **single-tenant default partition** — passing it explicitly keeps the tenant boundary
visible at every call site (the defense against cross-tenant access / IDOR). Single-tenant apps use
a `SingleTenant` facade to drop the argument. `ErrTenantMismatch` guards record/argument mismatch.

## Conformance test suites (for Store/Service implementers)

Cross-backend behavior is locked by shared suites — memory and pgx both run them, and external
implementers MUST run them on upgrade (Store interfaces are monolithic for v0.x and may gain
methods in minor releases):

- `identity/storetest`, `identity/servicetest`
- `sessions/storetest`, `mfa/storetest`, `otp/storetest`, `passkey/storetest`
- `tokens/issuertest`
- `passwords/hashertest`

## Cross-cutting seams (bring-your-own)

- `identity.Mailer` / `identity.SMSSender` — delivery; egauth never sends mail/SMS itself.
- `event.Sink` — security/audit events; nil = no-op. `event.NewSlogSink` for the slog case.
- `ratelimit.Limiter` — throttling; `TokenBucket` reference + middleware.
- `health.Pinger` — readiness; pgx stores implement it.
- `janitor.Start(ctx, interval, fn)` — periodic eviction loop for in-memory stores.
- `passwords.Hasher` / `passwords.Policy` / `passwords.BreachChecker` — pluggable; argon2/policy/hibp references.

See [infra.md](infra.md), [passwords.md](passwords.md).

## Composition graph (who pairs with whom)

- **Credential verification** = `identity` (manages accounts; does NOT issue tokens/sessions).
- **Issue auth state** = `tokens` (stateless JWT + refresh) OR `sessions` (server-side, revocable). Pick one.
- **Social login** = `oauth` (+ `oauth/providers`) → `identity.LinkOrCreateIdentity` (JIT) → tokens/sessions.
- **Second factor** = `mfa` (TOTP), `passkey` (WebAuthn, can also be a primary/passwordless factor),
  `otp` (email/SMS one-time codes, also usable as passwordless primary).
- **Step-up** = `tokens` carries `AuthTime`/`AMR`; `Claims.FreshAuth(maxAge)` gates sensitive ops.
- **Account deletion fan-out** = `identity.WithAccountErasers(...)` runs cross-module revocation hooks before soft-delete.
- **Forced password change (temporary credentials)** = `identity.AdminCreateUser` / `identity.SetTemporaryPassword`
  flag a credential for a forced change at next login; the flagged user receives a full, renewable pair carrying
  `tokens.Claims.MustChangePassword=true`. The flag is recorded on the refresh-token family and `Rotate` replays it
  onto every silent refresh, so `tokens.WithPasswordChangeGate` keeps soft-redirecting every protected route to the
  reset page until the password is changed — a user cannot escape by waiting for the access token to expire. The
  credential stays valid — never a lockout. egauth does NOT do age-based/periodic rotation (NIST SP 800-63B
  discourages fixed-interval expiry). See [tokens.md](tokens.md) for the gate middleware and SECURITY.md for the
  full policy description.

See [recipes.md](recipes.md) for concrete wiring of each stack.

## Storage backends

- core module ships every `<module>/memory` store + `ratelimit.TokenBucket` (in-memory, self-bounding
  or janitor-evicted — see below).
- `adapters/pgx` is a separate go.mod so core consumers never pull pgx/testcontainers/Docker.
  `Migrate(ctx, pool)` once at startup (forward-only, versioned, idempotent). [storage-pgx.md](storage-pgx.md).

### In-memory store growth control

All three in-process stores that can grow without bound ship a **bounded variant** alongside the
original unbounded constructor:

| Package | Unbounded (original) | Bounded (new) | Cap policy |
|---|---|---|---|
| `sessions/memory` | `NewStore()` | `NewBoundedStore(n)` | evicts expired first, then soonest-expiring |
| `otp/memory` | `NewStore()` | `NewBoundedStore(n)` | evicts expired first, then soonest-expiring |
| `ratelimit` | `NewTokenBucket(…)` | `NewTokenBucket(…, WithMaxKeys(n))` | evicts most-refilled (least-pressure) bucket |

The unbounded constructors remain available for callers that prefer to schedule periodic eviction
via `janitor`. Both models are safe for concurrent use. The bounded variants require no external
scheduler and are recommended for Internet-facing deployments where key cardinality is unbounded.

## Module placement decisions (v1 API freeze)

### oauth/providers — keep in core module (decided 2026-06-15)

The 12 built-in OAuth providers (`apple`, `auth0`, `cognito`, `discord`, `facebook`, `github`,
`gitlab`, `google`, `keycloak`, `linkedin`, `microsoft`, `okta`) live in `oauth/providers` inside
the core `github.com/JLugagne/egauth` module, not in a separate module.

Rationale:
- Provider constructors are already stable and in active use (reference app, docs examples).
- Moving to a separate module before v1 would be a breaking import-path change for any existing
  consumer, which is worse than the status quo.
- Provider churn in v1.x can be absorbed by additive changes (new constructors, not changed ones).
  A provider signature never needs to change — only new providers are added.
- A separate module for providers would add go.mod/go.sum overhead with no real isolation benefit:
  providers import `oauth` core anyway, so the dependency graph is unchanged.

Trade-off accepted: `oauth/providers` is part of the v1 public API surface and is frozen under
SemVer. Breaking a provider constructor requires a v2. This is the accepted cost of keeping the
DX simple.

### passkey/passkeytest — test-helper package in core module (decided 2026-06-15)

`passkey/passkeytest` (package `passkeytest`) exports `SoftAuthenticator`, a minimal software
WebAuthn authenticator for integration testing. It lives in the core module rather than a separate
module because:
- It has no additional dependencies beyond what `passkey` itself imports.
- It mirrors the established pattern of `identity/servicetest`, `identity/storetest`, `mfa/storetest`,
  etc., which all live in the core module.
- A separate test-helper module would add friction with no benefit.

## Principal / Actor classification (M8)

Every authenticated request in egauth is represented by an `egauth.Actor`. The `Actor.Kind`
field (`egauth.PrincipalKind`) lets the application know — without inspecting token internals —
whether the request comes from a human or a machine:

| Kind | Value | `IsHuman()` | `IsMachine()` | Subject |
|---|---|---|---|---|
| `User` | `"user"` | true | false | `Actor.UserID` (the account UUID) |
| `PAT` | `"pat"` | true | false | `Actor.UserID` (the owning user) + `Actor.KeyID` (the key UUID) |
| `Service` | `"service"` | false | true | `Actor.KeyID` (the key's own UUID; `UserID` is zero) |

Zero-value `Kind` (`""`) is treated as `User` by both helpers, so a zero-value `Actor` (e.g. in
tests that do not set `Kind`) is always safe.

`Actor.Scopes` carries the permission scopes verbatim from the token. egauth never interprets or
enforces scopes — that is deliberately left to application middleware (e.g.
`tokens.WithRequiredScopes`). See [infra.md](infra.md) for the full `Actor` signature and API key
type constants.

**Minting API keys.** `tokens.Issuer.IssueAPIKey(ctx, prefix, keyType, createdBy, claims)` issues
an opaque API key. `keyType` is `tokens.KeyTypePAT` or `tokens.KeyTypeService`; `createdBy` is the
UUID of the human user performing the action (recorded in the `api_key.created` audit event). The
resulting `Actor.Kind` at verification time mirrors the stored `keyType`.

## Security posture (summary)

Secure-by-default: Argon2id hashing, enumeration-safe auth paths (uniform responses + decoy hashing),
brute-force lockout, single-use selector/verifier tokens, refresh-token rotation with family-based
theft detection, per-kid alg-pinned JWTs (symmetric HS256 or asymmetric RS256/ES256/EdDSA; reject `none`/alg-confusion), SHA-256-only storage of
refresh/API/session/OTP secrets, secure-by-default cookies, pre-auth body caps against hashing-DoS,
secret redaction on `fmt`/`slog`, SSRF guard on outbound OAuth/OIDC calls.

**Forced-password-change for temporary credentials.** `identity.AdminCreateUser` and
`identity.SetTemporaryPassword` provision a credential flagged for a forced change at next login
(admin-created accounts, admin-issued one-time passwords). A flagged login issues a full, renewable
pair carrying `tokens.Claims.MustChangePassword=true`; the flag is recorded on the refresh-token
family and `Rotate` replays it onto every silent refresh (overriding the `ClaimsProvider`), so the
flag cannot be dropped by refreshing. `tokens.WithPasswordChangeGate` enforces the gate generically
in the `RequireAuth` middleware. Forcing a change on a user's *existing* sessions is an explicit
admin action (revoke their token families, e.g. via `SetTemporaryPassword`'s erasers). egauth
deliberately does NOT force periodic, age-based rotation (NIST SP 800-63B discourages fixed-interval
expiry). Zero behavior change unless a credential is explicitly flagged.

Consumer responsibilities (NOT provided by egauth): CSRF tokens (origin check available via
`WithTrustedOrigins`), rate-limit policy, mail/SMS transport, metrics/tracing, request idempotency.

Full threat model + explicit trade-offs: `SECURITY.md`.
NOTE: security review to date is an AI-driven audit, not an independent third-party human audit (pre-1.0).
