# architecture — design model & conventions

module: `github.com/JLugagne/egauth` (Go 1.26+)
root package exports only `Actor` (see [infra.md](infra.md)). All behavior lives in sub-packages.

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

## Security posture (summary)

Secure-by-default: Argon2id hashing, enumeration-safe auth paths (uniform responses + decoy hashing),
brute-force lockout, single-use selector/verifier tokens, refresh-token rotation with family-based
theft detection, HS256-pinned JWTs (reject `none`/alg-confusion), SHA-256-only storage of
refresh/API/session/OTP secrets, secure-by-default cookies, pre-auth body caps against hashing-DoS,
secret redaction on `fmt`/`slog`, SSRF guard on outbound OAuth/OIDC calls.

Consumer responsibilities (NOT provided by egauth): CSRF tokens (origin check available via
`WithTrustedOrigins`), rate-limit policy, mail/SMS transport, metrics/tracing, request idempotency.

Full threat model + explicit trade-offs: `SECURITY.md`.
NOTE: security review to date is an AI-driven audit, not an independent third-party human audit (pre-1.0).
