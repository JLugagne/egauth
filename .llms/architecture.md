# Architecture

egauth v0.17 is one composition object plus a route builder. Read this first.

## Shape

- `egauth.New(cfg)` validates an `egauth.Config[C]` and returns an `egauth.Auth[C]`. `C` is the type of the application's custom claims; use `struct{}` for none.
- `Auth` owns every policy object, store handle and background worker until `Auth.Close`. It is safe for concurrent use. One of each, never exported.
- `Auth.Routes()` returns the deny-by-default route builder. `Build` returns the one `http.Handler` to serve at the server root.
- Handlers receive an `egauth.Principal` as an argument. There is no context accessor for it.
- Application code reaches administration through facades that check authorization themselves: `Auth.Accounts`, `Auth.Tenants`, `Auth.APIKeys`, and `Auth.System` for background work.

## Packages

| Package | Role |
|---|---|
| `egauth` | `New`, `Config`, `Auth`, `Routes`, `Principal`, facades, delivery messages, opt-outs |
| `memstore` | in-memory `egauth.Storage` for tests and development |
| `adapters/pgx/pgxstore` | PostgreSQL `egauth.Storage`, `Migrate` (separate module) |
| `adapters/otel` | OpenTelemetry event sink (separate module) |
| `kek` | key-encryption keys; associated data is mandatory on every seal and open |
| `signing` | `signing.Signer`, `signing.Verifier`, JWKS encoding and parsing |
| `principal` | `principal.Subject`, `principal.Caller`, `principal.TenantID`, `principal.Factor`, `principal.SessionAttrs` |
| `event` | `event.Sink`, `event.Event`, event types, slog sink |
| `passwords` | hashing, policy and breach-check seams; references in `passwords/argon2`, `passwords/policy`, `passwords/breach/hibp` |
| `federation` | `federation.Provider` specs; built-ins in `federation/providers` |
| `store/*` | store contracts (identity, ceremony, deployment, limiter, tokens, sessions, mfa, passkey, federation, keys) with `memory` implementations and `storetest` suites |
| `egauthtest`, `webauthntest` | test doubles |

Everything under `internal/` is unreachable from applications and adapters.

## Why misuse is hard

1. Cookies, issuers, sinks, limiters and gates are not parameters of anything an application calls.
2. `New` checks the whole wiring and returns all problems joined. See `config.md`.
3. Routes are declared through four verbs, and every undeclared request is 404. See `routes.md`.
4. A login produces sealed `principal.SessionAttrs` once; renewal only strengthens it. See `sessions.md`.
5. Opt-outs are fields of `egauth.InsecureOptOuts` with a reason, listed by `Auth.Posture`.
6. CI guards (G1 to G29, see CONTRIBUTING.md) reject changes that reopen these.

## Layering

Contracts (`store/*`, `kek`, `signing`, `principal`, `event`) import nothing above them. `internal/*` services sit on the contracts. The root package composes services. Adapters implement contracts and never import core `internal/`.

## Multi-tenancy

`egauth.Config.Tenancy` is `egauth.SingleTenant()`, `egauth.TenantBySubdomain()` (the public origin holds one `{tenant}` host label) or `egauth.TenantFromRequest(resolver)`. A request whose tenant cannot be resolved is 401, with no fallback. Credentials are bound to their tenant: a handle sealed for tenant A is refused under tenant B.

## Errors

`egauth.New` returns `egauth.ConfigError` values joined. Facades return `egauth.ErrForbidden`, `egauth.ErrTenantMismatch`, `egauth.ErrReauthRequired`, `egauth.ErrAPIKeyCaller`, `egauth.ErrResourceTokenCaller`, `egauth.ErrSessionEnded` and `store.ErrNotFound` for the cases an application maps to statuses. Endpoints answer JSON `{"error": "<code>"}`.
