# egauth

[![Go Reference](https://pkg.go.dev/badge/github.com/JLugagne/egauth.svg)](https://pkg.go.dev/github.com/JLugagne/egauth)
[![CI](https://github.com/JLugagne/egauth/actions/workflows/ci.yml/badge.svg)](https://github.com/JLugagne/egauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A complete, composable, non-opinionated authentication toolkit for Go.

> **About this project — please read.** egauth was built mostly through "vibe coding"
> (AI-assisted development). egauth's security review to date is an AI-driven audit only; it has
> not had an independent third-party human security audit, and that risk is accepted for v1.0 —
> pin a reviewed commit, commission your own audit, or wait if that trade-off is unacceptable. I
> wrote it because I wanted a library like this for my own projects. The code is engineered
> carefully and secure-by-default — an adversarial pass found no high/critical issue — but
> "AI-audited" is **not** a synonym for "audited", so weigh the status accordingly before using
> it for anything sensitive. The full audit status, scope, and escape hatch live in
> [AUDIT.md](AUDIT.md).
>
> **Comments, reviews, issues, and security audits are genuinely welcome.** If you spot something —
> a bug, a design smell, a crypto/protocol concern — please open an issue or PR; for anything
> security-sensitive see [SECURITY.md](SECURITY.md). Independent scrutiny is exactly what this
> project wants.

egauth is a set of independent modules in the style of the standard library's `database/sql`:
you **import the ones you need** and wire them together with dependency injection. There is no
framework to adopt — egauth never owns your HTTP router, your database access, or your
conventions. Every module exposes a `Service` interface plus a `Store` contract, with in-memory
and PostgreSQL (`pgx`) backends behind a shared cross-backend conformance suite.

> Status: The API is still settling; see [Stability](#stability).

## Modules

| Module       | What it does                                                                 |
|--------------|------------------------------------------------------------------------------|
| `identity`   | Accounts & credentials: register, login, password reset, email verification, magic link, change-password/email, account deletion, OAuth identity linking |
| `tokens`     | Stateless JWT access tokens + single-use refresh tokens with rotation & theft detection; API keys. Reference impl in `tokens/jwt` |
| `sessions`   | Server-side, revocable sessions with idle-timeout (`Touch`) and fixation defense (`Rotate`) |
| `passwords`  | Hashing/policy/breach **seams** + references: `argon2`, `policy`, `breach/hibp`, `breach/offline` |
| `mfa`        | TOTP (RFC 6238) with recovery codes                                          |
| `otp`        | One-time codes (email/SMS), enumeration-safe HTTP handlers                    |
| `passkey`    | WebAuthn / passkeys, including discoverable (usernameless) login             |
| `oauth`      | OAuth2 / OIDC, PKCE-S256, id_token/nonce/JWKS; 12 built-in providers (Apple, Auth0, Cognito, Discord, Facebook, GitHub, GitLab, Google, Keycloak, LinkedIn, Microsoft, Okta) in `oauth/providers` |
| `identity.Mailer` / `identity.SMSSender` | Bring-your-own-delivery seams: wire your own SMTP, SendGrid, Twilio, etc. — egauth never sends mail or SMS itself |
| `ratelimit`, `event`, `health` | Pluggable rate-limiting, audit-event, and readiness seams  |

## Install

```sh
go get github.com/JLugagne/egauth
```

The PostgreSQL storage backend lives in a **separate module** (`adapters/pgx`) so core consumers
never pull the `pgx` driver or the testcontainers/Docker chain into their dependency graph. Install
it only if you use the Postgres stores:

```sh
go get github.com/JLugagne/egauth/adapters/pgx
```

Requires Go 1.26+.

## Quickstart: login + refresh

The recommended stateless stack is `identity` (verify credentials) + `tokens/jwt` (issue and
rotate tokens). This wires it with the in-memory backends; swap in the `pgx` stores for
production.

Most applications carry no custom data in their tokens. For that common case use the
`tokens/basic` convenience layer, which specializes the token API to "no custom claims" so you
never spell the `[struct{}]` type argument. (Need custom claims? Use the generic API directly
with your own type — see [below](#with-custom-claims).) This is the runnable package example
(`go test ./tokens/basic -run Example`).

```go
ctx := context.Background()
const tenant = "" // empty string is the single-tenant default partition

// identity: credential verification + account lifecycle
idStore := identitymem.NewStore() // identity/memory; or adapters/pgx/identity.NewStore(pool)
svc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy())

// tokens: stateless access tokens + refresh rotation (no custom claims).
// claimsProvider re-derives a user's claims on every refresh, so a disabled or
// role-changed user is re-evaluated rather than frozen at login.
claimsProvider := basic.ClaimsProviderFunc(
    func(_ context.Context, userID uuid.UUID, tenantID string) (basic.Claims, error) {
        return basic.Claims{Subject: userID, TenantID: tenantID}, nil
    },
)
tokenStore := basic.NewMemoryStore() // tokens/memory; or adapters/pgx/tokens.NewStore(pool)
issuer := basic.NewIssuer(basic.Config{
    Store:          tokenStore,
    Issuer:         "example-app",
    SecretKey:      hs256SecretFromYourSecretStore, // >= 32 bytes
    AccessTTL:      15 * time.Minute,
    RefreshTTL:     720 * time.Hour,
    ClaimsProvider: claimsProvider, // required for Rotate (refresh)
})

// register, authenticate, issue a token pair
user, err := svc.Register(ctx, tenant, "alice@example.com", password)
// ... handle err
pair, err := issuer.IssueTokenPair(ctx, basic.Claims{Subject: user.ID, TenantID: tenant})

// later: refresh — rotation single-use-consumes the old refresh token
// (replaying it trips theft detection and revokes the family)
next, err := issuer.Rotate(ctx, tenant, pair.RefreshToken)
```

### Over HTTP

The handlers are à-la-carte `http.HandlerFunc` factories you mount on your own mux — egauth
imposes no router:

```go
claimsOf := func(u *identity.User) basic.Claims {
    return basic.Claims{Subject: u.ID, TenantID: u.TenantID}
}
mux := http.NewServeMux()
mux.Handle("POST /login",   identity.LoginHandler(svc, issuer, claimsOf))
mux.Handle("POST /refresh", basic.RefreshHandler(issuer))    // issuer is the Rotator
mux.Handle("POST /logout",  basic.LogoutHandler(tokenStore)) // revokes the refresh family

// protect a route with the access-token middleware:
mux.Handle("GET /me", basic.RequireAuth(issuer,
    func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, _ struct{}) {
        // actor.UserID / actor.TenantID are authenticated
    }))
```

### With custom claims

To carry application data in your tokens, use the generic `tokens` / `tokens/jwt` API directly
with your own claims type `C`. The shape is identical — `basic` is only a thin facade over it —
but every token type takes the type argument: `tokens.Claims[C]`, `jwt.New[C]`,
`tokens.RequireAuth[C]`, and so on. Use `tokens.Claims[struct{}]` if you ever need the generic
form with no custom claims. See `go doc github.com/JLugagne/egauth/tokens`.

## Multi-tenancy

Every tenant-scoped operation takes an explicit `tenantID string` argument. An empty string
(`""`) is the valid **single-tenant default partition** — passing it explicitly keeps the tenant
boundary visible at every call site (the defense against cross-tenant access / IDOR).

For a genuinely single-tenant application, wrap a `Service` once and drop the argument:

```go
app := identity.NewSingleTenant(svc) // every call uses the empty tenant ("")
user, err := app.Register(ctx, "bob@example.com", password)
```

`SingleTenant` facades exist on `identity`, `sessions`, `mfa`, `otp`, `passkey`, and `tokens/jwt`.

## Storage backends

Each module ships two interchangeable `Store` implementations behind one contract:

- `<module>/memory` — zero-dependency, for tests and single-process apps; lives in the core module.
- `adapters/pgx/<module>` — PostgreSQL via `jackc/pgx`, in the separate `adapters/pgx` module
  (`go get github.com/JLugagne/egauth/adapters/pgx`). Call `Migrate(ctx, pool)` once at startup
  (forward-only, versioned via a `schema_migrations` table; re-running is a no-op).

```go
import identitypgx "github.com/JLugagne/egauth/adapters/pgx/identity"

pool, _ := pgxpool.New(ctx, dsn)
_ = identitypgx.Migrate(ctx, pool)
store := identitypgx.NewStore(pool)
```

## Security

egauth is enumeration-safe by default (uniform responses + decoy hashing), enforces brute-force
lockout, pins JWTs to HS256 (rejecting `none`/alg-confusion), rotates refresh tokens with
family-based theft detection, stores only SHA-256 hashes of refresh/API/session/OTP secrets, and
caps pre-auth body size against hashing-DoS. Credential-bearing types redact their secrets on
`fmt`/`slog`. Read **[SECURITY.md](SECURITY.md)** for the full model — including the explicit
trade-offs (e.g. TOTP secrets stored recoverably, accepted account-existence disclosures) and the
boundaries egauth leaves to the application (CSRF tokens, rate-limit policy, mail/SMS transport,
observability, idempotency).

**Observability and idempotency** — egauth ships no first-party metrics or tracing adapter and no
request-level idempotency layer. Wire your metrics/audit pipeline to `event.Sink` (use
`event.NewSlogSink` for the common slog case, or implement the interface for Prometheus/OpenTelemetry);
use the propagated `context.Context` for span injection. Request-level idempotency is the application
layer's responsibility. See [SECURITY.md § Observability and idempotency](SECURITY.md#observability-and-idempotency-consumer-responsibility).

## Documentation

Full API reference: [pkg.go.dev/github.com/JLugagne/egauth](https://pkg.go.dev/github.com/JLugagne/egauth)

Each module has a package overview (`go doc github.com/JLugagne/egauth/identity`) and the
login-critical packages carry runnable examples.

## Production: evict in-memory stores

The `sessions/memory`, `otp/memory`, and `ratelimit.TokenBucket` backends grow without bound
unless their eviction methods (`DeleteExpired` / `Cleanup`) are called periodically. In any
non-trivial production deployment you **must** schedule this — a flood of unique keys, sessions,
or OTP codes otherwise exhausts available memory. Use the optional `janitor` helper:

```go
import "github.com/JLugagne/egauth/janitor"

j := janitor.Start(ctx, 5*time.Minute, func() {
    sessStore.DeleteExpired(context.Background(), tenantID)
})
defer j.Stop()
```

`janitor.Start` accepts any `func()`, so the same pattern covers `otpStore.DeleteExpired` and
`tokenBucket.Cleanup`. For production deployments beyond a single binary, swap the in-memory
stores for their `pgx` counterparts (which rely on the database for eviction instead).

## Stability

Pre-1.0: the API may change between minor versions until it settles, at which point releases will
follow SemVer with a CHANGELOG. Pin a commit or tag in `go.mod` for reproducible builds.

**Go version support policy.** egauth targets the newest major Go release as its minimum toolchain.
The `go.mod` directive is currently `go 1.26` and is bumped deliberately — each time a new major
Go version ships, the floor moves up to it. This is an intentional choice (not an accident): the
library is expected to be adopted in greenfield projects that run the current toolchain. If you
need support for an older Go version, pin an earlier egauth release.
