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
| `identity`   | Accounts & credentials: register, login, password reset, email verification, magic link, change-password/email, account deletion, OAuth identity linking; forced-password-change for temporary credentials (`AdminCreateUser`, `SetTemporaryPassword`) |
| `tokens`     | Stateless JWT access tokens (pluggable symmetric HS256 or asymmetric RS256/ES256/EdDSA signing, publishable JWKS) + single-use refresh tokens with rotation & theft detection; API keys (PAT & service tokens) with a full lifecycle — issue, list, revoke. Reference impl in `tokens/jwt` |
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

tokenStore := basic.NewMemoryStore() // tokens/memory; or adapters/pgx/tokens.NewStore(pool)

// identity: credential verification + account lifecycle.
// The revoker makes DisableUser/DeleteAccount cascade into the token store (killing the
// user's refresh families and API keys) — half of "deactivation ends access".
revoker := tokens.NewAccountRevoker(tokenStore)
idStore := identitymem.NewStore() // identity/memory; or adapters/pgx/identity.NewStore(pool)
svc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy(),
    identity.WithDisableRevokers(revoker),
    identity.WithAccountErasers(revoker),
)

// tokens: stateless access tokens + refresh rotation (no custom claims).
// claimsProvider re-derives a user's claims on every refresh, so a role change is picked
// up rather than frozen at login. ActiveClaimsProvider is the other half: it aborts the
// rotation of a disabled or deleted account, which would otherwise renew its session
// forever (each rotation pushes the refresh expiry out again).
claimsProvider := identity.ActiveClaimsProvider(svc, basic.ClaimsProviderFunc(
    func(_ context.Context, userID uuid.UUID, tenantID string) (basic.Claims, error) {
        return basic.Claims{Subject: userID, TenantID: tenantID}, nil
    },
))
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

For **asymmetric signing** (so verifiers hold only a public key), set `jwt.Config.Signers` with
`jwt.NewRSASigner` / `jwt.NewECDSASigner` / `jwt.NewEdDSASigner` instead of `SecretKey`, and serve
the public keys from `Service.PublicJWKS()`. The default `tokens/basic` facade stays HS256-only;
asymmetric signing uses the generic `tokens/jwt` API.

## API keys: PAT and service tokens

egauth issues two kinds of long-lived key through `IssueAPIKey`.

| Kind | `Actor.Kind` | `IsHuman()` | Subject | Typical use |
|------|-------------|-------------|---------|-------------|
| **PAT** (Personal Access Token) | `egauth.PAT` | `true` | The owning user's ID | CI tokens, script automation acting on behalf of a specific user |
| **Service token** | `egauth.Service` | `false` (`IsMachine()` true) | The key's own ID | Background jobs, inter-service calls with no human owner |

Set the type at issuance:

```go
// PAT — acts on behalf of user alice
pat, err := issuer.IssueAPIKey(ctx, "sk_", tokens.KeyTypePAT, alice.ID, tokens.Claims[C]{
    Subject:  alice.ID,
    TenantID: tenant,
    Scopes:   []string{"repo:read", "issues:write"},
})

// Service token — machine identity; Subject becomes the key's own ID after issuance
svcToken, err := issuer.IssueAPIKey(ctx, "svc_", tokens.KeyTypeService, operator.ID, tokens.Claims[C]{
    TenantID: tenant,
    Scopes:   []string{"metrics:ingest"},
})
```

**Authority model — `IssueAPIKey` does not copy the issuing user's roles.**
The key's authority is **only the scopes you pass** at issuance. egauth never silently inherits the
creating user's live roles: a PAT with `Scopes: ["repo:read"]` can only read repositories even if
the user can do far more. This is the safe default (a leaked PAT is bounded); if you want a richer
scope set, pass it explicitly. See [SECURITY.md](SECURITY.md) for
the full security model.

### Listing and revoking keys

Keys have a full server-side lifecycle, and the clear-text key value is **never retrievable after
issuance** — egauth stores only a SHA-256 hash, so a leaked database never yields a usable key.

```go
// List every key a user created — active and revoked — for a management UI.
// Listed keys carry a blank Token (the secret only ever exists at creation) and a
// populated RevokedAt on revoked keys.
keys, err := issuer.ListAPIKeysByCreator(ctx, tenant, alice.ID)

// Revoke a key by its ID — you never need to hold the secret to revoke it.
err = issuer.RevokeAPIKey(ctx, tenant, keys[0].ID)
```

Revocation is a **soft-revoke**: the row is kept (so the key stays visible to audit/management with
a `RevokedAt` timestamp) and `VerifyAPIKey` returns `tokens.ErrAPIKeyRevoked` for it from then on —
a distinct outcome from expiry (`ErrTokenExpired`) and from a missing key (`ErrAPIKeyNotFound`).
The in-memory and PostgreSQL backends enforce identical behaviour through one shared contract suite,
so neither can silently diverge.

### Opt-in route gates

`RequireAuth` accepts additional `AuthOption`s that gate routes on the principal's kind or scopes.
All gates are **opt-in** — the library imposes no default authority policy.

```go
// Restrict a route to machine (Service) callers only:
mux.Handle("/internal/ingest", basic.RequireAuth(issuer, ingestHandler,
    tokens.WithRequiredKind[struct{}](egauth.Service),
))

// Restrict a route to callers carrying a specific scope:
mux.Handle("/api/admin", basic.RequireAuth(issuer, adminHandler,
    tokens.WithRequiredScopes[struct{}]("admin:write"),
))

// Convenience wrappers for kind gating:
tokens.RequireMachine[C]() // equivalent to WithRequiredKind(egauth.Service)
tokens.RequireHuman[C]()   // equivalent to WithRequiredKind(egauth.User, egauth.PAT)
```

On a kind or scope mismatch the middleware returns `403 wrong_principal_kind` or `403 insufficient_scope`
respectively — the caller is authenticated but not allowed on this route. The `egauth.Actor`
injected into the handler carries `Kind`, `KeyID`, and `Scopes`, plus `HasScope` / `HasAllScopes` /
`HasAnyScope` helpers, so the application can also branch or enforce policy directly without
middleware gates.

For authorization the fixed gates don't cover, `WithGate` runs an application-supplied predicate
over the verified `egauth.Actor` **and** your custom claims `C` — one flexible evaluator instead of
a fixed policy vocabulary. It is opt-in like every other gate, and egauth still assigns no meaning to
your scopes or claims; your function decides.

```go
mux.Handle("/api/reports", basic.RequireAuth(issuer, reportsHandler,
    tokens.WithGate[struct{}](func(actor egauth.Actor, _ struct{}) error {
        if !actor.HasAllScopes("reports:read") {
            return errors.New("missing reports:read")
        }
        return nil // nil = allowed; any error → 403
    }),
))
```

### Audit events for key lifecycle

Wire `event.Sink` to observe the full key lifecycle:

| Event | When | Key `Attrs` |
|-------|------|-------------|
| `api_key.created` | Key issued | `"key_type"` (pat/service), `"created_by"` (user UUID) |
| `api_key.revoked` | Key revoked via `RevokeAPIKey` | `"key_id"` (the revoked key's UUID) |
| `api_key.auth.succeeded` | Key verified successfully | `"key_type"`, `"ip"`, `"user_agent"` (if `RequestContext` supplied) |
| `api_key.auth.failed` | Verification failed | `Event.Reason` = `not_found` / `expired` / `revoked` / `tenant_mismatch` / `wrong_type` |
| `api_key.purged` | Expired keys swept by `DeleteExpired` | `"count"` (number of rows deleted) |

`login.succeeded` and `login.failed` carry `"ip"` / `"user_agent"` when the handler receives a
`event.RequestContext`. Audit events never carry secrets, tokens, hashes or raw input — only short
machine `Reason` codes and safe metadata. See [SECURITY.md](SECURITY.md).

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
lockout, pins each JWT to its key's algorithm (rejecting `none`/alg-confusion) for symmetric (HS256) or asymmetric (RS256/ES256/EdDSA) signing, rotates refresh tokens with
family-based theft detection, stores only SHA-256 hashes of refresh/API/session/OTP secrets, and
caps pre-auth body size against hashing-DoS. Credential-bearing types redact their secrets on
`fmt`/`slog`. Read **[SECURITY.md](SECURITY.md)** for the full model — including the explicit
trade-offs (e.g. TOTP secrets stored recoverably, accepted account-existence disclosures) and the
boundaries egauth leaves to the application (CSRF tokens, rate-limit policy, mail/SMS transport,
observability, idempotency).

**Forced-password-change for temporary credentials.** Provision a one-time credential via
`identity.AdminCreateUser` (admin-created account) or `identity.SetTemporaryPassword` (admin-issued
temporary password); both flag the credential so the user must choose a new password at next login.
A flagged login issues a full, renewable pair carrying `tokens.Claims.MustChangePassword=true`; the
flag is recorded on the refresh-token family and carried onto every silent refresh, so mounting
`tokens.WithPasswordChangeGate` on your protected routes keeps soft-redirecting to the reset page
until the password is changed — a user cannot escape by waiting for the access token to expire. The
credential stays valid throughout — never a lockout. egauth does NOT do periodic, age-based rotation
(NIST SP 800-63B discourages fixed-interval expiry). See [SECURITY.md](SECURITY.md) for the full
semantics.

**Observability** — wire your metrics/audit pipeline to `event.Sink`. Use `event.NewSlogSink`
for the common structured-logging case, or `github.com/JLugagne/egauth/adapters/otel` for
OpenTelemetry spans (`NewSpanSink` creates one child span per security event with `egauth.*`
attributes). Combine them with `event.MultiSink`. Request-level idempotency is the application
layer's responsibility. See [SECURITY.md § Observability and idempotency](SECURITY.md#observability-and-idempotency-consumer-responsibility).

## Reference application

[`examples/fullstack`](examples/fullstack) is a self-contained runnable application that wires
the full egauth stack — identity + tokens with custom claims + MFA (TOTP) + passkey + admin
operations + audit events — over HTTP using only in-memory backends and the standard library
mux. It builds from the module proxy with no local `go.work` workspace:

```sh
go run github.com/JLugagne/egauth/examples/fullstack@latest
```

A smoke test (`go test ./examples/fullstack`) exercises all six concerns end-to-end.

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

**Go version support policy.**

- **For v1.x and later**: The `go.mod` `go` directive is **pinned for the life of the major version**.
  v1.0 through v1.x will all require `go 1.26` (the minimum toolchain at v1.0 release). Bumping to a
  newer major Go release is deferred to v2. This provides maximum build stability within a major
  version.
  
- **Pre-v1 releases**: egauth targets the newest major Go release as its minimum toolchain. The `go.mod`
  directive is bumped deliberately — each time a new major Go version ships, the floor moves up to it.
  This is an intentional choice (not an accident): the library is expected to be adopted in greenfield
  projects that run the current toolchain. If you need support for an older Go version, pin an earlier
  egauth release.
