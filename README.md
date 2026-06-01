# egauth

A complete, composable, non-opinionated authentication toolkit for Go.

egauth is a set of independent modules in the style of the standard library's `database/sql`:
you **import the ones you need** and wire them together with dependency injection. There is no
framework to adopt — egauth never owns your HTTP router, your database access, or your
conventions. Every module exposes a `Service` interface plus a `Store` contract, with in-memory
and PostgreSQL (`pgx`) backends behind a shared cross-backend conformance suite.

> Status: pre-1.0. The API is still settling; see [Stability](#stability).

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
| `oauth`      | OAuth2 / OIDC (Google, GitHub, Discord), PKCE-S256, id_token/nonce/JWKS      |
| `delivery`   | Optional reference SMTP mailer + template renderer + OTP sender              |
| `ratelimit`, `event`, `health` | Pluggable rate-limiting, audit-event, and readiness seams  |

## Install

```sh
go get github.com/JLugagne/egauth
```

Requires Go 1.26+.

## Quickstart: login + refresh

The recommended stateless stack is `identity` (verify credentials) + `tokens/jwt` (issue and
rotate tokens). This wires it with the in-memory backends; swap in the `pgx` stores for
production. It is the runnable package example (`go test ./identity -run Example`).

```go
ctx := context.Background()
const tenant = "" // empty string is the single-tenant default partition

// identity: credential verification + account lifecycle
idStore := identitymem.NewStore() // identity/memory; or identity/pgx.NewStore(pool)
svc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy())

// tokens: stateless access tokens + refresh rotation.
// claimsProvider re-derives a user's claims on every refresh, so a disabled or
// role-changed user is re-evaluated rather than frozen at login.
claimsProvider := tokens.ClaimsProviderFunc[struct{}](
    func(_ context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
        return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
    },
)
tokenStore := tokenmem.NewStore[struct{}]() // tokens/memory; or tokens/pgx.NewStore(pool)
issuer := jwt.New[struct{}](jwt.Config[struct{}]{
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
pair, err := issuer.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: user.ID, TenantID: tenant})

// later: refresh — rotation single-use-consumes the old refresh token
// (replaying it trips theft detection and revokes the family)
next, err := issuer.Rotate(ctx, tenant, pair.RefreshToken)
```

### Over HTTP

The handlers are à-la-carte `http.HandlerFunc` factories you mount on your own mux — egauth
imposes no router:

```go
claimsOf := func(u *identity.User) tokens.Claims[struct{}] {
    return tokens.Claims[struct{}]{Subject: u.ID, TenantID: u.TenantID}
}
mux := http.NewServeMux()
mux.Handle("POST /login",   identity.LoginHandler(svc, issuer, claimsOf))
mux.Handle("POST /refresh", tokens.RefreshHandler[struct{}](issuer))    // issuer is the Rotator
mux.Handle("POST /logout",  tokens.LogoutHandler(tokenStore))           // revokes the refresh family

// protect a route with the access-token middleware:
mux.Handle("GET /me", tokens.RequireAuth[struct{}](issuer,
    func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, _ struct{}) {
        // actor.UserID / actor.TenantID are authenticated
    }))
```

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

- `<module>/memory` — zero-dependency, for tests and single-process apps.
- `<module>/pgx` — PostgreSQL via `jackc/pgx`. Call `pgx.Migrate(ctx, pool)` once at startup
  (forward-only, versioned via a `schema_migrations` table; re-running is a no-op).

```go
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
boundaries egauth leaves to the application (CSRF tokens, rate-limit policy, mail/SMS transport).

## Documentation

Each module has a package overview (`go doc github.com/JLugagne/egauth/identity`) and the
login-critical packages carry runnable examples. See also `PRD.md` for design goals.

## Stability

Pre-1.0: the API may change between minor versions until it settles, at which point releases will
follow SemVer with a CHANGELOG. Pin a commit or tag in `go.mod` for reproducible builds.
