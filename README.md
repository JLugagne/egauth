# egauth

[![Go Reference](https://pkg.go.dev/badge/github.com/JLugagne/egauth.svg)](https://pkg.go.dev/github.com/JLugagne/egauth)
[![CI](https://github.com/JLugagne/egauth/actions/workflows/ci.yml/badge.svg)](https://github.com/JLugagne/egauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A misuse-resistant authentication library for Go: one validated composition object, one
deny-by-default route builder, and CI guards that keep both honest.

> **About this project — please read.** egauth was built mostly through "vibe coding"
> (AI-assisted development). egauth's security review to date is an AI-driven audit only; it has
> not had an independent third-party human security audit, and that risk is accepted for v1.0 —
> pin a reviewed commit, commission your own audit, or wait if that trade-off is unacceptable. I
> wrote it because I wanted a library like this for my own projects. "AI-audited" is **not** a
> synonym for "audited", so weigh the status accordingly before using it for anything sensitive.
> The full audit status, scope, and escape hatch live in [AUDIT.md](AUDIT.md).
>
> **Comments, reviews, issues, and security audits are genuinely welcome.** For anything
> security-sensitive see [SECURITY.md](SECURITY.md).

## The idea

Authentication bugs are usually configuration bugs: a cookie set up differently on two handlers,
a gate added to one route and forgotten on its sibling, an option the constructor silently
ignored. egauth removes those by construction:

- **One composition object.** `egauth.New` takes a single `egauth.Config` and returns an
  `egauth.Auth`. It owns every policy object, store handle and background worker. No handler,
  cookie, issuer or limiter is ever wired by hand.
- **Validated at startup.** Every field carries a tag that `New` enforces. All problems are
  returned together, as one error. There is no request-time "misconfigured" answer.
- **Deny by default.** The only way to serve your own routes is `Auth.Routes`. A route is
  `Protect`, `Optional`, `ProtectAPI` or `Public`, and every other request is a 404. The gate set
  of each kind is fixed by the library.
- **Opt-outs in one place.** Every weakening of a default lives in `egauth.InsecureOptOuts`, needs
  a written reason, and shows up in `Auth.Posture`.
- **Sealed session state.** What a login proved (factors, assurance time, must-change, remember-me)
  is minted once, sealed, stored on every artefact and replayed. Later steps can add a factor, never
  re-derive or upgrade one.
- **Guarded in CI.** Static guards (`tools/archtest`), behavioural journeys
  (`internal/journeytest`) and documentation guards (`tools/doclint`) fail the build when a
  contribution reopens one of these doors. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Install

```sh
go get github.com/JLugagne/egauth
go get github.com/JLugagne/egauth/adapters/pgx
```

The second module holds the PostgreSQL stores and keeps the driver out of your dependency graph
when you do not use it. Go 1.26 or newer.

## Quick start

`memstore` keeps everything in memory, so this runs without a database. The example registers a
password user, confirms the emailed link, logs in, calls a protected route, refreshes and logs out.

<!-- embed: example_test.go#ExampleNew -->
```go
key := make([]byte, 32)
_, _ = rand.Read(key)
seed := make([]byte, 32)
_, _ = rand.Read(seed)
k, _ := kek.NewLocal(key)
signer, _ := signing.EdDSA("k1", seed)
mail := inbox{links: make(chan string, 1)}

auth, err := egauth.New(egauth.Config[struct{}]{
	PublicOrigin: "http://localhost:8080",
	Proxy:        egauth.DirectClients(),
	Storage:      memstore.New(k),
	KEK:          k,
	Sessions:     egauth.JWT(egauth.StaticKeys(signer)),
	Transport:    egauth.Bearer,
	Admin:        egauth.RoleAdmin("admin"),
	Email:        mail,
	Pages:        egauth.Pages{Login: "/login", AfterLogin: "/", ConfirmRegistration: "/confirm", PasswordReset: "/reset", SecurityRevert: "/revert"},
	Modules:      egauth.Modules{Password: &egauth.PasswordModule{}},
})
if err != nil {
	fmt.Println("new:", err)
	return
}
defer func() { _ = auth.Close() }()

h, err := auth.Routes().
	Protect("GET /me", func(w http.ResponseWriter, _ *http.Request, _ egauth.Principal[struct{}]) {
		_, _ = fmt.Fprintln(w, "hello")
	}).
	Build()
if err != nil {
	fmt.Println("routes:", err)
	return
}

call := func(method, path, token string, body map[string]any, hdr ...string) (*httptest.ResponseRecorder, map[string]any) {
	var payload strings.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		payload = *strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, "http://localhost:8080"+path, &payload)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", "http://localhost:8080")
	req.Header.Set(egauth.HeaderTransport, "bearer")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

const email, password = "ada@example.com", "tapir-granite-velvet-orbit-29"
rec, begin := call("POST", "/auth"+egauth.PathRegister, "", map[string]any{egauth.FieldIdentifier: email, egauth.FieldPassword: password})
fmt.Println("register:", rec.Code)

link, _ := url.Parse(<-mail.links)
bind, _ := begin[egauth.FieldBind].(string)
rec, _ = call("POST", "/auth"+egauth.PathRegisterConfirm, "", map[string]any{egauth.FieldToken: link.Query().Get(egauth.FieldToken), egauth.FieldBind: bind})
fmt.Println("confirm:", rec.Code)

rec, _ = call("POST", "/auth"+egauth.PathLogin, "", map[string]any{egauth.FieldIdentifier: email, egauth.FieldPassword: password})
access, refresh := rec.Header().Get("X-Egauth-Access-Token"), rec.Header().Get("X-Egauth-Refresh-Token")
fmt.Println("login:", rec.Code)

rec, _ = call("GET", "/me", access, nil)
fmt.Println("me:", rec.Code)

rec, _ = call("POST", "/auth"+egauth.PathRefresh, "", nil, "X-Egauth-Refresh-Token", refresh)
access, refresh = rec.Header().Get("X-Egauth-Access-Token"), rec.Header().Get("X-Egauth-Refresh-Token")
fmt.Println("refresh:", rec.Code)

rec, _ = call("POST", "/auth"+egauth.PathLogout, access, nil)
fmt.Println("logout:", rec.Code)

rec, _ = call("POST", "/auth"+egauth.PathRefresh, "", nil, "X-Egauth-Refresh-Token", refresh)
fmt.Println("refresh after logout:", rec.Code)
// Output:
// register: 202
// confirm: 200
// login: 200
// me: 200
// refresh: 200
// logout: 200
// refresh after logout: 401
```

## Declaring routes

`Routes` mounts the auth endpoints under the base path and serves exactly what you declare.

<!-- embed: example_test.go#ExampleRoutes -->
```go
var auth *egauth.Auth[struct{}]
var page, report, adminDisable egauth.PrincipalHandler[struct{}]
var health http.Handler

h, err := auth.Routes().
	Optional("GET /", page).
	Protect("POST /admin/disable/{id}", adminDisable,
		egauth.RequireAnyRole("admin"), egauth.RequireMFA(), egauth.RequireFreshAuth(egauth.Fresh5m)).
	ProtectAPI("GET /api/report", report, egauth.Kinds("automation"), egauth.RequireAnyScope("report:read")).
	Public("GET /healthz", health).
	Build()
if err != nil {
	return
}
_ = http.ListenAndServe("localhost:8080", h)
```

| Declaration | Who is served |
|---|---|
| `Protect` | an established human session that passes every session gate |
| `Optional` | everyone; a caller failing any `Protect` gate is presented as anonymous |
| `ProtectAPI` | an API key of a declared kind; sessions are refused |
| `Public` | everyone, without authentication |

Session-only requirements (`egauth.RequireMFA`, `egauth.RequireFreshAuth`) do not compile on a
`ProtectAPI` route.

## Production storage

`pgxstore.New` fills every `egauth.Storage` field from one pool. `pgxstore.Migrate` is
expand-only and idempotent.

<!-- embed: adapters/pgx/pgxstore/example_test.go#ExampleNew_postgres -->
```go
ctx := context.Background()
pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
if err != nil {
	log.Fatal(err)
}
defer pool.Close()

if err := pgxstore.Migrate(ctx, pool); err != nil {
	log.Fatal(err)
}
storage, err := pgxstore.New(ctx, pool)
if err != nil {
	log.Fatal(err)
}

auth, err := egauth.New(egauth.Config[struct{}]{
	PublicOrigin: "https://auth.example.com",
	Proxy:        egauth.DirectClients(),
	Storage:      storage,
	KEK:          kekFromEnv("EGAUTH_KEK"),
	Sessions:     egauth.JWT(egauth.StaticKeys(signerFromEnv("EGAUTH_SIGNING_SEED"))),
	Admin:        egauth.RoleAdmin("admin"),
	Email:        mailer{},
	Pages:        egauth.Pages{Login: "/login", AfterLogin: "/", ConfirmRegistration: "/confirm", PasswordReset: "/reset", SecurityRevert: "/revert"},
	Modules:      egauth.Modules{Password: &egauth.PasswordModule{}},
})
if err != nil {
	log.Fatal(err)
}
defer func() { _ = auth.Close() }()
```

## What you get

| Module (field of `egauth.Modules`) | Capability |
|---|---|
| `Password` | register by verified email, login, reset, change; Argon2id with a policy and breach-check seam |
| `MagicLink`, `LoginCode` | emailed link or emailed and texted codes as primary factors |
| `Passkey` | WebAuthn with discoverable credentials and user verification required |
| `OAuth`, `External` | OIDC and OAuth2 providers (12 built in), or an external primary factor |
| `MFA` | TOTP and recovery codes; enrollment is read from stored state, never from configuration |
| `Verification` | email, phone and recovery-email verification |
| `SelfDelete`, `APIKeys` | account self-deletion and kind-scoped API keys |

Sessions run on `egauth.JWT` (short-lived access tokens, rotating refresh tokens) or
`egauth.Stateful` (server-side sessions). Both pass the same backend suite. Cookies, Bearer tokens
or both are selected with `egauth.Config.Transport`. Tenancy is single-tenant, by subdomain, or
resolved from the request.

Resource servers that only verify tokens use `egauth.NewResourceServer`.

## Upgrading from v0.16

v0.17 is a breaking redesign and a session cutover: every user logs in again and outstanding
emailed links stop working. Credentials carry over. The steps are in
[CHANGELOG.md](CHANGELOG.md) under "Upgrading", and the secret upgrade is shown here:

<!-- embed: example_test.go#ExampleUpgradeSecretsV016 -->
```go
ctx := context.Background()
var storage egauth.Storage
var oldKey, newKey []byte

legacy, err := kek.LegacyLocalV016(oldKey)
if err != nil {
	return
}
current, err := kek.NewLocal(newKey)
if err != nil {
	return
}
report, err := egauth.UpgradeSecretsV016(ctx, storage, legacy, current)
if err != nil {
	return
}
fmt.Println(report)
```

## Reference application

[examples/fullstack](examples/fullstack) composes password, magic link, passkey, TOTP, self-delete
and API keys with `New` and `Routes`, on in-memory storage:

```sh
go run github.com/JLugagne/egauth/examples/fullstack@latest
```

## Documentation

| Document | Purpose |
|---|---|
| [llms.txt](llms.txt) and [.llms/](.llms) | compact, machine-readable reference |
| [SECURITY.md](SECURITY.md) | secret handling, guarantees and consumer responsibilities |
| [docs/](docs) | developer manual sources |
| [CONTRIBUTING.md](CONTRIBUTING.md) | the invariants and the guard that enforces each |
| [CHANGELOG.md](CHANGELOG.md), [RELEASING.md](RELEASING.md) | releases |

## Stability

Pre-1.0: the API may change between minor versions until it settles. Pin a tag in `go.mod` for
reproducible builds. The packages proposed for the v1 freeze are analysed in
[ADR 0001](docs/adr/0001-v1-scope-and-stability-classes.md).

Before v1, egauth targets the newest major Go release as its minimum toolchain, and the `go`
directive moves up each time a new major release ships. From v1 it is pinned for the life of the
major version.
