---
title: "Routes and Gates"
weight: 2
---

# Routes and Gates

`Auth.Routes` is the only way to serve application routes. `Build` mounts the auth endpoints under `Config.BasePath` and serves exactly what you declare. Every other request is 404.

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

## The four verbs

| Verb | Served to | On a failed gate |
|---|---|---|
| `Protect` | an established human session | 401, 403 or 429 as the gate says |
| `Optional` | everyone | the handler runs with an anonymous principal |
| `ProtectAPI` | an API key of a declared kind | 401 |
| `Public` | everyone | none |

## Requirements

Claim requirements work on session and API routes: `egauth.RequireAnyRole`, `egauth.RequireAllRoles` and the scope and group forms. The first argument is mandatory, so an empty list cannot be written.

Session requirements work on `Protect` and `Optional`: `egauth.RequireMFA`, `egauth.RequireFreshAuth`, `egauth.RequireFactor` and `egauth.AcceptMustChange`. They do not compile on `ProtectAPI`.

## The principal

Handlers receive an `egauth.Principal` as an argument. Its methods are `Subject`, `Caller`, `Claims`, `Kind`, `Session`, `SessionID` and `APIKey`. `Caller` is what the facades take. Tests build a principal with `egauthtest.NewPrincipal`.

## Facades

Administration goes through facades that check authorization themselves.

<!-- embed: example_test.go#ExampleAccounts -->
```go
ctx := context.Background()
var auth *egauth.Auth[struct{}]
var admin principal.Caller
var user uuid.UUID

if err := auth.Accounts().Disable(ctx, admin, user); err != nil {
	if errors.Is(err, egauth.ErrForbidden) || errors.Is(err, store.ErrNotFound) {
		return
	}
}
```

`Auth.Accounts`, `Auth.Tenants` and `Auth.APIKeys` take the caller from the principal. `Auth.System` mints a system caller for background work and is refused inside a request.

Only a first-party session caller or a system caller passes a facade. An API-key caller is refused with `ErrAPIKeyCaller`, and the caller of a `ResourceServer` route with `ErrResourceTokenCaller`: a resource token is a short-lived delegation, not a session. A session caller is bound to the session it came from. Once that session is logged out, revoked or reissued, every facade refuses it with `ErrSessionEnded`, so take the caller from the current request and do not keep it.

## API keys

Enable `Modules.APIKeys` with the kinds you issue, create keys with `Auth.APIKeys().Create`, and serve them with `ProtectAPI`. A key never reaches a session route and a session never reaches an API route.
