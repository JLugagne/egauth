# Routes and gates

`Auth.Routes()` is the only way to serve application routes. `Build` serves the auth endpoints under `Config.BasePath`, the discovery document and exactly the declared routes; every other request is 404. `Build` returns all problems joined: patterns without a method, overlaps with the base path or another route, invalid requirements, an API kind not in `APIKeyModule.Kinds`, `ProtectAPI` without `Modules.APIKeys`.

| Verb | Served to | On a failed gate |
|---|---|---|
| `Protect(pattern, h, opts...)` | an established human session | 401, 403 or 429 as the gate says |
| `Optional(pattern, h, opts...)` | everyone | the handler runs with an anonymous principal |
| `ProtectAPI(pattern, h, kinds, opts...)` | an API key of one of `egauth.Kinds(...)` | 401 |
| `Public(pattern, handler)` | everyone | none |

Handlers are `egauth.PrincipalHandler[C]`: `func(w, r, p egauth.Principal[C])`.

## Requirements

- Claims (session and API routes): `egauth.RequireAnyRole`, `egauth.RequireAllRoles`, and the scope and group forms. The first argument is mandatory, so an empty list cannot be written.
- Session only: `egauth.RequireMFA`, `egauth.RequireFreshAuth` (`egauth.Fresh5m`, `egauth.Fresh15m`, `egauth.Fresh1h`), `egauth.RequireFactor`, `egauth.AcceptMustChange`. They do not compile on `ProtectAPI`.

## Gate sets

| Gate | Protect | Optional | ProtectAPI |
|---|---|---|---|
| credential kind | session only | session only; an API key is anonymous | API key of a declared kind |
| tenant against resolver | 401 | anonymous | 401 |
| revocation (family, epoch) | 401 | anonymous, cookie cleared | 401 |
| must-change password | 403 unless accepted | anonymous unless accepted | not applicable |
| CSRF and fetch metadata | 403 | 403 for cookie-carrying unsafe requests | not applicable |
| invalid Bearer | 401 | 401 | 401 |

A failed gate on `Optional` is always anonymous, never a weaker authenticated principal.

## Principal

`egauth.Principal` offers `Subject()`, `Caller()`, `Claims()`, `Kind()`, `Session()`, `SessionID()` and `APIKey()`. `Caller()` is what a facade takes. The zero value is anonymous. Tests build one with `egauthtest.NewPrincipal`.

## Facades

- `Auth.Accounts()`: `Create`, `Disable`, `Enable`, `Delete`, `RevokeSessions`, `SetTemporaryPassword`, `UnlockMFA`. Needs a system caller or a session caller allowed by `Config.Admin`, fresh and multi-factor when enrolled.
- `Auth.Tenants()`: `Erase`, `ImportKey`, `RenewKeys`, `RevokeKeys`, `SetOAuthProvider`, `RemoveOAuthProvider`.
- `Auth.APIKeys()`: `Create`, `List`, `Revoke` for the calling user.
- `Auth.System(tenant, reason)` mints a system caller for background work; it is refused inside a request.

## Auth endpoints

Mounted under `Config.BasePath`: session, logout, logout-everywhere, reauth, refresh, exchange, resource-token, security revert, JWKS, register, register confirm, login, password forgot, reset and change, magic link request and consume, code request and verify, passkey login, registration and credential management, OAuth begin, callback and link, external login, MFA challenge, passkey and TOTP enrollment and recovery codes, email, phone and recovery-email verification, and account delete. The path constants are `egauth.PathLogin`, `egauth.PathRefresh` and siblings; request fields are `egauth.FieldIdentifier` and siblings. `egauth.HeaderTransport` selects Bearer transport on a login request.

Each endpoint has a fixed body cap, a rate-limit class, a CSRF decision and an enumeration-uniform answer, all derived from its route metadata.
