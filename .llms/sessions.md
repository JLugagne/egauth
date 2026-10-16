# Sessions, transport and revocation

## Backends

- `egauth.JWT(keys)`: short-lived access token plus a single-use rotating refresh token. Keys are `egauth.StaticKeys(active, verifyOnly...)` built from `signing.EdDSA`, `signing.ES256`, `signing.RS256` or `signing.HS256`, or `egauth.TenantKeys()` for per-tenant keys held in `store/keys`. Audiences need asymmetric keys.
- `egauth.Stateful()`: a server-side session row; the cookie or Bearer value is an opaque handle.

Both pass the same backend suite: subject, tenant and lineage stay pinned, every sealed field is preserved across renewal, factors are never added by renewal, and a revoked session is refused within the poll bound.

## Sealed attributes

A login mints `principal.SessionAttrs` once: subject, tenant, factors (injective, role-typed), authentication time, must-change, remember-me, return target. They are sealed, stored on every artefact and replayed. Access tokens carry the same sealed bytes plus application claims. A token without them is refused.

## Renewal

Every `SessionPolicy.RecheckEvery` the session is re-admitted: account state, security epoch, multi-factor rule and the `egauth.ClaimsSource` are re-read. A `ClaimsSource` returning `egauth.ErrUnknownSubject` ends the session.

## Revocation

A per-subject security epoch is bumped atomically with every security mutation (password change, factor change, disable, delete, session revocation) and sealed into artefacts. A session whose epoch is stale is refused. Event fan-out is only cleanup; a stale poller falls back to store lookups and never fails open.

Refresh reuse outside the grace window, or inside it from another client fingerprint, revokes the whole family.

## Transport

- Cookies: `__Host-` prefixed, `Secure` (except on a loopback origin), `HttpOnly`, with three closed classes: session, flow (the MFA handle, `SameSite=Strict`) and bind (browser binding of an unauthenticated ceremony).
- Bearer: tokens in `X-Egauth-Access-Token`, `X-Egauth-Refresh-Token` and `X-Egauth-Session-Token` response headers; requests send `Authorization: Bearer`. A login selects it with `egauth.HeaderTransport` set to `bearer`, when `Config.Transport` allows it.
- A request that presents a cookie and a Bearer credential together is refused.

## Multi-factor

Enrollment is `confirmed TOTP or active passkey`, read from storage at every primary login, whatever the modules. An enrolled subject gets an MFA flow handle first, which is not a session, and a session only after a second factor. Recovery codes exist only while a factor does. Passkey step-up cannot reuse the credential that logged in.

## Sensitive actions

Account changes, API-key management and facades need a session that is established, multi-factor when enrolled, and fresh within `SessionPolicy.ReauthWindow` (role-aware: a password-only reauth does not freshen an MFA session). Failure is 403 `reauth_required`.

## Logout

`egauth.PathLogout` ends the current session; `egauth.PathLogoutEverywhere` bumps the epoch. An already-issued stateless access token is refused at its next recheck, within `RecheckEvery`.
