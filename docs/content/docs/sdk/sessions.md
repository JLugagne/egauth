---
title: "Sessions"
weight: 4
---

# Sessions

## Backends

`egauth.JWT(keys)` issues short-lived access tokens with a single-use rotating refresh token. `egauth.Stateful()` keeps a server-side session row. Both pass the same backend suite.

Keys for the JWT backend come from `egauth.StaticKeys(signer)`, built with `signing.EdDSA`, `signing.ES256`, `signing.RS256` or `signing.HS256`, or from `egauth.TenantKeys()` for per-tenant keys.

## Transport

`egauth.Config.Transport` is `egauth.Cookies` (the default), `egauth.Bearer` or `egauth.CookiesAndBearer`. Cookies are `__Host-` prefixed, `Secure` (on a loopback origin the prefix and `Secure` are dropped) and `HttpOnly`. Under Bearer, tokens travel in the `X-Egauth-*` headers, selected on login with `egauth.HeaderTransport`. A request presenting a cookie and a Bearer credential together is refused.

## Single-page applications

A single-page application served by the `Build` handler itself is same-origin and needs nothing more. One served from a sibling host of its site, such as `https://app.example.com` for a `PublicOrigin` of `https://auth.example.com` or a development server on `http://localhost:5173`, is listed in `egauth.Config.SPAOrigins`:

- every route `Build` serves answers those exact origins with credentialed CORS (`Access-Control-Allow-Origin` echoing the origin, `Access-Control-Allow-Credentials: true`, `Vary: Origin`), refusals included, so the application can read them;
- a preflight is answered `204` only when a route serves the requested method on that path; the only extra request header allowed is `Content-Type`, and only `Retry-After` is exposed;
- the cross-site gate accepts `Sec-Fetch-Site: same-site` only with an `Origin` header naming one of them, never a `Referer`; `cross-site` stays refused;
- the session stays in `HttpOnly` cookies on the `PublicOrigin` host. The application calls it with `fetch(url, {credentials: "include"})` and a JSON body, and never sees a token: `Authorization` and `X-Egauth-Transport` are not allowed headers, so it cannot switch itself to Bearer;
- `Pages` entries, `AfterLogin`, `MFA` and `Reauth` included, and `return_to` may be absolute URLs on a SPA origin.

`New` refuses a SPA origin that is cross-site (another scheme or registrable domain), carries a `{tenant}` label, or equals `PublicOrigin`, an `ExtraOrigins` entry or an audience. With passkeys, the browser runs the ceremony on the SPA origin, so the relying party id must cover it: set `PasskeyModule.RPID` to the shared parent domain (`example.com`). The relying party id is bound into every credential, so setting or changing it on a deployment that already has passkeys makes them unusable.

## Sealed attributes

A login mints the session attributes once and they are replayed on every renewal. A renewal re-reads the account state, the security epoch, the multi-factor rule and the claims source every `SessionPolicy.RecheckEvery`.

## Lifetimes

Defaults: idle 168h, absolute 720h, recheck 5m, reauthentication window 10m. The absolute lifetime is bounded at 90 days, or 400 days with `Insecure.LongSessions`.

## Revocation

The security epoch makes revocation state-derived: a password change, factor change, disable, delete or session revocation bumps it atomically, and a session with a stale epoch is refused at its next recheck. Replaying a consumed refresh token outside the grace window revokes the whole family. The refresh protocol is specified in [the refresh family state machine](https://github.com/JLugagne/egauth/blob/main/docs/protocols/refresh-family.md).

## Claims

`egauth.ClaimsSource` is the single source of roles, groups, scopes and custom claims. It is read at admission and on every renewal. Returning `egauth.ErrUnknownSubject` ends the subject's session.
