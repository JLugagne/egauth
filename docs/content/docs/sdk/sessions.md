---
title: "Sessions"
weight: 4
---

# Sessions

## Backends

`egauth.JWT(keys)` issues short-lived access tokens with a single-use rotating refresh token. `egauth.Stateful()` keeps a server-side session row. Both pass the same backend suite.

Keys for the JWT backend come from `egauth.StaticKeys(signer)`, built with `signing.EdDSA`, `signing.ES256`, `signing.RS256` or `signing.HS256`, or from `egauth.TenantKeys()` for per-tenant keys.

## Transport

`egauth.Config.Transport` is `egauth.Cookies` (the default), `egauth.Bearer` or `egauth.CookiesAndBearer`. Cookies are `__Host-` prefixed, `Secure` (except on a loopback origin) and `HttpOnly`. Under Bearer, tokens travel in the `X-Egauth-*` headers, selected on login with `egauth.HeaderTransport`. A request presenting a cookie and a Bearer credential together is refused.

## Sealed attributes

A login mints the session attributes once and they are replayed on every renewal. A renewal re-reads the account state, the security epoch, the multi-factor rule and the claims source every `SessionPolicy.RecheckEvery`.

## Lifetimes

Defaults: idle 168h, absolute 720h, recheck 5m, reauthentication window 10m. The absolute lifetime is bounded at 90 days, or 400 days with `Insecure.LongSessions`.

## Revocation

The security epoch makes revocation state-derived: a password change, factor change, disable, delete or session revocation bumps it atomically, and a session with a stale epoch is refused at its next recheck. Replaying a consumed refresh token outside the grace window revokes the whole family. The refresh protocol is specified in [the refresh family state machine](https://github.com/JLugagne/egauth/blob/main/docs/protocols/refresh-family.md).

## Claims

`egauth.ClaimsSource` is the single source of roles, groups, scopes and custom claims. It is read at admission and on every renewal. Returning `egauth.ErrUnknownSubject` ends the subject's session.
