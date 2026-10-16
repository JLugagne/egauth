# Configuration

`egauth.Config[C]` is the whole wiring. Tags drive validation: `required`, `optional`, `default=<key>`, `module=<path>` (required exactly when a named module is enabled) and predicates (`origin`, `path`, `each=...`, `bound=...`). `New` returns every violation, each with the exact field path.

| Field | Meaning |
|---|---|
| `PublicOrigin` | https, or http on a loopback host, with no path. Under `TenantBySubdomain` it holds one `{tenant}` label |
| `BasePath` | where the auth endpoints mount; default is set by the library; starts with `/`, no trailing `/` |
| `ExtraOrigins`, `Audiences` | exact origins; an audience differs from `PublicOrigin` and needs asymmetric keys |
| `Proxy` | `egauth.DirectClients()` or `egauth.TrustedProxies(prefixes...)`; decides which peers may set forwarding headers |
| `Tenancy` | `egauth.SingleTenant()` (default), `egauth.TenantBySubdomain()`, `egauth.TenantFromRequest(r)` |
| `Storage` | every store; from `memstore.New` or `pgxstore.New` |
| `KEK` | `kek.KEK` that seals secrets at rest |
| `Sessions` | `egauth.JWT(keys)` or `egauth.Stateful()`; keys are `egauth.StaticKeys(signer)` or `egauth.TenantKeys()` |
| `Transport` | `egauth.Cookies` (default), `egauth.Bearer` or `egauth.CookiesAndBearer` |
| `Policy` | `egauth.SessionPolicy`: idle 168h, max 720h (at most 2160h), recheck 5m (at most 15m), reauth window 10m (at most 1h), remember-me policy |
| `Admin` | `egauth.RoleAdmin(role)` or `egauth.SelfServiceOnly()`; who may use the `Accounts` and `Tenants` facades |
| `Claims` | `egauth.ClaimsSource[C]`, the single source of roles, groups, scopes and custom claims; capped at `egauth.MaxAppClaimsBytes` |
| `Events` | `event.Sink`; defaults to slog |
| `Email`, `SMS` | `egauth.EmailDeliverer`, `egauth.SMSDeliverer`; one method per message kind |
| `Pages` | `egauth.Pages`: application pages the library links or redirects to |
| `Modules` | `egauth.Modules`; at least one primary module |
| `RateLimit` | defaults to the storage limiter; an integrator limiter can only tighten |
| `Outbound` | `egauth.OutboundObserver`, an observer of outbound calls; there is no integrator transport |
| `Hooks` | `egauth.Hooks`: `BeforeEndpoint`, `AccountDeleted`, `TenantErased` |
| `Insecure` | `egauth.InsecureOptOuts`; empty in production |

## Modules

`egauth.Modules` fields: `Password`, `MagicLink`, `LoginCode`, `Passkey`, `OAuth`, `External`, `MFA`, `Verification`, `SelfDelete`, `APIKeys`. A nil module is off. Primary modules (`Password`, `MagicLink`, `LoginCode` with a channel, `Passkey`, `OAuth`, `External`) establish a login; `MFA`, `Verification`, `SelfDelete` and `APIKeys` add capabilities.

## What New checks

1. Tags, bounds and defaults.
2. Origins, base path, shared cookie domain.
3. Passkey relying-party ID against every origin.
4. Store durability: every security store reports the same level; ephemeral stores are accepted only on a loopback origin or with `Insecure.EphemeralState`.
5. Schema: every embedded migration is recorded.
6. KEK canary: existing data opens with the configured KEK.
7. Legacy secrets: none remain un-upgraded (`egauth.UpgradeSecretsV016`), and no v0.16 account has unchecked identifiers (`egauth.UpgradeIdentifiersV016`).
8. MFA enrollment versus enabled modules: stored enrollments need their module.
9. Modules: deliverers, pages and API-key kinds.
10. OAuth provider specs are complete and issuers are pinned.
11. Limiter probe: burst plus one requests produce a deny.
12. Every set `Insecure` field carries a non-empty reason; each is emitted once as an event.
13. The auth route table has no pattern conflict.

## Insecure opt-outs

`egauth.InsecureOptOuts` fields: `NoOriginCheck`, `NoRateLimit`, `NoReauthWindow`, `LongSessions`, `EphemeralState`, `SharedCookieDomain`, `OutboundPrivateNetwork`, `TenantOutboundPrivateNetwork`. Build the acknowledgement with `egauth.Acknowledge(reason)`; `SharedCookieDomain` and the two outbound opt-outs take a `*SharedCookieDomain` or `*OutboundAllowance` instead. `Auth.Posture().OptOuts` lists every set field.

## Resource servers

`egauth.NewResourceServer[C](egauth.ResourceConfig)` verifies tokens issued by an `Auth` over HTTP discovery and JWKS, with revocation from `egauth.FromStorage`. Its routes come from `egauth.APIRoutes`.
