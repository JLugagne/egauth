# Secure defaults

| Control | Default | Opt-out |
|---|---|---|
| Multi-factor for enrolled users on every primary login | on, read from storage | none |
| Pre-MFA state used as a session | impossible | none |
| Account state, epoch and MFA rule at admission and renewal | on | none |
| Must-change password sessions | refused | `egauth.AcceptMustChange` per route |
| CSRF and fetch metadata on unsafe and cross-site requests | on | `egauth.InsecureOptOuts.NoOriginCheck` |
| Browser binding of unauthenticated ceremonies | on | none |
| Sensitive actions need freshness and MFA | on | `egauth.InsecureOptOuts.NoReauthWindow` (freshness only) |
| Rate limits | on | `egauth.InsecureOptOuts.NoRateLimit` |
| Request body caps | 4 KiB, 64 KiB | none |
| Tenant resolution | 401 when unresolved | none |
| Cookies | `Secure`, `HttpOnly`, `__Host-` | `egauth.InsecureOptOuts.SharedCookieDomain` |
| Session lifetime | at most 90 days | `egauth.InsecureOptOuts.LongSessions` (400 days) |
| Durable shared state off loopback | required | `egauth.InsecureOptOuts.EphemeralState` |
| Outbound requests refuse private networks | on | `egauth.InsecureOptOuts.OutboundPrivateNetwork` |
| Open redirect | only pages and origins of the deployment | none |
| Enumeration uniformity | on | none |
| Password floor | 8 to 1024 characters, NFKC, breach check if configured | none |
| Federated identity auto-link | never | none |
| Passkeys | discoverable and user verification required | none |
| Weak or symmetric keys on resource servers | refused | none |
| Secrets at rest | sealed with associated data | none |
