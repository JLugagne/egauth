# Feature (later): per-tenant OIDC / OAuth provider assignment

**Status:** BACKLOG — deferred. Builds on important item **I9** (generic OIDC: id_token /
nonce / JWKS validation). Do I9 first, then this.

## Goal
In a multi-tenant deployment, each tenant can be assigned its own set of OAuth/OIDC
providers — including arbitrary OIDC IdPs (Okta, Azure AD / Entra, Auth0, Keycloak, Google
Workspace, …) — with **per-tenant client credentials and endpoints**. Today the provider set
is fixed at construction (`oauth.BeginHandler`/`CallbackHandler` take a static provider list:
Google/GitHub/Discord), so every tenant shares the same providers and the same client config.

## Why
- Enterprise tenants bring their own IdP ("bring your own SSO"): tenant A → Okta,
  tenant B → Entra, tenant C → Google. Each has distinct client_id/secret/issuer.
- Same provider, different credentials per tenant (separate OAuth apps per customer).
- Must compose with existing tenant scoping (`WithTenant`, `WithTenantResolver`) and the
  account-takeover-safe linking already in `LinkOrCreateIdentity`.

## Design sketch (decide details at implementation time)
- [ ] **Generic OIDC provider** (prereq = I9): a `Provider` built from an issuer URL via
      discovery (`/.well-known/openid-configuration`) + JWKS, so new IdPs need config, not code.
      Cache discovery docs + JWKS with refresh.
- [ ] **ProviderResolver seam**: `ProviderResolver func(ctx, tenantID, providerName) (Provider, error)`
      (or an interface). The oauth handlers resolve the provider+client config at request time
      from (tenant, providerName) instead of from a static map. Default resolver = today's
      static global set (back-compat).
- [ ] **Per-tenant provider config store**: optional `oauth.ProviderStore` (memory + pgx,
      matching the repo's Store/contract-test pattern) holding `{tenant_id, provider_name,
      issuer, client_id, client_secret_ref, scopes, redirect_url, enabled}`. Client secrets
      MUST NOT be stored in plaintext — store a reference resolved via a consumer-supplied
      secret source (or document an encryption seam). Cross-reference SECURITY.md.
- [ ] **Tenant binding through the flow**: tenant + providerName must be carried in the signed
      OAuth `state` (and the OIDC `nonce` from I9) so the callback resolves the SAME tenant's
      provider config it began with. Reject mismatches.
- [ ] **Routing**: handler reads tenant via the existing `WithTenantResolver` and provider via
      a path/query param; `/oauth/{tenant}/{provider}/begin` style is the consumer's choice.
- [ ] **Discoverability/admin**: a way to list/enable providers per tenant (API or just the
      store) so a tenant admin UI can manage their SSO.
- [ ] **JIT provisioning + linking per tenant**: ensure `LinkOrCreateIdentity` scopes by tenant
      (it already threads `opts...`); confirm the email-collision takeover guard holds per tenant.

## Tests to add
- [ ] Two tenants, same provider name, different client config → each resolves its own.
- [ ] Tenant with a generic OIDC issuer → discovery + id_token/nonce validated (I9).
- [ ] state/nonce bound to (tenant, provider); callback with mismatched tenant rejected.
- [ ] ProviderStore contract test (memory + pgx) like the other stores.
- [ ] Back-compat: no resolver configured → static global providers still work.

## Open questions (resolve before building)
- Secret storage model: reference + external secret source, or built-in encryption with a
  consumer-provided key? (Lean: reference + `SecretSource` seam, no plaintext at rest.)
- Is GitHub/Discord (non-OIDC OAuth2) also per-tenant, or OIDC-only? (Likely both via the
  same resolver; non-OIDC just skips id_token validation.)
