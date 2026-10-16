---
title: "OAuth and Federation"
weight: 6
---

# OAuth and Federation

Enable `Modules.OAuth` with `federation.Provider` specs, or `Modules.External` for an external primary factor.

## Providers

`federation/providers` ships 12 built-in constructors: `providers.Google`, `providers.GitHub`, `providers.Microsoft`, `providers.Apple`, `providers.Okta`, `providers.Auth0`, `providers.Cognito`, `providers.Keycloak`, `providers.GitLab`, `providers.Facebook`, `providers.Discord` and `providers.LinkedIn`, plus `providers.OIDC` for any compliant issuer. Each declares how its email verification is trusted, and each OIDC provider pins its issuer and key set.

## Protocol

The authorization-code flow uses PKCE (S256), a single-use `state` bound to the browser, nonce and `id_token` validation with algorithm pinning, and exact-issuer checks. Token and userinfo requests go through the single outbound client, which refuses private networks unless `Insecure.OutboundPrivateNetwork` says otherwise.

## Linking

A federated identity is never linked to an existing account automatically. A login with an identity that has no account creates one only when the provider vouches for the email. Linking an identity to your own account is an authenticated, sensitive action behind `egauth.PathOAuthLink`.

## Per-tenant providers

With `OAuthModule.PerTenant`, a tenant administrator registers providers at runtime through `Auth.Tenants().SetOAuthProvider`. Their endpoints are discovered and pinned at registration, and the outbound allowance for tenant providers is separate.

## Testing

`egauthtest.NewIdP` is an in-process OIDC provider that drives the whole flow without network access.
