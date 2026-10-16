---
title: "Tenants"
weight: 7
---

# Tenants

## Modes

- `egauth.SingleTenant()`: one tenant, the empty one.
- `egauth.TenantBySubdomain()`: the public origin contains exactly one `{tenant}` host label, for example `https://{tenant}.example.com`.
- `egauth.TenantFromRequest(resolver)`: your `egauth.TenantResolver` maps a request to a tenant.

A request whose tenant cannot be resolved is refused with 401, with no fallback. Credentials, ceremony handles and OAuth state are bound to their tenant, and a handle sealed for one tenant is refused under another, without being consumed.

## Administration

`Auth.Tenants` erases a tenant, imports, renews and revokes tenant signing keys, and manages runtime OAuth providers. Each call needs a system caller minted for that tenant with `Auth.System(tenant, reason)`, or an authorised session caller of that tenant. Any other tenant returns `egauth.ErrTenantMismatch`.

## Keys

`egauth.TenantKeys()` gives each tenant its own signing keys, held in `store/keys` and sealed by the KEK. A tombstone blocks provisioning after revocation.
