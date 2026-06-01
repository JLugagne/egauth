---
title: "Tenants Configuration"
weight: 1
---

# Multi-tenancy Settings

`egauth` supports native multi-tenancy via the Options pattern.

## Without Tenants

If your application does not use tenants (single-tenant mode), you can simply omit the tenant option when interacting with the stores. Ensure that your service is configured with tenant mode **disabled**.

```go
// Tenant mode disabled in configuration
// Calls to the store do not require WithTenant option
user, err := store.FindUserByEmail(ctx, "user@example.com")
if err != nil {
    // handle error
}
```

## With Tenants

When multi-tenancy is activated, every call to a stateful store MUST include the `WithTenant` option. If it is omitted, the store will return an error to prevent accidental data leaks across tenants.

```go
import "github.com/JLugagne/egauth/identity"

// Finding a user for a specific tenant
tenantID := "tenant_abc123"
user, err := store.FindUserByEmail(ctx, "user@example.com", identity.WithTenant(tenantID))
if err != nil {
    // handle error
}

// Creating a new user for a specific tenant
newUser, err := store.CreateUser(ctx, "new@example.com", identity.WithTenant(tenantID))
if err != nil {
    // handle error
}
```

### Constraints
In the database, uniqueness constraints reflect this partitioning. For example, a user's email is unique per tenant:
`UNIQUE(tenant_id, email)`
