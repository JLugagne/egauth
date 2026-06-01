---
title: "Tenants"
weight: 7
---

# Multi-Tenancy

`egauth` was built from the ground up to support native multi-tenancy. Every stateful operation across all modules (Identity, Tokens, Sessions, MFA) requires a Tenant ID. This physically guarantees isolation and prevents Cross-Tenant Insecure Direct Object References (IDORs).

## Explicit Tenancy

When calling any service method, the `tenantID` is explicitly passed as the second argument (immediately following the `context.Context`).

```go
user, err := identityService.Register(
	ctx, 
	"org-abc-123", // the tenantID
	"bob@example.com", 
	"Password123!", 
)
```

## Single-Tenant Mode

If your application does not require multi-tenancy, the empty string `""` acts as the valid default partition.

To avoid passing `""` everywhere, each module provides a `NewSingleTenant` facade that automatically wraps the service and strips away the `tenantID` argument from the method signatures.

```go
// 1. Create the core service
svc := identity.NewService(store, hasher, policy)

// 2. Wrap it in the SingleTenant facade
app := identity.NewSingleTenant(svc) 

// 3. Call methods without the tenant argument!
user, err := app.Register(ctx, "bob@example.com", "Password123!")
```
