---
title: "Tenants"
weight: 7
---

# Multi-Tenancy

`egauth` was built from the ground up to support native multi-tenancy. Every stateful operation across all modules (Identity, Tokens, Sessions, MFA) requires a Tenant ID. This physically guarantees isolation and prevents Cross-Tenant Insecure Direct Object References (IDORs).

## Explicit Tenancy

When calling any service method, inject the tenant context via the functional option.

```go
user, err := identityService.Register(
	ctx, 
	"bob@example.com", 
	"Password123!", 
	identity.WithTenant("org-abc-123"), 
)
```

## Single-Tenant Mode

If your application does not require multi-tenancy, you can safely use the predefined "Single Tenant" wrappers, which automatically inject an empty string `""` partition into all database queries under the hood.

```go
// identity.SingleTenant() acts as the default partition.
user, err := identityService.Register(
	ctx, 
	"bob@example.com", 
	"Password123!", 
	identity.SingleTenant(),
)
```
