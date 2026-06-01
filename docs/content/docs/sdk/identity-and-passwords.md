---
title: "Identity and Passwords"
weight: 2
---

# Identity and Passwords

The Identity module is the heart of user management. It securely handles user creation, soft-deletion, and authentication (verifying credentials).

## Registering a User

When registering a user, the `identity.Service` hashes the password using your configured `Hasher` (e.g., Argon2) and enforces the `Policy` you defined (length, symbols, etc.). 

If you are using multi-tenancy, you must specify the tenant via `identity.WithTenant`. If you are running a single-tenant application, simply omit the tenant option.

```go
// Example: Registering a user inside a specific tenant
user, err := identityService.Register(
    ctx, 
    "alice@example.com", 
    "StrongPassword123!", 
    identity.WithTenant("tenant-abc"),
)

if err != nil {
    // Handle error (e.g. email already exists, weak password)
}
fmt.Printf("User created with ID: %s\n", user.ID)
```

## Authenticating a User

To log a user in, use the `Authenticate` method. It will retrieve the identity and safely compare the hashes.

```go
// Authenticate using the "password" provider
authUser, err := identityService.Authenticate(
    ctx, 
    "password", 
    "alice@example.com", 
    "StrongPassword123!", 
    identity.WithTenant("tenant-abc"),
)

if err != nil {
    // Handle error (e.g., identity.ErrInvalidCredentials)
    return
}
fmt.Println("User authenticated successfully!")
```

## User Lifecycle and Soft-Deletes

If a user requests account deletion, `egauth` supports soft-deletes via the store. This anonymizes the email address to remain GDPR-compliant, while allowing the user to sign up again with the exact same email later.

```go
// Deleting a user
err = store.DeleteUser(ctx, authUser.ID, identity.WithTenant("tenant-abc"))
if err != nil {
    // Handle error
}
```
