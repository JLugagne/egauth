---
title: "Identity and Passwords"
weight: 2
---

# Identity and Passwords

The `identity` module safely manages user accounts, credentials, password resetting, and GDPR-compliant soft-deletion.

## Registering Users

Registration automatically hashes passwords using your configured KDF (e.g., Argon2id) and validates complexity against your policy. Every stateful operation takes a `tenantID` string as its second argument.

```go
user, err := identityService.Register(
	ctx, 
	"tenant-123", // Tenant isolation is natively required for all stateful operations
	"alice@example.com", 
	"CorrectHorseBatteryStaple!", 
)

if err != nil {
	// Errors like ErrEmailAlreadyExists or password policy failures are returned here
	log.Println("Registration failed:", err)
	return
}

fmt.Printf("Registered user %s successfully", user.ID)
```

## Authentication & Decoy Hashing

To authenticate a user, call `Authenticate()`. This method implements decoy hashing, ensuring that the response time is indistinguishable whether the user exists or not, preventing username enumeration attacks.

```go
authUser, err := identityService.Authenticate(
	ctx, 
	"tenant-123",
	"password", // Authentication Provider type
	"alice@example.com", 
	"CorrectHorseBatteryStaple!", 
)

if err != nil {
	// Never reveal IF the user exists to the client
	http.Error(w, "invalid email or password", http.StatusUnauthorized)
	return
}
```

## User Lifecycle: Soft Deletes

For compliance (like GDPR), deleting a user anonymizes their Personally Identifiable Information (PII) rather than dropping the row entirely, which protects your database's relational integrity.

```go
err := identityService.DeleteAccount(ctx, "tenant-123", authUser.ID)
// The user's email is replaced with a random UUID, and their credentials are wiped.
```

## Password Resets

The Identity module handles generating secure password reset tokens. You must implement the `identity.Mailer` interface to actually deliver the email.

```go
// 1. Generate the token (Decoy enabled: returns no error if user doesn't exist)
token, _, err := identityService.RequestPasswordReset(ctx, "tenant-123", "bob@example.com")

// 2. In your Mailer implementation, send the reset link:
// https://yourapp.com/reset?token=<token>

// 3. Complete the reset
err = identityService.ResetPassword(ctx, "tenant-123", tokenFromURL, "NewSecurePassword123!")
```
