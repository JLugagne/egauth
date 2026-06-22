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

## User Lifecycle: Disabling Accounts

`DisableUser` administratively suspends an account: it blocks new logins (`Authenticate` returns `ErrAccountDisabled`) and stops the account from consuming verification tokens. Unlike deletion it is **reversible** with `EnableUser` — so enrollment data (MFA secrets, passkeys) is intentionally preserved.

Blocking new logins is not enough on its own: a user disabled mid-session still holds refresh tokens and API keys minted before the suspension. To kill those immediately, register **disable revokers** when you build the service. `tokens.NewAccountRevoker` revokes a user's refresh tokens and API keys in one hook; add `sessions.Service.RevokeAllForUser` for sessions.

```go
svc := identity.NewService(
	store, hasher, policy,
	// Revoke refresh tokens + API keys when an account is disabled.
	identity.WithDisableRevokers(tokens.NewAccountRevoker(tokenStore)),
)

// Stamps DisabledAt, emits AccountDisabled, then revokes the user's tokens and keys.
err := svc.DisableUser(ctx, "tenant-123", authUser.ID)
```

The `DisabledAt` stamp is written **first** (fail-closed: the account is blocked even if a downstream revoker errors), and any revoker error is returned so you can retry — the revokers are idempotent. Without revokers wired, `DisableUser` still blocks new logins but leaves already-issued tokens valid until they expire.

> Use `WithDisableRevokers` (not `WithAccountErasers`) for disable: erasers run on permanent `DeleteAccount` and may destroy MFA/passkey enrollment, which a reversible disable must keep.

## Password Resets

The Identity module handles generating secure password reset tokens. `identity.Mailer` is a struct of delivery callbacks (one per flow, e.g. `PasswordReset`) that you supply to actually deliver the email — egauth never sends mail itself. Programmatic callers can skip the Mailer entirely and use the token returned directly by `RequestPasswordReset`.

```go
// 1. Generate the token (Decoy enabled: returns no error if user doesn't exist)
token, _, err := identityService.RequestPasswordReset(ctx, "tenant-123", "bob@example.com")

// 2. In your Mailer.PasswordReset callback, send the reset link:
// https://yourapp.com/reset?token=<token>

// 3. Complete the reset
err = identityService.ResetPassword(ctx, "tenant-123", tokenFromURL, "NewSecurePassword123!")
```
