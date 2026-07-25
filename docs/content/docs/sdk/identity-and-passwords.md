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

Blocking new logins is not enough on its own: a user disabled mid-session still holds refresh tokens and API keys minted before the suspension. Ending their access takes **two** hooks, and either one alone leaves a hole.

First, register **disable revokers** when you build the service. `tokens.NewAccountRevoker` revokes a user's refresh tokens and API keys in one hook; add `sessions.Service.RevokeAllForUser` for sessions.

```go
revoker := tokens.NewAccountRevoker(tokenStore)
svc := identity.NewService(
	store, hasher, policy,
	// Revoke refresh tokens + API keys when an account is disabled...
	identity.WithDisableRevokers(revoker),
	// ...and on permanent deletion / password reset too.
	identity.WithAccountErasers(revoker),
)

// Stamps DisabledAt, emits AccountDisabled, then revokes the user's tokens and keys.
err := svc.DisableUser(ctx, "tenant-123", authUser.ID)
```

Second, make refresh-token **rotation** re-check account status. `Rotate` resolves fresh claims through the issuer's `ClaimsProvider`, and that provider is the only place a rotation can be refused — so wrap yours:

```go
issuer := jwtissuer.New(jwtissuer.Config[MyClaims]{
	// ...
	ClaimsProvider: identity.ActiveClaimsProvider(svc, myClaimsProvider),
})
```

`ActiveClaimsProvider` calls `Service.EnsureActive` and returns `ErrAccountDisabled` / `ErrUserNotFound`, which aborts the rotation; `RefreshHandler` then answers `401` and clears the auth cookies. Skip it and a suspended user refreshes **forever**: every rotation resets the refresh expiry to `now+RefreshTTL`, so access is renewed rather than merely retained.

The `DisabledAt` stamp is written **first** (fail-closed: the account is blocked even if a downstream revoker errors), and any revoker error is returned so you can retry — the revokers are idempotent. With neither hook wired, `DisableUser` still blocks new logins but leaves already-issued refresh families live and rotatable. One thing survives even a fully wired disable: an already-issued access token, until it expires — it is a stateless JWT, so keep `AccessTTL` short.

If your composition root only receives an already-built `identity.Service` (a DI container, or `webapp.NewWebApp`), register the hooks through `identity.RevocationRegistry` — `RegisterDisableRevokers` / `RegisterAccountErasers` — during wiring. `webapp.NewWebApp` does exactly that, plus the `ActiveClaimsProvider` wrap, and refuses to build if it cannot.

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
