---
title: "MFA and TOTP"
weight: 6
---

# Multi-Factor Authentication (MFA)

`egauth` offers robust Multi-Factor Authentication through Time-Based One-Time Passwords (TOTP) following RFC 6238, as well as Recovery Codes. 

## Initializing the MFA Service

The MFA Service handles enrolling factors, verifying codes, managing recovery codes, and securely tracking the `LastUsedStep` to prevent replay attacks.

```go
import (
    "github.com/JLugagne/egauth/mfa"
    "github.com/JLugagne/egauth/mfa/pgx"
)

// 1. Initialize the MFA Store
mfaStore := pgx.NewStore(dbPool)

// 2. Create the Service
mfaService := mfa.NewService(
    mfaStore,
    mfa.WithIssuer("MyAwesomeApp"),
    mfa.WithEventSink(myAuditLogger), // Optional: automatically emit security events
)
```

## Enrolling a User

To set up MFA, you generate an enrollment URI (which you display to the user as a QR code) and then require them to verify it.

```go
// 1. Begin Enrollment
enrollment, err := mfaService.EnrollTOTP(ctx, authUser.ID, authUser.Email, mfa.WithTenant("tenant-abc"))
if err != nil {
    // Handle error
}

// Send `enrollment.URI` to the frontend to render as a QR code.
// The enrollment remains inactive until confirmed.

// 2. Confirm Enrollment (once the user types the code from their authenticator app)
recoveryCodes, err := mfaService.ConfirmTOTP(ctx, authUser.ID, "123456", mfa.WithTenant("tenant-abc"))
if err != nil {
    // e.g., mfa.ErrInvalidCode
}

// Display the recoveryCodes to the user ONE TIME ONLY.
```

## Verifying a Code During Login

If your Identity Store indicates a user has MFA enabled, you must pause the login flow and require a TOTP code before issuing a final session or JWT.

```go
err := mfaService.VerifyTOTP(ctx, authUser.ID, "123456", mfa.WithTenant("tenant-abc"))
if err != nil {
    // Incorrect code, or the code was already used (Replay attack prevented!)
    http.Error(w, "Invalid Code", http.StatusUnauthorized)
    return
}

// Success! Issue the JWT or Stateful Session.
```

## Recovery Codes

If a user loses their device, they can use one of their one-time recovery codes to regain access.

```go
err := mfaService.VerifyRecoveryCode(ctx, authUser.ID, "a1b2c3d4", mfa.WithTenant("tenant-abc"))
if err != nil {
    // Handle invalid code
}

// Success! The code is consumed and can never be used again.
```
