---
title: "MFA and Passkeys"
weight: 6
---

# Multi-Factor Authentication (MFA) & Passkeys

The `mfa` and `passkey` modules add strong, hardware-backed or application-backed second factors to your authentication flow.

## TOTP (Authenticator Apps)

The `mfa` module implements RFC 6238 Time-Based One-Time Passwords.

### Enrollment

When a user enables MFA, generate a secret and provide them with a URI to scan via a QR code.

```go
import "github.com/JLugagne/egauth/mfa"

mfaSvc := mfa.NewService(mfaStore, mfa.WithIssuer("MyApp"))

// 1. Begin Enrollment (takes tenantID as the second argument)
enrollment, err := mfaSvc.Enroll(ctx, "tenant-123", userID)

// 2. Show the URI as a QR Code to the user:
fmt.Println(enrollment.URI) // e.g., otpauth://totp/MyApp:alice@example.com?secret=JBSWY...
```

The enrollment remains pending until the user confirms they set it up correctly by providing the first code.

```go
err := mfaSvc.Confirm(ctx, "tenant-123", enrollment.ID, "123456")
if err == nil {
	// MFA is now fully enabled.
}
```

### Verification during Login

During the login flow, if the user requires MFA, you prompt them for a code.

```go
// Verify the 6-digit code
err := mfaSvc.Verify(ctx, "tenant-123", userID, "123456")

if err == nil {
	// Step-up authentication succeeded!
	// Issue a new token with the AMR claim set to "mfa"
}
```

> **Note on Storage:** The TOTP shared secret must be re-evaluated by the server and cannot be hashed. For maximum security, configure your database with Transparent Data Encryption (TDE) or encrypt the secret at the application layer before passing it to `egauth`.

---

## Passkeys (WebAuthn)

Passkeys eliminate passwords entirely by using the user's device (FaceID, TouchID, YubiKey) for cryptographic authentication.

`egauth` exposes HTTP Handlers for the Passkey ceremonies.

```go
import "github.com/JLugagne/egauth/passkey"

passkeySvc := passkey.NewService(passkeyStore, passkey.WithRelyingParty("MyApp", "myapp.com", "https://myapp.com"))

// Requires a random, stable 32-byte key to HMAC sign the ceremony cookies
cookieKey := []byte("very-secure-32-byte-secret-key!!")

// Registration endpoints
mux.Handle("/passkey/register/begin", passkey.BeginRegistrationHandler(passkeySvc, passkey.WithCookieKey(cookieKey)))
mux.Handle("/passkey/register/finish", passkey.FinishRegistrationHandler(passkeySvc, passkey.WithCookieKey(cookieKey)))

// Login endpoints
mux.Handle("/passkey/login/begin", passkey.BeginLoginHandler(passkeySvc, passkey.WithCookieKey(cookieKey)))
mux.Handle("/passkey/login/finish", passkey.FinishLoginHandler(passkeySvc, passkey.WithCookieKey(cookieKey), func(w http.ResponseWriter, r *http.Request, userID string) {
	// Successfully logged in via Passkey! Issue your JWT/Session here.
}))
```
