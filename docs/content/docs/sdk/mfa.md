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
import (
	"github.com/JLugagne/egauth/mfa"
	"github.com/google/uuid"
)

mfaSvc := mfa.NewService(mfaStore, mfa.WithIssuer("MyApp"))

// 1. Begin enrollment. userID is a uuid.UUID; account is the label shown
//    in the authenticator (e.g. the user's email).
enrollment, err := mfaSvc.EnrollTOTP(ctx, "tenant-123", userID, "alice@example.com")
if err != nil {
	// handle error
}

// 2. Show the URI as a QR Code to the user (the raw Secret is also available
//    via enrollment.Secret for manual entry):
fmt.Println(enrollment.URI) // e.g., otpauth://totp/MyApp:alice@example.com?secret=JBSWY...
```

`mfa.NewService` also accepts options such as `WithDigits`, `WithPeriod`, `WithSkew`, and `WithRecoveryCodeCount`.

The enrollment remains pending until the user confirms they set it up correctly by providing the first code. Confirming returns a fresh set of single-use recovery codes — show them to the user once.

```go
recoveryCodes, err := mfaSvc.ConfirmTOTP(ctx, "tenant-123", userID, "123456")
if err == nil {
	// MFA is now fully enabled. Display recoveryCodes to the user.
}
```

### Verification during Login

During the login flow, if the user requires MFA, you prompt them for a code.

```go
// Verify the 6-digit code
err := mfaSvc.VerifyTOTP(ctx, "tenant-123", userID, "123456")

if err == nil {
	// Step-up authentication succeeded!
	// Issue a new token with the AMR claim set to "mfa"
}
```

A lost device is recovered with `mfaSvc.VerifyRecoveryCode(ctx, tenantID, userID, code)`, which consumes one of the codes issued at confirmation.

> **Note on Storage:** The TOTP shared secret must be re-evaluated by the server and cannot be hashed. For maximum security, configure your database with Transparent Data Encryption (TDE) or encrypt the secret at the application layer before passing it to `egauth`.

> **Single-tenant apps:** if you don't use tenants, wrap the service with `mfa.NewSingleTenant(mfaSvc)` to get the same methods without the `tenantID` argument.

---

## Passkeys (WebAuthn)

Passkeys eliminate passwords entirely by using the user's device (FaceID, TouchID, YubiKey) for cryptographic authentication.

`egauth` exposes HTTP Handlers for the Passkey ceremonies. The service is constructed from a `passkey.Config` struct and returns an error.

```go
import (
	"net/http"

	"github.com/JLugagne/egauth/passkey"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

passkeySvc, err := passkey.NewService(passkeyStore, passkey.Config{
	RPID:             "myapp.com",
	RPDisplayName:    "MyApp",
	RPOrigins:        []string{"https://myapp.com"},
	UserVerification: protocol.VerificationRequired,
})
if err != nil {
	// handle error
}

// Requires a random, stable 32-byte key to HMAC sign the ceremony cookies
cookieKey := []byte("very-secure-32-byte-secret-key!!")

// Registration endpoints
mux.Handle("/passkey/register/begin", passkey.BeginRegistrationHandler(passkeySvc, passkey.WithCookieKey(cookieKey)))
mux.Handle("/passkey/register/finish", passkey.FinishRegistrationHandler(passkeySvc, passkey.WithCookieKey(cookieKey)))

// Login endpoints. The success callback is wired via WithLoginSuccess; its
// userID argument is a uuid.UUID.
mux.Handle("/passkey/login/begin", passkey.BeginLoginHandler(passkeySvc, passkey.WithCookieKey(cookieKey)))
mux.Handle("/passkey/login/finish", passkey.FinishLoginHandler(passkeySvc,
	passkey.WithCookieKey(cookieKey),
	passkey.WithLoginSuccess(func(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
		// Successfully logged in via Passkey! Issue your JWT/Session here.
	}),
))
```

`Config.UserVerification` controls whether the authenticator must prove user presence with a PIN/biometric; setting `protocol.VerificationRequired` enforces it during both registration and login. For replay protection of one-time challenges across a cluster, supply a `passkey.ChallengeStore` via the `passkey.WithChallengeStore(...)` handler option. See [Security Hardening]({{< ref "security-hardening" >}}) for depth on both.

> **Single-tenant apps:** `passkey.NewSingleTenant(passkeySvc)` exposes the service methods without the `tenantID` argument.
