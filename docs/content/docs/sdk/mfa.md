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

> **HTTP handlers are fail-closed.** If you mount `mfa.EnrollHandler` / `mfa.ConfirmHandler`, wire `mfa.WithCredentialAssurance(tokens.DenyInterim)` (otherwise they answer `403 assurance_required`, and an interim pre-MFA session could enrol a factor). `mfa.StepUpHandler` requires an authoritative `mfa.WithSessionStateResolver(...)` or answers `500 misconfigured`; the concrete service returned by `identity.NewService` implements `issuance.Resolver`, so assert it (`idSvc.(issuance.Resolver)`) or supply your own. `mfa.WithInsecureEchoSessionState()` restores the legacy echo behaviour only as an explicit, insecure opt-out. See [Security Hardening]({{< ref "security-hardening" >}}).

> **Note on Storage:** The TOTP shared secret must be re-evaluated by the server and cannot be hashed. For maximum security, configure your database with Transparent Data Encryption (TDE) or encrypt the secret at the application layer before passing it to `egauth`.

> **Single-tenant apps:** if you don't use tenants, wrap the service with `mfa.NewSingleTenant(mfaSvc)` to get the same methods without the `tenantID` argument.

---

## Passkeys (WebAuthn)

Passkeys eliminate passwords entirely by using the user's device (FaceID, TouchID, YubiKey) for cryptographic authentication.

`egauth` exposes HTTP Handlers for the Passkey ceremonies. The service is constructed from a `passkey.Config` struct and returns an error.

```go
import (
	"net/http"
	"os"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/passkey"
	passkeymem "github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

// The ceremony-cookie HMAC key must come from your environment or a secret manager —
// never hardcode it in source. passkey.NewService rejects keys shorter than 32 bytes,
// all-zero/repeated-byte keys, and any key copied from a published example or doc.
cookieKey := []byte(os.Getenv("EGAUTH_PASSKEY_COOKIE_KEY")) // crypto/rand-generated, >= 32 bytes

passkeySvc, err := passkey.NewService(passkeyStore, passkey.Config{
	RPID:             "myapp.com",
	RPDisplayName:    "MyApp",
	RPOrigins:        []string{"https://myapp.com"},
	UserVerification: protocol.VerificationRequired, // also the zero-value default
	CookieKey:        cookieKey,                      // required; fail-fast if unset/too short/trivial/published
	ChallengeStore:   passkeymem.NewChallengeStore(), // required: single-use server-side replay protection
})
if err != nil {
	// ErrCookieKeyMissing / ErrChallengeStoreMissing fail here, at startup.
}

// Registration is gated fail-closed: without an assurance gate these answer
// 403 assurance_required. tokens.DenyInterim refuses only an interim (pre-MFA) session,
// so a stolen password cannot enrol an attacker authenticator.
regOpts := []passkey.HandlerOption{
	passkey.WithUserResolver(resolveUser), // your resolver
	passkey.WithCredentialAssurance(tokens.DenyInterim),
}
mux.Handle("/passkey/register/begin", passkey.BeginRegistrationHandler(passkeySvc, regOpts...))
mux.Handle("/passkey/register/finish", passkey.FinishRegistrationHandler(passkeySvc, regOpts...))

// Login endpoints. The success callback is wired via WithLoginSuccess; its
// userID argument is a uuid.UUID.
mux.Handle("/passkey/login/begin", passkey.BeginLoginHandler(passkeySvc, passkey.WithUserResolver(resolveUser)))
mux.Handle("/passkey/login/finish", passkey.FinishLoginHandler(passkeySvc,
	passkey.WithUserResolver(resolveUser),
	passkey.WithLoginSuccess(func(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
		// Successfully logged in via Passkey! Issue your JWT/Session here.
	}),
))

// REQUIRED for account recovery: a password reset / change or account deletion must
// evict the user's passkeys. Register the eraser (and the token revoker) on the
// identity service.
identitySvc := identity.NewService(idStore, hasher, passwordPolicy,
	identity.WithAccountErasers(
		tokens.NewAccountRevoker(tokenStore), // refresh families + API keys
		passkeySvc.AccountEraser(),           // every passkey the user registered
	))
```

> **Security Note:** the passkey `CookieKey` must never be hardcoded or copied from documentation — a key published anywhere is attacker-known, and `passkey.NewService` rejects such values outright (trivial all-zero/repeated-byte keys, published-example literals and near-copies too). Generate a unique 32-byte key with `crypto/rand` and load it at startup from your secret manager (environment variable, vault). Keys shorter than `passkey.MinCookieKeyLength` (32 bytes) are also rejected.

`Config.UserVerification` controls whether the authenticator must prove user presence with a PIN/biometric; it defaults to `protocol.VerificationRequired`, so an assertion whose UV flag is unset is rejected at Finish across registration, login and discoverable login. Relax it to `VerificationPreferred`/`VerificationDiscouraged` only for a flow where another factor already authenticated the user. `Config.ChallengeStore` keeps each ceremony challenge single-use server-side; back it with a shared store (e.g. Redis) in a load-balanced deployment. See [Security Hardening]({{< ref "security-hardening" >}}) for depth on both.

> **Single-tenant apps:** `passkey.NewSingleTenant(passkeySvc)` exposes the service methods without the `tenantID` argument.
