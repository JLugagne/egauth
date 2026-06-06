// Package passkey implements WebAuthn / FIDO2 passkeys (registration and login ceremonies) on
// top of the go-webauthn library, following egauth's conventions: a credential Store
// (memory + pgx implementations with a shared contract), a Service that runs the ceremonies,
// and à-la-carte HTTP handlers. The ceremony challenge (SessionData) is carried between the
// Begin and Finish steps in a short-lived, HMAC-signed secure cookie (the signing key is
// supplied via Config.CookieKey and verified before the data is trusted), so the server stays
// stateless between the two calls without letting the client tamper with the challenge or the
// user-verification requirement.
//
// # Passwordless / step-up hardening checklist
//
// The package is SECURE BY DEFAULT: NewService fails fast on a misconfigured passwordless or
// step-up setup rather than degrading silently. For a secure deployment:
//
//   - Config.CookieKey — REQUIRED. A stable, random secret of at least MinCookieKeyLength (32)
//     bytes. NewService returns ErrCookieKeyMissing if it is unset or too short. The cookie is
//     trusted state (challenge + UV requirement); an unauthenticated cookie is forgeable.
//   - Config.ChallengeStore — REQUIRED. Provides single-use, server-side replay protection so a
//     captured raw Finish request cannot be replayed within the cookie TTL. NewService returns
//     ErrChallengeStoreMissing unless it is set or the explicit opt-out
//     Config.InsecureNoChallengeStore is true (cookie-only protection — do not use for
//     passwordless). The memory and pgx subpackages provide implementations.
//   - Config.UserVerification — defaults to protocol.VerificationRequired (UV enforced). Leave
//     it at the zero value for passwordless/step-up; set it explicitly to
//     protocol.VerificationPreferred/Discouraged ONLY for a flow where another factor already
//     authenticated the user.
//   - Serve over HTTPS so the Secure ceremony cookie is sent. WithInsecureCookies is for local
//     HTTP development only.
//   - Rate-limit ceremony attempts in front of the handlers (egauth does not throttle them).
package passkey

import (
	"time"

	"github.com/google/uuid"
)

// Credential is a stored WebAuthn credential record for a user. Data holds the full
// go-webauthn Credential serialized as JSON (the source of truth used to rebuild the
// authenticator state); ID/PublicKey/SignCount are denormalized for indexing and display.
type Credential struct {
	UserID    uuid.UUID
	TenantID  string
	ID        []byte // credential ID (raw bytes); unique per user
	PublicKey []byte
	SignCount uint32
	Data      []byte // JSON of webauthn.Credential
	CreatedAt time.Time
}
