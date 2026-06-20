package tokens

import (
	"time"

	"github.com/google/uuid"
)

// Authentication Method Reference values (RFC 8176), used in Claims.AMR to record HOW the
// subject authenticated, so middleware can enforce step-up / AAL2 on sensitive routes.
const (
	AMRPassword = "pwd" // a password / passphrase was verified
	AMROTP      = "otp" // a one-time password (TOTP authenticator app) was verified
	AMRWebAuthn = "hwk" // a WebAuthn / passkey (hardware-backed key) was used
	AMRMFA      = "mfa" // multiple factors were verified in this session
)

// KeyType identifies the kind of API key, aligning with egauth.PrincipalKind at the
// Actor-construction boundary. Defined locally in the tokens package to avoid an import
// cycle: the tokens package is imported by the root egauth package, so tokens must not
// import egauth in return.
type KeyType string

const (
	// KeyTypePAT is a Personal Access Token acting on behalf of a human user.
	// At the Actor boundary it maps to egauth.PrincipalKind == PAT, and IsHuman() is true.
	KeyTypePAT KeyType = "pat"
	// KeyTypeService is a machine/service identity decoupled from any human.
	// At the Actor boundary it maps to egauth.PrincipalKind == Service, and IsMachine() is true.
	KeyTypeService KeyType = "service"
)

// Claims represents standard JWT claims plus custom generic claims.
type Claims[C any] struct {
	Subject  uuid.UUID
	TenantID string
	IssuedAt time.Time
	// AuthTime is when the subject last actually authenticated (OIDC "auth_time"). Unlike
	// IssuedAt it is NOT advanced by a silent refresh — it is preserved across rotation within a
	// family — so it anchors step-up / "sudo mode" freshness checks (see middleware
	// WithMaxAuthAge and Claims.FreshAuth). It is set at issuance (defaulting to the issue time)
	// and re-verified, never extended, by refresh.
	AuthTime  time.Time
	ExpiresAt time.Time
	Audiences []string
	Scopes    []string
	Groups    []string
	Roles     []string
	// AMR lists the authentication methods used to obtain this token (RFC 8176). It is set by
	// the application when issuing the pair (e.g. after a second factor) and is enforced by the
	// RequireAuth middleware via WithRequiredAMR. On refresh it is whatever the ClaimsProvider
	// returns, so the assurance level is re-evaluated rather than frozen at login.
	AMR []string
	// MustChangePassword is a first-class advisory flag telling the middleware the subject must
	// change their credential before proceeding. It is a soft gate: a flagged token still
	// authenticates, but RequireAuth (with WithPasswordChangeGate) soft-redirects to the reset page.
	// It is set at issuance for an admin-provisioned/temporary credential and is carried across
	// refresh: the flag is recorded on the RefreshToken family and Rotate replays it verbatim onto
	// every silent refresh, so a flagged session cannot escape the gate by waiting for the access
	// token to expire. Living here rather than inside Custom lets the middleware enforce it
	// generically.
	MustChangePassword bool
	Custom             C
}

// FreshAuth reports whether the subject authenticated within maxAge of now, anchored on AuthTime
// (OIDC auth_time). It backs step-up / "sudo mode" gating: a sensitive action requires a recent
// re-authentication. A non-positive maxAge means "no freshness requirement" (always fresh); a
// zero AuthTime is treated as stale (fails closed) whenever a positive maxAge is required.
func (c Claims[C]) FreshAuth(maxAge time.Duration) bool {
	if maxAge <= 0 {
		return true
	}
	if c.AuthTime.IsZero() {
		return false
	}
	return time.Since(c.AuthTime) <= maxAge
}

// TokenPair represents an access and refresh token pair.
type TokenPair[C any] struct {
	AccessToken           string
	RefreshToken          string
	RefreshTokenHash      string // SHA-256 hash of the refresh token for storage
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	Claims                Claims[C]
}

// APIKey represents a long-lived API access key.
type APIKey[C any] struct {
	ID        uuid.UUID
	TenantID  string
	Prefix    string // e.g., "sk_live_"
	Token     string // The clear text value (only available at creation)
	Hash      string // The hashed value (SHA-256) stored in DB
	ExpiresAt *time.Time
	// Type identifies whether the key is a PAT (personal access token acting on behalf of a
	// human) or a Service token (machine identity). It is chosen at issuance, persisted in the
	// store, and surfaced on the resulting Actor via egauth.PrincipalKind at the Actor-
	// construction boundary.
	Type KeyType
	// CreatedBy records the uuid of the human user who created the key. For PATs this is the
	// key owner. For service tokens the Subject in Claims is the key's own ID, so CreatedBy is
	// the only field tying the key back to the creating user.
	CreatedBy uuid.UUID
	Claims    Claims[C]
}

// RefreshToken represents a single-use refresh token belonging to a rotation family.
// Only the hash of the clear-text token is ever persisted.
type RefreshToken struct {
	Hash     string
	FamilyID uuid.UUID
	UserID   uuid.UUID
	TenantID string
	// AuthTime is when the subject authenticated to start this rotation family. It is set on the
	// initial pair and carried unchanged onto every rotated descendant, so a silent refresh does
	// not reset step-up freshness (see Claims.AuthTime).
	AuthTime time.Time
	// MustChangePassword records whether this rotation family is gated on a forced password change.
	// Like AuthTime it is set on the initial pair and carried unchanged onto every rotated
	// descendant: Rotate copies it verbatim onto the new token's claims (overriding the
	// ClaimsProvider), so a flagged session stays flagged across every silent refresh — a user
	// cannot escape the WithPasswordChangeGate by waiting for the access token to expire. It is
	// cleared only by minting a fresh family (a new login after the password has been changed).
	MustChangePassword bool
	ExpiresAt          time.Time
	CreatedAt          time.Time
	ConsumedAt         *time.Time
}
