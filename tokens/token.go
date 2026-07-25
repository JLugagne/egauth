package tokens

import (
	"time"

	"github.com/JLugagne/egauth"
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
	// Kind records the principal classification of the credential that produced this token.
	// It is set by the issuer when minting API-key-backed tokens (PAT or Service) and is used
	// by actorFromClaims to propagate the classification into the egauth.Actor so that the
	// WithRequiredKind middleware gate can enforce it. Interactive tokens (IssueTokenPair)
	// leave Kind at its zero value, which actorFromClaims treats as egauth.User (human).
	// The zero value is therefore the safe default and fully backward-compatible.
	Kind     egauth.PrincipalKind
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
	// Interim marks a PRE-STEP-UP credential: the subject cleared a FIRST factor (password, magic
	// link, federated IdP) but has NOT yet completed the second factor their account requires. It
	// is stamped by the MFA-gated login paths (identity.WithMFAGate, oauth.WithMFAGate) and is NOT
	// an ordinary session: RequireAuth and ContextMiddleware reject an interim credential with 403
	// "step_up_required" unless the route explicitly opts in with WithInterimAllowed (mount that
	// ONLY on the step-up route), and the factor-mutating / destructive handlers refuse it outright.
	// It is cleared only by completing the second factor (mfa.StepUpHandler re-issues a full pair),
	// never by refreshing: an interim credential is issued without a refresh token.
	Interim bool
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

// HasStepUpFactor reports whether amr (RFC 8176) records a verified SECOND — or single strong,
// phishing-resistant — factor. It accepts AMRMFA, AMROTP and AMRWebAuthn. AMRPassword alone is
// not a second factor and never satisfies it, so a password-only (or pre-step-up) credential
// fails closed.
func HasStepUpFactor(amr []string) bool {
	for _, v := range amr {
		switch v {
		case AMRMFA, AMROTP, AMRWebAuthn:
			return true
		}
	}
	return false
}

// SatisfiesStepUp reports whether these claims prove a completed second factor: the credential is
// not an Interim (pre-step-up) one AND its AMR records a step-up factor (see HasStepUpFactor). It
// is the predicate the factor-mutating and destructive handlers enforce (mfa.DisableHandler,
// mfa.RegenerateRecoveryCodesHandler, identity.DeleteAccountHandler), so stripping or resetting a
// second factor requires a token that carries one.
func (c Claims[C]) SatisfiesStepUp() bool {
	return !c.Interim && HasStepUpFactor(c.AMR)
}

// AsInterim returns a copy of c stamped as a short-lived PRE-STEP-UP interim credential: Interim is
// set, every step-up factor marker is stripped from AMR (so an AMR gate can never be satisfied by a
// credential that has not completed the second factor) and ExpiresAt is set to ttl from now. A
// non-positive ttl leaves ExpiresAt untouched. Issue the result with an AccessTokenIssuer (or
// discard the refresh half) — an interim credential must never be renewable.
func (c Claims[C]) AsInterim(ttl time.Duration) Claims[C] {
	c.Interim = true
	if len(c.AMR) > 0 {
		kept := make([]string, 0, len(c.AMR))
		for _, v := range c.AMR {
			switch v {
			case AMRMFA, AMROTP, AMRWebAuthn:
				continue
			default:
				kept = append(kept, v)
			}
		}
		c.AMR = kept
	}
	if ttl > 0 {
		c.ExpiresAt = time.Now().Add(ttl)
	}
	return c
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
	// RevokedAt is the soft-revoke marker: nil means the key is active. When set, the key has
	// been administratively revoked. The store still returns a revoked key from
	// FindAPIKeyByHash with RevokedAt populated; the verify layer decides to reject it (mapping
	// RevokedAt to ErrAPIKeyRevoked) so revoked keys stay visible to management tooling and
	// produce a distinct error from not-found.
	RevokedAt *time.Time
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
