package tokens

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
)

// APIKey is a long-lived key owned by a subject. It carries no session state, only the claims
// subset requested at creation (AppClaims, encoded) and the owner's security epoch at that time
// (CreatedEpoch); the effective claims are recomputed from the owner at verification. A zero
// ExpiresAt never expires; a non-zero RevokedAt marks a soft-revoked key that the store still
// returns.
type APIKey struct {
	ID           uuid.UUID
	Owner        principal.Subject
	Kind         string
	Name         string
	KeyHash      []byte
	AppClaims    []byte
	CreatedEpoch uint64
	CreatedAt    time.Time
	ExpiresAt    time.Time
	RevokedAt    time.Time
}

// MaxAPIKeyLabelLen bounds APIKey.Kind and APIKey.Name, in bytes.
const MaxAPIKeyLabelLen = 128

// Validate returns ErrInvalidRecord unless k is complete: stores call it before persisting a key.
func (k APIKey) Validate() error {
	var problem string
	switch {
	case k.ID == uuid.Nil:
		problem = "id is required"
	case k.Owner.IsZero():
		problem = "owner is required"
	case k.Kind == "" || len(k.Kind) > MaxAPIKeyLabelLen || len(k.Name) > MaxAPIKeyLabelLen:
		problem = "kind is required and labels are bounded"
	case len(k.KeyHash) != HashLen:
		problem = "key hash must be a SHA-256 digest"
	case len(k.AppClaims) > MaxAppClaimsLen:
		problem = "application claims are too large"
	case k.CreatedAt.IsZero():
		problem = "creation time is required"
	case !k.ExpiresAt.IsZero() && !k.ExpiresAt.After(k.CreatedAt):
		problem = "expiry must fall after creation"
	default:
		return nil
	}
	return errors.Join(ErrInvalidRecord, errors.New(problem))
}
