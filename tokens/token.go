package tokens

import (
	"time"

	"github.com/google/uuid"
)

// Claims represents standard JWT claims plus custom generic claims.
type Claims[C any] struct {
	Subject   uuid.UUID
	TenantID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Audiences []string
	Scopes    []string
	Groups    []string
	Roles     []string
	Custom    C
}

// TokenPair represents an access and refresh token pair.
type TokenPair[C any] struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	Claims                Claims[C]
}

// APIKey represents a long-lived API access key.
type APIKey[C any] struct {
	ID        uuid.UUID
	TenantID  string
	Prefix    string     // e.g., "sk_live_"
	Token     string     // The clear text value (only available at creation)
	Hash      string     // The hashed value (SHA-256) stored in DB
	ExpiresAt *time.Time
	Claims    Claims[C]
}
