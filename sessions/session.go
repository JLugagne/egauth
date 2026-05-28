package sessions

import (
	"time"

	"github.com/google/uuid"
)

// Session represents a user session.
type Session struct {
	ID        uuid.UUID
	TenantID  string
	UserID    uuid.UUID
	TokenHash string    // Hash (SHA-256) of the session token stored on the client
	UserAgent string
	IP        string
	ExpiresAt time.Time
	CreatedAt time.Time
}
