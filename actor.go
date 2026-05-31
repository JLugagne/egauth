package egauth

import (
	"github.com/google/uuid"
)

// Actor represents the authenticated entity making a request.
// It is explicitly passed as an argument to handlers, never transported via context.Context.
type Actor struct {
	UserID   uuid.UUID
	TenantID string
	// Other fields like TeamID could be added here if needed by the applications.
}
