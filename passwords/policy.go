package passwords

import (
	"context"
)

// Policy defines the contract for validating password strength requirements.
type Policy interface {
	// Verify checks if the provided password meets the policy requirements.
	// It returns nil if the policy is met, or an error (e.g., ErrPasswordTooShort) otherwise.
	Verify(ctx context.Context, password string) error
}
