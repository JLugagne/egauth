package tokens

import (
	"context"

	"github.com/google/uuid"
)

// ClaimsProvider supplies fresh claims for a user during refresh-token rotation.
//
// The PRD mandates that refresh does not persist static claims alongside the refresh
// token; instead, fresh claims (and the user's current status) are resolved at rotation
// time. This interface is defined here, in the consuming package, so that the tokens
// module never has to import identity: the identity layer (or the application) implements
// it. This keeps the dependency edge pointing identity -> tokens and the graph acyclic.
type ClaimsProvider[C any] interface {
	// ClaimsForUser returns the current claims for the given user within the given tenant.
	// Returning an error (e.g. the user was disabled or deleted) aborts the rotation, so
	// the old token stays consumed and no new pair is issued.
	ClaimsForUser(ctx context.Context, userID uuid.UUID, tenantID string) (Claims[C], error)
}

// ClaimsProviderFunc adapts a plain function to the ClaimsProvider interface.
type ClaimsProviderFunc[C any] func(ctx context.Context, userID uuid.UUID, tenantID string) (Claims[C], error)

// ClaimsForUser calls f(ctx, userID, tenantID).
func (f ClaimsProviderFunc[C]) ClaimsForUser(ctx context.Context, userID uuid.UUID, tenantID string) (Claims[C], error) {
	return f(ctx, userID, tenantID)
}

// Rotator performs single-use refresh-token rotation.
//
// On a successful call the presented refresh token is consumed and a brand-new access +
// refresh pair is issued within the SAME rotation family. If an already-consumed token is
// presented (replay), the implementation MUST revoke the entire family and return
// ErrRefreshTokenReused.
type Rotator[C any] interface {
	// Rotate consumes refreshToken within the given tenant and returns a fresh token pair in
	// the same family.
	Rotate(ctx context.Context, tenantID string, refreshToken string) (*TokenPair[C], error)
}

var _ ClaimsProvider[any] = (ClaimsProviderFunc[any])(nil)
