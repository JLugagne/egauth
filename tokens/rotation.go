package tokens

import (
	"context"
	"time"

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

// RotationContext describes the refresh-token family being rotated. It is attached to the
// context passed to ClaimsProvider.ClaimsForUser during Rotate so a provider can identify the
// specific session/family it is re-evaluating rather than seeing only the user and tenant.
//
// This is what makes the documented "on refresh the AMR is re-evaluated, not frozen at login"
// semantics implementable: the provider can look up per-family state (e.g. the AMR/assurance
// the family originally proved) keyed by FamilyID, and can preserve or DOWNGRADE it, but it can
// no longer be forced to either silently decay a legitimately elevated session or blindly
// elevate every session of an MFA-enrolled user — both of which break the step-up gate.
//
// AuthTime mirrors the family's preserved authentication time (set on the initial pair and
// carried unchanged onto every rotated descendant); it is provided here so the provider sees
// the same freshness value the issuer will stamp on the rotated claims.
type RotationContext struct {
	// FamilyID is the rotation family the presented refresh token belongs to. It is stable
	// across every rotation within a single login session.
	FamilyID uuid.UUID
	// AuthTime is the family's preserved authentication time (may be zero for a legacy token).
	AuthTime time.Time
}

// rotationContextKey is the unexported context key under which the issuer stores the
// RotationContext for the duration of a single ClaimsForUser call.
type rotationContextKey struct{}

// WithRotationContext returns a copy of ctx carrying rc. The Rotator implementation calls this
// to inform the ClaimsProvider which refresh family is being rotated; application code does not
// normally need it.
func WithRotationContext(ctx context.Context, rc RotationContext) context.Context {
	return context.WithValue(ctx, rotationContextKey{}, rc)
}

// RotationContextFromContext extracts the RotationContext attached by the Rotator during refresh
// rotation. ok is false when ctx carries none (e.g. claims are being resolved outside of a
// rotation, or by an older issuer). Providers should treat a missing rotation context as "not a
// rotation" rather than failing.
func RotationContextFromContext(ctx context.Context) (rc RotationContext, ok bool) {
	rc, ok = ctx.Value(rotationContextKey{}).(RotationContext)
	return rc, ok
}
