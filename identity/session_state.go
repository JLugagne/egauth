package identity

import (
	"context"

	"github.com/JLugagne/egauth/issuance"
	"github.com/google/uuid"
)

// SessionStateReader is the authoritative account-state capability the session-issuing handlers
// feed to the issuance pipeline. The Service returned by NewService implements it. A custom
// Service implementation must provide it (or the handler must be configured with
// WithSessionStateResolver) so every issued session is checked against the live account state,
// not just the state observed when the credential was verified.
//
// The resolver answers from the store at issuance time: a soft-deleted user is reported Deleted,
// an administratively suspended user Disabled, and MustChangePassword is resolved from the
// credential itself. Cross-tenant lookups fail rather than resolving into the wrong partition.
type SessionStateReader interface {
	ResolveSessionState(ctx context.Context, tenantID string, userID uuid.UUID) (issuance.State, error)
}

var _ SessionStateReader = (*service)(nil)

// ResolveSessionState implements SessionStateReader against the identity store.
func (s *service) ResolveSessionState(ctx context.Context, tenantID string, userID uuid.UUID) (issuance.State, error) {
	user, err := s.store.FindUserByID(ctx, tenantID, userID)
	if err != nil {
		return issuance.State{}, err
	}
	if user == nil {
		return issuance.State{}, ErrUserNotFound
	}
	// The store scopes lookups by tenant, but guard the binding explicitly too: a store that
	// returns a record carrying another tenant's ID must fail closed rather than let the
	// pipeline mint into the requested partition.
	if user.TenantID != "" && user.TenantID != tenantID {
		return issuance.State{}, ErrTenantMismatch
	}
	state := issuance.State{
		UserID:   user.ID,
		TenantID: tenantID,
		Disabled: user.DisabledAt != nil,
		Deleted:  user.DeletedAt != nil,
	}
	// A deleted account is rejected by the pipeline regardless, and its credential rows are
	// already anonymized, so skip the forced-change lookup for it.
	if !state.Deleted {
		mustChange, err := s.PasswordChangeRequired(ctx, tenantID, userID)
		if err != nil {
			return issuance.State{}, err
		}
		state.MustChangePassword = mustChange
	}
	return state, nil
}
