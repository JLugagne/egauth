package passkey

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
)

// AccountGate is the account-lifecycle chokepoint consulted by the login ceremonies. Given
// the tenant and the user the ceremony resolved, it returns nil when the account is live, or
// an error when the login must be refused: ErrAccountDisabled for a suspended account,
// ErrAccountDeleted for a deleted one, or any other error for a gate/infrastructure failure
// (which fails the request closed). Wire it via Config.AccountGate, typically with
// NewIdentityAccountGate(identityStore).
type AccountGate func(ctx context.Context, tenantID string, userID uuid.UUID) error

// NewIdentityAccountGate adapts an identity.UserStore to the AccountGate lifecycle check,
// mirroring authflow.NewIdentityAccountValidator. It refuses the login with ErrAccountDeleted
// when the account is soft-deleted (DeletedAt set) or the store cannot find it (hard-deleted,
// unknown or cross-tenant), and with ErrAccountDisabled when it is administratively suspended
// (DisabledAt set — the reversible DisableUser state that preserves passkey enrollment by
// design). Other store errors are returned unchanged so a transient infrastructure failure
// fails closed (HTTP 500) rather than masquerading as a lifecycle outcome.
func NewIdentityAccountGate(store identity.UserStore) AccountGate {
	return func(ctx context.Context, tenantID string, userID uuid.UUID) error {
		user, err := store.FindUserByID(ctx, tenantID, userID)
		if err != nil {
			if errors.Is(err, identity.ErrUserNotFound) {
				return ErrAccountDeleted
			}
			return err
		}
		if user == nil || user.DeletedAt != nil {
			return ErrAccountDeleted
		}
		if user.DisabledAt != nil {
			return ErrAccountDisabled
		}
		return nil
	}
}

// checkAccountGate consults the configured lifecycle gate, if any. A nil gate (passkey
// deployed without the identity module) allows the login unchanged.
func (s *Service) checkAccountGate(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if s.accountGate == nil {
		return nil
	}
	return s.accountGate(ctx, tenantID, userID)
}

// emitLifecycleBlocked records an AccountBlocked audit event when the lifecycle gate refuses
// an otherwise-valid assertion, so operators see an authentication attempt by a suspended or
// deleted principal. Non-lifecycle gate errors (infrastructure failures) emit nothing.
func (s *Service) emitLifecycleBlocked(ctx context.Context, tenantID string, userID uuid.UUID, gateErr error) {
	var reason string
	switch {
	case errors.Is(gateErr, ErrAccountDisabled):
		reason = "account_disabled"
	case errors.Is(gateErr, ErrAccountDeleted):
		reason = "account_deleted"
	default:
		return
	}
	s.emit(ctx, event.Event{
		Type:     event.AccountBlocked,
		UserID:   userID.String(),
		TenantID: tenantID,
		Reason:   reason,
	})
}
