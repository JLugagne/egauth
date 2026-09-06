package revocation

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// AccountRevocationHook is the narrow callback signature an account-scoped producing module uses
// after a mutation that should invalidate the user's live credentials (password changed or reset,
// account disabled or deleted). It matches the shape identity's post-mutation hooks already take,
// so wiring revocation into a service is a matter of passing this hook rather than restructuring
// the caller.
type AccountRevocationHook func(ctx context.Context, tenantID string, userID uuid.UUID) error

// NewAccountRevocationHook adapts a Bus into an AccountRevocationHook that publishes a
// user-scoped Revocation carrying the given reason and scope. CutoffTime is stamped with the
// current time so a subscriber can revoke only credentials issued before the triggering event,
// sparing (for example) the very session that just changed the password.
func NewAccountRevocationHook(bus Bus, reason Reason, scope Scope) AccountRevocationHook {
	return func(ctx context.Context, tenantID string, userID uuid.UUID) error {
		return bus.Publish(ctx, Revocation{
			TenantID:   tenantID,
			TargetType: TargetUser,
			TargetID:   userID.String(),
			Scope:      scope,
			Reason:     reason,
			CutoffTime: time.Now(),
		})
	}
}

// TenantRevocationHook is the narrow callback signature a tenant-scoped producing module uses
// after a mutation that should invalidate every credential in a tenant (tenant deactivated or
// deleted). It matches the shape keystore's TenantEraser-style hooks already take.
type TenantRevocationHook func(ctx context.Context, tenantID string) error

// NewTenantRevocationHook adapts a Bus into a TenantRevocationHook that publishes a tenant-scoped
// Revocation with ScopeAll (a tenant teardown revokes every credential kind), carrying the given
// reason and a current-time CutoffTime.
func NewTenantRevocationHook(bus Bus, reason Reason) TenantRevocationHook {
	return func(ctx context.Context, tenantID string) error {
		return bus.Publish(ctx, Revocation{
			TenantID:   tenantID,
			TargetType: TargetTenant,
			TargetID:   tenantID,
			Scope:      ScopeAll,
			Reason:     reason,
			CutoffTime: time.Now(),
		})
	}
}
