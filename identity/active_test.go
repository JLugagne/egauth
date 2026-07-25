package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnsureActive_ReportsAccountLifecycle pins the status gate long-lived credential paths rely
// on: live accounts pass, administratively suspended ones report ErrAccountDisabled, and unknown,
// cross-tenant or soft-deleted ones report ErrUserNotFound.
func TestEnsureActive_ReportsAccountLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "active_gate@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	assert.NoError(t, svc.EnsureActive(ctx, "", user.ID), "a live account must pass the gate")

	assert.ErrorIs(t, svc.EnsureActive(ctx, "", uuid.Must(uuid.NewV7())), identity.ErrUserNotFound,
		"an unknown user must not pass the gate")
	assert.ErrorIs(t, svc.EnsureActive(ctx, "other-tenant", user.ID), identity.ErrUserNotFound,
		"a cross-tenant user must not pass the gate")

	require.NoError(t, svc.DisableUser(ctx, "", user.ID))
	assert.ErrorIs(t, svc.EnsureActive(ctx, "", user.ID), identity.ErrAccountDisabled,
		"a suspended account must report ErrAccountDisabled")

	require.NoError(t, svc.EnableUser(ctx, "", user.ID))
	assert.NoError(t, svc.EnsureActive(ctx, "", user.ID), "re-enabling must restore the gate")

	require.NoError(t, svc.DeleteAccount(ctx, "", user.ID))
	assert.ErrorIs(t, svc.EnsureActive(ctx, "", user.ID), identity.ErrUserNotFound,
		"a soft-deleted account must report ErrUserNotFound")
}

// TestActiveClaimsProvider_RefusesInactiveAccounts proves the wrapper aborts refresh-token
// rotation for a suspended or deleted account (and only then), which is the only point at which a
// rotation can be refused.
func TestActiveClaimsProvider_RefusesInactiveAccounts(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "rotation_gate@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	var innerCalls int
	inner := tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
		innerCalls++
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
	})
	provider := identity.ActiveClaimsProvider(svc, inner)

	claims, err := provider.ClaimsForUser(ctx, user.ID, "")
	require.NoError(t, err, "a live account must still refresh")
	assert.Equal(t, user.ID, claims.Subject)
	assert.Equal(t, 1, innerCalls)

	require.NoError(t, svc.DisableUser(ctx, "", user.ID))
	_, err = provider.ClaimsForUser(ctx, user.ID, "")
	assert.ErrorIs(t, err, identity.ErrAccountDisabled,
		"rotation must be aborted for a suspended account")
	assert.Equal(t, 1, innerCalls, "the wrapped provider must not run for an inactive account")

	require.NoError(t, svc.DeleteAccount(ctx, "", user.ID))
	_, err = provider.ClaimsForUser(ctx, user.ID, "")
	assert.ErrorIs(t, err, identity.ErrUserNotFound,
		"rotation must be aborted for a deleted account")
}

// TestRevocationRegistry_RegistersHooksAfterConstruction proves the post-construction seam a
// composition root needs when it only receives an already-built Service: hooks registered through
// it run exactly as WithDisableRevokers / WithAccountErasers would have.
func TestRevocationRegistry_RegistersHooksAfterConstruction(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	registry, ok := svc.(identity.RevocationRegistry)
	require.True(t, ok, "the Service returned by NewService must implement RevocationRegistry")

	var revoked, erased []uuid.UUID
	registry.RegisterDisableRevokers(func(_ context.Context, _ string, userID uuid.UUID) error {
		revoked = append(revoked, userID)
		return nil
	})
	registry.RegisterAccountErasers(func(_ context.Context, _ string, userID uuid.UUID) error {
		erased = append(erased, userID)
		return nil
	})

	user, err := svc.Register(ctx, "", "registry@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	require.NoError(t, svc.DisableUser(ctx, "", user.ID))
	assert.Equal(t, []uuid.UUID{user.ID}, revoked, "DisableUser must run a late-registered revoker")
	assert.Empty(t, erased, "DisableUser must not run the account erasers")

	require.NoError(t, svc.DeleteAccount(ctx, "", user.ID))
	assert.Equal(t, []uuid.UUID{user.ID}, erased, "DeleteAccount must run a late-registered eraser")
}
