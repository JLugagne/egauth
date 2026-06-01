package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSingleTenantSvc(t *testing.T) (*identity.SingleTenant, identity.Service) {
	t.Helper()
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) { return "h:" + p, nil },
		CompareFunc: func(ctx context.Context, hash, p string) error {
			if hash != "h:"+p {
				return identity.ErrInvalidCredentials
			}
			return nil
		},
	}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
	svc := identity.NewService(store, hasher, policy)
	return identity.NewSingleTenant(svc), svc
}

// SingleTenant.Register must delegate to the empty tenant, so the account is reachable via a
// plain empty-tenant Authenticate.
func TestSingleTenant_Register_UsesEmptyTenant(t *testing.T) {
	ctx := context.Background()
	st, svc := newSingleTenantSvc(t)

	u, err := st.Register(ctx, "user@example.com", "pw")
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, "", u.TenantID, "SingleTenant writes to the empty default partition")

	// Authenticating on the empty tenant (what SingleTenant does internally) finds it.
	got, err := st.Authenticate(ctx, "password", "user@example.com", "pw")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	// And the underlying tenant-aware Service sees the same row under tenant "".
	gotDirect, err := svc.Authenticate(ctx, "", "password", "user@example.com", "pw")
	require.NoError(t, err)
	assert.Equal(t, u.ID, gotDirect.ID)
}

// IDOR guard: an account created through SingleTenant ("" tenant) must NOT be visible to a
// non-empty tenant on the same Service, and an account created under a non-empty tenant must
// NOT be visible through SingleTenant. The wrapper cannot cross the tenant boundary.
func TestSingleTenant_CannotReachOtherTenant(t *testing.T) {
	ctx := context.Background()
	st, svc := newSingleTenantSvc(t)

	// Created in the empty partition via the wrapper.
	_, err := st.Register(ctx, "shared@example.com", "pw")
	require.NoError(t, err)

	// A different tenant cannot authenticate that account.
	_, err = svc.Authenticate(ctx, "tenant-acme", "password", "shared@example.com", "pw")
	assert.ErrorIs(t, err, identity.ErrInvalidCredentials,
		"empty-tenant account must be invisible to tenant-acme")

	// Conversely, an account registered under tenant-acme is invisible to the wrapper.
	_, err = svc.Register(ctx, "tenant-acme", "other@example.com", "pw")
	require.NoError(t, err)
	_, err = st.Authenticate(ctx, "password", "other@example.com", "pw")
	assert.ErrorIs(t, err, identity.ErrInvalidCredentials,
		"tenant-acme account must be invisible through SingleTenant")
}
