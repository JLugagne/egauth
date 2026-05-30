// Package storetest provides a shared conformance suite for passkey.Store implementations.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/passkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// StoreContractTesting exercises any passkey.Store implementation for credential CRUD,
// sign-count updates and (optionally) tenant isolation.
func StoreContractTesting(t *testing.T, store passkey.Store, useMultiTenant bool) {
	ctx := context.Background()
	var tenantA, tenantB string
	if useMultiTenant {
		tenantA, tenantB = "tenant-A", "tenant-B"
	}

	t.Run("empty tenant is the default partition", func(t *testing.T) {
		// Without WithTenant, every backend must operate on the default (empty) tenant partition
		// rather than rejecting the call. A forgotten tenant is only an error under the explicit
		// WithStrictTenancy opt-in (see StrictTenancyTesting). This pins the cross-backend
		// agreement (I19): the pgx backend historically rejected an empty tenant on SaveCredential
		// while the memory backend accepted it.
		uid := uuid.New()
		cred := &passkey.Credential{
			UserID: uid, ID: []byte{0xd0, 0xd1}, PublicKey: []byte{0x01}, Data: []byte(`{}`), CreatedAt: time.Now(),
		}
		require.NoError(t, store.SaveCredential(ctx, cred), "empty tenant must be the valid default partition, not rejected")
		got, err := store.GetCredentials(ctx, uid)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, cred.ID, got[0].ID)

		cred.SignCount = 3
		require.NoError(t, store.UpdateCredential(ctx, cred))
		require.NoError(t, store.DeleteCredential(ctx, uid, cred.ID))
	})

	t.Run("save / get / update / delete", func(t *testing.T) {
		uid := uuid.New()

		got, err := store.GetCredentials(ctx, uid, passkey.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Empty(t, got, "no credentials initially")

		cred := &passkey.Credential{
			UserID:    uid,
			ID:        []byte{0x01, 0x02, 0x03},
			PublicKey: []byte{0xaa, 0xbb},
			SignCount: 0,
			Data:      []byte(`{"id":"AQID"}`),
			CreatedAt: time.Now(),
		}
		require.NoError(t, store.SaveCredential(ctx, cred, passkey.WithTenant(tenantA)))

		got, err = store.GetCredentials(ctx, uid, passkey.WithTenant(tenantA))
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, cred.ID, got[0].ID)
		assert.Equal(t, uint32(0), got[0].SignCount)

		// Update the signature counter (clone-detection state).
		cred.SignCount = 7
		cred.Data = []byte(`{"id":"AQID","sc":7}`)
		require.NoError(t, store.UpdateCredential(ctx, cred, passkey.WithTenant(tenantA)))
		got, err = store.GetCredentials(ctx, uid, passkey.WithTenant(tenantA))
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, uint32(7), got[0].SignCount)

		// Updating a non-existent credential fails.
		assert.ErrorIs(t, store.UpdateCredential(ctx, &passkey.Credential{UserID: uid, ID: []byte{0x09}}, passkey.WithTenant(tenantA)), passkey.ErrCredentialNotFound)

		// A second credential for the same user.
		require.NoError(t, store.SaveCredential(ctx, &passkey.Credential{
			UserID: uid, ID: []byte{0x04, 0x05}, PublicKey: []byte{0xcc}, Data: []byte(`{"id":"BAU"}`), CreatedAt: time.Now(),
		}, passkey.WithTenant(tenantA)))
		got, err = store.GetCredentials(ctx, uid, passkey.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Len(t, got, 2)

		// Delete one.
		require.NoError(t, store.DeleteCredential(ctx, uid, []byte{0x01, 0x02, 0x03}, passkey.WithTenant(tenantA)))
		got, err = store.GetCredentials(ctx, uid, passkey.WithTenant(tenantA))
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []byte{0x04, 0x05}, got[0].ID)

		// Deleting a missing credential fails.
		assert.ErrorIs(t, store.DeleteCredential(ctx, uid, []byte{0xff}, passkey.WithTenant(tenantA)), passkey.ErrCredentialNotFound)
	})

	t.Run("credential IDs are unique tenant-wide", func(t *testing.T) {
		uid1, uid2 := uuid.New(), uuid.New()
		id := []byte{0x55, 0x66, 0x77}
		require.NoError(t, store.SaveCredential(ctx, &passkey.Credential{
			UserID: uid1, ID: id, PublicKey: []byte{0x01}, Data: []byte(`{}`), CreatedAt: time.Now(),
		}, passkey.WithTenant(tenantA)))

		// Same ID for the same user, and for a different user in the same tenant, both rejected.
		err := store.SaveCredential(ctx, &passkey.Credential{UserID: uid1, ID: id, PublicKey: []byte{0x02}, Data: []byte(`{}`), CreatedAt: time.Now()}, passkey.WithTenant(tenantA))
		assert.ErrorIs(t, err, passkey.ErrCredentialExists)
		err = store.SaveCredential(ctx, &passkey.Credential{UserID: uid2, ID: id, PublicKey: []byte{0x03}, Data: []byte(`{}`), CreatedAt: time.Now()}, passkey.WithTenant(tenantA))
		assert.ErrorIs(t, err, passkey.ErrCredentialExists)
	})

	if useMultiTenant {
		t.Run("tenant isolation", func(t *testing.T) {
			uid := uuid.New()
			require.NoError(t, store.SaveCredential(ctx, &passkey.Credential{
				UserID: uid, ID: []byte{0x10}, PublicKey: []byte{0x01}, Data: []byte(`{}`), CreatedAt: time.Now(),
			}, passkey.WithTenant(tenantA)))

			got, err := store.GetCredentials(ctx, uid, passkey.WithTenant(tenantB))
			require.NoError(t, err)
			assert.Empty(t, got, "tenant B must not see tenant A's credentials")

			assert.ErrorIs(t, store.DeleteCredential(ctx, uid, []byte{0x10}, passkey.WithTenant(tenantB)), passkey.ErrCredentialNotFound)
		})
	}
}

// StrictTenancyTesting asserts that a store built WithStrictTenancy rejects every tenant-scoped
// operation performed without a tenant (no WithTenant) via passkey.ErrTenantRequired, and that
// the same operations succeed once a tenant is supplied. Pass a store constructed
// WithStrictTenancy.
func StrictTenancyTesting(t *testing.T, strict passkey.Store) {
	ctx := context.Background()
	uid := uuid.New()
	cred := &passkey.Credential{UserID: uid, ID: []byte{0xa0, 0xa1}, PublicKey: []byte{0x01}, Data: []byte(`{}`), CreatedAt: time.Now()}

	t.Run("strict: every tenant-scoped op rejects an empty tenant", func(t *testing.T) {
		assert.ErrorIs(t, strict.SaveCredential(ctx, cred), passkey.ErrTenantRequired,
			"SaveCredential without a tenant must be rejected in strict mode")

		_, err := strict.GetCredentials(ctx, uid)
		assert.ErrorIs(t, err, passkey.ErrTenantRequired)

		assert.ErrorIs(t, strict.UpdateCredential(ctx, cred), passkey.ErrTenantRequired)
		assert.ErrorIs(t, strict.DeleteCredential(ctx, uid, cred.ID), passkey.ErrTenantRequired)
	})

	t.Run("strict: the same ops succeed once a tenant is supplied", func(t *testing.T) {
		const tenant = "strict-tenant"
		ok := &passkey.Credential{UserID: uid, ID: []byte{0xb0, 0xb1}, PublicKey: []byte{0x02}, Data: []byte(`{}`), CreatedAt: time.Now()}
		require.NoError(t, strict.SaveCredential(ctx, ok, passkey.WithTenant(tenant)))
		got, err := strict.GetCredentials(ctx, uid, passkey.WithTenant(tenant))
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, ok.ID, got[0].ID)
		require.NoError(t, strict.DeleteCredential(ctx, uid, ok.ID, passkey.WithTenant(tenant)))
	})
}
