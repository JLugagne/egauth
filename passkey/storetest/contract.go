// Package storetest provides a shared conformance suite for passkey.Store implementations.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passkey"
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
		// An empty tenantID is a legal tenant key (the single-tenant default partition).
		// This pins the cross-backend agreement (I19): all backends must accept an empty
		// tenantID rather than rejecting the call.
		uid := uuid.New()
		cred := &passkey.Credential{
			UserID: uid, ID: []byte{0xd0, 0xd1}, PublicKey: []byte{0x01}, Data: []byte(`{}`), CreatedAt: time.Now(),
		}
		require.NoError(t, store.SaveCredential(ctx, "", cred), "empty tenant must be the valid default partition, not rejected")
		got, err := store.GetCredentials(ctx, "", uid)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, cred.ID, got[0].ID)

		cred.SignCount = 3
		require.NoError(t, store.UpdateCredential(ctx, "", cred))
		require.NoError(t, store.DeleteCredential(ctx, "", uid, cred.ID))
	})

	t.Run("save / get / update / delete", func(t *testing.T) {
		uid := uuid.New()

		got, err := store.GetCredentials(ctx, tenantA, uid)
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
		require.NoError(t, store.SaveCredential(ctx, tenantA, cred))

		got, err = store.GetCredentials(ctx, tenantA, uid)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, cred.ID, got[0].ID)
		assert.Equal(t, uint32(0), got[0].SignCount)

		// Update the signature counter (clone-detection state).
		cred.SignCount = 7
		cred.Data = []byte(`{"id":"AQID","sc":7}`)
		require.NoError(t, store.UpdateCredential(ctx, tenantA, cred))
		got, err = store.GetCredentials(ctx, tenantA, uid)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, uint32(7), got[0].SignCount)

		// Updating a non-existent credential fails.
		assert.ErrorIs(t, store.UpdateCredential(ctx, tenantA, &passkey.Credential{UserID: uid, ID: []byte{0x09}}), passkey.ErrCredentialNotFound)

		// A second credential for the same user.
		require.NoError(t, store.SaveCredential(ctx, tenantA, &passkey.Credential{
			UserID: uid, ID: []byte{0x04, 0x05}, PublicKey: []byte{0xcc}, Data: []byte(`{"id":"BAU"}`), CreatedAt: time.Now(),
		}))
		got, err = store.GetCredentials(ctx, tenantA, uid)
		require.NoError(t, err)
		assert.Len(t, got, 2)

		// Delete one.
		require.NoError(t, store.DeleteCredential(ctx, tenantA, uid, []byte{0x01, 0x02, 0x03}))
		got, err = store.GetCredentials(ctx, tenantA, uid)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []byte{0x04, 0x05}, got[0].ID)

		// Deleting a missing credential fails.
		assert.ErrorIs(t, store.DeleteCredential(ctx, tenantA, uid, []byte{0xff}), passkey.ErrCredentialNotFound)
	})

	t.Run("credential IDs are unique tenant-wide", func(t *testing.T) {
		uid1, uid2 := uuid.New(), uuid.New()
		id := []byte{0x55, 0x66, 0x77}
		require.NoError(t, store.SaveCredential(ctx, tenantA, &passkey.Credential{
			UserID: uid1, ID: id, PublicKey: []byte{0x01}, Data: []byte(`{}`), CreatedAt: time.Now(),
		}))

		// Same ID for the same user, and for a different user in the same tenant, both rejected.
		err := store.SaveCredential(ctx, tenantA, &passkey.Credential{UserID: uid1, ID: id, PublicKey: []byte{0x02}, Data: []byte(`{}`), CreatedAt: time.Now()})
		assert.ErrorIs(t, err, passkey.ErrCredentialExists)
		err = store.SaveCredential(ctx, tenantA, &passkey.Credential{UserID: uid2, ID: id, PublicKey: []byte{0x03}, Data: []byte(`{}`), CreatedAt: time.Now()})
		assert.ErrorIs(t, err, passkey.ErrCredentialExists)
	})

	t.Run("tenant mismatch is rejected", func(t *testing.T) {
		uid := uuid.New()
		cred := &passkey.Credential{
			UserID: uid, TenantID: "other-tenant", ID: []byte{0xee, 0xff},
			PublicKey: []byte{0x01}, Data: []byte(`{}`), CreatedAt: time.Now(),
		}
		err := store.SaveCredential(ctx, tenantA, cred)
		assert.ErrorIs(t, err, passkey.ErrTenantMismatch, "SaveCredential with mismatched TenantID must return ErrTenantMismatch")
	})

	t.Run("management metadata round-trips", func(t *testing.T) {
		uid := uuid.New()
		lastUsed := time.Date(2026, 6, 11, 8, 30, 0, 0, time.UTC)
		cred := &passkey.Credential{
			UserID:         uid,
			ID:             []byte{0xa1, 0xa2},
			PublicKey:      []byte{0x01},
			Data:           []byte(`{}`),
			CreatedAt:      time.Now(),
			Nickname:       "laptop",
			LastUsedAt:     &lastUsed,
			Transports:     []string{"internal", "hybrid"},
			BackupEligible: true,
			BackupState:    true,
		}
		require.NoError(t, store.SaveCredential(ctx, tenantA, cred))

		got, err := store.GetCredentials(ctx, tenantA, uid)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "laptop", got[0].Nickname)
		require.NotNil(t, got[0].LastUsedAt)
		// Compare by instant, not by struct: a timestamptz backend (pgx) round-trips the
		// value in a different *time.Location (e.g. time.Local) for the same moment, which
		// assert.Equal would reject. The contract guarantees the instant, not the zone.
		assert.True(t, lastUsed.Equal(*got[0].LastUsedAt), "LastUsedAt instant must round-trip")
		assert.Equal(t, []string{"internal", "hybrid"}, got[0].Transports)
		assert.True(t, got[0].BackupEligible)
		assert.True(t, got[0].BackupState)

		// Mutate all five via Update and re-assert via Get.
		newLastUsed := time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)
		cred.Nickname = "work laptop"
		cred.LastUsedAt = &newLastUsed
		cred.Transports = []string{"usb"}
		cred.BackupEligible = false
		cred.BackupState = false
		require.NoError(t, store.UpdateCredential(ctx, tenantA, cred))

		got, err = store.GetCredentials(ctx, tenantA, uid)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "work laptop", got[0].Nickname)
		require.NotNil(t, got[0].LastUsedAt)
		assert.True(t, newLastUsed.Equal(*got[0].LastUsedAt), "updated LastUsedAt instant must round-trip")
		assert.Equal(t, []string{"usb"}, got[0].Transports)
		assert.False(t, got[0].BackupEligible)
		assert.False(t, got[0].BackupState)

		require.NoError(t, store.DeleteCredential(ctx, tenantA, uid, cred.ID))
	})
	if useMultiTenant {
		t.Run("tenant isolation", func(t *testing.T) {
			uid := uuid.New()
			require.NoError(t, store.SaveCredential(ctx, tenantA, &passkey.Credential{
				UserID: uid, ID: []byte{0x10}, PublicKey: []byte{0x01}, Data: []byte(`{}`), CreatedAt: time.Now(),
			}))

			got, err := store.GetCredentials(ctx, tenantB, uid)
			require.NoError(t, err)
			assert.Empty(t, got, "tenant B must not see tenant A's credentials")

			assert.ErrorIs(t, store.DeleteCredential(ctx, tenantB, uid, []byte{0x10}), passkey.ErrCredentialNotFound)
		})
	}
}
