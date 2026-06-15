package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/passkey/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_Contract(t *testing.T) {
	storetest.StoreContractTesting(t, memory.NewStore(), true)
}

// TestMemoryStore_ManagementMetadataRoundTrip pins that the five management metadata
// fields survive a Save/Get round-trip and that the store deep-clones the reference-type
// ones (Transports slice, LastUsedAt pointer) so it never aliases caller-owned data.
func TestMemoryStore_ManagementMetadataRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	uid := uuid.Must(uuid.NewV7())

	lastUsed := time.Date(2026, 6, 11, 8, 30, 0, 0, time.UTC)
	transports := []string{"usb", "hybrid"}
	cred := &passkey.Credential{
		UserID:         uid,
		ID:             []byte{0x01, 0x02, 0x03},
		PublicKey:      []byte{0xaa},
		Data:           []byte(`{}`),
		CreatedAt:      time.Now(),
		Nickname:       "my yubikey",
		LastUsedAt:     &lastUsed,
		Transports:     transports,
		BackupEligible: true,
		BackupState:    true,
	}
	require.NoError(t, store.SaveCredential(ctx, "", cred))

	got, err := store.GetCredentials(ctx, "", uid)
	require.NoError(t, err)
	require.Len(t, got, 1)

	// All five fields round-trip intact.
	assert.Equal(t, "my yubikey", got[0].Nickname)
	require.NotNil(t, got[0].LastUsedAt)
	assert.Equal(t, lastUsed, *got[0].LastUsedAt)
	assert.Equal(t, []string{"usb", "hybrid"}, got[0].Transports)
	assert.True(t, got[0].BackupEligible)
	assert.True(t, got[0].BackupState)

	// Non-aliasing: mutating the caller's original slice / pointer after Save must
	// not affect the stored copy (deep-clone proof).
	transports[0] = "MUTATED"
	lastUsed = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)

	got, err = store.GetCredentials(ctx, "", uid)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, []string{"usb", "hybrid"}, got[0].Transports, "stored Transports must not alias caller slice")
	require.NotNil(t, got[0].LastUsedAt)
	assert.Equal(t, time.Date(2026, 6, 11, 8, 30, 0, 0, time.UTC), *got[0].LastUsedAt, "stored LastUsedAt must not alias caller pointer")
}
