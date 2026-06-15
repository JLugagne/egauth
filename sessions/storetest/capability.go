package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/sessions"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SessionStoreContract exercises the stable-core sessions.SessionStore capability: session
// create/lookup/mutate (UpdateSession, BindSession) and delete, the compare-and-set concurrency
// contract, duplicate-token rejection, expired-on-lookup behaviour and (optionally) tenant
// isolation. It deliberately takes the narrow SessionStore interface (not the full Store) so an
// implementer that provides only the core capability — without the schedulable DeleteExpired
// reaper — can still prove conformance against the core contract. The full Store suite
// (StoreContractTesting) composes this plus SessionReaperContract.
func SessionStoreContract(t *testing.T, store sessions.SessionStore, useMultiTenant bool) {
	t.Helper()
	ctx := context.Background()

	tenantA := ""
	tenantB := ""
	if useMultiTenant {
		tenantA = "tenant-A"
		tenantB = "tenant-B"
	}

	t.Run("Contract: Session CRUD", func(t *testing.T) {
		tokenHash := "session_token_hash"
		userID := uuid.New()
		sess := &sessions.Session{
			ID:        uuid.New(),
			TenantID:  tenantA,
			UserID:    userID,
			TokenHash: tokenHash,
			UserAgent: "Mozilla/5.0",
			IP:        "127.0.0.1",
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.CreateSession(ctx, tenantA, sess)
		require.NoError(t, err)

		found, err := store.FindSessionByHash(ctx, tenantA, tokenHash)
		require.NoError(t, err)
		assert.Equal(t, sess.ID, found.ID)
		assert.Equal(t, userID, found.UserID)

		_, err = store.FindSessionByHash(ctx, tenantA, "non_existent")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

		err = store.DeleteSession(ctx, tenantA, sess.ID)
		require.NoError(t, err)

		_, err = store.FindSessionByHash(ctx, tenantA, tokenHash)
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	})

	t.Run("Contract: Update Session (Touch/Rotate)", func(t *testing.T) {
		userID := uuid.New()
		sess := &sessions.Session{
			ID:        uuid.New(),
			TenantID:  tenantA,
			UserID:    userID,
			TokenHash: "update-h1",
			UserAgent: "UA",
			IP:        "1.1.1.1",
			ExpiresAt: time.Now().Add(time.Hour),
			CreatedAt: time.Now(),
		}
		require.NoError(t, store.CreateSession(ctx, tenantA, sess))

		newExpiry := time.Now().Add(24 * time.Hour)
		updated := *sess
		updated.TokenHash = "update-h2"
		updated.ExpiresAt = newExpiry
		require.NoError(t, store.UpdateSession(ctx, tenantA, &updated, "update-h1"))

		_, err := store.FindSessionByHash(ctx, tenantA, "update-h1")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "old token must be invalidated")

		found, err := store.FindSessionByHash(ctx, tenantA, "update-h2")
		require.NoError(t, err)
		assert.Equal(t, sess.ID, found.ID, "same logical session")
		assert.WithinDuration(t, newExpiry, found.ExpiresAt, time.Second, "expiry extended")

		stale := updated
		stale.TokenHash = "update-h3"
		err = store.UpdateSession(ctx, tenantA, &stale, "update-h1")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "stale compare-and-set must be rejected")

		err = store.UpdateSession(ctx, tenantA, &sessions.Session{ID: uuid.New(), TenantID: tenantA, TokenHash: "x", ExpiresAt: newExpiry}, "whatever")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	})

	t.Run("Contract: UpdateSession pins UserID and CreatedAt", func(t *testing.T) {
		originalUser := uuid.New()
		originalCreatedAt := time.Now().Add(-2 * time.Hour)
		sess := &sessions.Session{
			ID:        uuid.New(),
			TenantID:  tenantA,
			UserID:    originalUser,
			TokenHash: "pin-h1",
			UserAgent: "UA",
			IP:        "1.1.1.1",
			ExpiresAt: time.Now().Add(time.Hour),
			CreatedAt: originalCreatedAt,
		}
		require.NoError(t, store.CreateSession(ctx, tenantA, sess))

		tampered := *sess
		tampered.UserID = uuid.New()
		tampered.CreatedAt = time.Now()
		tampered.TokenHash = "pin-h2"
		require.NoError(t, store.UpdateSession(ctx, tenantA, &tampered, "pin-h1"))

		found, err := store.FindSessionByHash(ctx, tenantA, "pin-h2")
		require.NoError(t, err)
		assert.Equal(t, originalUser, found.UserID, "UpdateSession must not change UserID")
		assert.WithinDuration(t, originalCreatedAt, found.CreatedAt, time.Second, "UpdateSession must not change CreatedAt")
	})

	t.Run("Contract: BindSession re-binds the user", func(t *testing.T) {
		anonUser := uuid.New()
		originalCreatedAt := time.Now().Add(-3 * time.Hour)
		sess := &sessions.Session{
			ID:        uuid.New(),
			TenantID:  tenantA,
			UserID:    anonUser,
			TokenHash: "bind-anon",
			UserAgent: "UA",
			IP:        "1.1.1.1",
			ExpiresAt: time.Now().Add(time.Hour),
			CreatedAt: originalCreatedAt,
		}
		require.NoError(t, store.CreateSession(ctx, tenantA, sess))

		authUser := uuid.New()
		rebound := *sess
		rebound.UserID = authUser
		rebound.TokenHash = "bind-auth"
		rebound.CreatedAt = time.Now() // must be ignored
		require.NoError(t, store.BindSession(ctx, tenantA, &rebound, "bind-anon"))

		_, err := store.FindSessionByHash(ctx, tenantA, "bind-anon")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "old token must be invalidated")

		found, err := store.FindSessionByHash(ctx, tenantA, "bind-auth")
		require.NoError(t, err)
		assert.Equal(t, sess.ID, found.ID, "same logical session")
		assert.Equal(t, authUser, found.UserID, "BindSession must change UserID")
		assert.WithinDuration(t, originalCreatedAt, found.CreatedAt, time.Second, "BindSession must keep CreatedAt pinned")

		stale := found
		stale.TokenHash = "bind-h3"
		err = store.BindSession(ctx, tenantA, stale, "bind-anon")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "stale compare-and-set must be rejected")

		err = store.BindSession(ctx, tenantA, &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: uuid.New(), TokenHash: "y", ExpiresAt: time.Now().Add(time.Hour)}, "whatever")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	})

	t.Run("Contract: Delete by UserID", func(t *testing.T) {
		userID := uuid.New()
		sess1 := &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: userID, TokenHash: "h1", ExpiresAt: time.Now().Add(time.Hour)}
		sess2 := &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: userID, TokenHash: "h2", ExpiresAt: time.Now().Add(time.Hour)}

		_ = store.CreateSession(ctx, tenantA, sess1)
		_ = store.CreateSession(ctx, tenantA, sess2)

		err := store.DeleteSessionsByUserID(ctx, tenantA, userID)
		require.NoError(t, err)

		_, err = store.FindSessionByHash(ctx, tenantA, "h1")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	})

	t.Run("Contract: CreateSession duplicate token hash is rejected", func(t *testing.T) {
		userA := uuid.New()
		userB := uuid.New()
		sess := &sessions.Session{
			ID:        uuid.New(),
			TenantID:  tenantA,
			UserID:    userA,
			TokenHash: "dup-hash-contract",
			UserAgent: "UA",
			IP:        "127.0.0.1",
			ExpiresAt: time.Now().Add(time.Hour),
			CreatedAt: time.Now(),
		}
		require.NoError(t, store.CreateSession(ctx, tenantA, sess))

		duplicate := &sessions.Session{
			ID:        uuid.New(),
			TenantID:  tenantA,
			UserID:    userB,
			TokenHash: "dup-hash-contract",
			UserAgent: "UA2",
			IP:        "10.0.0.1",
			ExpiresAt: time.Now().Add(2 * time.Hour),
			CreatedAt: time.Now(),
		}
		err := store.CreateSession(ctx, tenantA, duplicate)
		assert.ErrorIs(t, err, sessions.ErrDuplicateToken, "duplicate token hash must be rejected")

		found, err := store.FindSessionByHash(ctx, tenantA, "dup-hash-contract")
		require.NoError(t, err)
		assert.Equal(t, userA, found.UserID, "original owner must not be overwritten")
	})

	t.Run("Contract: FindSessionByHash returns ErrSessionNotFound for expired session", func(t *testing.T) {
		userID := uuid.New()
		expired := &sessions.Session{
			ID:        uuid.New(),
			TenantID:  tenantA,
			UserID:    userID,
			TokenHash: "expired-lookup-h",
			UserAgent: "UA",
			IP:        "127.0.0.1",
			ExpiresAt: time.Now().Add(-time.Hour), // already expired
			CreatedAt: time.Now().Add(-2 * time.Hour),
		}
		require.NoError(t, store.CreateSession(ctx, tenantA, expired))

		_, err := store.FindSessionByHash(ctx, tenantA, "expired-lookup-h")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "expired session must not be returned by FindSessionByHash")
	})

	if useMultiTenant {
		t.Run("Contract: Multi-Tenant Isolation", func(t *testing.T) {
			sharedHash := "shared_session_hash"
			userID := uuid.New()

			sessA := &sessions.Session{
				ID:        uuid.New(),
				TenantID:  tenantA,
				UserID:    userID,
				TokenHash: sharedHash,
				ExpiresAt: time.Now().Add(time.Hour),
			}
			err := store.CreateSession(ctx, tenantA, sessA)
			require.NoError(t, err)

			_, err = store.FindSessionByHash(ctx, tenantB, sharedHash)
			assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

			err = store.DeleteSession(ctx, tenantB, sessA.ID)
			assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
		})

		t.Run("Contract: ErrTenantMismatch on record-vs-arg conflict", func(t *testing.T) {
			sess := &sessions.Session{
				ID:        uuid.New(),
				TenantID:  tenantA,
				UserID:    uuid.New(),
				TokenHash: "mismatch-h",
				ExpiresAt: time.Now().Add(time.Hour),
			}
			err := store.CreateSession(ctx, tenantB, sess)
			assert.ErrorIs(t, err, sessions.ErrTenantMismatch)
		})
	}
}

// SessionReaperContract exercises the optional sessions.SessionReaper capability: the schedulable
// DeleteExpired sweep that purges only past-expiry sessions while leaving live ones untouched. It
// takes a value satisfying both SessionStore (to seed fixtures) and SessionReaper (the capability
// under test), so the reaper contract can be run independently of the rest of the core suite. The
// full Store suite (StoreContractTesting) composes this with SessionStoreContract.
func SessionReaperContract(t *testing.T, store interface {
	sessions.SessionStore
	sessions.SessionReaper
}, useMultiTenant bool) {
	t.Helper()
	ctx := context.Background()

	tenantA := ""
	if useMultiTenant {
		tenantA = "tenant-A"
	}

	t.Run("Contract: DeleteExpired purges only expired sessions", func(t *testing.T) {
		userID := uuid.New()
		expired := &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: userID, TokenHash: "exp-h", ExpiresAt: time.Now().Add(-time.Hour)}
		live := &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: userID, TokenHash: "live-h", ExpiresAt: time.Now().Add(time.Hour)}
		require.NoError(t, store.CreateSession(ctx, tenantA, expired))
		require.NoError(t, store.CreateSession(ctx, tenantA, live))

		n, err := store.DeleteExpired(ctx, tenantA)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, int64(1))

		_, err = store.FindSessionByHash(ctx, tenantA, "exp-h")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "expired session must be gone")
		_, err = store.FindSessionByHash(ctx, tenantA, "live-h")
		assert.NoError(t, err, "live session must be kept")
	})
}
