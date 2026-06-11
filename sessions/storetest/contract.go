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

// MockStore is a functional mock of the sessions.Store interface.
type MockStore struct {
	CreateSessionFunc          func(ctx context.Context, tenantID string, session *sessions.Session) error
	FindSessionByHashFunc      func(ctx context.Context, tenantID string, tokenHash string) (*sessions.Session, error)
	UpdateSessionFunc          func(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error
	BindSessionFunc            func(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error
	DeleteSessionFunc          func(ctx context.Context, tenantID string, id uuid.UUID) error
	DeleteSessionsByUserIDFunc func(ctx context.Context, tenantID string, userID uuid.UUID) error
	DeleteExpiredFunc          func(ctx context.Context, tenantID string) (int64, error)
}

func (m *MockStore) CreateSession(ctx context.Context, tenantID string, session *sessions.Session) error {
	if m.CreateSessionFunc == nil {
		panic("called not defined CreateSessionFunc")
	}
	return m.CreateSessionFunc(ctx, tenantID, session)
}

func (m *MockStore) FindSessionByHash(ctx context.Context, tenantID string, tokenHash string) (*sessions.Session, error) {
	if m.FindSessionByHashFunc == nil {
		panic("called not defined FindSessionByHashFunc")
	}
	return m.FindSessionByHashFunc(ctx, tenantID, tokenHash)
}

func (m *MockStore) UpdateSession(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error {
	if m.UpdateSessionFunc == nil {
		panic("called not defined UpdateSessionFunc")
	}
	return m.UpdateSessionFunc(ctx, tenantID, session, expectedTokenHash)
}

func (m *MockStore) BindSession(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error {
	if m.BindSessionFunc == nil {
		panic("called not defined BindSessionFunc")
	}
	return m.BindSessionFunc(ctx, tenantID, session, expectedTokenHash)
}

func (m *MockStore) DeleteSession(ctx context.Context, tenantID string, id uuid.UUID) error {
	if m.DeleteSessionFunc == nil {
		panic("called not defined DeleteSessionFunc")
	}
	return m.DeleteSessionFunc(ctx, tenantID, id)
}

func (m *MockStore) DeleteSessionsByUserID(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if m.DeleteSessionsByUserIDFunc == nil {
		panic("called not defined DeleteSessionsByUserIDFunc")
	}
	return m.DeleteSessionsByUserIDFunc(ctx, tenantID, userID)
}

func (m *MockStore) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	if m.DeleteExpiredFunc == nil {
		panic("called not defined DeleteExpiredFunc")
	}
	return m.DeleteExpiredFunc(ctx, tenantID)
}

// StoreContractTesting runs a comprehensive suite of tests against any sessions.Store implementation.
func StoreContractTesting(t *testing.T, store sessions.Store, useMultiTenant bool) {
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

		// Find By Hash
		found, err := store.FindSessionByHash(ctx, tenantA, tokenHash)
		require.NoError(t, err)
		assert.Equal(t, sess.ID, found.ID)
		assert.Equal(t, userID, found.UserID)

		// Find non-existent
		_, err = store.FindSessionByHash(ctx, tenantA, "non_existent")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

		// Delete Session
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

		// Rotate the token and extend expiry on the SAME logical session (same ID). The
		// compare-and-set matches on the current token hash ("update-h1").
		newExpiry := time.Now().Add(24 * time.Hour)
		updated := *sess
		updated.TokenHash = "update-h2"
		updated.ExpiresAt = newExpiry
		require.NoError(t, store.UpdateSession(ctx, tenantA, &updated, "update-h1"))

		// The old token hash no longer resolves; the new one points at the same session.
		_, err := store.FindSessionByHash(ctx, tenantA, "update-h1")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "old token must be invalidated")

		found, err := store.FindSessionByHash(ctx, tenantA, "update-h2")
		require.NoError(t, err)
		assert.Equal(t, sess.ID, found.ID, "same logical session")
		assert.WithinDuration(t, newExpiry, found.ExpiresAt, time.Second, "expiry extended")

		// Compare-and-set: a stale expected hash (the loser of a concurrent rotation) is rejected
		// rather than silently overwriting the winner's token.
		stale := updated
		stale.TokenHash = "update-h3"
		err = store.UpdateSession(ctx, tenantA, &stale, "update-h1")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "stale compare-and-set must be rejected")

		// Updating an unknown session reports not-found.
		err = store.UpdateSession(ctx, tenantA, &sessions.Session{ID: uuid.New(), TenantID: tenantA, TokenHash: "x", ExpiresAt: newExpiry}, "whatever")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	})

	t.Run("Contract: UpdateSession pins UserID and CreatedAt", func(t *testing.T) {
		// UpdateSession is a token/expiry/last-seen mutator only. It must never re-bind the
		// session to a different user (that is BindSession's job) nor reset CreatedAt, which
		// anchors the absolute-lifetime cap. Both stores must agree here.
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

		// Attempt to re-bind the user and reset CreatedAt through UpdateSession.
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
		// BindSession is the anonymous-to-authenticated upgrade: it changes UserID and rotates the
		// token on the SAME logical session, while keeping CreatedAt pinned.
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

		// Old token gone, new token resolves to the SAME session now bound to the auth user.
		_, err := store.FindSessionByHash(ctx, tenantA, "bind-anon")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "old token must be invalidated")

		found, err := store.FindSessionByHash(ctx, tenantA, "bind-auth")
		require.NoError(t, err)
		assert.Equal(t, sess.ID, found.ID, "same logical session")
		assert.Equal(t, authUser, found.UserID, "BindSession must change UserID")
		assert.WithinDuration(t, originalCreatedAt, found.CreatedAt, time.Second, "BindSession must keep CreatedAt pinned")

		// Compare-and-set: a stale expected hash is rejected.
		stale := found
		stale.TokenHash = "bind-h3"
		err = store.BindSession(ctx, tenantA, stale, "bind-anon")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "stale compare-and-set must be rejected")

		// Unknown session reports not-found.
		err = store.BindSession(ctx, tenantA, &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: uuid.New(), TokenHash: "y", ExpiresAt: time.Now().Add(time.Hour)}, "whatever")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	})

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

			// Try to find from Tenant B
			_, err = store.FindSessionByHash(ctx, tenantB, sharedHash)
			assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

			// Try to delete from Tenant B
			err = store.DeleteSession(ctx, tenantB, sessA.ID)
			// Not found in tenant B — must return ErrSessionNotFound.
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
			// Record says tenantA, arg says tenantB → ErrTenantMismatch.
			err := store.CreateSession(ctx, tenantB, sess)
			assert.ErrorIs(t, err, sessions.ErrTenantMismatch)
		})
	}
}
