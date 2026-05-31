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
	CreateSessionFunc          func(ctx context.Context, session *sessions.Session, opts ...sessions.Option) error
	FindSessionByHashFunc      func(ctx context.Context, tokenHash string, opts ...sessions.Option) (*sessions.Session, error)
	UpdateSessionFunc          func(ctx context.Context, session *sessions.Session, expectedTokenHash string, opts ...sessions.Option) error
	DeleteSessionFunc          func(ctx context.Context, id uuid.UUID, opts ...sessions.Option) error
	DeleteSessionsByUserIDFunc func(ctx context.Context, userID uuid.UUID, opts ...sessions.Option) error
	DeleteExpiredFunc          func(ctx context.Context, opts ...sessions.Option) (int64, error)
}

func (m *MockStore) CreateSession(ctx context.Context, session *sessions.Session, opts ...sessions.Option) error {
	if m.CreateSessionFunc == nil {
		panic("called not defined CreateSessionFunc")
	}
	return m.CreateSessionFunc(ctx, session, opts...)
}

func (m *MockStore) FindSessionByHash(ctx context.Context, tokenHash string, opts ...sessions.Option) (*sessions.Session, error) {
	if m.FindSessionByHashFunc == nil {
		panic("called not defined FindSessionByHashFunc")
	}
	return m.FindSessionByHashFunc(ctx, tokenHash, opts...)
}

func (m *MockStore) UpdateSession(ctx context.Context, session *sessions.Session, expectedTokenHash string, opts ...sessions.Option) error {
	if m.UpdateSessionFunc == nil {
		panic("called not defined UpdateSessionFunc")
	}
	return m.UpdateSessionFunc(ctx, session, expectedTokenHash, opts...)
}

func (m *MockStore) DeleteSession(ctx context.Context, id uuid.UUID, opts ...sessions.Option) error {
	if m.DeleteSessionFunc == nil {
		panic("called not defined DeleteSessionFunc")
	}
	return m.DeleteSessionFunc(ctx, id, opts...)
}

func (m *MockStore) DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID, opts ...sessions.Option) error {
	if m.DeleteSessionsByUserIDFunc == nil {
		panic("called not defined DeleteSessionsByUserIDFunc")
	}
	return m.DeleteSessionsByUserIDFunc(ctx, userID, opts...)
}

func (m *MockStore) DeleteExpired(ctx context.Context, opts ...sessions.Option) (int64, error) {
	if m.DeleteExpiredFunc == nil {
		panic("called not defined DeleteExpiredFunc")
	}
	return m.DeleteExpiredFunc(ctx, opts...)
}

// StoreContractTesting runs a comprehensive suite of tests against any sessions.Store implementation.
func StoreContractTesting(t *testing.T, store sessions.Store, useMultiTenant bool) {
	ctx := context.Background()

	var tenantA, tenantB string
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

		err := store.CreateSession(ctx, sess, sessions.WithTenant(tenantA))
		require.NoError(t, err)

		// Find By Hash
		found, err := store.FindSessionByHash(ctx, tokenHash, sessions.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, sess.ID, found.ID)
		assert.Equal(t, userID, found.UserID)

		// Find non-existent
		_, err = store.FindSessionByHash(ctx, "non_existent", sessions.WithTenant(tenantA))
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

		// Delete Session
		err = store.DeleteSession(ctx, sess.ID, sessions.WithTenant(tenantA))
		require.NoError(t, err)

		_, err = store.FindSessionByHash(ctx, tokenHash, sessions.WithTenant(tenantA))
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
		require.NoError(t, store.CreateSession(ctx, sess, sessions.WithTenant(tenantA)))

		// Rotate the token and extend expiry on the SAME logical session (same ID). The
		// compare-and-set matches on the current token hash ("update-h1").
		newExpiry := time.Now().Add(24 * time.Hour)
		updated := *sess
		updated.TokenHash = "update-h2"
		updated.ExpiresAt = newExpiry
		require.NoError(t, store.UpdateSession(ctx, &updated, "update-h1", sessions.WithTenant(tenantA)))

		// The old token hash no longer resolves; the new one points at the same session.
		_, err := store.FindSessionByHash(ctx, "update-h1", sessions.WithTenant(tenantA))
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "old token must be invalidated")

		found, err := store.FindSessionByHash(ctx, "update-h2", sessions.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, sess.ID, found.ID, "same logical session")
		assert.WithinDuration(t, newExpiry, found.ExpiresAt, time.Second, "expiry extended")

		// Compare-and-set: a stale expected hash (the loser of a concurrent rotation) is rejected
		// rather than silently overwriting the winner's token.
		stale := updated
		stale.TokenHash = "update-h3"
		err = store.UpdateSession(ctx, &stale, "update-h1", sessions.WithTenant(tenantA))
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "stale compare-and-set must be rejected")

		// Updating an unknown session reports not-found.
		err = store.UpdateSession(ctx, &sessions.Session{ID: uuid.New(), TenantID: tenantA, TokenHash: "x", ExpiresAt: newExpiry}, "whatever", sessions.WithTenant(tenantA))
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	})

	t.Run("Contract: DeleteExpired purges only expired sessions", func(t *testing.T) {
		userID := uuid.New()
		expired := &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: userID, TokenHash: "exp-h", ExpiresAt: time.Now().Add(-time.Hour)}
		live := &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: userID, TokenHash: "live-h", ExpiresAt: time.Now().Add(time.Hour)}
		require.NoError(t, store.CreateSession(ctx, expired, sessions.WithTenant(tenantA)))
		require.NoError(t, store.CreateSession(ctx, live, sessions.WithTenant(tenantA)))

		n, err := store.DeleteExpired(ctx, sessions.WithTenant(tenantA))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, int64(1))

		_, err = store.FindSessionByHash(ctx, "exp-h", sessions.WithTenant(tenantA))
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "expired session must be gone")
		_, err = store.FindSessionByHash(ctx, "live-h", sessions.WithTenant(tenantA))
		assert.NoError(t, err, "live session must be kept")
	})

	t.Run("Contract: Delete by UserID", func(t *testing.T) {
		userID := uuid.New()
		sess1 := &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: userID, TokenHash: "h1", ExpiresAt: time.Now().Add(time.Hour)}
		sess2 := &sessions.Session{ID: uuid.New(), TenantID: tenantA, UserID: userID, TokenHash: "h2", ExpiresAt: time.Now().Add(time.Hour)}

		_ = store.CreateSession(ctx, sess1, sessions.WithTenant(tenantA))
		_ = store.CreateSession(ctx, sess2, sessions.WithTenant(tenantA))

		err := store.DeleteSessionsByUserID(ctx, userID, sessions.WithTenant(tenantA))
		require.NoError(t, err)

		_, err = store.FindSessionByHash(ctx, "h1", sessions.WithTenant(tenantA))
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
			err := store.CreateSession(ctx, sessA, sessions.WithTenant(tenantA))
			require.NoError(t, err)

			// Try to find from Tenant B
			_, err = store.FindSessionByHash(ctx, sharedHash, sessions.WithTenant(tenantB))
			assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

			// Try to delete from Tenant B
			err = store.DeleteSession(ctx, sessA.ID, sessions.WithTenant(tenantB))
			// Note: Implementation might return nil if not found, but for contract we expect it to be scoped to tenant.
			// If it's not found in tenant B, it should return ErrSessionNotFound.
			assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
		})
	}
}

// StrictTenancyTesting asserts that a store built WithStrictTenancy rejects every tenant-scoped
// operation whose effective tenant is empty (no WithTenant and no tenant carried on the session)
// via sessions.ErrTenantRequired, and that the same operations succeed once a tenant is supplied.
// DeleteExpired is intentionally NOT asserted: it is an exempt maintenance sweep that spans all
// tenants when no tenant is given. Pass a store constructed WithStrictTenancy.
func StrictTenancyTesting(t *testing.T, strict sessions.Store) {
	ctx := context.Background()
	sid := uuid.New()
	uid := uuid.New()

	t.Run("strict: every tenant-scoped op rejects an empty tenant", func(t *testing.T) {
		// No WithTenant AND the session carries no tenant of its own -> rejected.
		sess := &sessions.Session{ID: sid, UserID: uid, TokenHash: "strict-h", ExpiresAt: time.Now().Add(time.Hour)}
		assert.ErrorIs(t, strict.CreateSession(ctx, sess), sessions.ErrTenantRequired, "CreateSession without a tenant must be rejected in strict mode")

		_, err := strict.FindSessionByHash(ctx, "strict-h")
		assert.ErrorIs(t, err, sessions.ErrTenantRequired, "FindSessionByHash with no tenant must be rejected (no unscoped lookups in strict mode)")

		err = strict.UpdateSession(ctx, &sessions.Session{ID: sid, TokenHash: "x", ExpiresAt: time.Now().Add(time.Hour)}, "strict-h")
		assert.ErrorIs(t, err, sessions.ErrTenantRequired)

		assert.ErrorIs(t, strict.DeleteSession(ctx, sid), sessions.ErrTenantRequired)
		assert.ErrorIs(t, strict.DeleteSessionsByUserID(ctx, uid), sessions.ErrTenantRequired)
	})

	t.Run("strict: the same ops succeed once a tenant is supplied", func(t *testing.T) {
		const tenant = "strict-tenant"
		sess := &sessions.Session{
			ID: uuid.New(), TenantID: tenant, UserID: uid, TokenHash: "ok-h",
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
		require.NoError(t, strict.CreateSession(ctx, sess, sessions.WithTenant(tenant)))
		got, err := strict.FindSessionByHash(ctx, "ok-h", sessions.WithTenant(tenant))
		require.NoError(t, err)
		assert.Equal(t, sess.ID, got.ID)
		require.NoError(t, strict.DeleteSession(ctx, sess.ID, sessions.WithTenant(tenant)))
	})
}
