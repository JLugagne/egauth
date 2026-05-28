package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/sessions"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStore is a functional mock of the sessions.Store interface.
type MockStore struct {
	CreateSessionFunc          func(ctx context.Context, session *sessions.Session, opts ...sessions.Option) error
	FindSessionByHashFunc      func(ctx context.Context, tokenHash string, opts ...sessions.Option) (*sessions.Session, error)
	DeleteSessionFunc          func(ctx context.Context, id uuid.UUID, opts ...sessions.Option) error
	DeleteSessionsByUserIDFunc func(ctx context.Context, userID uuid.UUID, opts ...sessions.Option) error
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
