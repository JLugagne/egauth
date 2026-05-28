package sessions_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/sessions"
	"github.com/JLugagne/libauth/sessions/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := "tenant-1"

	t.Run("Create and Validate", func(t *testing.T) {
		mockStore := &storetest.MockStore{
			CreateSessionFunc: func(ctx context.Context, sess *sessions.Session, opts ...sessions.Option) error {
				return nil
			},
			FindSessionByHashFunc: func(ctx context.Context, hash string, opts ...sessions.Option) (*sessions.Session, error) {
				return &sessions.Session{
					ID:        uuid.New(),
					TenantID:  tenantID,
					UserID:    userID,
					ExpiresAt: time.Now().Add(time.Hour),
				}, nil
			},
		}

		svc := sessions.NewService(mockStore)
		sess, token, err := svc.CreateSession(ctx, userID, tenantID, "UA", "127.0.0.1", time.Hour)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Equal(t, userID, sess.UserID)

		found, err := svc.ValidateSession(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, userID, found.UserID)
	})

	t.Run("Expired session", func(t *testing.T) {
		mockStore := &storetest.MockStore{
			FindSessionByHashFunc: func(ctx context.Context, hash string, opts ...sessions.Option) (*sessions.Session, error) {
				return &sessions.Session{
					ExpiresAt: time.Now().Add(-time.Hour),
				}, nil
			},
		}

		svc := sessions.NewService(mockStore)
		_, err := svc.ValidateSession(ctx, "token")
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	})

	t.Run("Revoke Session", func(t *testing.T) {
		sessionID := uuid.New()
		mockStore := &storetest.MockStore{
			FindSessionByHashFunc: func(ctx context.Context, hash string, opts ...sessions.Option) (*sessions.Session, error) {
				return &sessions.Session{
					ID:       sessionID,
					TenantID: tenantID,
				}, nil
			},
			DeleteSessionFunc: func(ctx context.Context, id uuid.UUID, opts ...sessions.Option) error {
				assert.Equal(t, sessionID, id)
				return nil
			},
		}

		svc := sessions.NewService(mockStore)
		err := svc.RevokeSession(ctx, "token")
		assert.NoError(t, err)
	})

	t.Run("Create Session Store Error", func(t *testing.T) {
		mockStore := &storetest.MockStore{
			CreateSessionFunc: func(ctx context.Context, sess *sessions.Session, opts ...sessions.Option) error {
				return assert.AnError
			},
		}

		svc := sessions.NewService(mockStore)
		_, _, err := svc.CreateSession(ctx, userID, tenantID, "UA", "127.0.0.1", time.Hour)
		assert.ErrorIs(t, err, assert.AnError)
	})

	t.Run("Validate Session Store Error", func(t *testing.T) {
		mockStore := &storetest.MockStore{
			FindSessionByHashFunc: func(ctx context.Context, hash string, opts ...sessions.Option) (*sessions.Session, error) {
				return nil, assert.AnError
			},
		}

		svc := sessions.NewService(mockStore)
		_, err := svc.ValidateSession(ctx, "token")
		assert.ErrorIs(t, err, assert.AnError)
	})

	t.Run("Revoke Session Store Error Find", func(t *testing.T) {
		mockStore := &storetest.MockStore{
			FindSessionByHashFunc: func(ctx context.Context, hash string, opts ...sessions.Option) (*sessions.Session, error) {
				return nil, assert.AnError
			},
		}

		svc := sessions.NewService(mockStore)
		err := svc.RevokeSession(ctx, "token")
		assert.ErrorIs(t, err, assert.AnError)
	})

	t.Run("Store Options", func(t *testing.T) {
		opts := sessions.ApplyOptions([]sessions.Option{sessions.WithTenant("t1")})
		assert.NotNil(t, opts.TenantID)
		assert.Equal(t, "t1", *opts.TenantID)
	})
}
