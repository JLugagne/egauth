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

// Tests for the injectable clock seam (N3): session creation, expiry, and slide
// must use the service's clock so expiry is deterministic in tests.

func TestWithClock_DeterministicExpiry(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := "tenant-clock"

	// A frozen clock the test advances by hand.
	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	now := frozen
	clock := func() time.Time { return now }

	var stored *sessions.Session
	mockStore := &storetest.MockStore{
		CreateSessionFunc: func(ctx context.Context, sess *sessions.Session, opts ...sessions.Option) error {
			stored = sess
			return nil
		},
		FindSessionByHashFunc: func(ctx context.Context, hash string, opts ...sessions.Option) (*sessions.Session, error) {
			return stored, nil
		},
	}

	svc := sessions.NewService(mockStore, sessions.WithClock(clock))

	sess, token, err := svc.CreateSession(ctx, userID, tenantID, "UA", "127.0.0.1", time.Hour)
	require.NoError(t, err)
	// Timestamps must come from the injected clock, not wall time.
	assert.Equal(t, frozen.Add(time.Hour), sess.ExpiresAt, "ExpiresAt must be clock-now + duration")
	assert.Equal(t, frozen, sess.CreatedAt, "CreatedAt must be clock-now")

	// Still valid just before expiry.
	now = frozen.Add(time.Hour - time.Second)
	got, err := svc.ValidateSession(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)

	// Past expiry the validation must fail deterministically.
	now = frozen.Add(time.Hour + time.Second)
	_, err = svc.ValidateSession(ctx, token)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "expired session must not validate")
}
