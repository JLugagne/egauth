package sessions_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/sessions/memory"
	"github.com/JLugagne/egauth/sessions/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newService() sessions.Service {
	return sessions.NewService(memory.NewStore())
}

func TestTouch_ExtendsExpiry(t *testing.T) {
	ctx := context.Background()
	svc := newService()

	sess, token, err := svc.CreateSession(ctx, "", uuid.New(), "UA", "1.1.1.1", time.Minute)
	require.NoError(t, err)
	original := sess.ExpiresAt

	touched, err := svc.Touch(ctx, "", token, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, touched.ID)
	assert.True(t, touched.ExpiresAt.After(original), "Touch must extend the expiry")

	// The same token still validates, with the extended expiry.
	got, err := svc.ValidateSession(ctx, "", token)
	require.NoError(t, err)
	assert.WithinDuration(t, touched.ExpiresAt, got.ExpiresAt, time.Second)
}

func TestRotate_ChangesTokenAndInvalidatesOld(t *testing.T) {
	ctx := context.Background()
	svc := newService()

	sess, oldToken, err := svc.CreateSession(ctx, "", uuid.New(), "UA", "1.1.1.1", time.Minute)
	require.NoError(t, err)

	rotated, newToken, err := svc.Rotate(ctx, "", oldToken, time.Hour)
	require.NoError(t, err)
	assert.NotEqual(t, oldToken, newToken, "Rotate must mint a new token")
	assert.Equal(t, sess.ID, rotated.ID, "Rotate keeps the same logical session")

	// Old token no longer validates (fixation defense).
	_, err = svc.ValidateSession(ctx, "", oldToken)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "the pre-rotation token must stop working")

	// New token validates and resolves to the same session.
	got, err := svc.ValidateSession(ctx, "", newToken)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, sess.UserID, got.UserID)
}

func TestBindUser_RebindsUserAndRotatesToken(t *testing.T) {
	ctx := context.Background()
	svc := newService()

	anonUser := uuid.New()
	sess, oldToken, err := svc.CreateSession(ctx, "tenant-x", anonUser, "UA", "1.1.1.1", time.Minute)
	require.NoError(t, err)

	authUser := uuid.New()
	bound, newToken, err := svc.BindUser(ctx, "tenant-x", oldToken, authUser, time.Hour)
	require.NoError(t, err)
	assert.NotEqual(t, oldToken, newToken, "BindUser must mint a new token (fixation defense)")
	assert.Equal(t, sess.ID, bound.ID, "BindUser keeps the same logical session")
	assert.Equal(t, authUser, bound.UserID, "BindUser must re-bind the session to the new user")

	// The pre-auth token must stop working.
	_, err = svc.ValidateSession(ctx, "tenant-x", oldToken)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "the pre-auth token must stop working")

	// The new token validates and resolves to the same session bound to the authenticated user.
	got, err := svc.ValidateSession(ctx, "tenant-x", newToken)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, authUser, got.UserID)
}

func TestBindUser_UnknownToken(t *testing.T) {
	_, _, err := newService().BindUser(context.Background(), "", "nope", uuid.New(), time.Hour)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
}

func TestTouch_UnknownToken(t *testing.T) {
	_, err := newService().Touch(context.Background(), "", "nope", time.Hour)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
}

func TestTouchAndRotate_RejectExpiredSession(t *testing.T) {
	ctx := context.Background()
	svc := newService()

	// A session created already-expired must not be touchable or rotatable.
	_, token, err := svc.CreateSession(ctx, "", uuid.New(), "UA", "1.1.1.1", -time.Hour)
	require.NoError(t, err)

	_, err = svc.Touch(ctx, "", token, time.Hour)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

	_, _, err = svc.Rotate(ctx, "", token, time.Hour)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
}

// TestRotate_ConcurrentLoserGetsHonestError simulates the loser of a concurrent rotation: the
// store's compare-and-set fails (the token was already swapped by the winner), so Rotate must
// return ErrSessionNotFound rather than a fresh token that would never validate.
func TestRotate_ConcurrentLoserGetsHonestError(t *testing.T) {
	sess := &sessions.Session{ID: uuid.New(), TokenHash: "h-old", ExpiresAt: time.Now().Add(time.Hour)}
	store := &storetest.MockStore{
		FindSessionByHashFunc: func(_ context.Context, _ string, _ string) (*sessions.Session, error) {
			c := *sess
			return &c, nil
		},
		UpdateSessionFunc: func(_ context.Context, _ string, _ *sessions.Session, _ string) error {
			return sessions.ErrSessionNotFound // the compare-and-set lost the race
		},
	}
	svc := sessions.NewService(store)

	_, _, err := svc.Rotate(context.Background(), "", "any-token", time.Hour)
	require.ErrorIs(t, err, sessions.ErrSessionNotFound,
		"the loser of a concurrent rotation must get an error, not a non-validating token")
}

func TestRotate_PreservesUserAndTenant(t *testing.T) {
	ctx := context.Background()
	svc := newService()

	userID := uuid.New()
	_, token, err := svc.CreateSession(ctx, "tenant-x", userID, "UA", "1.1.1.1", time.Minute)
	require.NoError(t, err)

	rotated, newToken, err := svc.Rotate(ctx, "tenant-x", token, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, userID, rotated.UserID)
	assert.Equal(t, "tenant-x", rotated.TenantID)

	got, err := svc.ValidateSession(ctx, "tenant-x", newToken)
	require.NoError(t, err)
	assert.Equal(t, userID, got.UserID)
}
