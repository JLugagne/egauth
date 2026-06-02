package sessions_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/sessions/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMaxLifetime_TouchCannotExtendPastAbsoluteDeadline verifies SEC-08: with an absolute
// maximum lifetime configured, a session that is repeatedly Touched within the idle window
// stays valid only until CreatedAt+maxLifetime and is rejected afterwards.
func TestMaxLifetime_TouchCannotExtendPastAbsoluteDeadline(t *testing.T) {
	ctx := context.Background()

	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	now := frozen
	clock := func() time.Time { return now }

	const idle = time.Minute
	const maxLifetime = 5 * time.Minute

	svc := sessions.NewService(
		memory.NewStore(),
		sessions.WithClock(clock),
		sessions.WithMaxLifetime(maxLifetime),
	)

	_, token, err := svc.CreateSession(ctx, "", uuid.New(), "UA", "1.1.1.1", idle)
	require.NoError(t, err)

	// Touch every 30s (well within the idle window) until we cross the absolute deadline.
	// Idle alone would keep the session alive forever; the absolute cap must not.
	for i := 0; i < 9; i++ {
		now = now.Add(30 * time.Second)
		if now.Sub(frozen) < maxLifetime {
			_, err := svc.Touch(ctx, "", token, idle)
			require.NoError(t, err, "session must stay valid before the absolute deadline (elapsed=%s)", now.Sub(frozen))
		} else {
			_, err := svc.Touch(ctx, "", token, idle)
			assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "session must be rejected past the absolute deadline (elapsed=%s)", now.Sub(frozen))
		}
	}
}

// TestMaxLifetime_TouchClampsExpiryToDeadline verifies SEC-08 clamp: a Touch close to the
// absolute deadline must clamp the new ExpiresAt so it never slides past CreatedAt+maxLifetime.
func TestMaxLifetime_TouchClampsExpiryToDeadline(t *testing.T) {
	ctx := context.Background()

	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	now := frozen
	clock := func() time.Time { return now }

	const idle = time.Minute
	const maxLifetime = 5 * time.Minute
	deadline := frozen.Add(maxLifetime)

	svc := sessions.NewService(
		memory.NewStore(),
		sessions.WithClock(clock),
		sessions.WithMaxLifetime(maxLifetime),
	)

	_, token, err := svc.CreateSession(ctx, "", uuid.New(), "UA", "1.1.1.1", idle)
	require.NoError(t, err)

	// Keep the session warm with periodic Touches so it never idle-expires, until we are 30s
	// before the absolute deadline.
	for now.Before(deadline.Add(-30 * time.Second)) {
		now = now.Add(30 * time.Second)
		_, err := svc.Touch(ctx, "", token, idle)
		require.NoError(t, err)
	}

	// Now exactly 30s before the deadline. A Touch with a 1h idle duration would push ExpiresAt
	// far past the deadline; it must instead be clamped to the deadline.
	touched, err := svc.Touch(ctx, "", token, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, deadline, touched.ExpiresAt, "Touch must clamp ExpiresAt to the absolute deadline")
}

// TestMaxLifetime_RotateClampsExpiryToDeadline verifies SEC-08 clamp for Rotate.
func TestMaxLifetime_RotateClampsExpiryToDeadline(t *testing.T) {
	ctx := context.Background()

	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	now := frozen
	clock := func() time.Time { return now }

	const idle = time.Minute
	const maxLifetime = 5 * time.Minute
	deadline := frozen.Add(maxLifetime)

	svc := sessions.NewService(
		memory.NewStore(),
		sessions.WithClock(clock),
		sessions.WithMaxLifetime(maxLifetime),
	)

	_, token, err := svc.CreateSession(ctx, "", uuid.New(), "UA", "1.1.1.1", idle)
	require.NoError(t, err)

	// Keep the session warm so it never idle-expires, until 30s before the absolute deadline.
	for now.Before(deadline.Add(-30 * time.Second)) {
		now = now.Add(30 * time.Second)
		token, err = func() (string, error) {
			_, nt, e := svc.Rotate(ctx, "", token, idle)
			return nt, e
		}()
		require.NoError(t, err)
	}

	// Now 30s before the deadline: a Rotate with a 1h idle duration must clamp to the deadline.
	rotated, _, err := svc.Rotate(ctx, "", token, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, deadline, rotated.ExpiresAt, "Rotate must clamp ExpiresAt to the absolute deadline")
}

// TestMaxLifetime_ZeroDisablesCap verifies backward compatibility: the zero value disables
// the absolute cap, so Touch can keep extending indefinitely.
func TestMaxLifetime_ZeroDisablesCap(t *testing.T) {
	ctx := context.Background()

	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	now := frozen
	clock := func() time.Time { return now }

	svc := sessions.NewService(
		memory.NewStore(),
		sessions.WithClock(clock),
		sessions.WithMaxLifetime(0),
	)

	_, token, err := svc.CreateSession(ctx, "", uuid.New(), "UA", "1.1.1.1", time.Minute)
	require.NoError(t, err)

	// Far past any plausible absolute deadline, but each Touch is within idle: must stay valid.
	for i := 0; i < 100; i++ {
		now = now.Add(30 * time.Second)
		_, err := svc.Touch(ctx, "", token, time.Minute)
		require.NoError(t, err)
	}
}

// TestRevokeAllForUser verifies SEC-09: revoking all sessions for a user stops every one of
// that user's sessions from validating, while another user's session is untouched.
func TestRevokeAllForUser(t *testing.T) {
	ctx := context.Background()
	svc := sessions.NewService(memory.NewStore())

	tenantID := "tenant-1"
	victim := uuid.New()
	other := uuid.New()

	var victimTokens []string
	for i := 0; i < 3; i++ {
		_, token, err := svc.CreateSession(ctx, tenantID, victim, "UA", "1.1.1.1", time.Hour)
		require.NoError(t, err)
		victimTokens = append(victimTokens, token)
	}

	_, otherToken, err := svc.CreateSession(ctx, tenantID, other, "UA", "2.2.2.2", time.Hour)
	require.NoError(t, err)

	// All victim sessions validate before revoke.
	for _, tok := range victimTokens {
		_, err := svc.ValidateSession(ctx, tenantID, tok)
		require.NoError(t, err)
	}

	require.NoError(t, svc.RevokeAllForUser(ctx, tenantID, victim))

	// Every victim session is now gone.
	for _, tok := range victimTokens {
		_, err := svc.ValidateSession(ctx, tenantID, tok)
		assert.ErrorIs(t, err, sessions.ErrSessionNotFound)
	}

	// The other user's session is untouched.
	_, err = svc.ValidateSession(ctx, tenantID, otherToken)
	assert.NoError(t, err)
}

// TestSingleTenant_RevokeAllForUser verifies the SingleTenant forwarder for SEC-09.
func TestSingleTenant_RevokeAllForUser(t *testing.T) {
	ctx := context.Background()
	st := sessions.NewSingleTenant(sessions.NewService(memory.NewStore()))

	victim := uuid.New()
	other := uuid.New()

	_, victimToken, err := st.CreateSession(ctx, victim, "UA", "1.1.1.1", time.Hour)
	require.NoError(t, err)
	_, otherToken, err := st.CreateSession(ctx, other, "UA", "2.2.2.2", time.Hour)
	require.NoError(t, err)

	require.NoError(t, st.RevokeAllForUser(ctx, victim))

	_, err = st.ValidateSession(ctx, victimToken)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

	_, err = st.ValidateSession(ctx, otherToken)
	assert.NoError(t, err)
}
