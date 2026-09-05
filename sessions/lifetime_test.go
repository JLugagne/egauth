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

	_, token, err := svc.CreateSession(ctx, "", uuid.Must(uuid.NewV7()), "UA", "1.1.1.1", idle)
	require.NoError(t, err)

	// Touch every 30s (well within the idle window) until we cross the absolute deadline.
	// Idle alone would keep the session alive forever; the absolute cap must not.
	for range 9 {
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

	_, token, err := svc.CreateSession(ctx, "", uuid.Must(uuid.NewV7()), "UA", "1.1.1.1", idle)
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

	_, token, err := svc.CreateSession(ctx, "", uuid.Must(uuid.NewV7()), "UA", "1.1.1.1", idle)
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

// TestMaxLifetime_CreateSessionClampsExpiryToDeadline verifies SEC-SES-06: CreateSession
// clamps initial ExpiresAt to CreatedAt+maxLifetime when duration > maxLifetime,
// preventing zombie sessions that persist in stores past maxLifetime without being purged.
func TestMaxLifetime_CreateSessionClampsExpiryToDeadline(t *testing.T) {
	ctx := context.Background()

	const maxLifetime = 1 * time.Hour
	const duration = 10 * time.Hour

	// Use a creation time in the past so real time.Now() (used by memory.Store.DeleteExpired)
	// has already passed maxLifetime.
	frozen := time.Now().Add(-2 * time.Hour)
	now := frozen
	clock := func() time.Time { return now }

	store := memory.NewStore()
	svc := sessions.NewService(
		store,
		sessions.WithClock(clock),
		sessions.WithMaxLifetime(maxLifetime),
	)

	tenantID := "tenant-sec06"
	sess, _, err := svc.CreateSession(ctx, tenantID, uuid.Must(uuid.NewV7()), "UA", "127.0.0.1", duration)
	require.NoError(t, err)

	// Assert CreateSession clamps ExpiresAt to CreatedAt.Add(maxLifetime)
	assert.Equal(t, sess.CreatedAt.Add(maxLifetime), sess.ExpiresAt,
		"CreateSession must clamp initial ExpiresAt to CreatedAt+maxLifetime when duration exceeds maxLifetime")

	// DeleteExpired purges the session after maxLifetime has elapsed
	deleted, err := store.DeleteExpired(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "DeleteExpired must purge the session after maxLifetime has elapsed")
}

// TestNoMaxLifetime_TouchCanExtendIndefinitely verifies that WithNoMaxLifetime disables the
// absolute cap so Touch can keep extending the session indefinitely (idle timeout only).
// This replaces the old TestMaxLifetime_ZeroDisablesCap now that WithMaxLifetime(0) means
// "keep the default" rather than "disable the cap".
func TestNoMaxLifetime_TouchCanExtendIndefinitely(t *testing.T) {
	ctx := context.Background()

	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	now := frozen
	clock := func() time.Time { return now }

	svc := sessions.NewService(
		memory.NewStore(),
		sessions.WithClock(clock),
		sessions.WithNoMaxLifetime(), // explicit insecure opt-out
	)

	_, token, err := svc.CreateSession(ctx, "", uuid.Must(uuid.NewV7()), "UA", "1.1.1.1", time.Minute)
	require.NoError(t, err)

	// Far past any plausible absolute deadline, but each Touch is within idle: must stay valid.
	for range 100 {
		now = now.Add(30 * time.Second)
		_, err := svc.Touch(ctx, "", token, time.Minute)
		require.NoError(t, err)
	}
}

// TestWithMaxLifetime_ZeroKeepsDefault verifies that WithMaxLifetime(0) is treated as
// "keep the default 30-day cap" — not as "disable the cap".
func TestWithMaxLifetime_ZeroKeepsDefault(t *testing.T) {
	ctx := context.Background()

	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	now := frozen
	clock := func() time.Time { return now }

	// WithMaxLifetime(0) must keep the secure default, not disable it.
	svc := sessions.NewService(
		memory.NewStore(),
		sessions.WithClock(clock),
		sessions.WithMaxLifetime(0),
	)

	const idle = time.Hour
	_, token, err := svc.CreateSession(ctx, "", uuid.Must(uuid.NewV7()), "UA", "1.1.1.1", idle)
	require.NoError(t, err)

	// Advance 31 days touching every hour: the session must be rejected around the 30-day mark.
	const thirtyOneDays = 31 * 24 * time.Hour
	var rejected bool
	for elapsed := time.Duration(0); elapsed < thirtyOneDays; elapsed += idle {
		now = frozen.Add(elapsed + idle)
		_, err := svc.Touch(ctx, "", token, idle)
		if err != nil {
			require.ErrorIs(t, err, sessions.ErrSessionNotFound)
			rejected = true
			break
		}
	}
	require.True(t, rejected,
		"WithMaxLifetime(0) must keep the 30-day default cap, not disable it")
}

// TestMaxLifetimeOptionOrdering_LastWins locks the documented "last option wins" semantics for
// the absolute-cap options: WithNoMaxLifetime followed by WithMaxLifetime(1h) must ENFORCE a 1h
// cap, and the reverse order must disable the cap. Before the fix the first ordering silently
// dropped the cap because WithMaxLifetime did not clear the noMaxLifetime disable flag.
func TestMaxLifetimeOptionOrdering_LastWins(t *testing.T) {
	ctx := context.Background()

	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	const idle = time.Minute
	const maxLifetime = time.Hour

	t.Run("NoMaxLifetime then MaxLifetime enforces the cap", func(t *testing.T) {
		now := frozen
		clock := func() time.Time { return now }

		svc := sessions.NewService(
			memory.NewStore(),
			sessions.WithClock(clock),
			sessions.WithNoMaxLifetime(),
			sessions.WithMaxLifetime(maxLifetime),
		)

		_, token, err := svc.CreateSession(ctx, "", uuid.Must(uuid.NewV7()), "UA", "1.1.1.1", idle)
		require.NoError(t, err)

		var rejected bool
		for range 200 {
			now = now.Add(30 * time.Second)
			_, touchErr := svc.Touch(ctx, "", token, idle)
			if touchErr != nil {
				require.ErrorIs(t, touchErr, sessions.ErrSessionNotFound)
				rejected = true
				break
			}
			require.Less(t, now.Sub(frozen), maxLifetime+idle,
				"session extended past the 1h absolute cap: WithMaxLifetime must re-enable the cap after WithNoMaxLifetime")
		}
		require.True(t, rejected,
			"WithNoMaxLifetime then WithMaxLifetime(1h) must enforce the 1h absolute cap (last option wins)")
	})

	t.Run("MaxLifetime then NoMaxLifetime disables the cap", func(t *testing.T) {
		now := frozen
		clock := func() time.Time { return now }

		svc := sessions.NewService(
			memory.NewStore(),
			sessions.WithClock(clock),
			sessions.WithMaxLifetime(maxLifetime),
			sessions.WithNoMaxLifetime(),
		)

		_, token, err := svc.CreateSession(ctx, "", uuid.Must(uuid.NewV7()), "UA", "1.1.1.1", idle)
		require.NoError(t, err)

		for range 200 {
			now = now.Add(30 * time.Second)
			_, err := svc.Touch(ctx, "", token, idle)
			require.NoError(t, err,
				"WithMaxLifetime then WithNoMaxLifetime must disable the cap (last option wins)")
		}
	})
}

// TestRevokeAllForUser verifies SEC-09: revoking all sessions for a user stops every one of
// that user's sessions from validating, while another user's session is untouched.
func TestRevokeAllForUser(t *testing.T) {
	ctx := context.Background()
	svc := sessions.NewService(memory.NewStore())

	tenantID := "tenant-1"
	victim := uuid.Must(uuid.NewV7())
	other := uuid.Must(uuid.NewV7())

	var victimTokens []string
	for range 3 {
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

	victim := uuid.Must(uuid.NewV7())
	other := uuid.Must(uuid.NewV7())

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

// TestDefaultMaxLifetime_TouchCannotExtendPastDefaultDeadline is the regression test for
// TASK-084: a default-configured NewService (no WithMaxLifetime) must enforce a 30-day
// absolute session lifetime. Without the fix, Touch keeps extending the session forever.
func TestDefaultMaxLifetime_TouchCannotExtendPastDefaultDeadline(t *testing.T) {
	ctx := context.Background()

	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	now := frozen
	clock := func() time.Time { return now }

	const idle = time.Hour
	const thirtyOneDays = 31 * 24 * time.Hour

	// Default service — no WithMaxLifetime option.
	svc := sessions.NewService(
		memory.NewStore(),
		sessions.WithClock(clock),
	)

	_, token, err := svc.CreateSession(ctx, "", uuid.Must(uuid.NewV7()), "UA", "1.1.1.1", idle)
	require.NoError(t, err)

	// Advance 31 days in 1-hour steps, Touching on every step to keep the idle window alive.
	// After the fix the session must be rejected once CreatedAt+30days is crossed; before the
	// fix every Touch succeeds because there is no absolute cap at all.
	var rejectedAt time.Duration
	for elapsed := time.Duration(0); elapsed < thirtyOneDays; elapsed += idle {
		now = frozen.Add(elapsed + idle)
		_, touchErr := svc.Touch(ctx, "", token, idle)
		if touchErr != nil {
			require.ErrorIs(t, touchErr, sessions.ErrSessionNotFound,
				"expected ErrSessionNotFound once past 30-day absolute deadline")
			rejectedAt = elapsed + idle
			break
		}
	}
	require.NotZero(t, rejectedAt,
		"session was never rejected: default NewService must enforce a 30-day absolute lifetime")
	require.LessOrEqual(t, rejectedAt, 31*24*time.Hour,
		"session should have been rejected at or before 31 days, got rejection at %s", rejectedAt)
}
