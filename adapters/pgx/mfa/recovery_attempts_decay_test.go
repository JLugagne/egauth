package pgx_test

import (
	"context"
	"testing"
	"time"

	mfapgx "github.com/JLugagne/egauth/adapters/pgx/mfa"
	"github.com/JLugagne/egauth/keystore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPgxStore_RecoveryLockoutDecayIsNotExtendedByLockedAttempts pins the lockout state machine
// of the atomic upsert: while the counter is at/over the limit and the lockout window has not
// decayed, the persisted counter and timestamp are frozen (a continuous attack cannot extend its
// own lockout) and every caller still receives an over-limit count; once the window measured from
// the last within-limit attempt elapses, the next attempt resets the counter to 1.
func TestPgxStore_RecoveryLockoutDecayIsNotExtendedByLockedAttempts(t *testing.T) {
	ctx := context.Background()
	pool := racePool(t, 4)
	kek, err := keystore.NewKEK(randomKEKKey(t))
	require.NoError(t, err)
	store := mfapgx.NewStore(pool, kek)

	tenant := "tenant-decay"
	uid := uuid.Must(uuid.NewV7())
	base := time.Now()
	const maxAttempts = 2
	const lockoutDuration = time.Minute

	n, err := store.IncrementRecoveryAttempts(ctx, tenant, uid, base, maxAttempts, lockoutDuration)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	n, err = store.IncrementRecoveryAttempts(ctx, tenant, uid, base.Add(time.Second), maxAttempts, lockoutDuration)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "the second within-limit attempt reaches the limit")

	n, err = store.IncrementRecoveryAttempts(ctx, tenant, uid, base.Add(2*time.Second), maxAttempts, lockoutDuration)
	require.NoError(t, err)
	assert.Greater(t, n, maxAttempts, "an attempt past the limit is reported over-limit")

	// Keep hammering inside the lockout window: the persisted state must not move.
	for _, at := range []time.Time{base.Add(30 * time.Second), base.Add(50 * time.Second)} {
		n, err = store.IncrementRecoveryAttempts(ctx, tenant, uid, at, maxAttempts, lockoutDuration)
		require.NoError(t, err)
		assert.Greater(t, n, maxAttempts)
	}

	var persisted int
	var lastAttemptAt time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT failed_attempts, last_attempt_at FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2`,
		tenant, uid).Scan(&persisted, &lastAttemptAt))
	assert.Equal(t, maxAttempts+1, persisted, "locked attempts must not keep incrementing the persisted counter")
	assert.WithinDuration(t, base.Add(time.Second), lastAttemptAt, time.Millisecond,
		"locked attempts must not advance last_attempt_at (otherwise an attacker extends their own lockout)")

	// After the window measured from the last within-limit attempt, the counter resets.
	n, err = store.IncrementRecoveryAttempts(ctx, tenant, uid, base.Add(time.Minute+2*time.Second), maxAttempts, lockoutDuration)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "once the lockout decays the next attempt starts a fresh budget")
}
