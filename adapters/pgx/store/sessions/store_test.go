package sessions_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sessionsstore "github.com/JLugagne/egauth/adapters/pgx/store/sessions"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/sessions"
	"github.com/JLugagne/egauth/store/sessions/storetest"
)

func travel(t *testing.T, _ sessions.Store, d time.Duration) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`UPDATE egauth_sessions SET idle_expires_at = idle_expires_at - $1::bigint * interval '1 microsecond',
    absolute_expires_at = absolute_expires_at - $1::bigint * interval '1 microsecond',
    checked_at = checked_at - $1::bigint * interval '1 microsecond',
    created_at = created_at - $1::bigint * interval '1 microsecond'`,
		`UPDATE egauth_session_revocations SET created_at = created_at - $1::bigint * interval '1 microsecond',
    expires_at = expires_at - $1::bigint * interval '1 microsecond'`,
	} {
		_, err := shared.pool.Exec(ctx, q, d.Microseconds())
		require.NoError(t, err)
	}
}

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{Restore: sessions.Restore, Travel: travel})
	storetest.Run(t, func(t *testing.T) sessions.Store { return sessionsstore.New(cleanPool(t)) })
}

func TestStoreIsShared(t *testing.T) {
	s := sessionsstore.New(cleanPool(t))
	require.Equal(t, store.Shared, s.Durability())
	require.NoError(t, s.Ping(context.Background()))
}
