package deployment_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	deploymentstore "github.com/JLugagne/egauth/adapters/pgx/store/deployment"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/deployment"
	"github.com/JLugagne/egauth/store/deployment/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) deployment.Store { return deploymentstore.New(cleanPool(t)) })
}

func TestStoreIsShared(t *testing.T) {
	s := deploymentstore.New(cleanPool(t))
	require.Equal(t, store.Shared, s.Durability())
	require.NoError(t, s.Ping(context.Background()))
}

func TestReapDeletesOnlyLapsedInstancesAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	s := deploymentstore.New(pool)
	gone, alive := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{gone, alive} {
		_, err := s.Heartbeat(ctx, id)
		require.NoError(t, err)
	}
	stored, err := s.PutSealedIfAbsent(ctx, "canary", []byte("sealed"))
	require.NoError(t, err)
	require.True(t, stored)
	_, err = pool.Exec(ctx, `UPDATE egauth_instances SET last_seen_at = now() - make_interval(secs => $2::double precision) WHERE instance_id = $1`,
		gone, (2 * deployment.LivenessWindow).Seconds())
	require.NoError(t, err)

	n, err := s.ReapExpired(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	var ids []uuid.UUID
	rows, err := pool.Query(ctx, `SELECT instance_id FROM egauth_instances`)
	require.NoError(t, err)
	for rows.Next() {
		var id uuid.UUID
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []uuid.UUID{alive}, ids)
	got, err := s.GetSealed(ctx, "canary")
	require.NoError(t, err)
	require.Equal(t, []byte("sealed"), got, "reaping never touches deployment values")
}
