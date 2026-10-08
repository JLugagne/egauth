package ceremony_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	ceremonystore "github.com/JLugagne/egauth/adapters/pgx/store/ceremony"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/ceremony/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, ceremony.Restore)
	storetest.Run(t, func(t *testing.T) ceremony.Store { return ceremonystore.New(cleanPool(t)) })
}

func TestStoreIsShared(t *testing.T) {
	s := ceremonystore.New(cleanPool(t))
	require.Equal(t, store.Shared, s.Durability())
	require.NoError(t, s.Ping(context.Background()))
}

func TestDeleteForScopeHasATenantScopeIndexAgainstPostgres(t *testing.T) {
	pool := cleanPool(t)
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_indexes
WHERE tablename = 'egauth_ceremonies' AND indexdef LIKE '%(tenant_id, scope_hash)'`).Scan(&n))
	require.Equal(t, 1, n, "DeleteForScope without a kind filter must not scan the whole tenant")
}
