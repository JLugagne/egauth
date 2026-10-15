package e2e_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/adapters/pgx/pgxstore"
	"github.com/JLugagne/egauth/store"
)

func TestPostgresDeploymentWithPasskeysIsTheGoldenConfiguration(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	require.NoError(t, pgxstore.Migrate(ctx, pool))

	auth, err := buildAuth(ctx, t, pool, newKEK(t))
	require.NoError(t, err, "passkeys need no ceremony-store opt-out on PostgreSQL")
	t.Cleanup(func() { _ = auth.Close() })

	posture := auth.Posture()
	require.Empty(t, posture.OptOuts)
	require.Equal(t, store.Shared, posture.Durability)
	require.NoError(t, auth.Ready(ctx))
}
