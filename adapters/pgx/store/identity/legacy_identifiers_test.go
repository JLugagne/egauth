package identity_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/adapters/pgx/internal/legacyfixture"
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

const legacyHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$legacy"

func v016Database(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := emptyDatabase(t)
	require.NoError(t, legacyfixture.Migrate(context.Background(), pool, legacyfixture.Identity))
	return pool
}

func upgradeSchema(t *testing.T, pool *pgxpool.Pool) *identitystore.Store {
	t.Helper()
	require.NoError(t, migrate.Run(context.Background(), pool, []migrate.Module{{Name: "identity", FS: identitystore.Migrations}}))
	return identitystore.New(pool)
}

func setLegacyPhone(t *testing.T, pool *pgxpool.Pool, sub principal.Subject, phone string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `UPDATE users SET phone = $2, phone_verified_at = now() WHERE id = $1`, sub.User, phone)
	require.NoError(t, err)
}

func TestV016AccountsWithNonCanonicalIdentifiersStayAdministrable(t *testing.T) {
	ctx := context.Background()
	pool := v016Database(t)
	quoted := legacyAccount(t, pool, "john doe@example.com", legacyHash)
	phone := legacyAccount(t, pool, "carol@example.com", legacyHash)
	setLegacyPhone(t, pool, phone, "+0123456789")
	st := upgradeSchema(t, pool)

	for name, sub := range map[string]principal.Subject{"quoted local part": quoted, "phone with a leading zero": phone} {
		t.Run(name, func(t *testing.T) {
			_, err := st.GetUser(ctx, sub)
			require.NoError(t, err, "a v0.16 row must stay readable")
			_, err = st.Apply(ctx, identity.SetDisabledState{Subject: sub, Disable: true})
			require.NoError(t, err, "an administrator must still be able to disable the account")
			_, err = st.Apply(ctx, identity.Tombstone{Subject: sub})
			require.NoError(t, err, "an administrator must still be able to delete the account")
		})
	}
}
