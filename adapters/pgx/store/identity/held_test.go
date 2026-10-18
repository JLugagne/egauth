package identity_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/adapters/pgx/internal/legacyfixture"
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

func TestAnAccountWithANonCanonicalIdentifierAcceptsOnlyProtectiveMutations(t *testing.T) {
	ctx := context.Background()
	pool := emptyDatabase(t)
	require.NoError(t, legacyfixture.Migrate(ctx, pool, legacyfixture.Identity))
	id, err := legacyfixture.CreatePasswordAccount(ctx, pool, legacyfixture.Account{Tenant: "acme", Email: "john doe@example.com", PHC: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$legacy"})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE users SET email_verified_at = now() WHERE id = $1`, id)
	require.NoError(t, err)
	acme, err := principal.ParseTenantID("acme")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: acme, User: id}
	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "identity", FS: identitystore.Migrations}}))
	st := identitystore.New(pool)

	to, err := identity.NewIdentifier(identity.IdentifierEmail, "attacker@example.com")
	require.NoError(t, err)
	phone, err := identity.NewIdentifier(identity.IdentifierPhone, "+33612345678")
	require.NoError(t, err)
	backup, err := identity.NewIdentifier(identity.IdentifierRecoveryEmail, "backup@example.com")
	require.NoError(t, err)
	phc := identity.NewPasswordHash("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$new")
	for name, m := range map[string]identity.Mutation{
		"ChangeEmail":       identity.ChangeEmail{Subject: sub, Email: to},
		"SetPhone":          identity.SetPhone{Subject: sub, Phone: phone},
		"SetRecoveryEmail":  identity.SetRecoveryEmail{Subject: sub, RecoveryEmail: backup},
		"SetPassword":       identity.SetPassword{Subject: sub, PHC: phc, Reason: identity.RotationPasswordChanged},
		"MarkEmailVerified": identity.MarkEmailVerified{Subject: sub, PHC: phc},
		"LinkFederated":     identity.LinkFederated{Subject: sub, Identity: identity.FederatedIdentity{Provider: "corp", ProviderSubject: "c-1", Authority: "static"}},
	} {
		_, err := st.Apply(ctx, m)
		require.ErrorIs(t, err, identity.ErrIdentifiersHeld, "%s applied to an account whose email is not canonical: its notices would go nowhere", name)
	}
	for name, m := range map[string]identity.Mutation{
		"SetDisabledState": identity.SetDisabledState{Subject: sub, Disable: true},
		"SetMustChange":    identity.SetMustChange{Subject: sub, MustChange: true},
		"BumpEpoch":        identity.BumpEpoch{Subject: sub, Keep: uuid.Nil, Change: identity.FactorTOTPRemoved},
	} {
		_, err := st.Apply(ctx, m)
		require.NoError(t, err, "%s protects a held account and must apply", name)
	}
	_, err = st.Apply(ctx, identity.Tombstone{Subject: sub})
	require.NoError(t, err, "a held account can still be deleted")
}
