package federation_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	federationstore "github.com/JLugagne/egauth/adapters/pgx/store/federation"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/federationsvc"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/identity"
)

type directoryUsers struct{}

func (directoryUsers) FindUser(context.Context, core.TenantID, identity.Identifier) (identity.User, error) {
	panic("FindUser must not be reached for a linked identity")
}

type directoryAccounts struct{}

func (directoryAccounts) AccountState(context.Context, core.Subject) (core.AccountState, error) {
	panic("AccountState must not be reached by SignIn")
}

func (directoryAccounts) Apply(context.Context, identity.Mutation) (identity.Applied, error) {
	panic("Apply must not be reached for a linked identity")
}

type directoryAudit struct{}

func (directoryAudit) Emit(context.Context, event.Type, audit.Scope, audit.Detail, error, ...audit.Attr) error {
	return nil
}

func TestRemovingAProviderKeepsTheAuthorityOfItsV016Links(t *testing.T) {
	ctx := context.Background()
	pool := emptyDatabase(t)
	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "identity", FS: identitystore.Migrations}, {Name: "federation", FS: legacyOnly(t)}}))
	_, err := pool.Exec(ctx, `INSERT INTO oauth_oidc_providers
    (tenant_id, provider_name, client_id, client_secret, auth_url, token_url, issuer, jwks_url, scopes)
VALUES ('tenant-a', 'corp', 'cid', 'c2VjcmV0', 'https://corp-idp.example/a', 'https://corp-idp.example/t',
        'https://corp-idp.example', 'https://corp-idp.example/j', 'openid email')`)
	require.NoError(t, err)
	victim := principal.Subject{Tenant: tenant(t, "tenant-a"), User: uuid.New()}
	_, err = pool.Exec(ctx, `INSERT INTO users (id, tenant_id, email, created_at, updated_at) VALUES ($1, 'tenant-a', 'victim@example.com', now(), now())`, victim.User)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO identities (id, user_id, tenant_id, provider, provider_id, created_at, updated_at)
VALUES ($1, $2, 'tenant-a', 'corp', '1042', now(), now())`, uuid.New(), victim.User)
	require.NoError(t, err)
	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "identity", FS: identitystore.Migrations}, {Name: "federation", FS: federationstore.Migrations}}))

	s := federationstore.New(pool)
	dir, err := federationsvc.NewDirectory(federationsvc.DirectoryConfig{
		Users: directoryUsers{}, Links: s, Accounts: directoryAccounts{}, Registration: federationsvc.RegistrationInviteOnly, Audit: directoryAudit{},
	})
	require.NoError(t, err)
	key := federation.LinkKey{Provider: "corp", ProviderSubject: "1042"}

	spec, err := s.GetProvider(ctx, victim.Tenant, "corp")
	require.NoError(t, err)
	runtime := federation.RuntimeAuthority(spec)
	before, err := s.FindLinked(ctx, victim.Tenant, key)
	require.NoError(t, err)
	require.Equal(t, runtime, before.Authority, "the v0.16 link is bound to the tenant's corp IdP")
	_, err = dir.SignIn(ctx, victim.Tenant, federationsvc.ProviderIdentity{Provider: "corp", Subject: "1042", Authority: federation.StaticAuthority})
	require.ErrorIs(t, err, federationsvc.ErrProviderChanged, "while the row exists, a static 'corp' cannot resolve it")

	require.NoError(t, s.DeleteProvider(ctx, victim.Tenant, "corp"))

	after, err := s.FindLinked(ctx, victim.Tenant, key)
	require.NoError(t, err)
	require.Equal(t, runtime, after.Authority, "removing the provider must not re-label its v0.16 link")

	_, err = dir.SignIn(ctx, victim.Tenant, federationsvc.ProviderIdentity{Provider: "corp", Subject: "1042", Authority: federation.StaticAuthority})
	require.ErrorIs(t, err, federationsvc.ErrProviderChanged, "a static provider named corp must not sign in as the victim")

	outside, err := s.HasLinksOutside(ctx, spec)
	require.NoError(t, err)
	require.False(t, outside, "re-registering the very same spec stays possible")
}
