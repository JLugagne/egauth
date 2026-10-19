package federation_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	federationstore "github.com/JLugagne/egauth/adapters/pgx/store/federation"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/federation"
)

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
	key := federation.LinkKey{Provider: "corp", ProviderSubject: "1042"}

	spec, err := s.GetProvider(ctx, victim.Tenant, "corp")
	require.NoError(t, err)
	runtime := federation.RuntimeAuthority(spec)
	before, err := s.FindLinked(ctx, victim.Tenant, key)
	require.NoError(t, err)
	require.Equal(t, runtime, before.Authority, "the v0.16 link is bound to the tenant's corp IdP")

	require.NoError(t, s.DeleteProvider(ctx, victim.Tenant, "corp"))

	after, err := s.FindLinked(ctx, victim.Tenant, key)
	require.NoError(t, err)
	require.Equal(t, runtime, after.Authority, "removing the provider must not re-label its v0.16 link")

	require.NotEqual(t, federation.StaticAuthority, after.Authority, "a static provider named corp would sign in as the victim")

	outside, err := s.HasLinksOutside(ctx, spec)
	require.NoError(t, err)
	require.False(t, outside, "re-registering the very same spec stays possible")
}
