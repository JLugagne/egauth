package e2e_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/adapters/pgx/pgxstore"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

const bobID = "0b7e9f10-2a3c-4d5e-9f60-718293a4b5c6"

func v016User(ctx context.Context, t *testing.T, db pgxstore.MigrationDB, email, phone string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, email, email_verified_at, phone, phone_verified_at, created_at, updated_at)
VALUES ($1, $2, $3, now(), nullif($4, ''), CASE WHEN $4 = '' THEN NULL ELSE now() END, now(), now())`, id, e2eTenant, email, phone)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO identities (id, user_id, tenant_id, provider, provider_id, password_hash, created_at, updated_at)
SELECT $1, $2, tenant_id, 'password', $3, password_hash, now(), now() FROM identities WHERE user_id = $4 AND provider = 'password'`,
		uuid.New(), id, email, bobID)
	require.NoError(t, err)
	return id
}

func passwordLogin(t *testing.T, h http.Handler, identifier string) string {
	t.Helper()
	login := send(h, call{method: http.MethodPost, path: "/auth" + egauth.PathLogin,
		header: http.Header{egauth.HeaderTransport: {"bearer"}},
		body:   fmt.Sprintf(`{%q:%q,%q:%q}`, egauth.FieldIdentifier, identifier, egauth.FieldPassword, e2ePassword)})
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	token := login.Header().Get("X-Egauth-Access-Token")
	require.NotEmpty(t, token, login.Body.String())
	me := send(h, call{method: http.MethodGet, path: "/me", header: bearer(token)})
	require.Equal(t, http.StatusOK, me.Code)
	return me.Body.String()
}

func TestV016IdentifiersAreRenormalisedInPlace(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	loadDump(ctx, t, pool)
	require.NoError(t, pgxstore.Migrate(ctx, pool))
	folded := v016User(ctx, t, pool, "ｊｏｈｎ@example.test", "")
	quoted := v016User(ctx, t, pool, "dan doe@example.test", "")
	phone := v016User(ctx, t, pool, "erin@example.test", "+0123456789")
	clash := v016User(ctx, t, pool, "ｂob@example.test", "")

	newKey := newKEK(t)
	st, err := pgxstore.New(ctx, pool)
	require.NoError(t, err)
	legacy, err := kek.LegacyLocalV016(legacyFixtureKey(t))
	require.NoError(t, err)
	_, err = egauth.UpgradeSecretsV016(ctx, st, legacy, newKey)
	require.NoError(t, err)
	_, err = buildAuth(ctx, t, pool, newKey)
	require.ErrorContains(t, err, "6 v0.16 accounts with unchecked identifiers; run egauth.UpgradeIdentifiersV016")

	tenant, err := principal.ParseTenantID(e2eTenant)
	require.NoError(t, err)
	sub := func(id uuid.UUID) principal.Subject { return principal.Subject{Tenant: tenant, User: id} }
	rep, err := egauth.UpgradeIdentifiersV016(ctx, st)
	require.ErrorIs(t, err, egauth.ErrIdentifiersHeld)
	require.Equal(t, 3, rep.Upgraded, "alice, bob and the folded account")
	require.Equal(t, 1, rep.Rewritten)
	require.ElementsMatch(t, []egauth.HeldIdentifier{
		{Subject: sub(quoted), Kind: identity.IdentifierEmail, Problem: egauth.IdentifierUnrepresentable},
		{Subject: sub(phone), Kind: identity.IdentifierPhone, Problem: egauth.IdentifierUnrepresentable},
		{Subject: sub(clash), Kind: identity.IdentifierEmail, Problem: egauth.IdentifierCollides},
	}, rep.Held)
	again, err := egauth.UpgradeIdentifiersV016(ctx, st)
	require.ErrorIs(t, err, egauth.ErrIdentifiersHeld)
	require.ElementsMatch(t, rep.Held, again.Held, "a second run reports the held accounts again")
	require.Zero(t, again.Upgraded)

	auth, err := buildAuth(ctx, t, pool, newKey)
	require.NoError(t, err, "held accounts do not stop New")
	h := serve(t, auth)

	t.Run("the folded account is found by its own address", func(t *testing.T) {
		require.Equal(t, folded.String(), passwordLogin(t, h, "ｊｏｈｎ@example.test"))
		require.Equal(t, folded.String(), passwordLogin(t, h, "John@Example.test"))
	})

	t.Run("a colliding account is never merged", func(t *testing.T) {
		bob, err := identity.NewIdentifier(identity.IdentifierEmail, "bob@example.test")
		require.NoError(t, err)
		owner, err := st.Identity.FindUser(ctx, tenant, bob)
		require.NoError(t, err)
		require.Equal(t, bobID, owner.Subject.User.String(), "the folded address still belongs to bob")
		var stored string
		require.NoError(t, pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, clash).Scan(&stored))
		require.Equal(t, "ｂob@example.test", stored)
	})

	t.Run("held accounts stay administrable", func(t *testing.T) {
		caller, err := auth.System(tenant, "v016-identifier-upgrade-test")
		require.NoError(t, err)
		for _, id := range []uuid.UUID{quoted, phone, clash} {
			require.NoError(t, auth.Accounts().Disable(ctx, caller, id))
			require.NoError(t, auth.Accounts().Enable(ctx, caller, id))
		}
		require.NoError(t, auth.Accounts().Delete(ctx, caller, quoted))
		u, err := st.Identity.GetUser(ctx, sub(phone))
		require.NoError(t, err)
		require.Equal(t, "erin@example.test", u.Email.Value())
		require.True(t, u.Phone.IsZero(), "a phone v0.17 cannot represent reads as absent")
	})
}
