package memory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/federation/memory"
	"github.com/JLugagne/egauth/store/federation/storetest"
	"github.com/JLugagne/egauth/store/identity"
	idmem "github.com/JLugagne/egauth/store/identity/memory"
)

var _ memory.Links = (*idmem.Store)(nil)

type backend struct {
	clk *clock.Test
	ids *idmem.Store
}

var backends sync.Map

func newStore(t *testing.T) *memory.Store {
	clk := clock.NewTest(clock.Clock{}.Now())
	ids := idmem.NewWithClock(clk.Clock())
	s := memory.NewWithClock(clk.Clock(), ids)
	backends.Store(s, backend{clk: clk, ids: ids})
	t.Cleanup(func() { backends.Delete(s) })
	return s
}

func backendOf(t *testing.T, s federation.Store) backend {
	t.Helper()
	b, ok := backends.Load(s)
	require.True(t, ok, "the store was not built by newStore")
	return b.(backend)
}

func email(t *testing.T, v string) identity.Identifier {
	t.Helper()
	if v == "" {
		return identity.Identifier{}
	}
	id, err := identity.NewIdentifier(identity.IdentifierEmail, v)
	require.NoError(t, err)
	return id
}

func newAccount(t *testing.T, s federation.Store, tn principal.TenantID) principal.Subject {
	t.Helper()
	applied, err := backendOf(t, s).ids.Apply(context.Background(), identity.CreateVerified{
		Tenant: tn,
		Email:  email(t, uuid.NewString()+"@seed.invalid"),
		PHC:    identity.NewPasswordHash("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$c2VlZA"),
	})
	require.NoError(t, err)
	return applied.Subject
}

func seedLink(t *testing.T, s federation.Store, l federation.LinkedIdentity) {
	t.Helper()
	b := backendOf(t, s)
	b.clk.Set(l.LinkedAt)
	defer b.clk.Set(clock.Clock{}.Now())
	_, err := b.ids.Apply(context.Background(), identity.LinkFederated{
		Subject: l.Subject,
		Identity: identity.FederatedIdentity{
			Provider:              l.Key.Provider,
			ProviderSubject:       l.Key.ProviderSubject,
			ProviderEmail:         email(t, l.ProviderEmail),
			ProviderEmailVerified: l.ProviderEmailVerified && l.ProviderEmail != "",
		},
		Keep: uuid.New(),
	})
	require.NoError(t, err)
}

func tombstone(t *testing.T, s federation.Store, sub principal.Subject) {
	t.Helper()
	_, err := backendOf(t, s).ids.Apply(context.Background(), identity.Tombstone{Subject: sub})
	require.NoError(t, err)
}

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{
		SeedV016: func(t *testing.T, s federation.Store, p federation.ProviderSpec) {
			t.Helper()
			s.(*memory.Store).AddV016(p)
		},
		NewAccount: newAccount,
		SeedLink:   seedLink,
		Tombstone:  tombstone,
	})
	storetest.Run(t, func(t *testing.T) federation.Store { return newStore(t) })
}

func TestStoreIsEphemeral(t *testing.T) {
	require.Equal(t, store.Ephemeral, memory.New(idmem.New()).Durability())
}

func TestLinksWrittenByTheIdentityStoreAreVisible(t *testing.T) {
	ctx := context.Background()
	ids := idmem.New()
	s := memory.New(ids)
	tn, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	google := identity.FederatedIdentity{Provider: "google", ProviderSubject: "g-1", ProviderEmail: email(t, "alice@example.com"), ProviderEmailVerified: true}
	applied, err := ids.Apply(ctx, identity.CreateVerified{Tenant: tn, Email: email(t, "alice@example.com"), Federated: google})
	require.NoError(t, err)

	got, err := s.FindLinked(ctx, tn, federation.LinkKey{Provider: "google", ProviderSubject: "g-1"})
	require.NoError(t, err, "a link made by the identity store's mutations is found through the federation store")
	require.Equal(t, applied.Subject, got.Subject)
	require.Equal(t, "alice@example.com", got.ProviderEmail)
	require.True(t, got.ProviderEmailVerified)
	list, err := s.LinkedFor(ctx, applied.Subject)
	require.NoError(t, err)
	require.Len(t, list, 1)

	_, err = ids.Apply(ctx, identity.UnlinkFederated{Subject: applied.Subject, Provider: "google", ProviderSubject: "g-1", Keep: uuid.New()})
	require.NoError(t, err)
	_, err = s.FindLinked(ctx, tn, federation.LinkKey{Provider: "google", ProviderSubject: "g-1"})
	require.ErrorIs(t, err, store.ErrNotFound, "an unlink by the identity store is seen at once")
}

func TestErasedLinksStayHiddenUntilRelinked(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewTest(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	ids := idmem.NewWithClock(clk.Clock())
	s := memory.NewWithClock(clk.Clock(), ids)
	tn, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	key := federation.LinkKey{Provider: "google", ProviderSubject: "g-1"}
	fed := identity.FederatedIdentity{Provider: key.Provider, ProviderSubject: key.ProviderSubject}
	applied, err := ids.Apply(ctx, identity.CreateVerified{Tenant: tn, Email: email(t, "alice@example.com"), Federated: fed})
	require.NoError(t, err)

	require.NoError(t, s.EraseTenant(ctx, tn))
	_, err = s.FindLinked(ctx, tn, key)
	require.ErrorIs(t, err, store.ErrNotFound)

	clk.Advance(time.Second)
	_, err = ids.Apply(ctx, identity.UnlinkFederated{Subject: applied.Subject, Provider: key.Provider, ProviderSubject: key.ProviderSubject, Keep: uuid.New()})
	require.NoError(t, err)
	_, err = ids.Apply(ctx, identity.LinkFederated{Subject: applied.Subject, Identity: fed, Keep: uuid.New()})
	require.NoError(t, err)
	_, err = s.FindLinked(ctx, tn, key)
	require.NoError(t, err, "a link made after the erasure is visible")

	require.NoError(t, s.DeleteForSubject(ctx, applied.Subject))
	_, err = s.FindLinked(ctx, tn, key)
	require.ErrorIs(t, err, store.ErrNotFound)
}

type rawLinks struct {
	link identity.FederatedLink
}

func (r rawLinks) GetUser(_ context.Context, s principal.Subject) (identity.User, error) {
	return identity.User{Subject: s}, nil
}

func (r rawLinks) FindFederated(context.Context, identity.FederatedKey) (identity.FederatedLink, error) {
	return r.link, nil
}

func (r rawLinks) ListFederated(context.Context, principal.Subject) ([]identity.FederatedLink, error) {
	return []identity.FederatedLink{r.link}, nil
}

func TestVerifiedFlagWithoutEmailIsNeverReported(t *testing.T) {
	ctx := context.Background()
	tn, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	s := memory.New(rawLinks{link: identity.FederatedLink{
		Subject:  sub,
		Identity: identity.FederatedIdentity{Provider: "github", ProviderSubject: "1", ProviderEmailVerified: true},
		LinkedAt: clock.Clock{}.Now(),
	}})
	got, err := s.FindLinked(ctx, tn, federation.LinkKey{Provider: "github", ProviderSubject: "1"})
	require.NoError(t, err)
	require.False(t, got.ProviderEmailVerified, "a verified flag without an email verifies nothing")
	list, err := s.LinkedFor(ctx, sub)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.False(t, list[0].ProviderEmailVerified)
}

func TestLinksFromAnotherKeyAreRefused(t *testing.T) {
	ctx := context.Background()
	tn, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	other, err := principal.ParseTenantID("tenant-b")
	require.NoError(t, err)
	s := memory.New(rawLinks{link: identity.FederatedLink{
		Subject:  principal.Subject{Tenant: other, User: uuid.New()},
		Identity: identity.FederatedIdentity{Provider: "github", ProviderSubject: "1"},
	}})
	_, err = s.FindLinked(ctx, tn, federation.LinkKey{Provider: "github", ProviderSubject: "1"})
	require.ErrorIs(t, err, store.ErrNotFound, "a link of another tenant is never returned")
}

func TestNilLinksFails(t *testing.T) {
	ctx := context.Background()
	s := memory.New(nil)
	_, err := s.FindLinked(ctx, principal.TenantID{}, federation.LinkKey{Provider: "github", ProviderSubject: "1"})
	require.Error(t, err)
	require.NotErrorIs(t, err, store.ErrNotFound, "a store without links never claims a link is absent")
	_, err = s.LinkedFor(ctx, principal.Subject{User: uuid.New()})
	require.Error(t, err)
	require.Error(t, s.DeleteForSubject(ctx, principal.Subject{User: uuid.New()}))
}
