package storetest

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

func identifierUniqueness(h *harness) {
	acme, other := h.tenant("acme"), h.tenant("other")
	a, b := h.full(acme), h.full(acme)
	ua := h.account(a).User
	beforeB := h.account(b)

	for _, m := range []identity.Mutation{
		identity.ChangeEmail{Subject: b, Email: ua.Email},
		identity.SetPhone{Subject: b, Phone: ua.Phone},
		identity.CreateVerified{Tenant: acme, Email: ua.Email},
	} {
		_, err := h.st.Apply(h.ctx, m)
		require.ErrorIs(h.t, err, identity.ErrIdentifierTaken, "%T reusing a live account's identifier", m)
	}
	require.Equal(h.t, beforeB, h.account(b), "a refused identifier change leaves the account as it was")

	h.apply(identity.SetRecoveryEmail{Subject: b, RecoveryEmail: ua.RecoveryEmail})
	require.Equal(h.t, ua.RecoveryEmail, h.account(b).User.RecoveryEmail, "a recovery email may be shared")

	elsewhere := h.apply(identity.CreateVerified{Tenant: other, Email: ua.Email}).Subject
	h.apply(identity.SetPhone{Subject: elsewhere, Phone: ua.Phone})

	h.apply(identity.ChangeEmail{Subject: a, Email: ua.Email})
	h.apply(identity.SetPhone{Subject: a, Phone: ua.Phone})

	h.apply(identity.Tombstone{Subject: a})
	fresh := h.apply(identity.CreateVerified{Tenant: acme, Email: ua.Email}).Subject
	h.apply(identity.SetPhone{Subject: fresh, Phone: ua.Phone})
	got, err := h.st.FindUser(h.ctx, acme, ua.Email)
	require.NoError(h.t, err)
	require.Equal(h.t, fresh, got.Subject, "a tombstone frees its identifiers")
	deleted := h.account(a).User
	require.Equal(h.t, ua.Email, deleted.Email, "Tombstone touches only deleted_at")

	email := h.email()
	var wins, taken atomic.Int32
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			_, err := h.st.Apply(h.ctx, identity.CreateVerified{Tenant: acme, Email: email})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, identity.ErrIdentifierTaken):
				taken.Add(1)
			default:
				h.t.Errorf("concurrent create: %v", err)
			}
		})
	}
	wg.Wait()
	require.EqualValues(h.t, 1, wins.Load(), "exactly one concurrent registration of an email wins")
	require.EqualValues(h.t, goroutines-1, taken.Load())
}

func federatedLinks(h *harness) {
	acme, other := h.tenant("acme"), h.tenant("other")
	s := h.create(acme)
	g := h.federated("google")
	h.apply(identity.LinkFederated{Subject: s, Identity: g})

	key := identity.FederatedKey{Tenant: acme, Provider: g.Provider, ProviderSubject: g.ProviderSubject}
	link, err := h.st.FindFederated(h.ctx, key)
	require.NoError(h.t, err)
	require.Equal(h.t, s, link.Subject)
	require.Equal(h.t, g, link.Identity, "provider email and its verification round-trip")
	h.recent(link.LinkedAt, "linked_at")
	_, err = h.st.FindFederated(h.ctx, identity.FederatedKey{Tenant: other, Provider: g.Provider, ProviderSubject: g.ProviderSubject})
	require.ErrorIs(h.t, err, store.ErrNotFound, "links never cross tenants")

	bare := g
	bare.ProviderSubject = "no-email-" + g.ProviderSubject
	bare.ProviderEmail, bare.ProviderEmailVerified = identity.Identifier{}, false
	h.apply(identity.LinkFederated{Subject: s, Identity: bare})
	links, err := h.st.ListFederated(h.ctx, s)
	require.NoError(h.t, err)
	sortLinks(links)
	require.Len(h.t, links, 2)
	require.Equal(h.t, bare, links[0].Identity, "a link without a provider email keeps none")

	_, err = h.st.Apply(h.ctx, identity.LinkFederated{Subject: s, Identity: g})
	require.ErrorIs(h.t, err, store.ErrConflict, "the same link twice is a conflict")
	t2 := h.create(acme)
	for _, m := range []identity.Mutation{
		identity.LinkFederated{Subject: t2, Identity: g},
		identity.CreateVerified{Tenant: acme, Email: h.email(), Federated: g},
	} {
		_, err := h.st.Apply(h.ctx, m)
		require.ErrorIs(h.t, err, identity.ErrIdentifierTaken, "%T of a provider account linked to another subject", m)
	}
	h.apply(identity.CreateVerified{Tenant: other, Email: h.email(), Federated: g})

	_, err = h.st.Apply(h.ctx, identity.UnlinkFederated{Subject: t2, Provider: g.Provider, ProviderSubject: g.ProviderSubject})
	require.ErrorIs(h.t, err, store.ErrNotFound, "a subject cannot unlink another subject's link")
	h.apply(identity.UnlinkFederated{Subject: s, Provider: g.Provider, ProviderSubject: g.ProviderSubject})
	_, err = h.st.FindFederated(h.ctx, key)
	require.ErrorIs(h.t, err, store.ErrNotFound)
	h.apply(identity.LinkFederated{Subject: t2, Identity: g})

	h.apply(identity.Tombstone{Subject: t2})
	_, err = h.st.FindFederated(h.ctx, key)
	require.ErrorIs(h.t, err, store.ErrNotFound, "FindFederated returns links of live accounts only")
	links, err = h.st.ListFederated(h.ctx, t2)
	require.NoError(h.t, err)
	require.Len(h.t, links, 1, "ListFederated still lists a tombstoned account's links")

	h.apply(identity.LinkFederated{Subject: s, Identity: g})
	link, err = h.st.FindFederated(h.ctx, key)
	require.NoError(h.t, err, "a tombstone frees its federated identities, like its email")
	require.Equal(h.t, s, link.Subject)
	links, err = h.st.ListFederated(h.ctx, t2)
	require.NoError(h.t, err)
	require.Empty(h.t, links, "the new link replaces the tombstoned account's one")

	h.apply(identity.Tombstone{Subject: s})
	fresh := h.apply(identity.CreateVerified{Tenant: acme, Email: h.email(), Federated: g}).Subject
	link, err = h.st.FindFederated(h.ctx, key)
	require.NoError(h.t, err, "a federated sign-up reclaims a tombstoned account's provider account")
	require.Equal(h.t, fresh, link.Subject)
	links, err = h.st.ListFederated(h.ctx, s)
	require.NoError(h.t, err)
	sortLinks(links)
	require.Len(h.t, links, 1)
	require.Equal(h.t, bare, links[0].Identity, "only the reclaimed link leaves the tombstoned account")
	h.ackAll(t2)
	require.NoError(h.t, h.st.EraseUser(h.ctx, t2))
	links, err = h.st.ListFederated(h.ctx, fresh)
	require.NoError(h.t, err)
	require.Len(h.t, links, 1, "erasing the former owner never touches the new owner's link")

	var wins, taken atomic.Int32
	var wg sync.WaitGroup
	h.apply(identity.Tombstone{Subject: fresh})
	for range goroutines {
		email := h.email()
		wg.Go(func() {
			_, err := h.st.Apply(h.ctx, identity.CreateVerified{Tenant: acme, Email: email, Federated: g})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, identity.ErrIdentifierTaken):
				taken.Add(1)
			default:
				h.t.Errorf("concurrent federated sign-up: %v", err)
			}
		})
	}
	wg.Wait()
	require.EqualValues(h.t, 1, wins.Load(), "exactly one concurrent sign-up reclaims a freed provider account")
	require.EqualValues(h.t, goroutines-1, taken.Load())
}

func markEmailVerified(h *harness) {
	acme := h.tenant("acme")
	s := newSubject(acme)
	email := h.email()
	h.h.Unverified(h.t, h.st, s, email)
	u := h.account(s).User
	require.Equal(h.t, email, u.Email)
	require.True(h.t, u.EmailVerifiedAt.IsZero())

	h.apply(identity.SetPassword{Subject: s, PHC: phc(), Reason: identity.RotationTemporaryPassword})
	h.apply(identity.LinkFederated{Subject: s, Identity: h.federated("google")})
	h.apply(identity.SetPhone{Subject: s, Phone: h.phone()})
	_, err := h.st.RecordPasswordFailure(h.ctx, s, identity.LockoutPolicy{Threshold: 5, Window: hour})
	require.NoError(h.t, err)
	before := h.account(s)
	require.NotNil(h.t, before.Password)
	require.True(h.t, before.User.MustChange)

	newPHC := phc()
	a := h.apply(identity.MarkEmailVerified{Subject: s, PHC: newPHC})
	after := h.account(s)
	h.recent(after.User.EmailVerifiedAt, "email_verified_at")
	require.NotNil(h.t, after.Password, "a registration confirm sets the registrant's password")
	require.Equal(h.t, newPHC.PHC(), after.Password.PHC, "the pre-verification password is wiped (C-39)")
	require.Zero(h.t, after.Password.FailedAttempts)
	require.True(h.t, after.Password.LockedUntil.IsZero())
	h.recent(after.Password.ChangedAt, "changed_at")
	require.Empty(h.t, after.Links, "pre-verification federated links are wiped (C-39)")

	expect := before
	expect.User.EmailVerifiedAt = after.User.EmailVerifiedAt
	expect.User.MustChange = false
	expect.User.SecurityEpoch = before.User.SecurityEpoch + 1
	expect.Password = after.Password
	expect.Links = nil
	require.Equal(h.t, expect, after, "MarkEmailVerified touches only the email verification and the credentials")
	require.Equal(h.t, expect.User.SecurityEpoch, a.NewEpoch)

	_, err = h.st.Apply(h.ctx, identity.MarkEmailVerified{Subject: s})
	require.ErrorIs(h.t, err, store.ErrConflict, "a replayed verification never wipes a verified account")
	require.Equal(h.t, after, h.account(s))

	w := newSubject(acme)
	h.h.Unverified(h.t, h.st, w, h.email())
	h.apply(identity.SetPassword{Subject: w, PHC: phc(), Reason: identity.RotationPasswordReset})
	h.apply(identity.MarkEmailVerified{Subject: w})
	wiped := h.account(w)
	require.Nil(h.t, wiped.Password, "an /email/verify without a password leaves none")
	_, err = h.st.GetPassword(h.ctx, w)
	require.ErrorIs(h.t, err, store.ErrNotFound)

	v := h.create(acme)
	_, err = h.st.Apply(h.ctx, identity.MarkEmailVerified{Subject: v})
	require.ErrorIs(h.t, err, store.ErrConflict, "CreateVerified accounts are already verified")
}

func federatedRebind(h *harness) {
	acme := h.tenant("acme")
	s := h.create(acme)
	g := h.federated("google")
	h.apply(identity.LinkFederated{Subject: s, Identity: g})
	key := identity.FederatedKey{Tenant: acme, Provider: g.Provider, ProviderSubject: g.ProviderSubject}
	before := h.epoch(s)
	pending := len(h.pending())

	rebound := g
	rebound.Authority = "tenant:" + g.ProviderSubject
	rebound.ProviderEmail, rebound.ProviderEmailVerified = identity.Identifier{}, false
	a := h.apply(identity.LinkFederated{Subject: s, Identity: rebound})
	require.Greater(h.t, a.NewEpoch, before, "a re-bound link bumps the epoch")
	require.Greater(h.t, len(h.pending()), pending, "a re-bound link notifies the owner")
	link, err := h.st.FindFederated(h.ctx, key)
	require.NoError(h.t, err)
	require.Equal(h.t, rebound, link.Identity, "the link carries its new authority")
	links, err := h.st.ListFederated(h.ctx, s)
	require.NoError(h.t, err)
	require.Len(h.t, links, 1, "a re-bind replaces the link, it adds none")

	_, err = h.st.Apply(h.ctx, identity.LinkFederated{Subject: s, Identity: rebound})
	require.ErrorIs(h.t, err, store.ErrConflict, "the same link under the same authority is a conflict")
	other := h.create(acme)
	_, err = h.st.Apply(h.ctx, identity.LinkFederated{Subject: other, Identity: g})
	require.ErrorIs(h.t, err, identity.ErrIdentifierTaken, "another subject never re-binds a link")
}
