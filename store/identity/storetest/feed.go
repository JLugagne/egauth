package storetest

import (
	"sync"
	"sync/atomic"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

func epochFeed(h *harness) {
	acme, other := h.tenant("acme"), h.tenant("other")
	first, c0, err := h.st.EpochsChangedSince(h.ctx, store.Cursor{})
	require.NoError(h.t, err)
	require.Empty(h.t, first)
	require.True(h.t, c0.IsZero(), "an empty feed keeps the zero cursor")

	a, b := h.create(acme), h.create(other)
	h.apply(identity.SetMustChange{Subject: a})
	h.apply(identity.SetDisabledState{Subject: a})
	h.apply(identity.BumpEpoch{Subject: a, Change: identity.FactorPasskeyAdded})
	h.apply(identity.SetPassword{Subject: b, PHC: phc(), Reason: identity.RotationPasswordReset})
	h.apply(identity.SetDisabledState{Subject: a, Disable: true})
	h.apply(identity.ChangeEmail{Subject: b, Email: h.email()})

	all, c1 := h.feed(store.Cursor{})
	require.Equal(h.t, []identity.EpochChange{
		{Subject: a, NewEpoch: 1, Reason: identity.EventFactorsChanged},
		{Subject: b, NewEpoch: 1, Reason: identity.EventCredentialRotated},
		{Subject: a, NewEpoch: 2, Reason: identity.EventDisable},
		{Subject: b, NewEpoch: 2, Reason: identity.EventIdentifierChanged},
	}, all, "the feed lists every bump of every tenant, oldest first")

	page, mid, err := h.st.EpochsChangedSince(h.ctx, store.Cursor{})
	require.NoError(h.t, err)
	require.NotEmpty(h.t, page)
	rest, _ := h.feed(mid)
	require.Equal(h.t, all, append(page, rest...), "resuming from a returned cursor neither skips nor repeats")

	again, c2 := h.feed(c1)
	require.Empty(h.t, again)
	require.Equal(h.t, c1, c2)

	h.apply(identity.Tombstone{Subject: a})
	tail, c3 := h.feed(c1)
	require.Equal(h.t, []identity.EpochChange{{Subject: a, NewEpoch: 3, Reason: identity.EventDelete}}, tail)
	require.True(h.t, c3.After(c1))
}

func epochFeedBackdated(h *harness) {
	acme := h.tenant("acme")
	a, b := h.create(acme), h.create(acme)
	h.apply(identity.BumpEpoch{Subject: a, Change: identity.FactorTOTPEnrolled})
	_, c := h.feed(store.Cursor{})
	h.apply(identity.BumpEpoch{Subject: b, Change: identity.FactorTOTPEnrolled})
	h.h.Age(h.t, h.st, b, 3*hour)
	got, _ := h.feed(c)
	require.Equal(h.t, []identity.EpochChange{{Subject: b, NewEpoch: 1, Reason: identity.EventFactorsChanged}}, got,
		"a change stamped before an earlier one is still returned after the cursor (C-18)")

	h.h.Age(h.t, h.st, a, 6*hour)
	h.apply(identity.BumpEpoch{Subject: a, Change: identity.FactorTOTPRemoved})
	got, _ = h.feed(c)
	require.Len(h.t, got, 2, "positions, not timestamps, order the feed")
	require.Equal(h.t, a, got[1].Subject)
	require.EqualValues(h.t, 2, got[1].NewEpoch)
}

func epochFeedConcurrent(h *harness) {
	acme := h.tenant("acme")
	const perSubject = 6
	subjects := make([]principal.Subject, goroutines)
	for i := range subjects {
		subjects[i] = h.create(acme)
	}
	var done atomic.Bool
	var seen []identity.EpochChange
	var poll sync.WaitGroup
	poll.Go(func() {
		c := store.Cursor{}
		for {
			stop := done.Load()
			got, nc, err := h.st.EpochsChangedSince(h.ctx, c)
			if err != nil {
				h.t.Errorf("poll: %v", err)
				return
			}
			if c.After(nc) {
				h.t.Errorf("cursor moved backwards")
				return
			}
			seen = append(seen, got...)
			c = nc
			if stop && len(got) == 0 {
				return
			}
		}
	})
	var wg sync.WaitGroup
	for _, s := range subjects {
		for range perSubject {
			wg.Go(func() {
				if _, err := h.st.Apply(h.ctx, identity.BumpEpoch{Subject: s, Change: identity.FactorPasskeyAdded}); err != nil {
					h.t.Errorf("bump: %v", err)
				}
			})
		}
	}
	wg.Wait()
	done.Store(true)
	poll.Wait()

	require.Len(h.t, seen, goroutines*perSubject, "a poller racing the writers sees every change exactly once")
	last := map[principal.Subject]uint64{}
	for _, ch := range seen {
		require.Equal(h.t, last[ch.Subject]+1, ch.NewEpoch, "each subject's epochs appear in order, without gaps")
		last[ch.Subject] = ch.NewEpoch
	}
	for _, s := range subjects {
		require.EqualValues(h.t, perSubject, h.epoch(s), "concurrent bumps never lose an increment")
	}
}

func currentEpoch(h *harness) {
	acme := h.tenant("acme")
	s := h.create(acme)
	require.Zero(h.t, h.epoch(s))
	_, err := h.st.CurrentEpoch(h.ctx, newSubject(acme))
	require.ErrorIs(h.t, err, store.ErrNotFound)

	want := uint64(0)
	for _, m := range []identity.Mutation{
		identity.SetMustChange{Subject: s, MustChange: true},
		identity.SetDisabledState{Subject: s, Disable: true},
		identity.SetDisabledState{Subject: s},
		identity.SetPhone{Subject: s, Phone: h.phone()},
		identity.BumpEpoch{Subject: s, Change: identity.FactorRecoveryCodesRegenerated},
		identity.Tombstone{Subject: s},
	} {
		a := h.apply(m)
		if identity.EffectsOf(m).BumpsEpoch {
			want++
		}
		require.Equal(h.t, want, a.NewEpoch, "%T", m)
		require.Equal(h.t, want, h.epoch(s), "%T", m)
		require.Equal(h.t, want, h.account(s).User.SecurityEpoch, "%T", m)
	}
}
