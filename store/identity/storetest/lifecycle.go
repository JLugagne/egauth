package storetest

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

func passwordLockout(h *harness) {
	acme := h.tenant("acme")
	s := h.create(acme)
	p := identity.LockoutPolicy{Threshold: 3, Window: hour}
	for _, bad := range []identity.LockoutPolicy{{}, {Threshold: 3}, {Window: hour}, {Threshold: -1, Window: hour}, {Threshold: 3, Window: -hour}} {
		_, err := h.st.RecordPasswordFailure(h.ctx, s, bad)
		require.ErrorIs(h.t, err, identity.ErrInvalidMutation, "a lockout cannot be switched off by %+v", bad)
	}
	bare := h.apply(identity.CreateVerified{Tenant: acme, Email: h.email()}).Subject
	_, err := h.st.RecordPasswordFailure(h.ctx, bare, p)
	require.ErrorIs(h.t, err, store.ErrNotFound, "an account without a password has no lockout")
	require.ErrorIs(h.t, h.st.ResetPasswordFailures(h.ctx, bare), store.ErrNotFound)

	fail := func() identity.Lockout {
		h.t.Helper()
		l, err := h.st.RecordPasswordFailure(h.ctx, s, p)
		require.NoError(h.t, err)
		return l
	}
	require.Equal(h.t, identity.Lockout{FailedAttempts: 1}, fail())
	require.Equal(h.t, identity.Lockout{FailedAttempts: 2}, fail())
	locked := fail()
	require.True(h.t, locked.JustLocked)
	require.Equal(h.t, 3, locked.FailedAttempts)
	require.WithinDuration(h.t, now().Add(hour), locked.LockedUntil, recent, "the lock lasts Window")
	more := fail()
	require.False(h.t, more.JustLocked, "only the failure that crosses the threshold locks")
	require.Equal(h.t, 4, more.FailedAttempts)
	require.True(h.t, more.LockedUntil.Equal(locked.LockedUntil), "failures during a lock do not extend it")
	cred, err := h.st.GetPassword(h.ctx, s)
	require.NoError(h.t, err)
	require.Equal(h.t, 4, cred.FailedAttempts)
	require.True(h.t, cred.LockedUntil.Equal(locked.LockedUntil))

	h.h.Age(h.t, h.st, s, hour+time.Minute)
	require.Equal(h.t, identity.Lockout{FailedAttempts: 1}, fail(), "an expired lock restarts the count")
	fail()
	h.h.Age(h.t, h.st, s, hour/2)
	relocked := fail()
	require.Equal(h.t, 3, relocked.FailedAttempts, "failures within Window accumulate")
	require.True(h.t, relocked.JustLocked, "a new lockout cycle reports its lock again")

	require.NoError(h.t, h.st.ResetPasswordFailures(h.ctx, s))
	cred, err = h.st.GetPassword(h.ctx, s)
	require.NoError(h.t, err)
	require.Zero(h.t, cred.FailedAttempts)
	require.True(h.t, cred.LockedUntil.IsZero())

	fail()
	fail()
	h.h.Age(h.t, h.st, s, hour+time.Minute)
	require.Equal(h.t, identity.Lockout{FailedAttempts: 1}, fail(), "failures older than Window decay")

	c := h.create(acme)
	cp := identity.LockoutPolicy{Threshold: 5, Window: hour}
	var justLocked atomic.Int32
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			l, err := h.st.RecordPasswordFailure(h.ctx, c, cp)
			if err != nil {
				h.t.Errorf("record failure: %v", err)
				return
			}
			if l.JustLocked {
				justLocked.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(h.t, 1, justLocked.Load(), "exactly one concurrent failure crosses the threshold")
	cred, err = h.st.GetPassword(h.ctx, c)
	require.NoError(h.t, err)
	require.Equal(h.t, goroutines, cred.FailedAttempts, "no concurrent failure is lost")

	h.apply(identity.SetPassword{Subject: c, PHC: phc(), Reason: identity.RotationPasswordReset})
	cred, err = h.st.GetPassword(h.ctx, c)
	require.NoError(h.t, err)
	require.Zero(h.t, cred.FailedAttempts, "SetPassword clears the lockout")
	require.True(h.t, cred.LockedUntil.IsZero())
}

func outbox(h *harness) {
	acme, other := h.tenant("acme"), h.tenant("other")
	s, o := h.create(acme), h.create(other)
	rows := h.apply(identity.SetPassword{Subject: s, PHC: phc(), Reason: identity.RotationPasswordReset}).Outbox
	h.apply(identity.SetPassword{Subject: o, PHC: phc(), Reason: identity.RotationPasswordReset})
	n := len(identity.Components())
	require.Len(h.t, rows, n)
	require.Len(h.t, h.pending(), 2*n, "PendingOutbox spans tenants")

	page, err := h.st.PendingOutbox(h.ctx, 3)
	require.NoError(h.t, err)
	require.Len(h.t, page, 3, "PendingOutbox honours limit")
	for i := range page {
		require.Equal(h.t, rows[i].ID, page[i].ID, "oldest first")
	}
	none, err := h.st.PendingOutbox(h.ctx, 0)
	require.NoError(h.t, err)
	require.Empty(h.t, none)

	require.NoError(h.t, h.st.AckOutbox(h.ctx, rows[0].ID))
	require.NoError(h.t, h.st.AckOutbox(h.ctx, rows[0].ID), "AckOutbox is idempotent")
	require.NotContains(h.t, ids(h.pending()), rows[0].ID)

	last := rows[n-1].ID
	for _, it := range h.pending() {
		last = max(last, it.ID)
	}
	require.ErrorIs(h.t, h.st.AckOutbox(h.ctx, last+1000), store.ErrNotFound)
	require.ErrorIs(h.t, h.st.FailOutbox(h.ctx, last+1000, now()), store.ErrNotFound)

	later := now().Add(hour)
	require.NoError(h.t, h.st.FailOutbox(h.ctx, rows[1].ID, later))
	require.NotContains(h.t, ids(h.pending()), rows[1].ID, "a deferred row is not due")
	h.h.Age(h.t, h.st, s, 2*hour)
	due := find(h.pending(), rows[1].ID)
	require.NotNil(h.t, due, "a deferred row is due once the store clock reaches it")
	require.Equal(h.t, 1, due.Attempts)

	require.NoError(h.t, h.st.FailOutbox(h.ctx, rows[2].ID, now().Add(-time.Minute)))
	require.NoError(h.t, h.st.FailOutbox(h.ctx, rows[2].ID, now().Add(-time.Minute)))
	retried := find(h.pending(), rows[2].ID)
	require.NotNil(h.t, retried)
	require.Equal(h.t, 2, retried.Attempts, "every failure is counted")
	require.WithinDuration(h.t, now().Add(-time.Minute), retried.NextAttemptAt, recent)

	require.NoError(h.t, h.st.FailOutbox(h.ctx, rows[0].ID, now().Add(-time.Minute)))
	require.NotContains(h.t, ids(h.pending()), rows[0].ID, "failing a done row never revives it")
}

func ids(items []identity.OutboxItem) []int64 {
	out := make([]int64, 0, len(items))
	for _, it := range items {
		out = append(out, it.ID)
	}
	return out
}

func find(items []identity.OutboxItem, id int64) *identity.OutboxItem {
	for _, it := range items {
		if it.ID == id {
			return &it
		}
	}
	return nil
}

func eraseUser(h *harness) {
	acme := h.tenant("acme")
	s, bystander := h.full(acme), h.full(acme)
	keepB := h.account(bystander)
	links := h.account(s).Links

	require.ErrorIs(h.t, h.st.EraseUser(h.ctx, newSubject(acme)), store.ErrNotFound)
	require.ErrorIs(h.t, h.st.EraseUser(h.ctx, s), identity.ErrNotTombstoned)

	h.apply(identity.Tombstone{Subject: s})
	require.ErrorIs(h.t, h.st.EraseUser(h.ctx, s), store.ErrConflict, "every other component must be done first (C-03)")
	h.ackAll(s, identity.ComponentIdentity, identity.ComponentHooks)
	require.ErrorIs(h.t, h.st.EraseUser(h.ctx, s), store.ErrConflict, "a failing hook keeps a retryable tombstone")
	h.ackAll(s, identity.ComponentIdentity)
	require.NoError(h.t, h.st.EraseUser(h.ctx, s))

	_, err := h.st.GetUser(h.ctx, s)
	require.ErrorIs(h.t, err, store.ErrNotFound)
	_, err = h.st.GetPassword(h.ctx, s)
	require.ErrorIs(h.t, err, store.ErrNotFound)
	_, err = h.st.ListFederated(h.ctx, s)
	require.ErrorIs(h.t, err, store.ErrNotFound)
	_, err = h.st.CurrentEpoch(h.ctx, s)
	require.ErrorIs(h.t, err, store.ErrNotFound)
	require.ErrorIs(h.t, h.st.EraseUser(h.ctx, s), store.ErrNotFound)
	require.Equal(h.t, keepB, h.account(bystander), "EraseUser touches no other account")
	h.apply(identity.LinkFederated{Subject: bystander, Identity: links[0].Identity})
	require.Len(h.t, h.account(bystander).Links, len(keepB.Links)+1, "an erased account frees its provider accounts")
	var identityRows int
	for _, it := range h.pending() {
		if it.Subject == s {
			require.Equal(h.t, identity.ComponentIdentity, it.Component, "EraseUser acknowledges nothing")
			identityRows++
		}
	}
	require.Positive(h.t, identityRows)
}

func eraseTenant(h *harness) {
	acme, other := h.tenant("acme"), h.tenant("other")
	a, o := h.full(acme), h.full(other)
	email := h.account(a).User.Email
	keepO := h.account(o)
	oFeed := feedOf(h, o)
	oRows := rowsOf(h.pending(), o)

	require.NoError(h.t, h.st.EraseTenant(h.ctx, acme))
	_, err := h.st.GetUser(h.ctx, a)
	require.ErrorIs(h.t, err, store.ErrNotFound)
	_, err = h.st.FindUser(h.ctx, acme, email)
	require.ErrorIs(h.t, err, store.ErrNotFound)
	all, _ := h.feed(store.Cursor{})
	require.Equal(h.t, oFeed, all, "the erased tenant leaves no epoch-log row")
	require.Equal(h.t, oRows, h.pending(), "the erased tenant leaves no outbox row")
	require.Equal(h.t, keepO, h.account(o), "other tenants are untouched")
	h.apply(identity.CreateVerified{Tenant: acme, Email: email})
	require.NoError(h.t, h.st.EraseTenant(h.ctx, acme), "EraseTenant is repeatable")
}

func feedOf(h *harness, s principal.Subject) []identity.EpochChange {
	all, _ := h.feed(store.Cursor{})
	var out []identity.EpochChange
	for _, c := range all {
		if c.Subject == s {
			out = append(out, c)
		}
	}
	return out
}

func rowsOf(items []identity.OutboxItem, s principal.Subject) []identity.OutboxItem {
	var out []identity.OutboxItem
	for _, it := range items {
		if it.Subject == s {
			out = append(out, it)
		}
	}
	return out
}

func reapExpired(h *harness) {
	acme := h.tenant("acme")
	old, fresh := h.full(acme), h.full(acme)
	h.apply(identity.Tombstone{Subject: old})
	acked := 0
	for i, it := range rowsOf(h.pending(), old) {
		if i%2 == 0 {
			require.NoError(h.t, h.st.AckOutbox(h.ctx, it.ID))
			acked++
		}
	}
	h.ackAll(fresh)
	stillPending := rowsOf(h.pending(), old)
	freshFeed := feedOf(h, fresh)
	logRows := len(feedOf(h, old))
	require.Positive(h.t, logRows)

	h.h.Age(h.t, h.st, old, identity.Retention-hour)
	n, err := h.st.ReapExpired(h.ctx)
	require.NoError(h.t, err)
	require.Zero(h.t, n, "rows younger than Retention are kept")

	h.h.Age(h.t, h.st, old, 2*hour)
	n, err = h.st.ReapExpired(h.ctx)
	require.NoError(h.t, err)
	require.EqualValues(h.t, acked+logRows, n, "done outbox rows and epoch-log rows older than Retention are reaped")
	after, _ := h.feed(store.Cursor{})
	require.Equal(h.t, freshFeed, after, "only the old epoch-log rows go")
	require.Len(h.t, rowsOf(h.pending(), old), len(stillPending), "a pending row is never reaped")
	_, err = h.st.GetUser(h.ctx, old)
	require.NoError(h.t, err, "ReapExpired never deletes an account")
	n, err = h.st.ReapExpired(h.ctx)
	require.NoError(h.t, err)
	require.Zero(h.t, n)
}
