package storetest

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

type touchCase struct {
	name    string
	subject func(h *harness, t principal.TenantID) principal.Subject
	setup   func(h *harness, s principal.Subject)
	m       func(h *harness, s principal.Subject, before account) identity.Mutation
	expect  func(h *harness, want *account, after account)
	old     func(before account) identity.Identifier
}

func touchCases() []touchCase {
	return []touchCase{
		{
			name: "SetPassword",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetPassword{Subject: s, PHC: phc(), Reason: identity.RotationPasswordChanged, Keep: uuid.New()}
			},
			expect: func(h *harness, want *account, after account) {
				require.NotNil(h.t, after.Password)
				h.recent(after.Password.ChangedAt, "changed_at")
				require.NotEqual(h.t, want.Password.PHC, after.Password.PHC)
				want.Password = &passwordState{PHC: after.Password.PHC, ChangedAt: after.Password.ChangedAt}
				want.User.MustChange = false
			},
		},
		{
			name: "SetPasswordTemporary",
			setup: func(h *harness, s principal.Subject) {
				h.apply(identity.SetMustChange{Subject: s})
			},
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetPassword{Subject: s, PHC: phc(), Reason: identity.RotationTemporaryPassword}
			},
			expect: func(h *harness, want *account, after account) {
				require.NotNil(h.t, after.Password)
				want.Password = &passwordState{PHC: after.Password.PHC, ChangedAt: after.Password.ChangedAt}
				want.User.MustChange = true
			},
		},
		{
			name:    "MarkEmailVerified",
			subject: (*harness).unverifiedFull,
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.MarkEmailVerified{Subject: s, PHC: phc()}
			},
			expect: func(h *harness, want *account, after account) {
				h.recent(after.User.EmailVerifiedAt, "email_verified_at")
				require.NotNil(h.t, after.Password, "the registration confirm sets the registrant's password")
				require.NotEqual(h.t, want.Password.PHC, after.Password.PHC, "the pre-verification password is wiped (C-39)")
				h.recent(after.Password.ChangedAt, "changed_at")
				want.User.EmailVerifiedAt, want.User.MustChange = after.User.EmailVerifiedAt, false
				want.Password = &passwordState{PHC: after.Password.PHC, ChangedAt: after.Password.ChangedAt}
				want.Links = nil
			},
		},
		{
			name:    "MarkEmailVerifiedWithoutPassword",
			subject: (*harness).unverifiedFull,
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.MarkEmailVerified{Subject: s}
			},
			expect: func(h *harness, want *account, after account) {
				h.recent(after.User.EmailVerifiedAt, "email_verified_at")
				want.User.EmailVerifiedAt, want.User.MustChange = after.User.EmailVerifiedAt, false
				want.Password, want.Links = nil, nil
			},
		},
		{
			name: "ChangeEmail",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.ChangeEmail{Subject: s, Email: h.email()}
			},
			expect: func(h *harness, want *account, after account) {
				h.recent(after.User.EmailVerifiedAt, "email_verified_at")
				want.User.Email, want.User.EmailVerifiedAt = after.User.Email, after.User.EmailVerifiedAt
			},
			old: func(b account) identity.Identifier { return b.User.Email },
		},
		{
			name: "SetPhone",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetPhone{Subject: s, Phone: h.phone()}
			},
			expect: func(h *harness, want *account, after account) {
				h.recent(after.User.PhoneVerifiedAt, "phone_verified_at")
				require.NotEqual(h.t, want.User.Phone, after.User.Phone)
				want.User.Phone, want.User.PhoneVerifiedAt = after.User.Phone, after.User.PhoneVerifiedAt
			},
			old: func(b account) identity.Identifier { return b.User.Phone },
		},
		{
			name: "RemovePhone",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetPhone{Subject: s}
			},
			expect: func(h *harness, want *account, after account) {
				want.User.Phone, want.User.PhoneVerifiedAt = identity.Identifier{}, after.User.PhoneVerifiedAt
				require.True(h.t, after.User.PhoneVerifiedAt.IsZero())
			},
			old: func(b account) identity.Identifier { return b.User.Phone },
		},
		{
			name: "SetRecoveryEmail",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetRecoveryEmail{Subject: s, RecoveryEmail: h.recovery()}
			},
			expect: func(h *harness, want *account, after account) {
				h.recent(after.User.RecoveryEmailVerifiedAt, "recovery_email_verified_at")
				require.NotEqual(h.t, want.User.RecoveryEmail, after.User.RecoveryEmail)
				want.User.RecoveryEmail, want.User.RecoveryEmailVerifiedAt = after.User.RecoveryEmail, after.User.RecoveryEmailVerifiedAt
			},
			old: func(b account) identity.Identifier { return b.User.RecoveryEmail },
		},
		{
			name: "RemoveRecoveryEmail",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetRecoveryEmail{Subject: s}
			},
			expect: func(h *harness, want *account, after account) {
				want.User.RecoveryEmail, want.User.RecoveryEmailVerifiedAt = identity.Identifier{}, time.Time{}
			},
			old: func(b account) identity.Identifier { return b.User.RecoveryEmail },
		},
		{
			name: "Disable",
			setup: func(h *harness, s principal.Subject) {
				h.apply(identity.SetDisabledState{Subject: s})
			},
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetDisabledState{Subject: s, Disable: true}
			},
			expect: func(h *harness, want *account, after account) {
				h.recent(after.User.DisabledAt, "disabled_at")
				want.User.DisabledAt = after.User.DisabledAt
			},
		},
		{
			name: "DisableAgain",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetDisabledState{Subject: s, Disable: true}
			},
			expect: func(*harness, *account, account) {},
		},
		{
			name: "Enable",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetDisabledState{Subject: s}
			},
			expect: func(h *harness, want *account, after account) {
				want.User.DisabledAt = time.Time{}
			},
		},
		{
			name: "SetMustChange",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.SetMustChange{Subject: s}
			},
			expect: func(h *harness, want *account, after account) {
				want.User.MustChange = false
			},
		},
		{
			name: "Tombstone",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.Tombstone{Subject: s}
			},
			expect: func(h *harness, want *account, after account) {
				h.recent(after.User.DeletedAt, "deleted_at")
				want.User.DeletedAt = after.User.DeletedAt
			},
		},
		{
			name: "BumpEpoch",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.BumpEpoch{Subject: s, Change: identity.FactorTOTPEnrolled, Keep: uuid.New()}
			},
			expect: func(*harness, *account, account) {},
		},
		{
			name: "LinkFederated",
			m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
				return identity.LinkFederated{Subject: s, Identity: h.federated("gitlab"), Keep: uuid.New()}
			},
			expect: func(h *harness, want *account, after account) {
				require.Len(h.t, after.Links, len(want.Links)+1)
				var added identity.FederatedLink
				for _, l := range after.Links {
					if l.Identity.Provider == "gitlab" {
						added = l
					}
				}
				h.recent(added.LinkedAt, "linked_at")
				want.Links = append(want.Links, added)
				sortLinks(want.Links)
			},
		},
		{
			name: "UnlinkFederated",
			m: func(h *harness, s principal.Subject, before account) identity.Mutation {
				l := before.Links[0].Identity
				return identity.UnlinkFederated{Subject: s, Provider: l.Provider, ProviderSubject: l.ProviderSubject}
			},
			expect: func(h *harness, want *account, after account) {
				want.Links = want.Links[1:]
			},
		},
	}
}

func (c touchCase) account(h *harness, t principal.TenantID) principal.Subject {
	h.t.Helper()
	if c.subject != nil {
		return c.subject(h, t)
	}
	return h.full(t)
}

func expectedAfter(h *harness, c touchCase, m identity.Mutation, before, after account) account {
	want := before
	want.Links = slices.Clone(before.Links)
	if before.Password != nil {
		p := *before.Password
		want.Password = &p
	}
	c.expect(h, &want, after)
	if identity.EffectsOf(m).BumpsEpoch {
		want.User.SecurityEpoch++
	}
	return want
}

func touchOwnState(h *harness) {
	acme, other := h.tenant("acme"), h.tenant("other")
	for _, c := range touchCases() {
		h.t.Run(c.name, func(t *testing.T) {
			h := &harness{t: t, st: h.st, h: h.h, ctx: h.ctx}
			s, bystander, foreign := c.account(h, acme), h.full(acme), h.full(other)
			if c.setup != nil {
				c.setup(h, s)
			}
			before := h.account(s)
			others := map[principal.Subject]account{bystander: h.account(bystander), foreign: h.account(foreign)}
			m := c.m(h, s, before)
			h.apply(m)
			after := h.account(s)
			require.Equal(t, expectedAfter(h, c, m, before, after), after, "%s must touch only its own columns (I-24)", c.name)
			for o, was := range others {
				require.Equal(t, was, h.account(o), "%s must not touch another account", c.name)
			}
		})
	}
}

func effectsAreAtomic(h *harness) {
	acme := h.tenant("acme")
	cases := append(touchCases(), touchCase{name: "CreateVerified", m: func(h *harness, s principal.Subject, _ account) identity.Mutation {
		return identity.CreateVerified{Tenant: s.Tenant, Email: h.email(), PHC: phc(), Federated: h.federated("google")}
	}})
	for _, c := range cases {
		h.t.Run(c.name, func(t *testing.T) {
			h := &harness{t: t, st: h.st, h: h.h, ctx: h.ctx}
			s := c.account(h, acme)
			if c.setup != nil {
				c.setup(h, s)
			}
			before := h.account(s)
			m := c.m(h, s, before)
			epochs, cur := h.feed(store.Cursor{})
			pending := h.pending()
			failures := 0
			for n := 0; ; n++ {
				require.Less(t, n, 256, "Apply never completed")
				a, err := h.st.Apply(h.h.Fail(t, h.ctx, h.st, n), m)
				if err == nil {
					if identity.EffectsOf(m).BumpsEpoch {
						changes, _ := h.feed(cur)
						require.Len(t, changes, 1)
						require.Equal(t, a.NewEpoch, changes[0].NewEpoch)
					}
					break
				}
				failures++
				require.ErrorIs(t, err, ErrInjected, "step %d", n)
				require.Equal(t, before, h.account(s), "a failure at step %d must leave the account untouched", n)
				got, _ := h.feed(store.Cursor{})
				require.Equal(t, epochs, got, "a failure at step %d must append no epoch-log row", n)
				require.Equal(t, pending, h.pending(), "a failure at step %d must write no outbox row", n)
				if cv, ok := m.(identity.CreateVerified); ok {
					_, err := h.st.FindUser(h.ctx, acme, cv.Email)
					require.ErrorIs(t, err, store.ErrNotFound, "a failure at step %d must create no account", n)
				}
			}
			require.GreaterOrEqual(t, failures, 2, "the Fail hook must reach every step of Apply, commit included")
		})
	}
}

func applyEffects(h *harness) {
	acme := h.tenant("acme")
	for _, c := range touchCases() {
		h.t.Run(c.name, func(t *testing.T) {
			h := &harness{t: t, st: h.st, h: h.h, ctx: h.ctx}
			s := c.account(h, acme)
			if c.setup != nil {
				c.setup(h, s)
			}
			before := h.account(s)
			_, cur := h.feed(store.Cursor{})
			pending := h.pending()
			m := c.m(h, s, before)
			a := h.apply(m)
			fx := identity.EffectsOf(m)

			require.Equal(t, s, a.Subject)
			wantEpoch := before.User.SecurityEpoch
			if fx.BumpsEpoch {
				wantEpoch++
			}
			require.Equal(t, wantEpoch, a.NewEpoch)
			require.Equal(t, wantEpoch, h.epoch(s))

			changes, _ := h.feed(cur)
			if fx.BumpsEpoch {
				require.Equal(t, []identity.EpochChange{{Subject: s, NewEpoch: wantEpoch, Reason: fx.Event}}, changes)
			} else {
				require.Empty(t, changes, "%s does not bump the epoch", c.name)
			}

			var old identity.Identifier
			if c.old != nil {
				old = c.old(before)
			}
			want := identity.OutboxFor(m, s, old)
			require.Len(t, a.Outbox, len(want))
			ids := map[int64]bool{}
			for i, it := range a.Outbox {
				require.Positive(t, it.ID)
				require.False(t, ids[it.ID], "outbox ids are unique")
				ids[it.ID] = true
				require.Zero(t, it.Attempts)
				h.recent(it.CreatedAt, "outbox created_at")
				require.False(t, it.NextAttemptAt.After(now().Add(recent)), "a new outbox row is due at once")
				w := want[i]
				w.ID, w.Attempts, w.NextAttemptAt, w.CreatedAt = it.ID, it.Attempts, it.NextAttemptAt, it.CreatedAt
				require.Equal(t, w, it)
			}
			got := h.pending()
			require.Len(t, got, len(pending)+len(want))
			for i, it := range a.Outbox {
				require.Equal(t, normItem(it), got[len(pending)+i], "PendingOutbox returns the rows Apply wrote")
			}
		})
	}
}
