package storetest

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

func createVerified(h *harness) {
	tn := h.tenant("acme")
	email, pw, fed := h.email(), phc(), h.federated("google")
	a := h.apply(identity.CreateVerified{Tenant: tn, Email: email, PHC: pw, MustChange: true, Federated: fed})
	require.Equal(h.t, tn, a.Subject.Tenant)
	require.NotEqual(h.t, uuid.Nil, a.Subject.User, "the store picks the user id")
	require.Zero(h.t, a.NewEpoch)
	require.Empty(h.t, a.Outbox, "creating an account queues nothing")

	got := h.account(a.Subject)
	require.Equal(h.t, a.Subject, got.User.Subject)
	require.Equal(h.t, email, got.User.Email)
	h.recent(got.User.EmailVerifiedAt, "email_verified_at")
	h.recent(got.User.CreatedAt, "created_at")
	require.True(h.t, got.User.MustChange)
	require.Zero(h.t, got.User.SecurityEpoch)
	require.True(h.t, got.User.Phone.IsZero() && got.User.PhoneVerifiedAt.IsZero())
	require.True(h.t, got.User.RecoveryEmail.IsZero() && got.User.RecoveryEmailVerifiedAt.IsZero())
	require.True(h.t, got.User.DisabledAt.IsZero() && got.User.DeletedAt.IsZero())
	require.NotNil(h.t, got.Password)
	require.Equal(h.t, pw.PHC(), got.Password.PHC)
	h.recent(got.Password.ChangedAt, "password changed_at")
	require.Zero(h.t, got.Password.FailedAttempts)
	require.Len(h.t, got.Links, 1)
	require.Equal(h.t, fed, got.Links[0].Identity)
	require.Equal(h.t, a.Subject, got.Links[0].Subject)
	h.recent(got.Links[0].LinkedAt, "linked_at")

	bare := h.apply(identity.CreateVerified{Tenant: tn, Email: h.email()})
	require.NotEqual(h.t, a.Subject, bare.Subject)
	b := h.account(bare.Subject)
	require.Nil(h.t, b.Password, "an account without a password has no credential")
	require.False(h.t, b.User.MustChange)
	require.Empty(h.t, b.Links)
	_, err := h.st.GetPassword(h.ctx, bare.Subject)
	require.ErrorIs(h.t, err, store.ErrNotFound)

	single := h.apply(identity.CreateVerified{Email: h.email()})
	require.True(h.t, single.Subject.Tenant.IsZero(), "the single tenant is a tenant like any other")
	require.Equal(h.t, single.Subject, h.account(single.Subject).User.Subject)
}

func lookups(h *harness) {
	acme, other := h.tenant("acme"), h.tenant("other")
	s := h.full(acme)
	u := h.account(s).User

	for _, id := range []identity.Identifier{u.Email, u.Phone} {
		got, err := h.st.FindUser(h.ctx, acme, id)
		require.NoError(h.t, err, "find by %s", id.Kind())
		require.Equal(h.t, s, got.Subject)
		_, err = h.st.FindUser(h.ctx, other, id)
		require.ErrorIs(h.t, err, store.ErrNotFound, "lookups never cross tenants")
	}
	_, err := h.st.FindUser(h.ctx, acme, u.RecoveryEmail)
	require.ErrorIs(h.t, err, identity.ErrInvalidIdentifier, "a recovery email is not unique, so it finds nobody")
	_, err = h.st.FindUser(h.ctx, acme, identity.Identifier{})
	require.ErrorIs(h.t, err, identity.ErrInvalidIdentifier)
	_, err = h.st.FindUser(h.ctx, acme, h.email())
	require.ErrorIs(h.t, err, store.ErrNotFound)

	foreign := newSubject(other)
	foreign.User = s.User
	for name, call := range map[string]func() error{
		"GetUser":       func() error { _, err := h.st.GetUser(h.ctx, foreign); return err },
		"GetPassword":   func() error { _, err := h.st.GetPassword(h.ctx, foreign); return err },
		"ListFederated": func() error { _, err := h.st.ListFederated(h.ctx, foreign); return err },
		"CurrentEpoch":  func() error { _, err := h.st.CurrentEpoch(h.ctx, foreign); return err },
		"ResetFailures": func() error { return h.st.ResetPasswordFailures(h.ctx, foreign) },
		"RecordFailure": func() error {
			_, err := h.st.RecordPasswordFailure(h.ctx, foreign, identity.LockoutPolicy{Threshold: 3, Window: 1})
			return err
		},
	} {
		require.ErrorIs(h.t, call(), store.ErrNotFound, "%s of the same user id in another tenant", name)
	}

	h.apply(identity.Tombstone{Subject: s})
	for _, id := range []identity.Identifier{u.Email, u.Phone} {
		_, err := h.st.FindUser(h.ctx, acme, id)
		require.ErrorIs(h.t, err, store.ErrNotFound, "a deleted account is not found by %s", id.Kind())
	}
	got, err := h.st.GetUser(h.ctx, s)
	require.NoError(h.t, err, "GetUser returns a tombstoned account")
	h.recent(got.DeletedAt, "deleted_at")
	_, err = h.st.CurrentEpoch(h.ctx, s)
	require.NoError(h.t, err, "CurrentEpoch returns the epoch of a tombstoned account")
}

func applyRefusals(h *harness) {
	acme := h.tenant("acme")
	s := h.full(acme)
	before := h.account(s)
	missing := newSubject(acme)
	all := func(target principal.Subject) []identity.Mutation {
		return []identity.Mutation{
			identity.SetPassword{Subject: target, PHC: phc(), Reason: identity.RotationPasswordReset},
			identity.MarkEmailVerified{Subject: target},
			identity.ChangeEmail{Subject: target, Email: h.email()},
			identity.SetPhone{Subject: target, Phone: h.phone()},
			identity.SetRecoveryEmail{Subject: target, RecoveryEmail: h.recovery()},
			identity.SetDisabledState{Subject: target, Disable: true},
			identity.SetDisabledState{Subject: target},
			identity.SetMustChange{Subject: target},
			identity.Tombstone{Subject: target},
			identity.BumpEpoch{Subject: target, Change: identity.FactorTOTPEnrolled},
			identity.LinkFederated{Subject: target, Identity: h.federated("google")},
			identity.UnlinkFederated{Subject: target, Provider: "google", ProviderSubject: "nobody"},
		}
	}
	for _, m := range all(missing) {
		_, err := h.st.Apply(h.ctx, m)
		require.ErrorIs(h.t, err, store.ErrNotFound, "%T of an unknown subject", m)
	}

	invalid := []identity.Mutation{
		nil,
		identity.SetPassword{Subject: s, Reason: identity.RotationPasswordReset},
		identity.ChangeEmail{Subject: s, Email: h.phone()},
		identity.BumpEpoch{Subject: s},
		identity.CreateVerified{Tenant: acme},
		identity.LinkFederated{Subject: s, Identity: identity.FederatedIdentity{Provider: "google"}},
		identity.LinkFederated{Subject: s, Identity: identity.FederatedIdentity{Provider: "google", ProviderSubject: "no-authority"}},
		identity.LinkFederated{Subject: s, Identity: identity.FederatedIdentity{Provider: "password", ProviderSubject: s.User.String()}},
		identity.CreateVerified{Tenant: acme, Email: h.email(), Federated: identity.FederatedIdentity{Provider: "password", ProviderSubject: "x"}},
	}
	for _, m := range invalid {
		_, err := h.st.Apply(h.ctx, m)
		require.ErrorIs(h.t, err, identity.ErrInvalidMutation, "%T %v must be refused", m, m)
	}
	require.Equal(h.t, before, h.account(s), "a refused mutation changes nothing")

	pending := h.pending()
	h.apply(identity.Tombstone{Subject: s})
	for _, m := range all(s) {
		_, err := h.st.Apply(h.ctx, m)
		require.ErrorIs(h.t, err, identity.ErrTombstoned, "%T of a deleted account", m)
	}
	require.Len(h.t, h.pending(), len(pending)+len(identity.Components()), "only the tombstone queued rows")
}
