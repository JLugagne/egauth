package storetest

import (
	"errors"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

func legacyIdentifiers(h *harness) {
	t := h.tenant("acme")
	created := h.create(t)
	n, err := h.st.CountLegacyIdentifiers(h.ctx)
	require.NoError(h.t, err)
	require.Zero(h.t, n, "an account CreateVerified creates is canonical")
	rows, err := h.st.V016Identifiers(h.ctx, principal.Subject{}, 10)
	require.NoError(h.t, err)
	require.Empty(h.t, rows)
	_, err = h.st.V016Identifiers(h.ctx, principal.Subject{}, 0)
	require.ErrorIs(h.t, err, identity.ErrInvalidMutation)
	u, err := h.st.GetUser(h.ctx, created)
	require.NoError(h.t, err)
	email := h.email()
	ok, err := h.st.UpgradeIdentifiers(h.ctx, identity.IdentifierUpgrade{
		Old:   identity.V016Identifiers{Subject: created, Email: u.Email.Value()},
		Email: &email, State: identity.IdentifiersCanonical,
	})
	require.NoError(h.t, err)
	require.False(h.t, ok, "a canonical account is never rewritten")
	require.Equal(h.t, u.Email, h.account(created).User.Email)
	_, err = h.st.UpgradeIdentifiers(h.ctx, identity.IdentifierUpgrade{Old: identity.V016Identifiers{Subject: created}})
	require.ErrorIs(h.t, err, identity.ErrInvalidMutation, "the state must be canonical or held")
	phone := h.phone()
	_, err = h.st.UpgradeIdentifiers(h.ctx, identity.IdentifierUpgrade{
		Old: identity.V016Identifiers{Subject: created}, Email: &phone, State: identity.IdentifiersCanonical,
	})
	require.ErrorIs(h.t, err, identity.ErrInvalidMutation, "an identifier of the wrong kind is refused")
	if h.h.SeedV016 == nil {
		return
	}
	legacyRows(h, t)
}

func legacyRows(h *harness, t principal.TenantID) {
	seed := func(email, phone, recovery string) principal.Subject {
		s := newSubject(t)
		h.h.SeedV016(h.t, h.st, identity.V016Identifiers{Subject: s, Email: email, Phone: phone, RecoveryEmail: recovery})
		return s
	}
	broken := seed("john doe@example.com", "+0123456789", "")
	compat := seed("ｊｏｈｎ@example.com", "", "Backup@Example.org")
	taken := h.apply(identity.CreateVerified{Tenant: t, Email: h.ident(identity.IdentifierEmail, "taken@example.com")}).Subject

	u, err := h.st.GetUser(h.ctx, broken)
	require.NoError(h.t, err, "a stored value NewIdentifier refuses never fails a read")
	require.True(h.t, u.Email.IsZero() && u.Phone.IsZero())
	_, err = h.st.Apply(h.ctx, identity.SetDisabledState{Subject: broken, Disable: true})
	require.NoError(h.t, err, "nor a mutation")

	n, err := h.st.CountLegacyIdentifiers(h.ctx)
	require.NoError(h.t, err)
	require.EqualValues(h.t, 2, n)
	first, err := h.st.V016Identifiers(h.ctx, principal.Subject{}, 1)
	require.NoError(h.t, err)
	require.Len(h.t, first, 1)
	rest, err := h.st.V016Identifiers(h.ctx, first[0].Subject, 10)
	require.NoError(h.t, err)
	require.Len(h.t, rest, 1)
	byUser := map[principal.Subject]identity.V016Identifiers{first[0].Subject: first[0], rest[0].Subject: rest[0]}
	require.Equal(h.t, identity.V016Identifiers{Subject: broken, Email: "john doe@example.com", Phone: "+0123456789",
		State: identity.IdentifiersUnchecked}, byUser[broken])
	require.Equal(h.t, identity.V016Identifiers{Subject: compat, Email: "ｊｏｈｎ@example.com", RecoveryEmail: "Backup@Example.org",
		State: identity.IdentifiersUnchecked}, byUser[compat])

	clash := h.ident(identity.IdentifierEmail, "taken@example.com")
	_, err = h.st.UpgradeIdentifiers(h.ctx, identity.IdentifierUpgrade{Old: byUser[compat], Email: &clash, State: identity.IdentifiersCanonical})
	require.True(h.t, errors.Is(err, identity.ErrIdentifierTaken), "a rewrite onto another live account's email is refused: %v", err)
	require.Equal(h.t, "taken@example.com", h.account(taken).User.Email.Value())

	stale := byUser[compat]
	stale.Email = "other@example.com"
	folded := h.ident(identity.IdentifierEmail, "john@example.com")
	ok, err := h.st.UpgradeIdentifiers(h.ctx, identity.IdentifierUpgrade{Old: stale, Email: &folded, State: identity.IdentifiersCanonical})
	require.NoError(h.t, err)
	require.False(h.t, ok, "a row that no longer holds Old is left alone")

	recovery := h.ident(identity.IdentifierRecoveryEmail, "backup@example.org")
	ok, err = h.st.UpgradeIdentifiers(h.ctx, identity.IdentifierUpgrade{Old: byUser[compat], Email: &folded, RecoveryEmail: &recovery, State: identity.IdentifiersCanonical})
	require.NoError(h.t, err)
	require.True(h.t, ok)
	found, err := h.st.FindUser(h.ctx, t, folded)
	require.NoError(h.t, err)
	require.Equal(h.t, compat, found.Subject)
	require.Equal(h.t, recovery, found.RecoveryEmail)

	ok, err = h.st.UpgradeIdentifiers(h.ctx, identity.IdentifierUpgrade{Old: byUser[broken], State: identity.IdentifiersHeld})
	require.NoError(h.t, err)
	require.True(h.t, ok)
	n, err = h.st.CountLegacyIdentifiers(h.ctx)
	require.NoError(h.t, err)
	require.Zero(h.t, n, "a held account is not counted")
	left, err := h.st.V016Identifiers(h.ctx, principal.Subject{}, 10)
	require.NoError(h.t, err)
	held := byUser[broken]
	held.State = identity.IdentifiersHeld
	require.Equal(h.t, []identity.V016Identifiers{held}, left, "a held account is listed again, verbatim")

	h.apply(identity.Tombstone{Subject: broken})
	left, err = h.st.V016Identifiers(h.ctx, principal.Subject{}, 10)
	require.NoError(h.t, err)
	require.Len(h.t, left, 1)
	require.True(h.t, left[0].Tombstoned)
}
