package egauth_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/identity/memory"
)

type v016Accounts struct {
	identity.Store
	mu        sync.Mutex
	rows      []identity.V016Identifiers
	takenOnce bool
	staleOnce map[principal.Subject]bool
	listErr   error
}

func newV016Accounts() *v016Accounts {
	return &v016Accounts{Store: memory.New(), staleOnce: map[principal.Subject]bool{}}
}

var acmeTenant = func() principal.TenantID {
	t, err := principal.ParseTenantID("acme")
	if err != nil {
		panic(err)
	}
	return t
}()

func (s *v016Accounts) seed(email, phone, recovery string, tombstoned bool) principal.Subject {
	sub := principal.Subject{Tenant: acmeTenant, User: uuid.New()}
	s.rows = append(s.rows, identity.V016Identifiers{Subject: sub, Email: email, Phone: phone, RecoveryEmail: recovery,
		Tombstoned: tombstoned, State: identity.IdentifiersUnchecked})
	return sub
}

func (s *v016Accounts) row(sub principal.Subject) *identity.V016Identifiers {
	for i := range s.rows {
		if s.rows[i].Subject == sub {
			return &s.rows[i]
		}
	}
	panic("v016Accounts: unknown subject")
}

func (s *v016Accounts) V016Identifiers(_ context.Context, after principal.Subject, limit int) ([]identity.V016Identifiers, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return nil, s.listErr
	}
	start := 0
	for i, r := range s.rows {
		if r.Subject == after {
			start = i + 1
		}
	}
	out := []identity.V016Identifiers{}
	for _, r := range s.rows[start:] {
		if len(out) == limit {
			break
		}
		if r.State != identity.IdentifiersCanonical {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *v016Accounts) CountLegacyIdentifiers(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, r := range s.rows {
		if r.State == identity.IdentifiersUnchecked {
			n++
		}
	}
	return n, nil
}

func (s *v016Accounts) FindUser(ctx context.Context, t principal.TenantID, id identity.Identifier) (identity.User, error) {
	s.mu.Lock()
	for _, r := range s.rows {
		stored := r.Email
		if id.Kind() == identity.IdentifierPhone {
			stored = r.Phone
		}
		if r.Subject.Tenant == t && !r.Tombstoned && stored == id.Value() {
			s.mu.Unlock()
			return identity.User{Subject: r.Subject}, nil
		}
	}
	s.mu.Unlock()
	return s.Store.FindUser(ctx, t, id)
}

func (s *v016Accounts) UpgradeIdentifiers(_ context.Context, u identity.IdentifierUpgrade) (bool, error) {
	if err := identity.ValidateUpgrade(u); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.takenOnce && u.State == identity.IdentifiersCanonical {
		s.takenOnce = false
		return false, identity.ErrIdentifierTaken
	}
	if s.staleOnce[u.Old.Subject] {
		delete(s.staleOnce, u.Old.Subject)
		return false, nil
	}
	r := s.row(u.Old.Subject)
	if r.State == identity.IdentifiersCanonical || r.Email != u.Old.Email || r.Phone != u.Old.Phone || r.RecoveryEmail != u.Old.RecoveryEmail {
		return false, nil
	}
	for _, f := range []struct {
		id  *identity.Identifier
		dst *string
	}{{u.Email, &r.Email}, {u.Phone, &r.Phone}, {u.RecoveryEmail, &r.RecoveryEmail}} {
		if f.id != nil {
			*f.dst = f.id.Value()
		}
	}
	r.State = u.State
	return true, nil
}

func upgradeAccounts(t *testing.T, s *v016Accounts) (egauth.IdentifierUpgradeReport, error) {
	t.Helper()
	return egauth.UpgradeIdentifiersV016(context.Background(), egauth.Storage{Identity: s})
}

func TestUpgradeIdentifiersV016FoldsTheFormsV016Kept(t *testing.T) {
	s := newV016Accounts()
	fullwidth := s.seed("ｊｏｈｎ@example.com", "", "", false)
	ligature := s.seed("ﬁle@example.com", "", "ｒｅｃｏｖｅｒ@example.org", false)
	circled := s.seed("x①@example.com", "", "", false)
	plain := s.seed("john.doe@example.com", "+33612345678", "", false)

	rep, err := upgradeAccounts(t, s)
	require.NoError(t, err)
	require.Equal(t, egauth.IdentifierUpgradeReport{Upgraded: 4, Rewritten: 4}, rep)
	for sub, want := range map[principal.Subject]identity.V016Identifiers{
		fullwidth: {Email: "john@example.com"},
		ligature:  {Email: "file@example.com", RecoveryEmail: "recover@example.org"},
		circled:   {Email: "x1@example.com"},
		plain:     {Email: "john.doe@example.com", Phone: "+33612345678"},
	} {
		want.Subject, want.State = sub, identity.IdentifiersCanonical
		require.Equal(t, want, *s.row(sub))
	}
	n, err := s.CountLegacyIdentifiers(context.Background())
	require.NoError(t, err)
	require.Zero(t, n, "New starts once every account is checked")

	again, err := upgradeAccounts(t, s)
	require.NoError(t, err)
	require.Equal(t, egauth.IdentifierUpgradeReport{}, again, "a second run finds nothing to do")
}

func TestUpgradeIdentifiersV016HoldsWhatV017CannotRepresent(t *testing.T) {
	s := newV016Accounts()
	quoted := s.seed("john doe@example.com", "", "", false)
	dots := s.seed("a..b@example.com", "", "", false)
	phone := s.seed("ｃａｒｏｌ@example.com", "+0123456789", "", false)

	rep, err := upgradeAccounts(t, s)
	require.ErrorIs(t, err, egauth.ErrIdentifiersHeld)
	require.Equal(t, 1, rep.Rewritten, "the representable email of a held account is still folded")
	require.Zero(t, rep.Upgraded)
	require.ElementsMatch(t, []egauth.HeldIdentifier{
		{Subject: quoted, Kind: identity.IdentifierEmail, Problem: egauth.IdentifierUnrepresentable},
		{Subject: dots, Kind: identity.IdentifierEmail, Problem: egauth.IdentifierUnrepresentable},
		{Subject: phone, Kind: identity.IdentifierPhone, Problem: egauth.IdentifierUnrepresentable},
	}, rep.Held)
	require.Equal(t, "john doe@example.com", s.row(quoted).Email, "a held value stays verbatim")
	require.Equal(t, identity.V016Identifiers{Subject: phone, Email: "carol@example.com", Phone: "+0123456789",
		State: identity.IdentifiersHeld}, *s.row(phone))
	n, err := s.CountLegacyIdentifiers(context.Background())
	require.NoError(t, err)
	require.Zero(t, n, "held accounts do not stop New")

	again, err := upgradeAccounts(t, s)
	require.ErrorIs(t, err, egauth.ErrIdentifiersHeld)
	require.ElementsMatch(t, rep.Held, again.Held, "every run reports the held accounts again")
}

func TestUpgradeIdentifiersV016NeverMergesTwoAccounts(t *testing.T) {
	s := newV016Accounts()
	email, err := identity.NewIdentifier(identity.IdentifierEmail, "john@example.com")
	require.NoError(t, err)
	live, err := s.Apply(context.Background(), identity.CreateVerified{Tenant: acmeTenant, Email: email})
	require.NoError(t, err)
	folded := s.seed("ｊｏｈｎ@example.com", "", "", false)
	first := s.seed("ｍary@example.com", "", "", false)
	second := s.seed("mａry@example.com", "", "", false)
	gone := s.seed("ｊoｈn@example.com", "", "", true)

	rep, err := upgradeAccounts(t, s)
	require.ErrorIs(t, err, egauth.ErrIdentifiersHeld)
	require.ElementsMatch(t, []egauth.HeldIdentifier{
		{Subject: folded, Kind: identity.IdentifierEmail, Problem: egauth.IdentifierCollides},
		{Subject: second, Kind: identity.IdentifierEmail, Problem: egauth.IdentifierCollides},
	}, rep.Held)
	require.Equal(t, "ｊｏｈｎ@example.com", s.row(folded).Email)
	require.Equal(t, "mary@example.com", s.row(first).Email, "the first account to fold keeps the address")
	require.Equal(t, "mａry@example.com", s.row(second).Email)
	require.Equal(t, "john@example.com", s.row(gone).Email, "a tombstoned account owns no identifier")
	got, err := s.FindUser(context.Background(), acmeTenant, email)
	require.NoError(t, err)
	require.Equal(t, live.Subject, got.Subject)
}

func TestUpgradeIdentifiersV016HoldsALostRace(t *testing.T) {
	s := newV016Accounts()
	sub := s.seed("ｒａｃｅ@example.com", "", "Ｂａｃｋ@example.org", false)
	s.takenOnce = true

	rep, err := upgradeAccounts(t, s)
	require.ErrorIs(t, err, egauth.ErrIdentifiersHeld)
	require.Equal(t, []egauth.HeldIdentifier{{Subject: sub, Kind: identity.IdentifierEmail, Problem: egauth.IdentifierCollides}}, rep.Held)
	require.Equal(t, identity.V016Identifiers{Subject: sub, Email: "ｒａｃｅ@example.com", RecoveryEmail: "back@example.org",
		State: identity.IdentifiersHeld}, *s.row(sub))
}

func TestUpgradeIdentifiersV016CountsAConcurrentWriter(t *testing.T) {
	s := newV016Accounts()
	sub := s.seed("ｊｏｈｎ@example.com", "", "", false)
	s.staleOnce[sub] = true
	rep, err := upgradeAccounts(t, s)
	require.NoError(t, err)
	require.Equal(t, egauth.IdentifierUpgradeReport{Concurrent: 1}, rep)
}

func TestUpgradeIdentifiersV016StopsOnAStoreFailure(t *testing.T) {
	s := newV016Accounts()
	s.seed("ｊｏｈｎ@example.com", "", "", false)
	down := errors.New("identity store down")
	s.listErr = down
	_, err := upgradeAccounts(t, s)
	require.ErrorIs(t, err, down)
	_, err = egauth.UpgradeIdentifiersV016(context.Background(), egauth.Storage{})
	require.Error(t, err, "Storage.Identity is required")
}

func TestUpgradeIdentifiersV016IsANoOpOnMemoryStores(t *testing.T) {
	rep, err := egauth.UpgradeIdentifiersV016(context.Background(), memstore.New(testKEK(t)))
	require.NoError(t, err)
	require.Equal(t, egauth.IdentifierUpgradeReport{}, rep)
}
