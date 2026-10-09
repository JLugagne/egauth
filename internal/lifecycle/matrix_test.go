package lifecycle_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

type matrixCase struct {
	user  identity.User
	keep  uuid.UUID
	world *fakeWorld
}

func newMatrixCase(t *testing.T) matrixCase {
	t.Helper()
	tenant := mustTenant(t, "acme")
	u := identity.User{
		Subject:       principalSubject(tenant),
		Email:         mustID(t, identity.IdentifierEmail, "owner@example.com"),
		Phone:         mustID(t, identity.IdentifierPhone, "+33612345678"),
		RecoveryEmail: mustID(t, identity.IdentifierRecoveryEmail, "backup@example.org"),
	}
	return matrixCase{user: u, keep: uuid.New(), world: newFakeWorld(t, u)}
}

func kindList(ks ...ceremony.Kind) string {
	names := make([]string, 0, len(ks))
	for _, k := range ks {
		names = append(names, k.String())
	}
	return strings.Join(names, ",")
}

type eventRun struct {
	name string
	run  func(ctx context.Context, s lifecycle.Subscriber) error
	row  identity.OutboxItem
}

func (m matrixCase) events() []eventRun {
	sub := m.user.Subject
	acct := lifecycle.AccountEvent{Subject: sub}
	row := func(e identity.Event) identity.OutboxItem {
		return identity.OutboxItem{ID: 7, Component: identity.ComponentNotices, Event: e, Subject: sub}
	}
	return []eventRun{
		{"CredentialRotated", func(ctx context.Context, s lifecycle.Subscriber) error {
			return s.OnCredentialRotated(ctx, lifecycle.CredentialRotated{Subject: sub, Keep: m.keep, Reason: lifecycle.RotationPasswordReset})
		}, row(identity.EventCredentialRotated)},
		{"FactorsChanged", func(ctx context.Context, s lifecycle.Subscriber) error {
			return s.OnFactorsChanged(ctx, lifecycle.FactorsChanged{Subject: sub, Keep: m.keep, Change: lifecycle.FactorTOTPEnrolled})
		}, row(identity.EventFactorsChanged)},
		{"IdentifierChanged", func(ctx context.Context, s lifecycle.Subscriber) error {
			return s.OnIdentifierChanged(ctx, lifecycle.IdentifierChanged{Subject: sub, Kind: lifecycle.IdentifierEmail, Old: "previous@example.com"})
		}, row(identity.EventIdentifierChanged)},
		{"Disable", func(ctx context.Context, s lifecycle.Subscriber) error { return s.OnDisabled(ctx, acct) }, row(identity.EventDisable)},
		{"Enable", func(ctx context.Context, s lifecycle.Subscriber) error { return s.OnEnabled(ctx, acct) }, row(identity.EventEnable)},
		{"Delete", func(ctx context.Context, s lifecycle.Subscriber) error { return s.OnDeleted(ctx, acct) }, row(identity.EventDelete)},
		{"TenantErased", func(ctx context.Context, s lifecycle.Subscriber) error {
			return s.OnTenantErased(ctx, lifecycle.TenantErased{Tenant: sub.Tenant})
		}, identity.OutboxItem{}},
		{"SessionEnded", func(ctx context.Context, s lifecycle.Subscriber) error {
			return s.OnSessionEnded(ctx, lifecycle.SessionEnded{Subject: sub, Family: m.keep})
		}, identity.OutboxItem{}},
	}
}

func (m matrixCase) expected() map[string][8][]string {
	u := m.user.Subject.User.String()
	keep := m.keep.String()
	cer := func(label string, ks ...ceremony.Kind) string {
		return "ceremony.DeleteForScope acme " + label + " " + kindList(ks...)
	}
	signIn := []ceremony.Kind{ceremony.MagicLink, ceremony.EmailCode, ceremony.SMSCode}
	idScopes := func(ks []ceremony.Kind, old bool) []string {
		var out []string
		if old {
			out = append(out, cer("email:previous@example.com", ks...))
		}
		return append(out, cer("email:owner@example.com", ks...), cer("phone:+33612345678", ks...),
			cer("recovery_email:backup@example.org", ks...))
	}
	allSubject := []ceremony.Kind{
		ceremony.MFAFlow, ceremony.PasskeyRegistration, ceremony.MFAPasskey, ceremony.PhoneVerification,
		ceremony.PasswordReset, ceremony.EmailVerification, ceremony.EmailChange, ceremony.RecoveryEmail,
		ceremony.Exchange, ceremony.PasswordResetCode,
	}
	allIdentifierButRevert := []ceremony.Kind{ceremony.MagicLink, ceremony.EmailCode, ceremony.SMSCode, ceremony.PendingRegistration}
	allIdentifier := append(slices.Clone(allIdentifierButRevert), ceremony.SecurityRevert)
	return map[string][8][]string{
		"sessions": {
			{"backend.OnCredentialRotated keep=" + keep}, {"backend.OnFactorsChanged keep=" + keep},
			{"backend.OnIdentifierChanged"}, {"backend.OnDisabled"}, {"backend.OnEnabled"}, {"backend.OnDeleted"},
			{"backend.OnTenantErased"}, {"backend.OnSessionEnded " + keep},
		},
		"api_keys": {nil, nil, nil, nil, nil, {"tokens.DeleteForSubject " + u}, {"tokens.EraseTenant acme"}, nil},
		"ceremonies": {
			append([]string{cer("subject", ceremony.PasswordReset, ceremony.PasswordResetCode, ceremony.MFAFlow)}, idScopes(signIn, false)...),
			{cer("subject", ceremony.MFAFlow, ceremony.MFAPasskey)},
			append([]string{cer("subject", ceremony.PasswordReset, ceremony.PasswordResetCode, ceremony.EmailVerification,
				ceremony.PhoneVerification, ceremony.EmailChange, ceremony.RecoveryEmail)}, idScopes(signIn, true)...),
			append([]string{cer("subject", allSubject...)}, idScopes(allIdentifierButRevert, false)...),
			nil,
			append(append([]string{cer("subject", allSubject...)}, idScopes(allIdentifier, false)...),
				cer("revert-history", allIdentifier...), cer("revert-tenure", allIdentifier...)),
			{"ceremony.EraseTenant acme"},
			nil,
		},
		"mfa":        {nil, nil, nil, nil, nil, {"mfa.DeleteForSubject " + u}, {"mfa.EraseTenant acme"}, nil},
		"passkeys":   {nil, nil, nil, nil, nil, {"passkey.DeleteForSubject " + u}, {"passkey.EraseTenant acme"}, nil},
		"federation": {nil, nil, nil, nil, nil, {"federation.DeleteForSubject " + u}, {"federation.EraseTenant acme"}, nil},
		"notices": {
			{"notices.Send credential_rotated"}, {"notices.Send factors_changed"}, {"notices.Send identifier_changed"},
			nil, nil, nil, nil, nil,
		},
		"keys":     {nil, nil, nil, nil, nil, nil, {"keys.Tombstone acme", "keys.EraseTenant acme"}, nil},
		"hooks":    {nil, nil, nil, nil, nil, {"hooks.AccountDeleted " + u}, {"hooks.TenantErased acme"}, nil},
		"identity": {nil, nil, nil, nil, nil, {"identity.EraseUser " + u}, {"identity.EraseTenant acme"}, nil},
	}
}

func subscriberOf(w lifecycle.Wiring, name string, row identity.OutboxItem) lifecycle.Subscriber {
	switch name {
	case "sessions":
		return w.Sessions
	case "api_keys":
		return w.APIKeys
	case "ceremonies":
		return w.Ceremonies
	case "mfa":
		return w.MFA
	case "passkeys":
		return w.Passkeys
	case "federation":
		return w.Federation
	case "notices":
		return w.Notices.For(row)
	case "keys":
		return w.Keys
	case "hooks":
		return w.Hooks
	case "identity":
		return w.Identity
	}
	return nil
}

func TestEveryMatrixCellMakesExactlyItsStoreCalls(t *testing.T) {
	m := newMatrixCase(t)
	ctx := context.Background()
	for name, cells := range m.expected() {
		for i, ev := range m.events() {
			t.Run(name+"/"+ev.name, func(t *testing.T) {
				s := subscriberOf(m.world.wiring, name, ev.row)
				m.world.c.take()
				if err := ev.run(ctx, s); err != nil {
					t.Fatalf("cell failed: %v", err)
				}
				got := m.world.c.take()
				if !reflect.DeepEqual(got, cells[i]) {
					t.Fatalf("calls:\n got  %q\n want %q", got, cells[i])
				}
			})
		}
	}
}

func TestCredentialRotationNeverErasesFactorsNorRevertLinks(t *testing.T) {
	m := newMatrixCase(t)
	ctx := context.Background()
	reasons := []lifecycle.RotationReason{
		lifecycle.RotationPasswordChanged, lifecycle.RotationPasswordReset, lifecycle.RotationTemporaryPassword,
		lifecycle.RotationSecurityRevert,
	}
	w := m.world.wiring
	for _, r := range reasons {
		e := lifecycle.CredentialRotated{Subject: m.user.Subject, Reason: r}
		for _, s := range []lifecycle.Subscriber{w.MFA, w.Passkeys, w.Federation, w.APIKeys, w.Keys, w.Hooks, w.Identity} {
			if err := s.OnCredentialRotated(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		if got := m.world.c.take(); len(got) != 0 {
			t.Fatalf("a %s rotation touched factor or key stores: %q (I-09, T-05)", r, got)
		}
		if err := w.Ceremonies.OnCredentialRotated(ctx, e); err != nil {
			t.Fatal(err)
		}
		for _, call := range m.world.c.take() {
			if strings.Contains(call, ceremony.SecurityRevert.String()) {
				t.Fatalf("a %s rotation deleted revert links: %s (C-45)", r, call)
			}
		}
	}
}

func TestGoldenIsTheDesignMatrix(t *testing.T) {
	g := lifecycle.Golden()
	design := map[identity.Component][8]lifecycle.Cell{
		identity.ComponentSessions: {"revoke all but Keep", "revoke all but Keep", "revoke all", "revoke all", "none",
			"revoke all", "EraseTenant", "revoke family"},
		identity.ComponentAPIKeys: {"none", "none", "none", "unusable via owner state", "usable again",
			"revoke all by erasure", "EraseTenant", "none"},
		identity.ComponentCeremonies: {"delete reset, link, code and flow", "delete MFA flow and MFA passkey",
			"delete link, code, reset and verification", "delete all but revert", "none", "delete all", "EraseTenant", "none"},
		identity.ComponentMFA:        {"none", "none", "none", "none", "none", "erase", "EraseTenant", "none"},
		identity.ComponentPasskeys:   {"none", "none", "none", "none", "none", "erase", "EraseTenant", "none"},
		identity.ComponentFederation: {"none", "none", "none", "none", "none", "erase", "EraseTenant", "none"},
		identity.ComponentNotices: {"notice to the current email with revert link", "notice to the current email with revert link",
			"notice to the old address with revert link", "none", "none", "none", "none", "none"},
		identity.ComponentKeys:  {"none", "none", "none", "none", "none", "none", "tombstone + erase", "none"},
		identity.ComponentHooks: {"none", "none", "none", "none", "none", "Hooks.AccountDeleted", "Hooks.TenantErased", "none"},
		identity.ComponentIdentity: {"none", "none", "none", "none", "none",
			"hard delete when every other outbox row of the subject is done", "EraseTenant (last)", "none"},
	}
	if len(g) != len(identity.Components()) || len(design) != len(identity.Components()) {
		t.Fatalf("golden has %d rows, want one per component", len(g))
	}
	for c, want := range design {
		r := g[c]
		got := [8]lifecycle.Cell{r.CredentialRotated, r.FactorsChanged, r.IdentifierChanged, r.Disable, r.Enable, r.Delete, r.TenantErased, r.SessionEnded}
		if got != want {
			t.Errorf("%s:\n got  %q\n want %q", c, got, want)
		}
	}
}

func TestDispatcherMatrixIsGoldenForAFullWiring(t *testing.T) {
	m := newMatrixCase(t)
	d, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: &memOutboxStub{}, Wiring: m.world.wiring, Reporter: &retries{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Matrix(); !reflect.DeepEqual(got, lifecycle.Golden()) {
		t.Fatalf("wired matrix differs from golden:\n got  %v\n want %v", got, lifecycle.Golden())
	}
}

func TestAbsentOptionalStoresAreReportedAndInert(t *testing.T) {
	m := newMatrixCase(t)
	w := m.world.wiring
	w.APIKeys, w.Federation, w.Keys = lifecycle.AbsentAPIKeys(), lifecycle.AbsentFederation(), lifecycle.AbsentKeys()
	d, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: &memOutboxStub{}, Wiring: w, Reporter: &retries{}})
	if err != nil {
		t.Fatal(err)
	}
	absent := lifecycle.Cells{"absent", "absent", "absent", "absent", "absent", "absent", "absent", "absent"}
	got := d.Matrix()
	for _, c := range []identity.Component{identity.ComponentAPIKeys, identity.ComponentFederation, identity.ComponentKeys} {
		if got[c] != absent {
			t.Errorf("%s: got %v, want absent", c, got[c])
		}
	}
	ctx := context.Background()
	for _, ev := range m.events() {
		for _, s := range []lifecycle.Subscriber{w.APIKeys, w.Federation, w.Keys} {
			if err := ev.run(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
	}
	if calls := m.world.c.take(); len(calls) != 0 {
		t.Fatalf("an absent store was called: %q", calls)
	}
}

func TestLifecycleEnumsMirrorTheOutboxEnums(t *testing.T) {
	for k := identity.IdentifierKind(0); k <= 4; k++ {
		if lifecycle.IdentifierKind(k).String() != k.String() {
			t.Errorf("identifier kind %d: lifecycle %q, identity %q", k, lifecycle.IdentifierKind(k), k)
		}
	}
	for r := identity.RotationReason(0); r <= 5; r++ {
		if lifecycle.RotationReason(r).String() != r.String() {
			t.Errorf("rotation reason %d: lifecycle %q, identity %q", r, lifecycle.RotationReason(r), r)
		}
	}
	for c := identity.FactorChange(0); c <= 8; c++ {
		if lifecycle.FactorChange(c).String() != c.String() {
			t.Errorf("factor change %d: lifecycle %q, identity %q", c, lifecycle.FactorChange(c), c)
		}
	}
}

type standInBackend struct{ lifecycle.Subscriber }

func TestDispatcherMatrixReflectsTheHooksActuallyWired(t *testing.T) {
	m := newMatrixCase(t)
	cases := []struct {
		name          string
		deleted       lifecycle.AccountDeletedHook
		erased        lifecycle.TenantErasedHook
		wantDelete    lifecycle.Cell
		wantTenantEra lifecycle.Cell
	}{
		{"both", m.world.hooks.accountDeleted, m.world.hooks.tenantErased, lifecycle.CellHookAccountDeleted, lifecycle.CellHookTenantErased},
		{"no account hook", nil, m.world.hooks.tenantErased, lifecycle.CellNone, lifecycle.CellHookTenantErased},
		{"no tenant hook", m.world.hooks.accountDeleted, nil, lifecycle.CellHookAccountDeleted, lifecycle.CellNone},
		{"none", nil, nil, lifecycle.CellNone, lifecycle.CellNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := m.world.wiring
			w.Hooks = lifecycle.NewHooks(tc.deleted, tc.erased)
			d, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: &memOutboxStub{}, Wiring: w, Reporter: &retries{}})
			if err != nil {
				t.Fatal(err)
			}
			row := d.Matrix()[identity.ComponentHooks]
			if row.Delete != tc.wantDelete || row.TenantErased != tc.wantTenantEra {
				t.Fatalf("hooks row %+v, want Delete=%q TenantErased=%q", row, tc.wantDelete, tc.wantTenantEra)
			}
			if reflect.DeepEqual(d.Matrix(), lifecycle.Golden()) != (tc.deleted != nil && tc.erased != nil) {
				t.Fatal("the matrix must equal Golden only when both hooks are wired")
			}
		})
	}
}

func TestDispatcherWiredExposesTheObjectsActedOn(t *testing.T) {
	m := newMatrixCase(t)
	w := m.world.wiring
	backend := &standInBackend{}
	var err error
	w.Sessions, err = lifecycle.NewSessions(backend)
	if err != nil {
		t.Fatal(err)
	}
	w.APIKeys = lifecycle.AbsentAPIKeys()
	d, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: &memOutboxStub{}, Wiring: w, Reporter: &retries{}})
	if err != nil {
		t.Fatal(err)
	}
	wired := d.Wired()
	if wired[identity.ComponentSessions] != any(backend) || w.Sessions.Backend() != lifecycle.Subscriber(backend) {
		t.Fatalf("sessions row must expose the wrapped backend, got %v", wired[identity.ComponentSessions])
	}
	if wired[identity.ComponentAPIKeys] != nil {
		t.Fatalf("an absent store must expose nil, got %v", wired[identity.ComponentAPIKeys])
	}
	for _, c := range []identity.Component{identity.ComponentCeremonies, identity.ComponentMFA, identity.ComponentPasskeys,
		identity.ComponentFederation, identity.ComponentKeys, identity.ComponentIdentity} {
		if wired[c] == nil {
			t.Errorf("%s: no wired object exposed", c)
		}
	}
}

func TestDeleteErasesTheRevertTrailLastAndStopsAtTheFirstFailure(t *testing.T) {
	m := newMatrixCase(t)
	ctx := context.Background()
	m.world.c.failOn("ceremony.DeleteForScope acme revert-history", errors.New("down"))
	m.world.c.take()
	if err := m.world.wiring.Ceremonies.OnDeleted(ctx, lifecycle.AccountEvent{Subject: m.user.Subject}); err == nil {
		t.Fatal("want the failure returned so the row is retried")
	}
	for _, call := range m.world.c.take() {
		if strings.Contains(call, "revert-tenure") {
			t.Fatalf("the tenure scope is the only record of previous addresses and must not be deleted after a failure: %s", call)
		}
	}
}

func TestDeleteFailsWhenTheRevertScopesCannotBeComputed(t *testing.T) {
	m := newMatrixCase(t)
	boom := errors.New("scope key unavailable")
	c, err := lifecycle.NewCeremonies(fakeCeremonies{c: m.world.c, labels: m.world.labels}, fakeAccounts{user: m.user},
		fakeScoper{labels: m.world.labels, err: boom})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.OnDeleted(context.Background(), lifecycle.AccountEvent{Subject: m.user.Subject}); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

type noopNotices struct{}

func (noopNotices) SecurityNotice(context.Context, identity.OutboxItem) error { return nil }

func TestWiredExposesTheNoticeSenderAndTheCeremonyCollaborators(t *testing.T) {
	m := newMatrixCase(t)
	w := m.world.wiring
	stand := noopNotices{}
	var err error
	w.Notices, err = lifecycle.NewNotices(stand)
	if err != nil {
		t.Fatal(err)
	}
	reader, scoper := &fakeAccounts{user: m.user}, &fakeScoper{labels: m.world.labels}
	store := &fakeCeremonies{c: m.world.c, labels: m.world.labels}
	w.Ceremonies, err = lifecycle.NewCeremonies(store, reader, scoper)
	if err != nil {
		t.Fatal(err)
	}
	d, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: &memOutboxStub{}, Wiring: w, Reporter: &retries{}})
	if err != nil {
		t.Fatal(err)
	}
	wired := d.Wired()
	if wired[identity.ComponentNotices] != any(stand) {
		t.Fatalf("notices row must expose its sender, got %v", wired[identity.ComponentNotices])
	}
	want := lifecycle.CeremoniesWiring{Store: store, Accounts: reader, Scoper: scoper}
	if wired[identity.ComponentCeremonies] != any(want) {
		t.Fatalf("ceremonies row must expose store, reader and scoper, got %v", wired[identity.ComponentCeremonies])
	}
}
