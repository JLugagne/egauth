package identity_test

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

const secretPHC = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"

var (
	alice = principal.Subject{User: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")}
	keep  = uuid.MustParse("0a1b2c3d-4e5f-4a6b-9c8d-7e6f5a4b3c2d")
)

func ident(t *testing.T, k identity.IdentifierKind, v string) identity.Identifier {
	t.Helper()
	id, err := identity.NewIdentifier(k, v)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func google(t *testing.T) identity.FederatedIdentity {
	return identity.FederatedIdentity{
		Provider: "google", ProviderSubject: "1234567890", Authority: "static",
		ProviderEmail: ident(t, identity.IdentifierEmail, "alice@gmail.com"), ProviderEmailVerified: true,
	}
}

type mutationCase struct {
	m      identity.Mutation
	bump   bool
	event  identity.Event
	broken identity.Mutation
}

func mutations(t *testing.T) map[string]mutationCase {
	return map[string]mutationCase{
		"SetPassword": {
			m:    identity.SetPassword{Subject: alice, PHC: identity.NewPasswordHash(secretPHC), Reason: identity.RotationPasswordChanged, Keep: keep},
			bump: true, event: identity.EventCredentialRotated,
			broken: identity.SetPassword{Subject: alice, PHC: identity.NewPasswordHash(secretPHC), Reason: identity.RotationPasswordReset, Keep: keep},
		},
		"MarkEmailVerified": {
			m:    identity.MarkEmailVerified{Subject: alice},
			bump: true, event: identity.EventIdentifierChanged,
			broken: identity.MarkEmailVerified{},
		},
		"ChangeEmail": {
			m:    identity.ChangeEmail{Subject: alice, Email: ident(t, identity.IdentifierEmail, "alice@new.example")},
			bump: true, event: identity.EventIdentifierChanged,
			broken: identity.ChangeEmail{Subject: alice, Email: ident(t, identity.IdentifierPhone, "+15551234567")},
		},
		"SetPhone": {
			m:    identity.SetPhone{Subject: alice, Phone: ident(t, identity.IdentifierPhone, "+15551234567")},
			bump: true, event: identity.EventIdentifierChanged,
			broken: identity.SetPhone{Subject: alice, Phone: ident(t, identity.IdentifierEmail, "a@b.c")},
		},
		"SetRecoveryEmail": {
			m:    identity.SetRecoveryEmail{Subject: alice, RecoveryEmail: ident(t, identity.IdentifierRecoveryEmail, "backup@example.com")},
			bump: true, event: identity.EventIdentifierChanged,
			broken: identity.SetRecoveryEmail{Subject: alice, RecoveryEmail: ident(t, identity.IdentifierEmail, "backup@example.com")},
		},
		"SetDisabledState": {
			m:    identity.SetDisabledState{Subject: alice, Disable: true},
			bump: true, event: identity.EventDisable,
			broken: identity.SetDisabledState{Disable: true},
		},
		"SetMustChange": {
			m:      identity.SetMustChange{Subject: alice, MustChange: true},
			broken: identity.SetMustChange{MustChange: true},
		},
		"Tombstone": {
			m:    identity.Tombstone{Subject: alice},
			bump: true, event: identity.EventDelete,
			broken: identity.Tombstone{},
		},
		"BumpEpoch": {
			m:    identity.BumpEpoch{Subject: alice, Keep: keep, Change: identity.FactorTOTPEnrolled},
			bump: true, event: identity.EventFactorsChanged,
			broken: identity.BumpEpoch{Subject: alice, Change: identity.FactorFederatedLinked},
		},
		"CreateVerified": {
			m:      identity.CreateVerified{Email: ident(t, identity.IdentifierEmail, "alice@example.com"), PHC: identity.NewPasswordHash(secretPHC), MustChange: true},
			broken: identity.CreateVerified{Email: ident(t, identity.IdentifierEmail, "alice@example.com"), MustChange: true},
		},
		"LinkFederated": {
			m:    identity.LinkFederated{Subject: alice, Identity: google(t), Keep: keep},
			bump: true, event: identity.EventFactorsChanged,
			broken: identity.LinkFederated{Subject: alice, Identity: identity.FederatedIdentity{Provider: "google"}},
		},
		"UnlinkFederated": {
			m:    identity.UnlinkFederated{Subject: alice, Provider: "google", ProviderSubject: "1234567890", Keep: keep},
			bump: true, event: identity.EventFactorsChanged,
			broken: identity.UnlinkFederated{Provider: "google", ProviderSubject: "1234567890"},
		},
	}
}

func TestMutationSetIsClosed(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var implementers []string
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "validate" {
				continue
			}
			implementers = append(implementers, fn.Recv.List[0].Type.(*ast.Ident).Name)
		}
	}
	sort.Strings(implementers)
	var want []string
	for name := range mutations(t) {
		want = append(want, name)
	}
	sort.Strings(want)
	if !slices.Equal(implementers, want) {
		t.Fatalf("Mutation implementers %v, want the 12 intent mutations %v (DESIGN §4.7)", implementers, want)
	}
	it := reflect.TypeFor[identity.Mutation]()
	for method := range it.Methods() {
		if method.IsExported() {
			t.Fatalf("Mutation exposes %s: an exported method lets other packages implement it", method.Name)
		}
	}
}

func TestMutationEffectsAndValidation(t *testing.T) {
	for name, c := range mutations(t) {
		if err := identity.Validate(c.m); err != nil {
			t.Errorf("%s: valid mutation refused: %v", name, err)
		}
		if err := identity.Validate(c.broken); !errors.Is(err, identity.ErrInvalidMutation) {
			t.Errorf("%s: broken mutation accepted: %v", name, err)
		}
		got := identity.EffectsOf(c.m)
		if got.BumpsEpoch != c.bump || got.Event != c.event {
			t.Errorf("%s: effects %+v, want bump=%v event=%s", name, got, c.bump, c.event)
		}
	}
	if err := identity.Validate(nil); !errors.Is(err, identity.ErrInvalidMutation) {
		t.Fatal("nil mutation must be refused")
	}
	enable := identity.EffectsOf(identity.SetDisabledState{Subject: alice})
	if enable.BumpsEpoch || enable.Event != identity.EventEnable {
		t.Fatalf("enabling must queue EventEnable without bumping the epoch, got %+v", enable)
	}
}

func TestOnlyAPasswordChangeKeepsASession(t *testing.T) {
	for _, r := range []identity.RotationReason{identity.RotationPasswordReset, identity.RotationTemporaryPassword, identity.RotationSecurityRevert} {
		m := identity.SetPassword{Subject: alice, PHC: identity.NewPasswordHash(secretPHC), Reason: r, Keep: keep}
		if err := identity.Validate(m); !errors.Is(err, identity.ErrInvalidMutation) {
			t.Errorf("%s: a reset-class rotation must not keep a session", r)
		}
		m.Keep = uuid.Nil
		if err := identity.Validate(m); err != nil {
			t.Errorf("%s: %v", r, err)
		}
	}
	if !identity.RotationTemporaryPassword.ForcesChange() || identity.RotationPasswordReset.ForcesChange() || identity.RotationPasswordChanged.ForcesChange() {
		t.Fatal("only a temporary password forces a change")
	}
	if err := identity.Validate(identity.SetPassword{Subject: alice, Reason: identity.RotationPasswordReset}); err == nil {
		t.Fatal("an empty hash must be refused")
	}
	if err := identity.Validate(identity.SetPassword{Subject: alice, PHC: identity.NewPasswordHash(secretPHC)}); err == nil {
		t.Fatal("a missing reason must be refused")
	}
}

func TestOutboxFanOutCoversEveryComponent(t *testing.T) {
	old := ident(t, identity.IdentifierEmail, "alice@old.example")
	for name, c := range mutations(t) {
		items := identity.OutboxFor(c.m, alice, old)
		if c.event == 0 {
			if items != nil {
				t.Errorf("%s queues no event but got %d rows", name, len(items))
			}
			continue
		}
		var comps []identity.Component
		for _, it := range items {
			if it.Event != c.event || it.Subject != alice {
				t.Errorf("%s: row %+v carries the wrong event or subject", name, it)
			}
			comps = append(comps, it.Component)
		}
		if !slices.Equal(comps, identity.Components()) {
			t.Errorf("%s: rows for %v, want one per component %v", name, comps, identity.Components())
		}
	}
	pw := identity.OutboxFor(identity.SetPassword{Subject: alice, PHC: identity.NewPasswordHash(secretPHC), Reason: identity.RotationPasswordChanged, Keep: keep}, alice, identity.Identifier{})
	if pw[0].Keep != keep || pw[0].Rotation != identity.RotationPasswordChanged {
		t.Fatal("credential rotation rows must carry Keep and the reason")
	}
	ce := identity.OutboxFor(identity.ChangeEmail{Subject: alice, Email: ident(t, identity.IdentifierEmail, "alice@new.example")}, alice, old)
	if ce[0].Identifier != identity.IdentifierEmail || ce[0].Old != old {
		t.Fatal("identifier change rows must carry the kind and the previous value")
	}
	link := identity.OutboxFor(identity.LinkFederated{Subject: alice, Identity: google(t), Keep: keep}, alice, identity.Identifier{})
	unlink := identity.OutboxFor(identity.UnlinkFederated{Subject: alice, Provider: "google", ProviderSubject: "1", Keep: keep}, alice, identity.Identifier{})
	bump := identity.OutboxFor(identity.BumpEpoch{Subject: alice, Change: identity.FactorPasskeyRemoved}, alice, identity.Identifier{})
	if link[0].Change != identity.FactorFederatedLinked || unlink[0].Change != identity.FactorFederatedUnlinked || bump[0].Change != identity.FactorPasskeyRemoved || link[0].Keep != keep {
		t.Fatal("factor rows must carry the change and Keep")
	}
	if identity.OutboxFor(nil, alice, old) != nil {
		t.Fatal("a nil mutation queues nothing")
	}
}

func TestComponents(t *testing.T) {
	names := map[identity.Component]string{
		identity.ComponentSessions: "sessions", identity.ComponentAPIKeys: "api_keys", identity.ComponentCeremonies: "ceremonies",
		identity.ComponentMFA: "mfa", identity.ComponentPasskeys: "passkeys", identity.ComponentFederation: "federation",
		identity.ComponentNotices: "notices", identity.ComponentKeys: "keys", identity.ComponentHooks: "hooks",
		identity.ComponentIdentity: "identity",
	}
	all := identity.Components()
	if len(all) != len(names) || all[len(all)-1] != identity.ComponentIdentity {
		t.Fatalf("components %v must list every component with the hard delete last", all)
	}
	for _, c := range all {
		if !c.Valid() || c.String() != names[c] {
			t.Errorf("component %d: persisted name %q, want %q", c, c.String(), names[c])
		}
		back, err := identity.ParseComponent(c.String())
		if err != nil || back != c {
			t.Errorf("component %s does not parse back", c)
		}
	}
	if _, err := identity.ParseComponent("invalid"); !errors.Is(err, identity.ErrUnknownComponent) {
		t.Fatal("an unknown subscriber name must be refused")
	}
	if identity.Component(0).Valid() || identity.Component(11).Valid() {
		t.Fatal("undeclared components must be invalid")
	}
}

func TestEnumsMatchLifecycle(t *testing.T) {
	for _, r := range []identity.RotationReason{1, 2, 3, 4} {
		if !r.Valid() || r.String() != lifecycle.RotationReason(r).String() {
			t.Errorf("rotation reason %d: %q vs lifecycle %q", r, r, lifecycle.RotationReason(r))
		}
	}
	for _, c := range []identity.FactorChange{1, 2, 3, 4, 5, 6, 7} {
		if !c.Valid() || c.String() != lifecycle.FactorChange(c).String() {
			t.Errorf("factor change %d: %q vs lifecycle %q", c, c, lifecycle.FactorChange(c))
		}
	}
	for _, k := range []identity.IdentifierKind{1, 2, 3} {
		if !k.Valid() || k.String() != lifecycle.IdentifierKind(k).String() {
			t.Errorf("identifier kind %d: %q vs lifecycle %q", k, k, lifecycle.IdentifierKind(k))
		}
	}
	if identity.RotationReason(5).Valid() || identity.FactorChange(8).Valid() || identity.IdentifierKind(4).Valid() {
		t.Fatal("values past the declared range must be invalid")
	}
	if identity.RotationReason(5).String() != "invalid" || identity.FactorChange(0).String() != "invalid" || identity.IdentifierKind(0).String() != "invalid" {
		t.Fatal("undeclared values must name themselves invalid")
	}
	events := map[identity.Event]string{
		identity.EventCredentialRotated: "credential_rotated", identity.EventFactorsChanged: "factors_changed",
		identity.EventIdentifierChanged: "identifier_changed", identity.EventDisable: "disable",
		identity.EventEnable: "enable", identity.EventDelete: "delete",
	}
	for e, name := range events {
		if !e.Valid() || e.String() != name {
			t.Errorf("event %d: %q, want %q", e, e, name)
		}
	}
	if identity.Event(0).Valid() || identity.Event(7).Valid() || identity.Event(7).String() != "invalid" {
		t.Fatal("undeclared events must be invalid")
	}
}

func TestNewIdentifierAcceptsOnlyCanonicalValues(t *testing.T) {
	good := []struct {
		k identity.IdentifierKind
		v string
	}{
		{identity.IdentifierEmail, "alice@example.com"},
		{identity.IdentifierRecoveryEmail, "backup+tag@example.co.uk"},
		{identity.IdentifierPhone, "+15551234567"},
		{identity.IdentifierPhone, "+33612345678"},
	}
	for _, g := range good {
		id, err := identity.NewIdentifier(g.k, g.v)
		if err != nil || id.Kind() != g.k || id.Value() != g.v || id.IsZero() {
			t.Errorf("%s %q: %v", g.k, g.v, err)
		}
	}
	bad := []struct {
		k identity.IdentifierKind
		v string
	}{
		{identity.IdentifierEmail, ""},
		{identity.IdentifierEmail, "Alice@example.com"},
		{identity.IdentifierEmail, " alice@example.com"},
		{identity.IdentifierEmail, "alice@example.com\n"},
		{identity.IdentifierEmail, "alice"},
		{identity.IdentifierEmail, "a@b@c"},
		{identity.IdentifierEmail, "@example.com"},
		{identity.IdentifierEmail, "ÉLISE@example.com"},
		{identity.IdentifierEmail, "a@" + strings.Repeat("x", identity.MaxIdentifierLen)},
		{identity.IdentifierEmail, "a@b\xff"},
		{identity.IdentifierRecoveryEmail, "Backup@example.com"},
		{identity.IdentifierPhone, "15551234567"},
		{identity.IdentifierPhone, "+1 555 123 4567"},
		{identity.IdentifierPhone, "+1234567"},
		{identity.IdentifierPhone, "+1234567890123456"},
		{identity.IdentifierPhone, "+05551234567"},
		{identity.IdentifierPhone, "+1555abc4567"},
		{0, "alice@example.com"},
		{9, "alice@example.com"},
	}
	for _, b := range bad {
		if _, err := identity.NewIdentifier(b.k, b.v); !errors.Is(err, identity.ErrInvalidIdentifier) {
			t.Errorf("%s %q must be refused, got %v", b.k, b.v, err)
		}
	}
	if !(identity.Identifier{}).IsZero() {
		t.Fatal("the zero identifier means none")
	}
}

func TestPasswordHashNeverFormats(t *testing.T) {
	values := []any{
		identity.PasswordCredential{Subject: alice, PHC: identity.NewPasswordHash(secretPHC), FailedAttempts: 2},
		identity.SetPassword{Subject: alice, PHC: identity.NewPasswordHash(secretPHC), Reason: identity.RotationPasswordReset},
		identity.CreateVerified{Email: ident(t, identity.IdentifierEmail, "a@b.c"), PHC: identity.NewPasswordHash(secretPHC)},
	}
	for _, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, "argon2id") {
				t.Errorf("%T formatted with %s leaks the hash: %s", v, verb, out)
			}
		}
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "v", v)
		if strings.Contains(buf.String(), "argon2id") {
			t.Errorf("%T leaks the hash through slog: %s", v, buf.String())
		}
	}
}

func TestStoreContract(t *testing.T) {
	st := reflect.TypeFor[identity.Store]()
	for _, base := range []reflect.Type{
		reflect.TypeFor[store.Base](),
		reflect.TypeFor[store.Reaper](),
	} {
		if !st.Implements(base) {
			t.Fatalf("identity.Store must embed %s", base)
		}
	}
	for _, m := range []string{
		"Apply", "EpochsChangedSince", "CurrentEpoch", "PendingOutbox", "AckOutbox", "FailOutbox", "EraseUser",
		"GetUser", "FindUser", "GetPassword", "RecordPasswordFailure", "ResetPasswordFailures", "FindFederated", "ListFederated",
	} {
		if _, ok := st.MethodByName(m); !ok {
			t.Errorf("identity.Store lacks %s", m)
		}
	}
	for method := range st.Methods() {
		name := method.Name
		if strings.HasPrefix(name, "Update") || strings.Contains(name, "Verification") || strings.HasPrefix(name, "Set") {
			t.Errorf("identity.Store.%s: accounts change only through Apply (I-24)", name)
		}
	}
}
