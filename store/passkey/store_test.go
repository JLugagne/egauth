package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/passkey"
	"github.com/google/uuid"
)

var (
	_ func(passkey.Store, context.Context, principal.Subject, passkey.CredentialID, uint32) (bool, error) = passkey.Store.UpdateSignCount
	_ func(passkey.Store, context.Context, principal.Subject) (bool, error)                               = passkey.Store.HasActive
	_ func(passkey.Store, context.Context) (bool, error)                                                  = passkey.Store.AnyEnrolled
	_ func(passkey.Store, context.Context) (int64, error)                                                 = passkey.Store.CountEnrolled
)

func TestCredentialIDJSONIsBase64URL(t *testing.T) {
	id := passkey.CredentialID{0xfb, 0xff, 0xfe, 0x01}
	b, err := json.Marshal(id)
	if err != nil || string(b) != `"-__-AQ"` {
		t.Fatalf("got %s, %v", b, err)
	}
	var back passkey.CredentialID
	if err := json.Unmarshal(b, &back); err != nil || !back.Equal(id) {
		t.Fatalf("round trip: %v, %v", back, err)
	}
}

func TestCredentialIDRejectsOtherEncodings(t *testing.T) {
	for _, in := range []string{`"-__-AQ=="`, `"+//+AQ"`, `"a b"`, `42`, `""`, `null`} {
		var c passkey.CredentialID
		err := json.Unmarshal([]byte(in), &c)
		if in == `null` {
			if err != nil || c != nil {
				t.Fatalf("null: %v %v", c, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s accepted as %v", in, c)
		}
	}
}

func TestCredentialIDInStructMarshalsAsString(t *testing.T) {
	b, err := json.Marshal(struct {
		ID passkey.CredentialID `json:"credential_id"`
	}{ID: passkey.CredentialID{1, 2, 3}})
	if err != nil || string(b) != `{"credential_id":"AQID"}` {
		t.Fatalf("got %s, %v", b, err)
	}
}

func TestDiscoverableStatePersistedValues(t *testing.T) {
	want := map[passkey.DiscoverableState]uint8{passkey.Legacy: 0, passkey.Confirmed: 1, passkey.Inferred: 2}
	for s, v := range want {
		if uint8(s) != v || !s.Valid() {
			t.Fatalf("%v: persisted value drifted", s)
		}
	}
	if passkey.DiscoverableState(3).Valid() || passkey.DiscoverableState(3).String() != "invalid" {
		t.Fatal("undeclared state must be invalid")
	}
	if !passkey.Legacy.NeedsReregistration() || passkey.Confirmed.NeedsReregistration() || passkey.Inferred.NeedsReregistration() {
		t.Fatal("only Legacy needs re-registration")
	}
	var zero passkey.Credential
	if zero.Discoverable != passkey.Legacy {
		t.Fatal("a v0.16 row defaults to Legacy")
	}
}

func TestSuspendedCredentialIsNotActive(t *testing.T) {
	now := time.Now()
	if !(passkey.Credential{}).Active() || (passkey.Credential{SuspendedAt: &now}).Active() {
		t.Fatal("Active must follow SuspendedAt")
	}
}

func TestStoreMethodSet(t *testing.T) {
	st := reflect.TypeFor[passkey.Store]()
	for _, name := range []string{"Ping", "EraseTenant", "Durability", "DeleteForSubject", "Suspend", "Get"} {
		if _, ok := st.MethodByName(name); !ok {
			t.Fatalf("passkey.Store lacks %s", name)
		}
	}
}

func TestUpdateSignCountIsMonotonicNotACompareAndSwap(t *testing.T) {
	m, ok := reflect.TypeFor[passkey.Store]().MethodByName("UpdateSignCount")
	if !ok {
		t.Fatal("passkey.Store lacks UpdateSignCount")
	}
	if last := m.Type.In(m.Type.NumIn() - 1); last != reflect.TypeFor[uint32]() {
		t.Fatalf("UpdateSignCount takes %v: it must take only the new counter, never the value read (P-12)", last)
	}
}

func TestCredentialJSONOmitsKeyMaterialAndSubject(t *testing.T) {
	tenant, err := principal.ParseTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(passkey.Credential{
		Subject:   principal.Subject{Tenant: tenant, User: uuid.MustParse("6f1c2a52-6d0e-4d43-9a8b-0f3a3c1b2d4e")},
		ID:        passkey.CredentialID{1, 2, 3},
		PublicKey: []byte{9, 9},
		SignCount: 42,
		Data:      []byte("x"),
		Nickname:  "laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, leak := range []string{"PublicKey", "public_key", "CQk", "Data", "eA", "SignCount", "sign_count", "42", "Subject", "subject", "acme", "6f1c2a52"} {
		if strings.Contains(out, leak) {
			t.Fatalf("credential JSON leaks %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, `"id":"AQID"`) || !strings.Contains(out, `"nickname":"laptop"`) {
		t.Fatalf("credential JSON lost its listing fields: %s", out)
	}
}

func TestStartupEnrollmentCheckIsDeploymentWide(t *testing.T) {
	st := reflect.TypeFor[passkey.Store]()
	for _, name := range []string{"AnyEnrolled", "CountEnrolled"} {
		m, ok := st.MethodByName(name)
		if !ok || m.Type.NumIn() != 1 {
			t.Fatalf("%s must take only a context: New has no subject to ask about (C-01)", name)
		}
	}
}

func TestSignCountZeroAgainstStoredCounterIsTheCloneSignal(t *testing.T) {
	cases := []struct {
		name         string
		stored, next uint32
		want         bool
	}{
		{"counterless authenticator", 0, 0, true},
		{"first use", 0, 1, true},
		{"advance", 5, 6, true},
		{"cloned key asserting zero", 5, 0, false},
		{"replayed counter", 5, 5, false},
		{"regressed counter", 5, 4, false},
	}
	for _, c := range cases {
		if got := (passkey.Credential{SignCount: c.stored}).AcceptsSignCount(c.next); got != c.want {
			t.Fatalf("%s: stored %d, AcceptsSignCount(%d) = %v", c.name, c.stored, c.next, got)
		}
	}
}

func TestUpdateSignCountDocNeverCallsZeroNextCounterless(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "store.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Store" {
			return true
		}
		for _, m := range ts.Type.(*ast.InterfaceType).Methods.List {
			if len(m.Names) == 1 && m.Names[0].Name == "UpdateSignCount" {
				doc = m.Doc.Text()
			}
		}
		return false
	})
	if !strings.Contains(doc, "AcceptsSignCount") || strings.Contains(doc, "with a zero next it means") {
		t.Fatalf("UpdateSignCount must follow AcceptsSignCount, where only 0/0 is counterless: %q", doc)
	}
}

func TestStoreHasNoReaper(t *testing.T) {
	if _, ok := reflect.TypeFor[passkey.Store]().MethodByName("ReapExpired"); ok {
		t.Fatal("credentials never expire: passkey.Store must not embed store.Reaper")
	}
}

func TestCredentialIDLengthIsCapped(t *testing.T) {
	longest := passkey.CredentialID(bytes.Repeat([]byte{7}, passkey.MaxCredentialIDLen))
	b, err := json.Marshal(longest)
	if err != nil {
		t.Fatal(err)
	}
	var back passkey.CredentialID
	if err := json.Unmarshal(b, &back); err != nil || !back.Equal(longest) {
		t.Fatalf("a %d-byte id must decode: %v", passkey.MaxCredentialIDLen, err)
	}
	over, err := json.Marshal(append(longest, 7))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(over, &back); err == nil {
		t.Fatal("an id over MaxCredentialIDLen must be refused")
	}
	huge, err := json.Marshal(strings.Repeat("A", 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	var c passkey.CredentialID
	if err := json.Unmarshal(huge, &c); err == nil || c != nil {
		t.Fatalf("a 1 MiB id must be refused, got %d bytes", len(c))
	}
}

func TestCredentialWithoutIDRoundTrips(t *testing.T) {
	b, err := json.Marshal(passkey.Credential{Nickname: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"id":null`) {
		t.Fatalf("an empty id must encode as null: %s", b)
	}
	var back passkey.Credential
	if err := json.Unmarshal(b, &back); err != nil || back.ID != nil || back.Nickname != "x" {
		t.Fatalf("round trip: %+v, %v", back, err)
	}
}
