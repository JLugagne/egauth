package federation_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/federation"
)

var (
	_ func(federation.Store, context.Context, federation.Reseal) (bool, error)                               = federation.Store.ReplaceSealed
	_ func(federation.Store, context.Context, store.Cursor, int) ([]federation.V016Row, store.Cursor, error) = federation.Store.V016Sealed
)

func TestEmailVerificationFailsClosedAndIsPersistedStable(t *testing.T) {
	var zero federation.EmailVerification
	if zero != federation.Never {
		t.Fatal("the zero EmailVerification must be Never")
	}
	want := map[federation.EmailVerification]uint8{federation.Never: 0, federation.ClaimBased: 1, federation.Always: 2}
	for v, n := range want {
		if uint8(v) != n || !v.Valid() {
			t.Fatalf("%v: persisted value drifted", v)
		}
	}
	if federation.EmailVerification(3).Valid() || federation.EmailVerification(3).String() != "invalid" {
		t.Fatal("undeclared value must be invalid")
	}
}

func TestStoreMethodSet(t *testing.T) {
	st := reflect.TypeFor[federation.Store]()
	for _, name := range []string{"Ping", "EraseTenant", "Durability", "DeleteForSubject", "FindLinked", "CountLegacySealed"} {
		if _, ok := st.MethodByName(name); !ok {
			t.Fatalf("federation.Store lacks %s", name)
		}
	}
}

func TestLinkedIdentityCarriesProviderEmailState(t *testing.T) {
	f, ok := reflect.TypeFor[federation.LinkedIdentity]().FieldByName("ProviderEmailVerified")
	if !ok || f.Type.Kind() != reflect.Bool {
		t.Fatal("LinkedIdentity must carry ProviderEmailVerified (C-37)")
	}
}

func TestResealComparesTheSealedBytesRead(t *testing.T) {
	r := reflect.TypeFor[federation.Reseal]()
	for _, name := range []string{"Old", "New"} {
		f, ok := r.FieldByName(name)
		if !ok || f.Type != reflect.TypeFor[[]byte]() {
			t.Fatalf("Reseal lacks the sealed bytes %s: a re-seal must CAS on the bytes it read", name)
		}
	}
	if f, ok := r.FieldByName("Ref"); !ok || f.Type != reflect.TypeFor[federation.SealedRef]() {
		t.Fatal("Reseal must address its row")
	}
}

func TestFreshWritesRefuseLegacyAADVersion(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "store.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Store" {
			return true
		}
		for _, m := range ts.Type.(*ast.InterfaceType).Methods.List {
			if len(m.Names) == 1 {
				docs[m.Names[0].Name] = m.Doc.Text()
			}
		}
		return false
	})
	for _, name := range []string{"PutProvider"} {
		if !strings.Contains(docs[name], "ErrLegacyAADVersion") {
			t.Fatalf("%s writes a sealed secret but accepts AADVersionLegacy: startup would then refuse (C-58)", name)
		}
	}
	if !strings.Contains(docs["V016Sealed"], "LegacySealed(cursor)") {
		t.Fatal("V016Sealed must record its DESIGN name LegacySealed(cursor)")
	}
	if federation.ErrLegacyAADVersion == nil {
		t.Fatal("ErrLegacyAADVersion must be declared")
	}
}
