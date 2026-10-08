package keys_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/keys"
)

var (
	_ func(keys.Store, context.Context, principal.TenantID) (bool, error)                        = keys.Store.IsTombstoned
	_ func(keys.Store, context.Context, store.Cursor) ([]keys.Change, store.Cursor, error)       = keys.Store.ChangesSince
	_ func(keys.Store, context.Context, keys.Reseal) (bool, error)                               = keys.Store.ReplaceSealed
	_ func(keys.Store, context.Context, store.Cursor, int) ([]keys.V016Row, store.Cursor, error) = keys.Store.V016Sealed
)

func TestStoreEmbedsBaseAndReaper(t *testing.T) {
	st := reflect.TypeFor[keys.Store]()
	for _, name := range []string{"Ping", "EraseTenant", "Durability", "ReapExpired", "Tombstone", "CountLegacySealed"} {
		if _, ok := st.MethodByName(name); !ok {
			t.Fatalf("keys.Store lacks %s", name)
		}
	}
}

func TestResealComparesTheSealedBytesRead(t *testing.T) {
	r := reflect.TypeFor[keys.Reseal]()
	for _, name := range []string{"Old", "New"} {
		f, ok := r.FieldByName(name)
		if !ok || f.Type != reflect.TypeFor[[]byte]() {
			t.Fatalf("Reseal lacks the sealed bytes %s: a re-seal must CAS on the bytes it read", name)
		}
	}
}

func storeMethodDocs(t *testing.T) map[string]string {
	t.Helper()
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
	return docs
}

func TestEveryKeyInsertRefusesATombstonedTenant(t *testing.T) {
	docs := storeMethodDocs(t)
	for _, name := range []string{"CreateTenant", "PutKey", "Rotate"} {
		if !strings.Contains(docs[name], "ErrTenantTombstoned") {
			t.Fatalf("%s inserts a key but does not refuse a tombstoned tenant (T-13)", name)
		}
	}
	for _, name := range []string{"PutKey", "Rotate"} {
		if !strings.Contains(docs[name], "store.ErrConflict") {
			t.Fatalf("%s must refuse to reuse a key id", name)
		}
	}
}

func TestRotationOverlapIsBounded(t *testing.T) {
	at := time.Unix(1000, 0)
	next := keys.Key{KeyID: "k2", NotAfter: at.Add(time.Hour), AADVersion: keys.AADVersionCurrent}
	retired := at
	cases := []struct {
		name string
		r    keys.Rotation
		want bool
	}{
		{"ok", keys.Rotation{Previous: "k1", Next: next, RetiredAt: at, OverlapUntil: at.Add(time.Minute)}, true},
		{"no overlap", keys.Rotation{Previous: "k1", Next: next, RetiredAt: at, OverlapUntil: at}, true},
		{"never overlap", keys.Rotation{Previous: "k1", Next: next, RetiredAt: at}, false},
		{"overlap before retirement", keys.Rotation{Previous: "k1", Next: next, RetiredAt: at, OverlapUntil: at.Add(-time.Second)}, false},
		{"zero retirement", keys.Rotation{Previous: "k1", Next: next, OverlapUntil: at}, false},
		{"no key id", keys.Rotation{Previous: "k1", Next: keys.Key{AADVersion: keys.AADVersionCurrent}, RetiredAt: at, OverlapUntil: at}, false},
		{"retired next", keys.Rotation{Previous: "k1", Next: keys.Key{KeyID: "k2", AADVersion: keys.AADVersionCurrent, RetiredAt: &retired}, RetiredAt: at, OverlapUntil: at}, false},
		{"expired next", keys.Rotation{Previous: "k1", Next: keys.Key{KeyID: "k2", AADVersion: keys.AADVersionCurrent, NotAfter: at}, RetiredAt: at, OverlapUntil: at}, false},
	}
	for _, c := range cases {
		if c.r.Valid() != c.want {
			t.Fatalf("%s: Valid = %v", c.name, !c.want)
		}
	}
}

func TestRotationNamesTheSignerItRetires(t *testing.T) {
	at := time.Unix(1000, 0)
	next := keys.Key{KeyID: "k2", AADVersion: keys.AADVersionCurrent}
	if (keys.Rotation{Next: next, RetiredAt: at, OverlapUntil: at}).Valid() {
		t.Fatal("a rotation without Previous lets a concurrent rotation retire the key the winner just activated")
	}
	if (keys.Rotation{Previous: "k2", Next: next, RetiredAt: at, OverlapUntil: at}).Valid() {
		t.Fatal("a rotation must not retire the key it activates")
	}
	doc := storeMethodDocs(t)["Rotate"]
	if !strings.Contains(doc, "r.Previous is not the") || !strings.Contains(doc, "store.ErrConflict") {
		t.Fatalf("Rotate must refuse with store.ErrConflict when r.Previous is no longer the signer: %q", doc)
	}
}

func TestNewKeysAreNeverLegacySealed(t *testing.T) {
	at := time.Unix(1000, 0)
	r := keys.Rotation{Previous: "k1", Next: keys.Key{KeyID: "k2", AADVersion: keys.AADVersionLegacy}, RetiredAt: at, OverlapUntil: at}
	if r.Valid() {
		t.Fatal("a rotation must not insert v0.16-format key material (C-58)")
	}
	docs := storeMethodDocs(t)
	for _, name := range []string{"CreateTenant", "PutKey"} {
		if !strings.Contains(docs[name], "ErrLegacyAADVersion") {
			t.Fatalf("%s inserts a key but accepts AADVersionLegacy", name)
		}
	}
}

func TestChangeFeedRecordsDeletions(t *testing.T) {
	doc := storeMethodDocs(t)["ChangesSince"]
	for _, name := range []string{"CreateTenant", "PutKey", "Rotate", "RevokeTenantKeys", "Tombstone", "EraseTenant", "ReapExpired"} {
		if !strings.Contains(doc, name) {
			t.Fatalf("ChangesSince must name %s as a feed producer: other instances would keep its keys cached (T-15)", name)
		}
	}
}

func TestRetiredKeyWithoutNotAfterNeverVerifies(t *testing.T) {
	now := time.Unix(1000, 0)
	retired := now.Add(-time.Hour)
	cases := []struct {
		name string
		k    keys.Key
		want bool
	}{
		{"active never-expiring", keys.Key{}, true},
		{"retired never-expiring", keys.Key{RetiredAt: &retired}, false},
		{"retired within overlap", keys.Key{RetiredAt: &retired, NotAfter: now.Add(time.Second)}, true},
		{"retired past overlap", keys.Key{RetiredAt: &retired, NotAfter: now}, false},
		{"active past NotAfter", keys.Key{NotAfter: now}, false},
	}
	for _, c := range cases {
		if c.k.Verifies(now) != c.want {
			t.Fatalf("%s: Verifies = %v", c.name, !c.want)
		}
	}
}
