package store_test

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

var (
	_ func(store.Base, context.Context) error                     = store.Base.Ping
	_ func(store.Base, context.Context, principal.TenantID) error = store.Base.EraseTenant
	_ func(store.Base) store.Durability                           = store.Base.Durability
	_ func(store.Reaper, context.Context) (int64, error)          = store.Reaper.ReapExpired
)

func TestBaseAndReaperMethodSets(t *testing.T) {
	want := map[reflect.Type][]string{
		reflect.TypeFor[store.Base]():   {"Durability", "EraseTenant", "Ping"},
		reflect.TypeFor[store.Reaper](): {"ReapExpired"},
	}
	for typ, names := range want {
		if typ.NumMethod() != len(names) {
			t.Fatalf("%s: want %d methods, got %d", typ, len(names), typ.NumMethod())
		}
		for i, name := range names {
			if got := typ.Method(i).Name; got != name {
				t.Fatalf("%s: method %d is %s, want %s (T-13)", typ, i, got, name)
			}
		}
	}
}

func TestDurability(t *testing.T) {
	var zero store.Durability
	if zero.Valid() || zero.String() != "invalid" {
		t.Fatal("the zero Durability must be invalid")
	}
	if !store.Ephemeral.Valid() || !store.Shared.Valid() || store.Ephemeral == store.Shared {
		t.Fatal("declared durabilities must be valid and distinct")
	}
	if store.Ephemeral.String() != "ephemeral" || store.Shared.String() != "shared" {
		t.Fatal("unexpected names")
	}
}

func TestCursor(t *testing.T) {
	var zero store.Cursor
	if !zero.IsZero() {
		t.Fatal("zero cursor must be the start")
	}
	c := store.RestoreCursor(7)
	if c.IsZero() || c.Position() != 7 || !c.After(zero) || zero.After(c) || c.After(c) {
		t.Fatal("cursor ordering broken")
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	all := []error{store.ErrNotFound, store.ErrConflict, store.ErrCapacity}
	for i, a := range all {
		for j, b := range all {
			if (i == j) != errors.Is(a, b) {
				t.Fatalf("errors %d and %d are not distinct", i, j)
			}
		}
	}
}

func TestContractsImportOnlyPrincipalAndEvent(t *testing.T) {
	const module = "github.com/JLugagne/egauth"
	dirs := []string{"."}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != "testdata" {
			dirs = append(dirs, e.Name())
		}
	}
	scanned := 0
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			scanned++
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				path, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if path != module && !strings.HasPrefix(path, module+"/") {
					continue
				}
				if path == module+"/principal" || path == module+"/event" || path == module+"/store" ||
					strings.HasPrefix(path, module+"/store/") {
					continue
				}
				t.Errorf("store contract %s imports %s; contracts may import only principal and event (G15)", f, path)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no store contract file scanned")
	}
}
