package routes_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/routes"
)

func TestPathsAreUniqueRooted(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range routes.All() {
		if !strings.HasPrefix(p, "/") || seen[p] {
			t.Fatalf("path %q is not rooted or duplicated", p)
		}
		seen[p] = true
		if m := routes.Method(p); m != http.MethodGet && m != http.MethodPost {
			t.Fatalf("path %q has method %q", p, m)
		}
	}
	if len(seen) != 46 {
		t.Fatalf("want 46 endpoints, got %d", len(seen))
	}
	if routes.Method("/nope") != "" {
		t.Fatal("unknown path must have no method")
	}
}

func TestFieldsAreUniqueAndComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range routes.Fields() {
		if f == "" || seen[f] {
			t.Fatalf("field %q empty or duplicated", f)
		}
		seen[f] = true
	}
	if len(seen) != 18 {
		t.Fatalf("want 18 fields, got %d", len(seen))
	}
	if egauth.FieldCredentialID != routes.FieldCredentialID || routes.FieldCredentialID != "credential_id" {
		t.Fatal("credential id field mismatch")
	}
}
