package pgxstore

import (
	"slices"
	"testing"
)

func TestModulesRegistryIsClosedAndUnique(t *testing.T) {
	want := []string{
		"ceremony", "deployment", "limiter", "identity", "tokens", "sessions", "mfa", "passkey",
		"federation", "keys",
	}
	var got []string
	for _, m := range modules() {
		if m.Name == "" || slices.Contains(got, m.Name) {
			t.Fatalf("module %q is unnamed or registered twice", m.Name)
		}
		got = append(got, m.Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("modules %v, want %v", got, want)
	}
}
