package legacyfixture_test

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/JLugagne/egauth/adapters/pgx/internal/legacyfixture"
)

func TestFSRejectsAnUnknownModule(t *testing.T) {
	for _, m := range []legacyfixture.Module{"nope", "", "../identity", "identity/migrations"} {
		if _, err := legacyfixture.FS(m); !errors.Is(err, legacyfixture.ErrUnknownModule) {
			t.Errorf("FS(%q) error = %v, want ErrUnknownModule", m, err)
		}
	}
}

func TestFSServesEveryDeclaredModule(t *testing.T) {
	for _, m := range []legacyfixture.Module{legacyfixture.Identity, legacyfixture.OTP, legacyfixture.Sessions} {
		fsys, err := legacyfixture.FS(m)
		if err != nil {
			t.Fatalf("FS(%q): %v", m, err)
		}
		entries, err := fs.ReadDir(fsys, "migrations")
		if err != nil || len(entries) == 0 {
			t.Errorf("FS(%q) has no migrations: %v", m, err)
		}
	}
}
