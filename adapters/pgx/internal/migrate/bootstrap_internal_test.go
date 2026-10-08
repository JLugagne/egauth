package migrate

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLegacyFilesMatchTheV016MigrationDirectories(t *testing.T) {
	dirs := map[string]string{
		"identity": "identity", "keystore": "keys", "mfa": "mfa", "oauth": "federation", "otp": "otp",
		"passkey": "passkey", "sessions": "sessions", "tokens": "tokens",
	}
	if got := slices.Sorted(maps.Values(dirs)); !slices.Equal(got, slices.Sorted(maps.Keys(legacyFiles))) {
		t.Fatalf("legacy modules %v, want one per v0.16 package %v", slices.Sorted(maps.Keys(legacyFiles)), got)
	}
	for dir, module := range dirs {
		entries, err := fs.ReadDir(os.DirFS(filepath.Join("..", "..", dir)), "migrations")
		if errors.Is(err, fs.ErrNotExist) {
			t.Logf("v0.16 package %s was removed; legacyFiles stays frozen", dir)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if !slices.Equal(names, legacyFiles[module]) {
			t.Errorf("%s: v0.16 files %v, legacyFiles[%q] %v", dir, names, module, legacyFiles[module])
		}
	}
}

func TestLegacyOwnerFlagsOnlyTheSharedBasename(t *testing.T) {
	var shared []string
	for _, files := range legacyFiles {
		for _, f := range files {
			if _, unique := legacyOwner(f); !unique && !slices.Contains(shared, f) {
				shared = append(shared, f)
			}
		}
	}
	if !slices.Equal(shared, []string{"002_add_expires_at_index.sql"}) {
		t.Fatalf("shared basenames %v", shared)
	}
	if owner, unique := legacyOwner("001_init.sql"); !unique || owner != "federation" {
		t.Fatalf("owner %q unique %v", owner, unique)
	}
	if _, unique := legacyOwner("009_security_epoch.sql"); unique {
		t.Fatal("a file v0.16 never shipped has no legacy owner")
	}
}
