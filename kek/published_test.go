package kek_test

import (
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/kek"
)

func publishedRepositoryKeys(t *testing.T) map[string][]byte {
	t.Helper()
	fixture, _ := loadLegacy(t)
	raw, err := os.ReadFile("../adapters/pgx/e2e/testdata/v016_key.hex")
	if err != nil {
		t.Fatal(err)
	}
	pgxFixture := unhex(t, strings.TrimSpace(string(raw)))
	digest := func(s string) []byte {
		sum := sha256.Sum256([]byte(s))
		return sum[:]
	}
	return map[string][]byte{
		"kek/testdata/v016_fixtures.json":        fixture,
		"adapters/pgx/e2e/testdata/v016_key.hex": pgxFixture,
		"former egauthtest.Config KEK":           digest("egauthtest development kek, public and worthless"),
		"former journeytest KEK":                 digest("journeytest kek, public and worthless"),
		"former store/mfa/storetest KEK":         digest("egauth/storetest/current"),
	}
}

func TestNewLocalRefusesKeysPublishedInTheRepository(t *testing.T) {
	good := randomKey(t)
	for name, key := range publishedRepositoryKeys(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := kek.NewLocal(key); !errors.Is(err, kek.ErrInvalidKey) {
				t.Fatalf("NewLocal = %v, want ErrInvalidKey: the key is readable from the public repository", err)
			}
			if _, err := kek.NewLocal(good, key); !errors.Is(err, kek.ErrInvalidKey) {
				t.Fatalf("NewLocal(good, published) = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestLegacyLocalV016StillAcceptsTheV016FixtureKey(t *testing.T) {
	key, _ := loadLegacy(t)
	if _, err := kek.LegacyLocalV016(key); err != nil {
		t.Fatalf("LegacyLocalV016 must keep opening what v0.16 sealed: %v", err)
	}
}
