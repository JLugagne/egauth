package kek_test

import (
	"errors"
	"testing"

	"github.com/JLugagne/egauth/internal/secretpolicy"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/keystore"
)

func TestNewLocalRejectsEveryPublishedCredential(t *testing.T) {
	good := randomKey(t)
	checked := 0
	for denied := range secretpolicy.Denied {
		if len(denied) != kek.KeyLength {
			continue
		}
		checked++
		if _, err := kek.NewLocal([]byte(denied)); !errors.Is(err, kek.ErrInvalidKey) {
			t.Errorf("NewLocal(%q) = %v, want ErrInvalidKey", denied, err)
		}
		if _, err := kek.NewLocal(good, []byte(denied)); !errors.Is(err, kek.ErrInvalidKey) {
			t.Errorf("NewLocal(good, %q) = %v, want ErrInvalidKey", denied, err)
		}
		if _, err := kek.LegacyLocalV016([]byte(denied)); !errors.Is(err, kek.ErrInvalidKey) {
			t.Errorf("LegacyLocalV016(%q) = %v, want ErrInvalidKey", denied, err)
		}
	}
	if checked == 0 {
		t.Fatal("secretpolicy.Denied has no KeyLength entry; the parity check is vacuous")
	}
}

func TestNewLocalRejectsPublishedNearCopies(t *testing.T) {
	nearCopy := []byte("x-minimum-hs256-signing-secret-y")
	if len(nearCopy) != kek.KeyLength {
		t.Fatalf("fixture is %d bytes", len(nearCopy))
	}
	if err := secretpolicy.Validate("KEK", nearCopy, kek.KeyLength); !errors.Is(err, secretpolicy.ErrNearCopy) {
		t.Fatalf("fixture is not a near-copy for secretpolicy: %v", err)
	}
	if _, err := kek.NewLocal(nearCopy); !errors.Is(err, kek.ErrInvalidKey) {
		t.Fatalf("NewLocal(near-copy) = %v, want ErrInvalidKey", err)
	}
	if _, err := kek.LegacyLocalV016(nearCopy); !errors.Is(err, kek.ErrInvalidKey) {
		t.Fatalf("LegacyLocalV016(near-copy) = %v, want ErrInvalidKey", err)
	}
}

func TestLegacyLocalV016AcceptsExactlyTheV016Keys(t *testing.T) {
	for name, key := range map[string][]byte{
		"two distinct bytes":   []byte("abababababababababababababababcd"),
		"seven distinct bytes": []byte("abcdefgabcdefgabcdefgabcdefgabcd"),
		"random":               randomKey(t),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := keystore.NewKEK(key); err != nil {
				t.Fatalf("fixture refused by v0.16 keystore.NewKEK: %v", err)
			}
			if _, err := kek.LegacyLocalV016(key); err != nil {
				t.Fatalf("LegacyLocalV016 refuses a key v0.16 accepted: %v", err)
			}
		})
	}
	for name, key := range map[string][]byte{
		"short":         make([]byte, kek.KeyLength-1),
		"all zero":      make([]byte, kek.KeyLength),
		"repeated byte": []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := keystore.NewKEK(key); err == nil {
				t.Fatal("fixture accepted by v0.16 keystore.NewKEK")
			}
			if _, err := kek.LegacyLocalV016(key); !errors.Is(err, kek.ErrInvalidKey) {
				t.Fatalf("LegacyLocalV016 = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestNewLocalStaysStricterThanV016(t *testing.T) {
	if _, err := kek.NewLocal([]byte("abababababababababababababababcd")); !errors.Is(err, kek.ErrInvalidKey) {
		t.Fatalf("NewLocal(low diversity) = %v, want ErrInvalidKey", err)
	}
}
