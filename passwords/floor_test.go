package passwords_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passwords"
)

func TestFloorRefusesShortPasswords(t *testing.T) {
	for _, pw := range []string{"", "1234567", "abcdefg", "ééééééé"} {
		if _, err := passwords.Floor(pw); !errors.Is(err, passwords.ErrPasswordTooShort) {
			t.Errorf("Floor(%q) = %v, want ErrPasswordTooShort", pw, err)
		}
	}
}

func TestFloorCountsCharactersBeforeAndAfterNFKC(t *testing.T) {
	got, err := passwords.Floor("ﬁﬁﬁﬁﬁﬁﬁﬁ")
	if err != nil {
		t.Fatalf("eight ligatures are eight characters typed and sixteen under NFKC: %v", err)
	}
	if got != "fifififififififi" {
		t.Fatalf("Floor returned %q, want the NFKC form", got)
	}
	for _, pw := range []string{"ﬁﬁﬁﬁ", "\uFDFA", "\uFDFB", "\u33AF\u33AF"} {
		if _, err := passwords.Floor(pw); !errors.Is(err, passwords.ErrPasswordTooShort) {
			t.Errorf("Floor(%q) = %v: a compatibility character that expands under NFKC counts once as typed", pw, err)
		}
	}
	if _, err := passwords.Floor(strings.Repeat("e\u0301", 7)); !errors.Is(err, passwords.ErrPasswordTooShort) {
		t.Fatalf("fourteen code points composing into seven characters: %v", err)
	}
	if _, err := passwords.Floor("①②③④⑤⑥⑦"); !errors.Is(err, passwords.ErrPasswordTooShort) {
		t.Fatalf("seven circled digits stay seven characters: %v", err)
	}
}

func TestFloorReturnsTheNFKCForm(t *testing.T) {
	got, err := passwords.Floor("Ｃｏｒｒｅｃｔ horse")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Correct horse" {
		t.Fatalf("Floor = %q", got)
	}
	if passwords.Canonical("Ｃｏｒｒｅｃｔ horse") != got {
		t.Fatal("Canonical and Floor disagree")
	}
}

func TestFloorRefusesLongPasswords(t *testing.T) {
	if _, err := passwords.Floor(strings.Repeat("a", passwords.MaxPasswordLength)); err != nil {
		t.Fatalf("a password of MaxPasswordLength bytes is accepted: %v", err)
	}
	if _, err := passwords.Floor(strings.Repeat("a", passwords.MaxPasswordLength+1)); !errors.Is(err, passwords.ErrPasswordTooLong) {
		t.Fatalf("one byte over MaxPasswordLength: %v", err)
	}
	if _, err := passwords.Floor(strings.Repeat("é", passwords.MaxPasswordLength/2+1)); !errors.Is(err, passwords.ErrPasswordTooLong) {
		t.Fatalf("the bound is in bytes, so the hasher never refuses a floor-accepted password: %v", err)
	}
	if _, err := passwords.Floor(strings.Repeat("ﷺ", 200)); !errors.Is(err, passwords.ErrPasswordTooLong) {
		t.Fatalf("the bound applies after NFKC expansion: %v", err)
	}
}

func TestFloorRefusesInvalidUTF8(t *testing.T) {
	if _, err := passwords.Floor("abcdefgh\xff"); !errors.Is(err, passwords.ErrPasswordEncoding) {
		t.Fatalf("Floor = %v, want ErrPasswordEncoding", err)
	}
}
