package identitysvc_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

func TestNormalizeEmailCollapsesVariants(t *testing.T) {
	want := "jose@example.com"
	for _, raw := range []string{
		"jose@example.com",
		"  JOSE@Example.COM ",
		"ｊｏｓｅ@ｅｘａｍｐｌｅ.ｃｏｍ",
		"Jose@EXAMPLE.com\t",
	} {
		id, err := identitysvc.Normalize(raw)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", raw, err)
		}
		if id.Kind() != identity.IdentifierEmail || id.Value() != want {
			t.Errorf("Normalize(%q) = %v %q, want %q", raw, id.Kind(), id.Value(), want)
		}
	}
}

func TestNormalizeEmailFoldsUnicodeDomainsAndComposedLocalParts(t *testing.T) {
	a, err := identitysvc.Normalize("José@Bücher.example")
	if err != nil {
		t.Fatal(err)
	}
	b, err := identitysvc.Normalize("josé@xn--bcher-kva.example")
	if err != nil {
		t.Fatal(err)
	}
	if a.Value() != b.Value() || a.Value() != "josé@xn--bcher-kva.example" {
		t.Fatalf("variants differ: %q vs %q", a.Value(), b.Value())
	}
}

func TestNormalizeRefusesMalformedEmails(t *testing.T) {
	for _, raw := range []string{
		"", "@example.com", "user@", "user@@example.com", "us er@example.com", ".user@example.com",
		"user.@example.com", "us..er@example.com", "\"quoted\"@example.com", "user@exa mple.com",
		"user@-example.com", "user@example..com", "user@example.com.", "Bob <bob@example.com>",
		"user\x00@example.com", strings.Repeat("a", 65) + "@example.com", "plainuser", "user@ex_ample.com",
	} {
		if id, err := identitysvc.Normalize(raw); err == nil {
			t.Errorf("Normalize(%q) = %q, want an error", raw, id.Value())
		}
	}
}

func TestNormalizePhone(t *testing.T) {
	for _, raw := range []string{"+33 6 12 34 56 78", "+33-6-12-34-56-78", "+33 (6) 12.34.56.78", "＋３３６１２３４５６７８"} {
		id, err := identitysvc.Normalize(raw)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", raw, err)
		}
		if id.Kind() != identity.IdentifierPhone || id.Value() != "+33612345678" {
			t.Errorf("Normalize(%q) = %q", raw, id.Value())
		}
	}
	for _, raw := range []string{"+0612345678", "+33 6 12 34 56 7x", "0612345678", "+1234567", "+1234567890123456"} {
		if _, err := identitysvc.Normalize(raw); err == nil {
			t.Errorf("Normalize(%q) accepted", raw)
		}
	}
}

func TestNormalizeAsChecksTheKind(t *testing.T) {
	if _, err := identitysvc.NormalizeAs(identity.IdentifierEmail, "+33612345678"); err == nil {
		t.Fatal("a phone number is not an email")
	}
	if _, err := identitysvc.NormalizeAs(identity.IdentifierPhone, "a@example.com"); err == nil {
		t.Fatal("an email is not a phone number")
	}
	id, err := identitysvc.NormalizeAs(identity.IdentifierRecoveryEmail, "Backup@Example.com")
	if err != nil || id.Kind() != identity.IdentifierRecoveryEmail || id.Value() != "backup@example.com" {
		t.Fatalf("recovery email = %v %q %v", id.Kind(), id.Value(), err)
	}
	if _, err := identitysvc.NormalizeAs(0, "a@example.com"); !errors.Is(err, identity.ErrInvalidIdentifier) {
		t.Fatalf("zero kind: %v", err)
	}
}

func TestNormalizerAdaptsNormalize(t *testing.T) {
	id, err := identitysvc.Normalizer{}.Normalize("A@Example.com")
	if err != nil || id.Value() != "a@example.com" {
		t.Fatalf("Normalizer = %q, %v", id.Value(), err)
	}
}

func TestScopeKeyIsKeyedAndDeterministic(t *testing.T) {
	if _, err := identitysvc.NewScopeKey(make([]byte, 16)); !errors.Is(err, identitysvc.ErrInvalidScopeKey) {
		t.Fatalf("short key: %v", err)
	}
	k1, err := identitysvc.NewScopeKey(testDataKey(1))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := identitysvc.NewScopeKey(testDataKey(2))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := identitysvc.Normalize("a@example.com")
	b, _ := identitysvc.Normalize("A@EXAMPLE.COM")
	c, _ := identitysvc.Normalize("c@example.com")
	sa, err := k1.Scope(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := k1.Scope(b)
	sc, _ := k1.Scope(c)
	other, _ := k2.Scope(a)
	if sa.Class() != ceremony.Identifier || len(sa.Hash()) != ceremony.IdentifierScopeLen {
		t.Fatalf("scope = %v", sa.Class())
	}
	if !bytes.Equal(sa.Hash(), sb.Hash()) {
		t.Fatal("normalised variants must share a scope")
	}
	if bytes.Equal(sa.Hash(), sc.Hash()) || bytes.Equal(sa.Hash(), other.Hash()) {
		t.Fatal("scope must depend on the identifier and the key")
	}
	if bytes.Contains(sa.Hash(), []byte("example")) {
		t.Fatal("scope leaks the identifier")
	}
	if _, err := (identitysvc.ScopeKey{}).Scope(a); !errors.Is(err, identitysvc.ErrInvalidScopeKey) {
		t.Fatalf("zero key: %v", err)
	}
	if _, err := k1.Scope(identity.Identifier{}); err == nil {
		t.Fatal("zero identifier accepted")
	}
}

func testDataKey(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed*31 + byte(i)*7 + 3
	}
	return k
}
