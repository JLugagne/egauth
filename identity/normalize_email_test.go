package identity

import "testing"

// Regression tests for TASK-059: normalizeEmail must canonicalize Unicode
// (NFC) local parts and IDN/punycode domains so that human/IdP-identical
// addresses map to a single byte-exact identity key.

// TestNormalizeEmail_NFDvsNFC_SameKey proves that the NFD and NFC forms of the
// same address normalize to the same key. Before the fix they differed,
// allowing a second account to be JIT-provisioned for one human address.
func TestNormalizeEmail_NFDvsNFC_SameKey(t *testing.T) {
	// "josé@example.com" — precomposed (NFC, U+00E9) vs decomposed (NFD, "e"+U+0301).
	nfc := "josé@example.com"
	nfd := "josé@example.com"

	if nfc == nfd {
		t.Fatal("test inputs are byte-identical; they must be distinct NFC/NFD forms")
	}

	gotNFC, err := normalizeEmail(nfc)
	if err != nil {
		t.Fatalf("normalizeEmail(NFC) returned error: %v", err)
	}
	gotNFD, err := normalizeEmail(nfd)
	if err != nil {
		t.Fatalf("normalizeEmail(NFD) returned error: %v", err)
	}

	if gotNFC != gotNFD {
		t.Fatalf("NFC and NFD forms produced different keys: NFC=%q NFD=%q", gotNFC, gotNFD)
	}
}

// TestNormalizeEmail_IDN_UnicodeVsPunycode_SameKey proves that a Unicode (U-label)
// domain and its punycode (A-label) equivalent normalize to the same key.
func TestNormalizeEmail_IDN_UnicodeVsPunycode_SameKey(t *testing.T) {
	unicodeDomain := "user@münchen.de"         // münchen.de (U-label)
	punycodeDomain := "user@xn--mnchen-3ya.de" // A-label equivalent

	gotUnicode, err := normalizeEmail(unicodeDomain)
	if err != nil {
		t.Fatalf("normalizeEmail(unicode domain) returned error: %v", err)
	}
	gotPuny, err := normalizeEmail(punycodeDomain)
	if err != nil {
		t.Fatalf("normalizeEmail(punycode domain) returned error: %v", err)
	}

	if gotUnicode != gotPuny {
		t.Fatalf("unicode and punycode domains produced different keys: unicode=%q puny=%q", gotUnicode, gotPuny)
	}
}
