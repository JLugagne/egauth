package oauth

import (
	"strings"
	"testing"
)

// PoC (injection audit): the state cookie packs five fields joined by "." and an
// HMAC signature. Provider/tenant are attacker-influenced (tenant resolver,
// provider registry). If framing could be broken, an attacker could smuggle a
// foreign tenant/provider into the post-callback trust decision. These tests
// prove the framing holds and tampering fails closed.
func TestPocStateSeparatorInjection(t *testing.T) {
	key := []byte("poc-signing-key-0123456789abcdef")
	evil := []string{
		"a.b", "a..b", ".", ".....", "a/b\\c",
		"x'; DROP TABLE users; --", "a\r\nSet-Cookie: x=1", "a\nb",
		"üñï_t", strings.Repeat("A", 512),
	}
	for _, provider := range evil {
		for _, tenant := range evil {
			packed := packState("st", "ver", "non", provider, tenant, key)
			if strings.ContainsAny(packed, "\r\n") {
				t.Fatalf("packed state contains CRLF for provider %q tenant %q", provider, tenant)
			}
			st, ver, non, gotP, gotT, ok := unpackState(packed, key)
			if !ok {
				t.Fatalf("valid packed state rejected for provider %q tenant %q", provider, tenant)
			}
			if st != "st" || ver != "ver" || non != "non" || gotP != provider || gotT != tenant {
				t.Fatalf("round-trip mismatch: got provider %q tenant %q", gotP, gotT)
			}
		}
	}
}

// PoC: signed-cookie tampering (field swap, truncation, extension, bit-flip)
// must fail closed.
func TestPocStateTamperFailsClosed(t *testing.T) {
	key := []byte("poc-signing-key-0123456789abcdef")
	good := packState("st", "ver", "non", "github", "t1", key)
	parts := strings.Split(good, stateSeparator)
	if len(parts) != 6 {
		t.Fatalf("expected 6 signed parts, got %d", len(parts))
	}
	other := packState("st", "ver", "non", "gitlab", "t2", key)
	otherParts := strings.Split(other, stateSeparator)

	cases := map[string]string{
		"bit-flip signature":   strings.Join(parts[:5], stateSeparator) + stateSeparator + "A" + parts[5][1:],
		"truncated":            strings.Join(parts[:5], stateSeparator),
		"extended":             good + ".extra",
		"swapped provider":     strings.Join([]string{parts[0], parts[1], parts[2], otherParts[3], parts[4], parts[5]}, stateSeparator),
		"empty state":          strings.Join([]string{"", parts[1], parts[2], parts[3], parts[4], parts[5]}, stateSeparator),
		"wrong key":            good,
		"legacy 3-field shape": "a.b.c",
	}
	for name, raw := range cases {
		k := key
		if name == "wrong key" {
			k = []byte("different-key-0123456789abcdef")
		}
		if _, _, _, _, _, ok := unpackState(raw, k); ok {
			t.Fatalf("tampered state cookie accepted (%s)", name)
		}
	}
}
