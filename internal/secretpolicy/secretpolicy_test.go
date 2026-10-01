// Package secretpolicy_test pins the shared credential-material policy and the public alias
// tokens/jwt.DeniedSecrets re-exports: the policy moved to internal/secretpolicy and the alias
// must stay the same map, not a copy that can drift.
package secretpolicy_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	secretpolicy "github.com/JLugagne/egauth/internal/secretpolicy"

	"github.com/JLugagne/egauth/tokens/jwt"
)

// randomKey returns n cryptographically random bytes or fails the test.
func randomKey(t *testing.T, n int) []byte {
	t.Helper()
	key := make([]byte, n)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return key
}

// publishedLiteral is a stable denylist entry used by the exact-literal cases; if it is ever
// removed from the denylist the test fails, which is the point.
const publishedLiteral = "super-secret-32-byte-key-here!!!"

func TestValidate(t *testing.T) {
	nearCopy := []byte("prefix-" + "minimum-hs256-signing-secret" + "-suffix")
	tests := []struct {
		name    string
		key     []byte
		minLen  int
		wantErr error
	}{
		{name: "random key above the floor", key: randomKey(t, 32), minLen: 32},
		{name: "exactly at the length floor", key: randomKey(t, 32), minLen: 32},
		{name: "one byte under the floor", key: randomKey(t, 31), minLen: 32, wantErr: secretpolicy.ErrTooShort},
		{name: "length gate disabled", key: []byte("abcd"), minLen: 0},
		{name: "all-zero key", key: make([]byte, 32), minLen: 32, wantErr: secretpolicy.ErrTrivial},
		{name: "repeated-byte key", key: bytes.Repeat([]byte{'A'}, 32), minLen: 32, wantErr: secretpolicy.ErrTrivial},
		{name: "exact published literal", key: []byte(publishedLiteral), minLen: 32, wantErr: secretpolicy.ErrPublished},
		{name: "near-copy marker", key: nearCopy, minLen: 32, wantErr: secretpolicy.ErrNearCopy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := secretpolicy.Validate("test key", tt.key, tt.minLen)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate(%q) = %v, want nil", tt.key, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate(%q) = %v, want errors.Is %v", tt.key, err, tt.wantErr)
			}
		})
	}
}

// TestValidateRejectsEveryPublishedLiteral walks the whole denylist so a newly added literal is
// enforced by the policy, not just the one pinned above.
func TestValidateRejectsEveryPublishedLiteral(t *testing.T) {
	if len(secretpolicy.Denied) == 0 {
		t.Fatal("secretpolicy.Denied is empty; the policy has nothing to enforce")
	}
	for denied := range secretpolicy.Denied {
		if err := secretpolicy.Validate("test key", []byte(denied), 32); !errors.Is(err, secretpolicy.ErrPublished) {
			t.Errorf("Validate(%q) = %v, want errors.Is ErrPublished", denied, err)
		}
	}
}

func TestReason(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		want string
	}{
		{name: "empty key", key: nil, want: ""},
		{name: "random key", key: randomKey(t, 32), want: ""},
		{name: "short non-trivial key", key: []byte("abcd"), want: ""},
		{name: "all-zero key", key: make([]byte, 32), want: "trivially guessable"},
		{name: "repeated-byte key", key: bytes.Repeat([]byte{'x'}, 40), want: "trivially guessable"},
		{name: "published literal", key: []byte(publishedLiteral), want: "credential published"},
		{name: "near-copy marker", key: []byte("xx-minimum-hs256-signing-secret-xx"), want: "near-copy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := secretpolicy.Reason(tt.key)
			if tt.want == "" {
				if reason != "" {
					t.Fatalf("Reason(%q) = %q, want no reason", tt.key, reason)
				}
				return
			}
			if !strings.Contains(reason, tt.want) {
				t.Fatalf("Reason(%q) = %q, want it to contain %q", tt.key, reason, tt.want)
			}
		})
	}
}

func TestIsTrivial(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		want bool
	}{
		{name: "nil key", key: nil, want: false},
		{name: "empty key", key: []byte{}, want: false},
		{name: "single zero byte", key: []byte{0}, want: true},
		{name: "all zero bytes", key: make([]byte, 32), want: true},
		{name: "single repeated byte", key: bytes.Repeat([]byte{'a'}, 32), want: true},
		{name: "mixed bytes", key: []byte("abcdabcdabcdabcdabcdabcdabcdabcd"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretpolicy.IsTrivial(tt.key); got != tt.want {
				t.Fatalf("IsTrivial(%q) = %t, want %t", tt.key, got, tt.want)
			}
		})
	}
}

func TestJWTDeniedSecretsAliasesSharedDenied(t *testing.T) {
	if len(jwt.DeniedSecrets) != len(secretpolicy.Denied) {
		t.Fatalf("jwt.DeniedSecrets has %d entries, secretpolicy.Denied has %d; the alias fragmented",
			len(jwt.DeniedSecrets), len(secretpolicy.Denied))
	}
	for literal := range secretpolicy.Denied {
		if !jwt.DeniedSecrets[literal] {
			t.Errorf("jwt.DeniedSecrets is missing %q, which secretpolicy.Denied refuses", literal)
		}
	}
	// Same map, not a copy: fragmentation cannot return silently.
	if fmt.Sprintf("%p", jwt.DeniedSecrets) != fmt.Sprintf("%p", secretpolicy.Denied) {
		t.Error("jwt.DeniedSecrets is a copy of secretpolicy.Denied; it must alias the same map")
	}
}
