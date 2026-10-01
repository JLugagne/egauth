package secretpolicy

import (
	"bytes"
	"errors"
	"fmt"
)

// Sentinel errors let every key-loading path map a refusal onto its own public error while
// sharing one policy. Callers wrap them with the purpose of the key (see Validate).
var (
	// ErrTooShort reports a key shorter than the caller-supplied minimum.
	ErrTooShort = errors.New("key is shorter than the minimum")
	// ErrTrivial reports a key an attacker can guess without reading anything: every byte zero,
	// or a single byte value repeated throughout.
	ErrTrivial = errors.New("key is trivially guessable (all-zero or a single repeated byte)")
	// ErrPublished reports a byte-for-byte match with a credential this project published in its
	// examples or SDK documentation.
	ErrPublished = errors.New("key is a credential published in this project's examples or docs")
	// ErrNearCopy reports a key containing a marker from a published example credential, so a
	// near-copy cannot slip past the exact-match list.
	ErrNearCopy = errors.New("key contains a marker from a credential published in this project's examples or docs")
)

// Denied lists every credential literal this project has published in its examples or SDK
// documentation. They are attacker-known (public on GitHub) yet long enough to satisfy the
// module's minimum-length gates, so length alone cannot reject them. New key-loading paths must
// consult this list through Validate rather than keeping a private partial copy: the fragmented
// per-package denylists were themselves the finding.
//
// tokens/jwt.DeniedSecrets aliases this map for backward compatibility.
var Denied = map[string]bool{
	"replace-with-a-32-byte-minimum-secret-in-production!": true,
	"super-secret-32-byte-key-here!!!":                     true,
	"a-high-entropy-secret-kept-out-of-source-control":     true,
	"super-secret-key-change-me-in-production":             true,
	"a-32-byte-minimum-hs256-signing-secret!!":             true,
	"very-secure-32-byte-secret-key!!":                     true,
	"kek-fixture-0123456789abcdefghij":                     true,
}

// markers are substrings that appear in published example credentials. A key containing one is
// refused even when it is not byte-identical to a listed entry.
var markers = []string{
	"minimum-hs256-signing-secret",
}

// MinKeyLength is the minimum length this module requires of any HMAC-class key (HS256 signing
// keys, OAuth state keys, ceremony-cookie keys, KEKs). A shorter HMAC-SHA-256 key is
// brute-forceable offline from a single captured message.
const MinKeyLength = 32

// IsTrivial reports whether key is all zero bytes or a single byte value repeated throughout.
// Such a key satisfies any minimum-length gate, so it cannot be caught by a length rule.
func IsTrivial(key []byte) bool {
	if len(key) == 0 {
		return false
	}
	first := key[0]
	for _, b := range key[1:] {
		if b != first {
			return false
		}
	}
	return true
}

// Reason returns a human-readable reason when key must be refused, or "" when the key passes the
// shared policy (length is checked separately by Validate).
func Reason(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	if IsTrivial(key) {
		return "is trivially guessable (all bytes zero or a single byte repeated); an attacker can guess it without reading anything"
	}
	if Denied[string(key)] {
		return "is a credential published in this project's examples or docs; copy-pasting it hands anyone holding the public string your authority"
	}
	for _, m := range markers {
		if bytes.Contains(key, []byte(m)) {
			return "is a near-copy of a credential published in this project's examples or docs; it is refused even though it is not byte-identical"
		}
	}
	return ""
}

// Validate applies the shared credential-material policy to key. purpose names the key in the
// returned error (for example "HS256 signing key") and minLen, when positive, is the minimum
// accepted length. The returned error wraps ErrTooShort, ErrTrivial, ErrPublished or ErrNearCopy
// so callers can map it onto their own sentinels with errors.Is.
func Validate(purpose string, key []byte, minLen int) error {
	if minLen > 0 && len(key) < minLen {
		return fmt.Errorf("%s: %w (%d bytes, want at least %d)", purpose, ErrTooShort, len(key), minLen)
	}
	if reason := Reason(key); reason != "" {
		err := ErrPublished
		if IsTrivial(key) {
			err = ErrTrivial
		} else if !Denied[string(key)] {
			err = ErrNearCopy
		}
		return fmt.Errorf("%s %s: %w; generate a unique key with crypto/rand or load one from a secret manager", purpose, reason, err)
	}
	return nil
}
