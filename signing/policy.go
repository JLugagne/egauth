package signing

import (
	"bytes"
	"errors"
)

const minDistinct = 8

var publishedKeys = map[string]bool{
	"replace-with-a-32-byte-minimum-secret-in-production!": true,
	"super-secret-32-byte-key-here!!!":                     true,
	"a-high-entropy-secret-kept-out-of-source-control":     true,
	"super-secret-key-change-me-in-production":             true,
	"a-32-byte-minimum-hs256-signing-secret!!":             true,
	"very-secure-32-byte-secret-key!!":                     true,
	"kek-fixture-0123456789abcdefghij":                     true,
}

var publishedMarkers = []string{
	"minimum-hs256-signing-secret",
}

func checkSecret(key []byte) error {
	if distinctBytes(key) < minDistinct {
		return errors.New("key is trivially guessable; generate it with crypto/rand")
	}
	if publishedKeys[string(key)] {
		return errors.New("key is a credential published in egauth's examples or docs")
	}
	for _, m := range publishedMarkers {
		if bytes.Contains(key, []byte(m)) {
			return errors.New("key is a near-copy of a credential published in egauth's examples or docs")
		}
	}
	return nil
}

func distinctBytes(key []byte) int {
	var seen [256]bool
	n := 0
	for _, b := range key {
		if !seen[b] {
			seen[b] = true
			n++
		}
	}
	return n
}
