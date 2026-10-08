package kek

import (
	"bytes"
	"errors"
	"strconv"
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

func checkKey(key []byte) error {
	if err := checkLegacyKey(key); err != nil {
		return err
	}
	if distinctBytes(key) < minDistinct {
		return errors.New("key is trivially guessable; generate it with crypto/rand")
	}
	return nil
}

func checkLegacyKey(key []byte) error {
	if len(key) != KeyLength {
		return errors.New("key must be exactly " + strconv.Itoa(KeyLength) + " bytes")
	}
	if distinctBytes(key) < 2 {
		return errors.New("key is trivially guessable (all-zero or a single repeated byte)")
	}
	if published(key) {
		return errors.New("key is a credential published in egauth's examples or docs; generate it with crypto/rand")
	}
	return nil
}

func published(key []byte) bool {
	if publishedKeys[string(key)] {
		return true
	}
	for _, m := range publishedMarkers {
		if bytes.Contains(key, []byte(m)) {
			return true
		}
	}
	return false
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
