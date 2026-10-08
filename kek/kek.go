// Package kek holds the key-encryption key that seals every secret egauth persists: TOTP seeds,
// OAuth client secrets, tenant signing keys and the deployment data key. Associated data is
// mandatory, so a ciphertext cannot be moved to another row, tenant or purpose, and every
// ciphertext carries the id of the key that sealed it, so a rotated KEK keeps opening data sealed by
// its predecessors and stale ciphertexts can be re-sealed lazily.
package kek

import (
	"context"
	"errors"
)

// AAD is the associated data bound to a ciphertext. It is a distinct type so that plaintext and
// associated data cannot be swapped at a call site. egauth computes it in one place; an empty AAD
// is refused by Seal and Open with ErrAADRequired.
type AAD []byte

// KEK seals with mandatory associated data; an empty aad returns ErrAADRequired. Ciphertexts carry
// the sealing key id so that a rotated KEK still opens data sealed by its predecessors.
// Implementations must be safe for concurrent use. CheckConformance verifies the contract and
// kektest.Run runs it as a test suite.
type KEK interface {
	Seal(ctx context.Context, pt []byte, aad AAD) ([]byte, error)
	Open(ctx context.Context, ct []byte, aad AAD) ([]byte, error)
	CurrentKeyID() string
	KeyIDOf(ct []byte) (string, error)
}

// LegacyOpener opens v0.16 blobs (nonce||ciphertext||tag, no key id). Their associated data is
// optional: an empty aad opens a blob sealed without one. It exists only for the one-shot secret
// upgrade and is removed in v0.18.
type LegacyOpener interface {
	OpenLegacy(ctx context.Context, blob []byte, aad AAD) ([]byte, error)
}

var (
	// ErrAADRequired is returned by Seal and Open when the associated data is empty.
	ErrAADRequired = errors.New("kek: associated data is required")
	// ErrInvalidKey is returned by the constructors for a key that is not 32 bytes, is trivially
	// guessable, or duplicates another key of the same KEK.
	ErrInvalidKey = errors.New("kek: invalid key")
	// ErrMalformed is returned for a ciphertext that is not in the v1 format.
	ErrMalformed = errors.New("kek: malformed ciphertext")
	// ErrUnknownKey is returned by Open for a ciphertext sealed by a key this KEK does not hold:
	// the key was rotated out, or the KEK is the wrong one.
	ErrUnknownKey = errors.New("kek: ciphertext sealed by an unknown key")
	// ErrOpenFailed is returned when authentication fails: wrong key, wrong associated data or a
	// tampered ciphertext.
	ErrOpenFailed = errors.New("kek: cannot open ciphertext")
	// ErrNonConforming is returned by CheckConformance, joined with every property the KEK breaks.
	ErrNonConforming = errors.New("kek: implementation breaks the KEK contract")
)
