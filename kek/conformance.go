package kek

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
)

// CheckConformance exercises k with a random probe and reports every broken property of the KEK
// contract, joined with ErrNonConforming: an empty AAD must be refused by Seal and Open, a sealed
// probe must open under its AAD only, must not contain the plaintext, must be randomised, must name
// CurrentKeyID through KeyIDOf, and must not open once tampered. It writes nothing outside k, so it
// is safe on a production KEK; egauth uses it to reject a KEK that ignores associated data.
func CheckConformance(ctx context.Context, k KEK) error {
	if k == nil {
		return errors.Join(ErrNonConforming, errors.New("nil KEK"))
	}
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return errors.Join(ErrNonConforming, err)
	}
	aad := AAD("egauth/kek-conformance/v1\x00a")
	other := AAD("egauth/kek-conformance/v1\x00b")
	var problems []error
	fail := func(msg string, err error) {
		problems = append(problems, errors.Join(errors.New(msg), err))
	}
	if k.CurrentKeyID() == "" {
		fail("CurrentKeyID is empty", nil)
	}
	if _, err := k.Seal(ctx, probe, nil); !errors.Is(err, ErrAADRequired) {
		fail("Seal with an empty AAD did not return ErrAADRequired", err)
	}
	ct, err := k.Seal(ctx, probe, aad)
	if err != nil {
		fail("Seal failed", err)
		return errors.Join(append([]error{ErrNonConforming}, problems...)...)
	}
	if _, err := k.Open(ctx, ct, nil); !errors.Is(err, ErrAADRequired) {
		fail("Open with an empty AAD did not return ErrAADRequired", err)
	}
	if pt, err := k.Open(ctx, ct, aad); err != nil || !bytes.Equal(pt, probe) {
		fail("Open did not return the sealed plaintext", err)
	}
	if _, err := k.Open(ctx, ct, other); err == nil {
		fail("Open succeeded under another AAD", nil)
	}
	if bytes.Contains(ct, probe) {
		fail("ciphertext contains the plaintext", nil)
	}
	if again, err := k.Seal(ctx, probe, aad); err != nil || bytes.Equal(again, ct) {
		fail("Seal is not randomised", err)
	}
	if id, err := k.KeyIDOf(ct); err != nil || id != k.CurrentKeyID() {
		fail("KeyIDOf does not name the current key", err)
	}
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := k.Open(ctx, tampered, aad); err == nil {
		fail("Open accepted a tampered ciphertext", nil)
	}
	if len(problems) == 0 {
		return nil
	}
	return errors.Join(append([]error{ErrNonConforming}, problems...)...)
}
