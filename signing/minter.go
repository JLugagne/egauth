package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
)

const (
	ownerTypeName = "signingOwner"
	ownerPackage  = "/internal/session/jwt"
)

var modulePath = strings.TrimSuffix(reflect.TypeFor[Signer]().PkgPath(), "/signing")

// Minter produces signatures with Signers. It is the only signing path, and it exists only inside
// egauth: NewMinter hands one out solely to an owner value of an unexported struct type named
// signingOwner declared in egauth's internal/session/jwt, the access-token codec, so neither an
// application holding a Signer nor another egauth package can mint tokens with it (C-06). The zero
// Minter refuses to sign.
type Minter struct {
	granted bool
}

// NewMinter returns a Minter for owner, which must be a value of an unexported struct type named
// signingOwner declared in egauth's internal/session/jwt. Any other owner returns ErrNotOwner.
func NewMinter(owner any) (*Minter, error) {
	t := reflect.TypeOf(owner)
	if t == nil || t.Kind() != reflect.Struct || t.Name() != ownerTypeName {
		return nil, ErrNotOwner
	}
	if t.PkgPath() != modulePath+ownerPackage {
		return nil, ErrNotOwner
	}
	return &Minter{granted: true}, nil
}

// Sign returns the JWS signature of signingInput (base64url(header) "." base64url(payload)) under
// s: raw r ‖ s for ES256, as RFC 7518 requires.
func (m *Minter) Sign(s Signer, signingInput string) ([]byte, error) {
	if m == nil || !m.granted {
		return nil, ErrNotOwner
	}
	if s.k == nil {
		return nil, ErrZeroKey
	}
	k := s.k
	switch {
	case k.ed != nil:
		return ed25519.Sign(k.ed, []byte(signingInput)), nil
	case k.ec != nil:
		digest := sha256.Sum256([]byte(signingInput))
		r, ss, err := ecdsa.Sign(rand.Reader, k.ec, digest[:])
		if err != nil {
			return nil, errors.Join(errors.New("signing: ES256"), err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		ss.FillBytes(out[32:])
		return out, nil
	case k.rsa != nil:
		digest := sha256.Sum256([]byte(signingInput))
		sig, err := rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, digest[:])
		if err != nil {
			return nil, errors.Join(errors.New("signing: RS256"), err)
		}
		return sig, nil
	case k.mac != nil:
		h := hmac.New(sha256.New, k.mac)
		h.Write([]byte(signingInput))
		return h.Sum(nil), nil
	}
	return nil, ErrZeroKey
}
