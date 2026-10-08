// Package ceremonycodec owns the typed payload of every ceremony kind and the stateless handle
// sealer. A Codec binds one ceremony.Kind to one payload type, so a payload written for one kind
// cannot be read as another. Stateless anonymous begins (D3) carry kind ‖ tenant ‖ sealed Pending ‖
// payload ‖ expiresAt in an AEAD handle under the deployment data key; opening one always checks
// the kind, the tenant and the expiry (O-07). Stored kinds are looked up by the SHA-256 of a 256-bit
// random Handle, never by a short code.
package ceremonycodec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/JLugagne/egauth/store/ceremony"
)

const (
	payloadVersion  byte = 1
	maxPayloadBytes      = 4 << 10
)

var (
	// ErrWrongKind is returned when a payload or handle of one ceremony kind is read as another.
	ErrWrongKind = errors.New("ceremonycodec: wrong ceremony kind")
	// ErrMalformedPayload is returned for a payload that is not the canonical encoding of the
	// codec's type, or that fails its validation.
	ErrMalformedPayload = errors.New("ceremonycodec: malformed payload")
)

// Codec encodes the payload P of one ceremony kind. Codecs come only from the per-kind
// constructors of this package; the zero Codec refuses everything.
type Codec[P any] struct {
	kind  ceremony.Kind
	check func(P) error
}

func (c Codec[P]) Kind() ceremony.Kind { return c.kind }

// Encode validates p and encodes it as version ‖ kind ‖ JSON, bounded to 4 KiB.
func (c Codec[P]) Encode(p P) ([]byte, error) {
	if !c.kind.Valid() || c.check == nil {
		return nil, ErrWrongKind
	}
	if err := c.check(p); err != nil {
		return nil, errors.Join(ErrMalformedPayload, err)
	}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, errors.Join(ErrMalformedPayload, err)
	}
	if len(body)+2 > maxPayloadBytes {
		return nil, errors.Join(ErrMalformedPayload, errors.New("payload exceeds "+strconv.Itoa(maxPayloadBytes)+" bytes"))
	}
	return append([]byte{payloadVersion, byte(c.kind)}, body...), nil
}

// Decode reads a payload written by Encode of the same codec. A payload of another kind returns
// ErrWrongKind; unknown fields, trailing data or a value failing validation return
// ErrMalformedPayload.
func (c Codec[P]) Decode(b []byte) (P, error) {
	var zero P
	if !c.kind.Valid() || c.check == nil {
		return zero, ErrWrongKind
	}
	if len(b) < 2 || len(b) > maxPayloadBytes || b[0] != payloadVersion {
		return zero, ErrMalformedPayload
	}
	if ceremony.Kind(b[1]) != c.kind {
		return zero, errors.Join(ErrWrongKind, errors.New("payload of "+ceremony.Kind(b[1]).String()+" read as "+c.kind.String()))
	}
	dec := json.NewDecoder(bytes.NewReader(b[2:]))
	dec.DisallowUnknownFields()
	var p P
	if err := dec.Decode(&p); err != nil {
		return zero, errors.Join(ErrMalformedPayload, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return zero, errors.Join(ErrMalformedPayload, errors.New("trailing data"))
	}
	if err := c.check(p); err != nil {
		return zero, errors.Join(ErrMalformedPayload, err)
	}
	return p, nil
}

func codec[P any](k ceremony.Kind, check func(P) error) Codec[P] {
	return Codec[P]{kind: k, check: check}
}

func noCheck[P any](P) error { return nil }

// MFAFlow is the codec of ceremony.MFAFlow; the parked login lives in the sealed Pending.
func MFAFlow() Codec[Empty] { return codec(ceremony.MFAFlow, noCheck[Empty]) }

func PasskeyRegistration() Codec[WebAuthn] {
	return codec(ceremony.PasskeyRegistration, WebAuthn.validate)
}

func MFAPasskey() Codec[WebAuthn] { return codec(ceremony.MFAPasskey, WebAuthn.validate) }

// MagicLink is the codec of ceremony.MagicLink; the link handle is the only secret.
func MagicLink() Codec[Empty] { return codec(ceremony.MagicLink, noCheck[Empty]) }

func EmailCode() Codec[Code] { return codec(ceremony.EmailCode, Code.validate) }

func SMSCode() Codec[Code] { return codec(ceremony.SMSCode, Code.validate) }

func PhoneVerification() Codec[PhoneCode] {
	return codec(ceremony.PhoneVerification, PhoneCode.validate)
}

func PasswordReset() Codec[Empty] { return codec(ceremony.PasswordReset, noCheck[Empty]) }

func PendingRegistration() Codec[Registration] {
	return codec(ceremony.PendingRegistration, Registration.validate)
}

func EmailVerification() Codec[Address] {
	return codec(ceremony.EmailVerification, Address.validate)
}

// EmailChange is the codec of ceremony.EmailChange; the Address is the new email.
func EmailChange() Codec[Address] { return codec(ceremony.EmailChange, Address.validate) }

func RecoveryEmail() Codec[Address] { return codec(ceremony.RecoveryEmail, Address.validate) }

func SecurityRevert() Codec[Revert] { return codec(ceremony.SecurityRevert, Revert.validate) }

// Exchange is the codec of ceremony.Exchange; the browser binding lives in the sealed Pending.
func Exchange() Codec[Empty] { return codec(ceremony.Exchange, noCheck[Empty]) }

// DiscoverablePasskey is the codec of the stateless ceremony.DiscoverablePasskey handle.
func DiscoverablePasskey() Codec[WebAuthn] {
	return codec(ceremony.DiscoverablePasskey, WebAuthn.validate)
}

// UsernameFirstPasskey is the codec of the stateless ceremony.UsernameFirstPasskey handle.
func UsernameFirstPasskey() Codec[WebAuthn] {
	return codec(ceremony.UsernameFirstPasskey, WebAuthn.validate)
}

// OAuthState is the codec of the stateless ceremony.OAuthState handle.
func OAuthState() Codec[OAuth] { return codec(ceremony.OAuthState, OAuth.validate) }

// ExternalLogin is the codec of the stateless ceremony.ExternalLogin handle.
func ExternalLogin() Codec[External] { return codec(ceremony.ExternalLogin, External.validate) }

func PasswordResetCode() Codec[Code] { return codec(ceremony.PasswordResetCode, Code.validate) }
