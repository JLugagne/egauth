package ceremonycodec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
)

const (
	maxCodeLen      = 64
	maxSessionBytes = 2048
	maxAddressLen   = 320
	maxNameLen      = 128
	maxHashLen      = 512
	maxURILen       = 2048
	minPKCEVerifier = 43
	maxPKCEVerifier = 128
	redacted        = "REDACTED"
)

// Empty is the payload of kinds whose whole state lives in the sealed Pending and the handle.
type Empty struct{}

// WebAuthn carries the serialised WebAuthn session data (challenge, allowed credentials, user
// verification) of a passkey ceremony.
type WebAuthn struct {
	Session []byte
}

func (w WebAuthn) validate() error {
	if len(w.Session) == 0 || len(w.Session) > maxSessionBytes {
		return errors.New("webauthn session must be 1 to " + strconv.Itoa(maxSessionBytes) + " bytes")
	}
	return nil
}

// String redacts the challenge.
func (w WebAuthn) String() string { return "ceremonycodec.WebAuthn{" + redacted + "}" }

// GoString redacts like String.
func (w WebAuthn) GoString() string { return w.String() }

// LogValue redacts like String.
func (w WebAuthn) LogValue() slog.Value { return slog.StringValue(w.String()) }

// Code is a one-time code a user types. Only its HMAC-SHA-256 under a subkey of the deployment
// data key is kept, compared in constant time, so a read of the ceremony table does not reveal a
// low-entropy code by brute force; the code is never a lookup key (C-30). The zero Code matches
// nothing.
type Code struct {
	digest []byte
}

// NewCode keys code under s. It returns ErrMalformedPayload for an empty or oversized code or a nil
// s.
func NewCode(s *Sealer, code string) (Code, error) {
	if s == nil {
		return Code{}, errors.Join(ErrMalformedPayload, errors.New("nil sealer"))
	}
	if code == "" || len(code) > maxCodeLen {
		return Code{}, errors.Join(ErrMalformedPayload, errors.New("code must be 1 to "+strconv.Itoa(maxCodeLen)+" bytes"))
	}
	return Code{digest: s.codeDigest(code)}, nil
}

func (s *Sealer) codeDigest(code string) []byte {
	mac := hmac.New(sha256.New, s.codeKey)
	mac.Write([]byte(code))
	return mac.Sum(nil)
}

// Matches reports, in constant time, whether code is the code c was built from under s. A Code
// built under another data key, or a nil s, matches nothing.
func (c Code) Matches(s *Sealer, code string) bool {
	if s == nil || len(c.digest) != sha256.Size || len(code) > maxCodeLen {
		return false
	}
	return hmac.Equal(c.digest, s.codeDigest(code))
}

func (c Code) validate() error {
	if len(c.digest) != sha256.Size {
		return errors.New("code digest missing")
	}
	return nil
}

// MarshalJSON encodes the keyed digest only.
func (c Code) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(c.digest))
}

// UnmarshalJSON decodes a digest written by MarshalJSON.
func (c *Code) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	c.digest = d
	return nil
}

// String redacts the digest.
func (c Code) String() string { return "ceremonycodec.Code{" + redacted + "}" }

// GoString redacts like String.
func (c Code) GoString() string { return c.String() }

// LogValue redacts like String.
func (c Code) LogValue() slog.Value { return slog.StringValue(c.String()) }

// PhoneCode is the payload of a phone verification: the texted code and the number it proves.
type PhoneCode struct {
	Code  Code
	Phone string
}

func (p PhoneCode) validate() error {
	if err := p.Code.validate(); err != nil {
		return err
	}
	return nonEmpty("phone", p.Phone, maxNameLen)
}

// String redacts the code.
func (p PhoneCode) String() string {
	return "ceremonycodec.PhoneCode{Code: " + redacted + ", Phone: " + strconv.Quote(p.Phone) + "}"
}

// GoString redacts like String.
func (p PhoneCode) GoString() string { return p.String() }

// LogValue redacts the code.
func (p PhoneCode) LogValue() slog.Value {
	return slog.GroupValue(slog.String("code", redacted), slog.String("phone", p.Phone))
}

// Registration is a sign-up held until its email is verified (D5): the normalised email and the
// password hash chosen at /register. No account exists before it is consumed.
type Registration struct {
	Email        string
	PasswordHash string
}

func (r Registration) validate() error {
	return errors.Join(nonEmpty("email", r.Email, maxAddressLen), nonEmpty("password hash", r.PasswordHash, maxHashLen))
}

// String redacts the password hash.
func (r Registration) String() string {
	return "ceremonycodec.Registration{Email: " + strconv.Quote(r.Email) + ", PasswordHash: " + redacted + "}"
}

// GoString redacts like String.
func (r Registration) GoString() string { return r.String() }

// LogValue redacts the password hash.
func (r Registration) LogValue() slog.Value {
	return slog.GroupValue(slog.String("email", r.Email), slog.String("password_hash", redacted))
}

// Address is the email address a verification, email change or recovery-email link proves.
type Address struct {
	Address string
}

func (a Address) validate() error { return nonEmpty("address", a.Address, maxAddressLen) }

// Revert is the payload of a security notice's revert link: the address the notice went to and
// the egauth.SecurityEvent it reported (non-zero).
type Revert struct {
	Address string
	Event   uint16
}

func (r Revert) validate() error {
	if r.Event == 0 {
		return errors.New("event missing")
	}
	return nonEmpty("address", r.Address, maxAddressLen)
}

// OAuth is the state of a federated login begin: the provider, the PKCE verifier (43 to 128
// characters, or empty for a provider without PKCE), the OIDC nonce (empty for plain OAuth) and
// the redirect URI replayed at the token exchange.
type OAuth struct {
	Provider     string
	PKCEVerifier string
	Nonce        string
	RedirectURI  string
}

func (o OAuth) validate() error {
	var pkce error
	if n := len(o.PKCEVerifier); n != 0 && (n < minPKCEVerifier || n > maxPKCEVerifier) {
		pkce = errors.New("PKCE verifier must be 43 to 128 characters")
	}
	var nonce error
	if len(o.Nonce) > maxNameLen {
		nonce = errors.New("nonce too long")
	}
	return errors.Join(nonEmpty("provider", o.Provider, maxNameLen), nonEmpty("redirect URI", o.RedirectURI, maxURILen), pkce, nonce)
}

// String redacts the PKCE verifier and nonce.
func (o OAuth) String() string {
	return "ceremonycodec.OAuth{Provider: " + strconv.Quote(o.Provider) + ", PKCEVerifier: " + redacted +
		", Nonce: " + redacted + ", RedirectURI: " + strconv.Quote(o.RedirectURI) + "}"
}

// GoString redacts like String.
func (o OAuth) GoString() string { return o.String() }

// LogValue redacts the PKCE verifier and nonce.
func (o OAuth) LogValue() slog.Value {
	return slog.GroupValue(slog.String("provider", o.Provider), slog.String("pkce_verifier", redacted),
		slog.String("nonce", redacted), slog.String("redirect_uri", o.RedirectURI))
}

// External names the integrator-provided login (Modules.External) a begin is for.
type External struct {
	Name string
}

func (e External) validate() error { return nonEmpty("name", e.Name, maxNameLen) }

func nonEmpty(field, v string, max int) error {
	if v == "" || len(v) > max {
		return errors.New(field + " must be 1 to " + strconv.Itoa(max) + " bytes")
	}
	return nil
}
