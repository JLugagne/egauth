package identity

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IdentifierKind tells which contact identifier a value is. Its numeric value is persisted and
// equals lifecycle.IdentifierKind's, so a value is never renumbered or reused.
type IdentifierKind uint8

const (
	IdentifierEmail         IdentifierKind = 1
	IdentifierPhone         IdentifierKind = 2
	IdentifierRecoveryEmail IdentifierKind = 3
)

// Valid reports whether k is declared.
func (k IdentifierKind) Valid() bool {
	return k >= IdentifierEmail && k <= IdentifierRecoveryEmail
}

// String returns the snake_case name of k, or "invalid".
func (k IdentifierKind) String() string {
	switch k {
	case IdentifierEmail:
		return "email"
	case IdentifierPhone:
		return "phone"
	case IdentifierRecoveryEmail:
		return "recovery_email"
	}
	return "invalid"
}

// MaxIdentifierLen bounds an identifier value, in bytes.
const MaxIdentifierLen = 320

// Identifier is a normalised contact identifier: an email, a phone number in E.164 form, or a
// recovery email. Only identitysvc.Normalize produces the value given to NewIdentifier, and no other
// package transforms one (G6). The zero Identifier means "none".
type Identifier struct {
	kind  IdentifierKind
	value string
}

// NewIdentifier wraps an already normalised value. It does not normalise: it returns
// ErrInvalidIdentifier for a value that is not canonical for k (an email with upper-case letters,
// spaces, control characters or not exactly one '@'; a phone that is not '+' followed by 8 to 15
// digits), so a non-normalised value can never reach a store.
func NewIdentifier(k IdentifierKind, normalized string) (Identifier, error) {
	if !k.Valid() || normalized == "" || len(normalized) > MaxIdentifierLen || !utf8.ValidString(normalized) {
		return Identifier{}, ErrInvalidIdentifier
	}
	if k == IdentifierPhone {
		if !canonicalPhone(normalized) {
			return Identifier{}, errors.Join(ErrInvalidIdentifier, errors.New("phone must be in E.164 form"))
		}
		return Identifier{kind: k, value: normalized}, nil
	}
	if !canonicalEmail(normalized) {
		return Identifier{}, errors.Join(ErrInvalidIdentifier, errors.New("email is not in canonical form"))
	}
	return Identifier{kind: k, value: normalized}, nil
}

func canonicalPhone(s string) bool {
	digits, ok := strings.CutPrefix(s, "+")
	if !ok || len(digits) < 8 || len(digits) > 15 || digits[0] == '0' {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func canonicalEmail(s string) bool {
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	for _, c := range s {
		if unicode.IsSpace(c) || unicode.IsControl(c) || unicode.IsUpper(c) {
			return false
		}
	}
	return true
}

func (i Identifier) Kind() IdentifierKind { return i.kind }

// Value returns the normalised value, as stored and as compared for uniqueness.
func (i Identifier) Value() string { return i.value }

// IsZero reports whether i holds no identifier.
func (i Identifier) IsZero() bool { return i.kind == 0 }
