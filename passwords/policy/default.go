package policy

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/JLugagne/egauth/passwords"
)

// DefaultPolicy enforces standard password complexity rules.
type DefaultPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
}

// NewDefaultPolicy creates a DefaultPolicy with sensible default requirements.
func NewDefaultPolicy() *DefaultPolicy {
	return &DefaultPolicy{
		MinLength:        8,
		MaxLength:        72,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
	}
}

// Verify checks if the provided password meets all configured policy requirements.
func (p *DefaultPolicy) Verify(ctx context.Context, password string) error {
	// Length is measured in characters (runes), not bytes, so multibyte passwords are neither
	// under-counted against MinLength nor over-restricted against MaxLength. This matches the
	// passphrase policy. (The pre-auth byte-length DoS cap lives in the hasher, not here.)
	length := utf8.RuneCountInString(password)
	if length < p.MinLength {
		return passwords.ErrPasswordTooShort
	}
	if p.MaxLength > 0 && length > p.MaxLength {
		return passwords.ErrPasswordTooLong
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char) || strings.ContainsRune(" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", char):
			hasSpecial = true
		}
	}

	if p.RequireUppercase && !hasUpper {
		return passwords.ErrPasswordMissingUppercase
	}
	if p.RequireLowercase && !hasLower {
		return passwords.ErrPasswordMissingLowercase
	}
	if p.RequireNumber && !hasNumber {
		return passwords.ErrPasswordMissingNumber
	}
	if p.RequireSpecial && !hasSpecial {
		return passwords.ErrPasswordMissingSpecial
	}

	return nil
}

// Verify interface compliance.
var _ passwords.Policy = (*DefaultPolicy)(nil)
