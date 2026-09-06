package policy

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/breach/offline"
)

// ErrBreachedPassword is returned when a password matches known compromised/breached credentials.
var ErrBreachedPassword = passwords.ErrPasswordBreached

// DefaultPolicy enforces standard password complexity rules and screens against breached passwords.
type DefaultPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
	breach           passwords.BreachChecker
	denylist         map[string]struct{}
}

// DefaultOption configures a DefaultPolicy.
type DefaultOption func(*DefaultPolicy)

// WithDefaultBreachChecker configures a custom breach checker for DefaultPolicy.
func WithDefaultBreachChecker(b passwords.BreachChecker) DefaultOption {
	return func(p *DefaultPolicy) { p.breach = b }
}

// WithDefaultDenylist adds entries to the rejected-secret denylist.
func WithDefaultDenylist(entries ...string) DefaultOption {
	return func(p *DefaultPolicy) {
		for _, e := range entries {
			p.denylist[normalizeDenyEntry(e)] = struct{}{}
		}
	}
}

var defaultBreachedChecker passwords.BreachChecker

func init() {
	var err error
	defaultBreachedChecker, err = offline.LoadPasswords(strings.NewReader(defaultBreachedPasswordList))
	if err != nil {
		panic("failed to initialize default breach checker: " + err.Error())
	}
}

// NewDefaultPolicy creates a DefaultPolicy with sensible default requirements.
// By default, it screens candidate passwords against known breached passwords.
func NewDefaultPolicy(opts ...DefaultOption) *DefaultPolicy {
	p := &DefaultPolicy{
		MinLength:        8,
		MaxLength:        72,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
		breach:           defaultBreachedChecker,
		denylist:         make(map[string]struct{}),
	}
	for _, e := range defaultBreachedDenylist {
		p.denylist[normalizeDenyEntry(e)] = struct{}{}
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
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

	if _, bad := p.denylist[normalizeDenyEntry(password)]; bad {
		return ErrBreachedPassword
	}

	if p.breach != nil {
		breached, err := p.breach.IsBreached(ctx, password)
		if err != nil {
			return err
		}
		if breached {
			return ErrBreachedPassword
		}
	}

	return nil
}

const defaultBreachedPasswordList = `
Password123!
Admin2024!
Welcome1!
Summer2026!
P@ssword1
Password1!
Password!1
Admin2025!
Admin2026!
Welcome123!
Summer2024!
Summer2025!
Winter2024!
Winter2025!
Winter2026!
Spring2024!
Spring2025!
Spring2026!
Autumn2024!
Autumn2025!
Autumn2026!
P@ssword123!
P@ssw0rd1
P@ssw0rd123!
Qwerty123!
Qwerty1!
Letmein1!
Changeme1!
Iloveyou1!
`

var defaultBreachedDenylist = []string{
	"Password123!",
	"Admin2024!",
	"Welcome1!",
	"Summer2026!",
	"P@ssword1",
	"Password1!",
	"Admin2025!",
	"Admin2026!",
	"Welcome123!",
	"Summer2024!",
	"Summer2025!",
	"Winter2024!",
	"Winter2025!",
	"Winter2026!",
	"Spring2024!",
	"Spring2025!",
	"Spring2026!",
	"Autumn2024!",
	"Autumn2025!",
	"Autumn2026!",
	"P@ssword123!",
	"P@ssw0rd1",
	"P@ssw0rd123!",
	"Qwerty123!",
	"Qwerty1!",
	"Letmein1!",
	"Changeme1!",
	"Iloveyou1!",
}

// Verify interface compliance
var _ passwords.Policy = (*DefaultPolicy)(nil)
