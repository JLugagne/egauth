package policy

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/JLugagne/egauth/passwords"
)

// Passphrase-policy defaults aligned with NIST SP 800-63B.
const (
	// DefaultPassphraseMinLength is the minimum length. NIST requires at least 8 for memorized
	// secrets; 12 is a stronger, still-usable default that favors length over composition.
	DefaultPassphraseMinLength = 12
	// DefaultPassphraseMaxLength bounds the input to avoid a hashing denial-of-service while
	// comfortably exceeding the 64-character minimum NIST asks verifiers to accept.
	DefaultPassphraseMaxLength = 256
)

// PassphrasePolicy is a NIST SP 800-63B-aligned password policy. It deliberately drops
// composition rules (no "must contain an uppercase/number/symbol") in favor of length, and
// instead screens secrets against a denylist of common/compromised values and, optionally, a
// pluggable BreachChecker. This matches current guidance: long passphrases, no forced
// character classes, no periodic rotation, but reject known-bad secrets.
type PassphrasePolicy struct {
	// MinLength is the minimum number of Unicode code points (not bytes), so multi-byte
	// passphrases are not unfairly penalized.
	MinLength int
	// MaxLength is the maximum number of code points; 0 means no maximum.
	MaxLength int
	// denylist holds normalized (lowercased, trimmed) secrets that are always rejected.
	denylist map[string]struct{}
	// breach, when set, screens the secret against a known-compromised corpus.
	breach passwords.BreachChecker
}

// PassphraseOption configures a PassphrasePolicy.
type PassphraseOption func(*PassphrasePolicy)

// WithMinLength overrides the minimum length (in code points).
func WithMinLength(n int) PassphraseOption {
	return func(p *PassphrasePolicy) { p.MinLength = n }
}

// WithMaxLength overrides the maximum length (in code points); 0 disables the maximum.
func WithMaxLength(n int) PassphraseOption {
	return func(p *PassphrasePolicy) { p.MaxLength = n }
}

// WithDenylist adds entries to the rejected-secret denylist. Matching is case-insensitive and
// whitespace-insensitive (all whitespace is stripped on both sides before comparison), so a
// banned secret cannot be bypassed by re-spacing it. Call it multiple times to extend the list.
func WithDenylist(entries ...string) PassphraseOption {
	return func(p *PassphrasePolicy) {
		for _, e := range entries {
			p.denylist[normalizeDenyEntry(e)] = struct{}{}
		}
	}
}

// WithBreachChecker wires a BreachChecker (e.g. a HIBP k-anonymity client) into the policy.
func WithBreachChecker(b passwords.BreachChecker) PassphraseOption {
	return func(p *PassphrasePolicy) { p.breach = b }
}

// NewPassphrasePolicy builds a PassphrasePolicy with NIST-aligned defaults and a small
// built-in denylist of extremely common secrets. Supply WithBreachChecker for real
// compromised-credential screening (the built-in denylist is only a minimal backstop).
func NewPassphrasePolicy(opts ...PassphraseOption) *PassphrasePolicy {
	p := &PassphrasePolicy{
		MinLength: DefaultPassphraseMinLength,
		MaxLength: DefaultPassphraseMaxLength,
		denylist:  make(map[string]struct{}),
	}
	for _, e := range builtinDenylist {
		p.denylist[e] = struct{}{}
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Verify checks the password against length bounds, the denylist and the breach checker. It
// applies NO character-class requirements by design.
func (p *PassphrasePolicy) Verify(ctx context.Context, password string) error {
	n := utf8.RuneCountInString(password)
	if n < p.MinLength {
		return passwords.ErrPasswordTooShort
	}
	if p.MaxLength > 0 && n > p.MaxLength {
		return passwords.ErrPasswordTooLong
	}

	if _, bad := p.denylist[normalizeDenyEntry(password)]; bad {
		return passwords.ErrPasswordBreached
	}

	if p.breach != nil {
		breached, err := p.breach.IsBreached(ctx, password)
		if err != nil {
			// Propagate unchanged: the caller decides fail-open vs fail-closed.
			return err
		}
		if breached {
			return passwords.ErrPasswordBreached
		}
	}

	return nil
}

// normalizeDenyEntry canonicalizes a secret for denylist comparison by removing ALL
// whitespace and lowercasing, so trivial cosmetic edits ("correct horse battery staple",
// "password password") cannot slip a banned secret past an exact-string match.
func normalizeDenyEntry(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), ""))
}

// builtinDenylist is a minimal backstop of common secrets. It is intentionally small — real
// compromised-credential screening should come from a BreachChecker. Entries are stored
// already normalized (lowercase).
var builtinDenylist = []string{
	"password",
	"password1",
	"password123",
	"passw0rd",
	"123456",
	"12345678",
	"123456789",
	"1234567890",
	"qwerty",
	"qwertyuiop",
	"letmein",
	"iloveyou",
	"admin",
	"welcome",
	"changeme",
	"passwordpassword",
	"correcthorsebatterystaple",
}

// Verify interface compliance.
var _ passwords.Policy = (*PassphrasePolicy)(nil)
