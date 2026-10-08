package identitysvc

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"

	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	maxLocalPart  = 64
	maxDomain     = 253
	maxLabel      = 63
	scopeKeyBytes = 32
	scopeKeyInfo  = "egauth/identifier-scope/v1"
	atext         = "!#$%&'*+-/=?^_`{|}~"
	phoneMarks    = " -.()"
)

// ErrInvalidScopeKey is returned by NewScopeKey for a data key that is not 32 bytes.
var ErrInvalidScopeKey = errors.New("identitysvc: invalid scope key")

// Normalize is the only identifier normaliser (G6): every lookup, uniqueness check, limiter key and
// identifier scope uses its result. A value containing '@' is an email: NFKC, a dot-atom local part
// lower-cased, and a domain folded to its lower-case IDNA A-label. A value starting with '+' is a
// phone number: NFKC, separators removed, E.164. Anything else returns identity.ErrInvalidIdentifier.
func Normalize(raw string) (identity.Identifier, error) {
	s := strings.TrimSpace(norm.NFKC.String(raw))
	switch {
	case strings.Contains(s, "@"):
		return normalizeEmail(identity.IdentifierEmail, s)
	case strings.HasPrefix(s, "+"):
		return normalizePhone(s)
	}
	return identity.Identifier{}, identity.ErrInvalidIdentifier
}

// NormalizeAs is Normalize for a value that must be of kind k: an email for IdentifierEmail and
// IdentifierRecoveryEmail, a phone number for IdentifierPhone.
func NormalizeAs(k identity.IdentifierKind, raw string) (identity.Identifier, error) {
	s := strings.TrimSpace(norm.NFKC.String(raw))
	switch k {
	case identity.IdentifierEmail, identity.IdentifierRecoveryEmail:
		return normalizeEmail(k, s)
	case identity.IdentifierPhone:
		return normalizePhone(s)
	}
	return identity.Identifier{}, identity.ErrInvalidIdentifier
}

// Normalizer adapts Normalize to httpx.IdentifierNormalizer, so the preamble keys the
// per-identifier limiter on the normalised identifier.
type Normalizer struct{}

func (Normalizer) Normalize(raw string) (identity.Identifier, error) { return Normalize(raw) }

func normalizeEmail(k identity.IdentifierKind, s string) (identity.Identifier, error) {
	if len(s) > identity.MaxIdentifierLen || !utf8.ValidString(s) {
		return identity.Identifier{}, identity.ErrInvalidIdentifier
	}
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		return identity.Identifier{}, identity.ErrInvalidIdentifier
	}
	local, domain := s[:at], s[at+1:]
	if !dotAtom(local) {
		return identity.Identifier{}, identity.ErrInvalidIdentifier
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil || !hostname(ascii) {
		return identity.Identifier{}, identity.ErrInvalidIdentifier
	}
	return identity.NewIdentifier(k, strings.ToLower(local)+"@"+ascii)
}

func dotAtom(local string) bool {
	if local == "" || len(local) > maxLocalPart || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for _, r := range local {
		switch {
		case r == '.', r < utf8.RuneSelf && (isASCIIAlnum(r) || strings.ContainsRune(atext, r)):
		case r >= utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)):
		default:
			return false
		}
	}
	return true
}

func hostname(d string) bool {
	if d == "" || len(d) > maxDomain {
		return false
	}
	for label := range strings.SplitSeq(d, ".") {
		if label == "" || len(label) > maxLabel || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && !isASCIIAlnum(r) {
				return false
			}
			if r >= 'A' && r <= 'Z' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func normalizePhone(s string) (identity.Identifier, error) {
	if len(s) > identity.MaxIdentifierLen {
		return identity.Identifier{}, identity.ErrInvalidIdentifier
	}
	digits, ok := strings.CutPrefix(s, "+")
	if !ok {
		return identity.Identifier{}, identity.ErrInvalidIdentifier
	}
	var b strings.Builder
	b.WriteByte('+')
	for _, r := range digits {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case strings.ContainsRune(phoneMarks, r):
		default:
			return identity.Identifier{}, identity.ErrInvalidIdentifier
		}
	}
	return identity.NewIdentifier(identity.IdentifierPhone, b.String())
}

// ScopeKey keys the identifier scope of ceremony records: HMAC-SHA256 under a subkey of the
// deployment data key, so a read of the ceremony table does not reveal which identifiers have
// pending registrations or sign-in links. It is immutable and safe for concurrent use.
type ScopeKey struct {
	key []byte
}

// NewScopeKey derives the scope subkey from the 32-byte deployment data key with HKDF-SHA256
// (info "egauth/identifier-scope/v1"). It returns ErrInvalidScopeKey for any other length.
func NewScopeKey(dataKey []byte) (ScopeKey, error) {
	if len(dataKey) != scopeKeyBytes {
		return ScopeKey{}, ErrInvalidScopeKey
	}
	k, err := hkdf.Key(sha256.New, dataKey, nil, scopeKeyInfo, sha256.Size)
	if err != nil {
		return ScopeKey{}, errors.Join(ErrInvalidScopeKey, err)
	}
	return ScopeKey{key: k}, nil
}

// Scope returns the ceremony scope of id. It returns ErrInvalidScopeKey for the zero ScopeKey and
// identity.ErrInvalidIdentifier for the zero Identifier.
func (k ScopeKey) Scope(id identity.Identifier) (ceremony.Scope, error) {
	if len(k.key) == 0 {
		return ceremony.Scope{}, ErrInvalidScopeKey
	}
	if id.IsZero() {
		return ceremony.Scope{}, identity.ErrInvalidIdentifier
	}
	mac := hmac.New(sha256.New, k.key)
	mac.Write([]byte{byte(id.Kind())})
	mac.Write([]byte(id.Value()))
	return ceremony.IdentifierScope(mac.Sum(nil))
}

func (k ScopeKey) String() string { return "identitysvc.ScopeKey{REDACTED}" }

func (k ScopeKey) GoString() string { return k.String() }

func (k ScopeKey) LogValue() slog.Value { return slog.StringValue(k.String()) }
