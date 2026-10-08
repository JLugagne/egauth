// Package configcheck is the single parser and validator of `egauth` struct tags (DESIGN §3.2). The
// composition object's New and the G5 guard both use it, so a tag predicate that New does not
// enforce cannot exist.
//
// Grammar, comma separated, each key at most once:
//
//	requirement (exactly one): required | optional | default=<key> | module=<Path>|<Path>...
//	predicates:                nonempty | origin | path | token | provider | external |
//	                           oneof_primary | bound=max:<duration> | bound=le:<FieldPath> |
//	                           each=<predicate>
package configcheck

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TagName is the struct tag key read by this package.
const TagName = "egauth"

// ErrGrammar is joined into every error ParseTag returns.
var ErrGrammar = errors.New("configcheck: invalid egauth tag")

// Requirement says when a field must be set.
type Requirement uint8

const (
	// Required fields must be non-zero and pass every predicate.
	Required Requirement = iota + 1
	// Optional fields are checked only when non-zero.
	Optional
	// Defaulted fields take the registry value named by Tag.Default when zero.
	Defaulted
	// ModuleDependent fields are required exactly when one of Tag.Modules is enabled.
	ModuleDependent
)

// PredicateKind names a predicate of the grammar.
type PredicateKind uint8

const (
	// NonEmpty rejects a blank string and an empty slice, nil included.
	NonEmpty PredicateKind = iota + 1
	// Origin requires an exact https origin (http only on loopback), with at most one whole
	// {tenant} host label and a host already in the form browsers send in the Origin header.
	Origin
	// Path requires an absolute path with no trailing slash, empty or dot segment, and only
	// unreserved characters.
	Path
	// Token requires 1 to 32 characters of [a-z0-9_-], starting with a letter or digit.
	Token
	// Provider delegates to Options.Provider.
	Provider
	// External delegates to Options.External.
	External
	// OneOfPrimary requires one of Options.Primary to be enabled; it is valid only on the
	// Options.Modules field.
	OneOfPrimary
	// BoundMax requires a duration in (0, Max], or up to Options.Raised for the field.
	BoundMax
	// BoundLE requires a duration in (0, value of Ref], Ref being relative to the enclosing struct.
	BoundLE
	// Each applies Elem to every element of a slice or array.
	Each
)

var predicateKeywords = [...]string{
	NonEmpty:     "nonempty",
	Origin:       "orig" + "in",
	Path:         "path",
	Token:        "token",
	Provider:     "provider",
	External:     "external",
	OneOfPrimary: "oneof_primary",
	BoundMax:     "bound=max",
	BoundLE:      "bound=le",
	Each:         "each",
}

// String returns the grammar keyword of k, without the argument of bound= and each=.
func (k PredicateKind) String() string {
	if k < NonEmpty || k > Each {
		return "PredicateKind(" + strconv.Itoa(int(k)) + ")"
	}
	return predicateKeywords[k]
}

// Predicate is one parsed predicate.
type Predicate struct {
	Kind PredicateKind
	Max  time.Duration
	Ref  string
	Elem *Predicate
}

// Tag is a parsed egauth tag.
type Tag struct {
	Requirement Requirement
	Default     string
	Modules     []string
	Predicates  []Predicate
}

var (
	defaultKey = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	fieldPath  = regexp.MustCompile(`^[A-Z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*$`)
)

// ParseTag parses raw. Every error wraps ErrGrammar.
func ParseTag(raw string) (Tag, error) {
	var t Tag
	if raw == "" {
		return t, grammar("empty tag")
	}
	seen := map[PredicateKind]bool{}
	for _, tok := range strings.Split(raw, ",") {
		if tok == "" {
			return Tag{}, grammar("empty key in " + quote(raw))
		}
		isReq, err := parseRequirement(&t, tok)
		if err != nil {
			return Tag{}, err
		}
		if isReq {
			continue
		}
		p, err := parsePredicate(tok, false)
		if err != nil {
			return Tag{}, err
		}
		if seen[p.Kind] {
			return Tag{}, grammar("duplicate predicate " + quote(tok))
		}
		seen[p.Kind] = true
		t.Predicates = append(t.Predicates, p)
	}
	if t.Requirement == 0 {
		return Tag{}, grammar("no requirement (required, optional, default= or module=) in " + quote(raw))
	}
	return t, nil
}

func parseRequirement(t *Tag, tok string) (bool, error) {
	var r Requirement
	switch {
	case tok == "required":
		r = Required
	case tok == "optional":
		r = Optional
	case strings.HasPrefix(tok, "default="):
		key := strings.TrimPrefix(tok, "default=")
		if !defaultKey.MatchString(key) {
			return false, grammar("invalid default key " + quote(key))
		}
		r, t.Default = Defaulted, key
	case strings.HasPrefix(tok, "module="):
		paths, err := parseModules(strings.TrimPrefix(tok, "module="))
		if err != nil {
			return false, err
		}
		r, t.Modules = ModuleDependent, paths
	default:
		return false, nil
	}
	if t.Requirement != 0 {
		return false, grammar("more than one requirement at " + quote(tok))
	}
	t.Requirement = r
	return true, nil
}

func parseModules(raw string) ([]string, error) {
	paths := strings.Split(raw, "|")
	seen := map[string]bool{}
	for _, p := range paths {
		if !fieldPath.MatchString(p) {
			return nil, grammar("invalid module path " + quote(p))
		}
		if seen[p] {
			return nil, grammar("duplicate module path " + quote(p))
		}
		seen[p] = true
	}
	return paths, nil
}

func parsePredicate(tok string, nested bool) (Predicate, error) {
	for k := NonEmpty; k <= OneOfPrimary; k++ {
		if tok != k.String() {
			continue
		}
		if nested && k == OneOfPrimary {
			return Predicate{}, grammar("oneof_primary cannot be applied to elements")
		}
		return Predicate{Kind: k}, nil
	}
	switch {
	case strings.HasPrefix(tok, "each="):
		if nested {
			return Predicate{}, grammar("nested each= in " + quote(tok))
		}
		inner, err := parsePredicate(strings.TrimPrefix(tok, "each="), true)
		if err != nil {
			return Predicate{}, err
		}
		return Predicate{Kind: Each, Elem: &inner}, nil
	case strings.HasPrefix(tok, "bound=max:"):
		d, err := time.ParseDuration(strings.TrimPrefix(tok, "bound=max:"))
		if err != nil {
			return Predicate{}, errors.Join(grammar("invalid bound "+quote(tok)), err)
		}
		if d <= 0 {
			return Predicate{}, grammar("bound must be positive in " + quote(tok))
		}
		return Predicate{Kind: BoundMax, Max: d}, nil
	case strings.HasPrefix(tok, "bound=le:"):
		ref := strings.TrimPrefix(tok, "bound=le:")
		if !fieldPath.MatchString(ref) {
			return Predicate{}, grammar("invalid field path in " + quote(tok))
		}
		return Predicate{Kind: BoundLE, Ref: ref}, nil
	}
	return Predicate{}, grammar("unknown key " + quote(tok))
}

func grammar(problem string) error {
	return errors.Join(ErrGrammar, errors.New(problem))
}

func quote(s string) string {
	return `"` + s + `"`
}
