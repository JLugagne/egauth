package archtest

import (
	"slices"
	"strings"
)

// GuardID names a static guard such as "G01".
type GuardID string

// WorkPackage names the work package or release that removes an exemption.
type WorkPackage string

// Work packages and releases that may be named by an exemption.
const (
	WP4       WorkPackage = "WP4"
	WP5       WorkPackage = "WP5"
	WP7       WorkPackage = "WP7"
	WP16      WorkPackage = "WP16"
	WPV018    WorkPackage = "v0.18"
	Permanent WorkPackage = "permanent"
)

// KnownWorkPackages returns every WorkPackage an exemption may name in RemovedBy; G20 rejects any
// other value.
func KnownWorkPackages() []WorkPackage {
	return []WorkPackage{WP4, WP5, WP7, WP16, WPV018, Permanent}
}

var guardCatalog = []GuardID{
	"G01", "G02", "G03", "G04", "G05", "G06", "G07a", "G07b", "G08", "G09", "G10", "G11", "G12",
	"G13", "G14", "G15", "G16", "G17", "G18", "G19", "G21", "G22", "G23", "G24", "G25", "G26",
	"G27", "G28", "G29",
}

// KnownGuards returns the guard IDs of DESIGN.md section 9 that may carry exemptions, spelled as
// every guard constant must spell them (two digits, "G07a"/"G07b" for the split G7). G20 rejects an
// exemption or a list naming any other ID.
func KnownGuards() []GuardID {
	out := make([]GuardID, len(guardCatalog))
	copy(out, guardCatalog)
	return out
}

// Exemption is a typed, resolvable waiver of one guard. Free text is never accepted.
//
// Symbol is either "<import path>/..." (package path prefix), an import path, or
// "<import path>.<Name>[.<Member>]" resolved through go/types; a Symbol that no longer resolves
// is reported by G20. ReliesOnAbsenceOf, when set, is an identifier that must not exist in the
// workspace for the exemption to stay valid.
type Exemption struct {
	Guard             GuardID
	Symbol            string
	ReliesOnAbsenceOf string
	RemovedBy         WorkPackage
}

// ExemptionList is the ratchet of one guard: MaxEntries must equal len(Entries), so adding an
// entry requires raising the constant in a reviewable diff and removing one requires lowering it.
type ExemptionList struct {
	Guard      GuardID
	MaxEntries int
	Entries    []Exemption
}

// Violation is one finding of a guard. Symbols are the candidate exemption symbols for it.
// Exposers are the other packages whose API reaches the offending type: a package prefix
// exemption covers the finding only when it covers Pkg and every exposer, so new API cannot
// expose a legacy type under the legacy package's exemption.
type Violation struct {
	Guard    GuardID
	Pkg      string
	Pos      string
	Symbols  []string
	Msg      string
	Exposers []string
}

func (v Violation) String() string {
	return string(v.Guard) + " " + v.Pos + " " + v.Pkg + ": " + v.Msg
}

var registry []ExemptionList

// RegisterList adds a guard's exemption list to the ratchet. It is meant to be called from init.
func RegisterList(l ExemptionList) {
	registry = append(registry, l)
}

// Lists returns every registered exemption list.
func Lists() []ExemptionList {
	out := make([]ExemptionList, len(registry))
	copy(out, registry)
	return out
}

// Covers reports whether an entry of the list exempts v: an entry naming one of its symbols, or
// package prefix entries covering v.Pkg and every one of v.Exposers.
func (l ExemptionList) Covers(v Violation) bool {
	for _, e := range l.Entries {
		if e.Guard == l.Guard && !strings.HasSuffix(e.Symbol, "/...") && slices.Contains(v.Symbols, e.Symbol) {
			return true
		}
	}
	if !l.coversPackage(v.Pkg) {
		return false
	}
	for _, p := range v.Exposers {
		if !l.coversPackage(p) {
			return false
		}
	}
	return true
}

func (l ExemptionList) coversPackage(pkgPath string) bool {
	for _, e := range l.Entries {
		if e.Guard != l.Guard {
			continue
		}
		if prefix, ok := strings.CutSuffix(e.Symbol, "/..."); ok && (pkgPath == prefix || strings.HasPrefix(pkgPath, prefix+"/")) {
			return true
		}
	}
	return false
}

func dedupe(vs []Violation) []Violation {
	index := map[string]int{}
	var out []Violation
	for _, v := range vs {
		key := string(v.Guard) + "|" + v.Pos + "|" + v.Msg
		if i, ok := index[key]; ok {
			for _, p := range v.Exposers {
				if !slices.Contains(out[i].Exposers, p) {
					out[i].Exposers = append(out[i].Exposers, p)
				}
			}
			continue
		}
		index[key] = len(out)
		v.Exposers = slices.Clone(v.Exposers)
		out = append(out, v)
	}
	return out
}

// Filter returns the violations not covered by the list, deduplicated by position and message.
func Filter(vs []Violation, l ExemptionList) []Violation {
	seen := map[string]bool{}
	var out []Violation
	for _, v := range vs {
		key := v.Pos + "|" + v.Msg
		if seen[key] || l.Covers(v) {
			continue
		}
		seen[key] = true
		out = append(out, v)
	}
	return out
}

var legacyRelPrefixes = []string{
	"webapp", "tokens", "sessions", "identity", "mfa", "passkey", "oauth", "otp", "issuance",
	"authflow", "origin", "revocation", "janitor", "health", "ratelimit", "keystore",
	"internal/loginflowtest", "internal/securitydefaults", "internal/doctest", "internal/httputil",
	"internal/safehttp",
	"adapters/pgx/identity", "adapters/pgx/sessions", "adapters/pgx/tokens", "adapters/pgx/mfa",
	"adapters/pgx/otp", "adapters/pgx/passkey", "adapters/pgx/oauth", "adapters/pgx/keystore",
	"adapters/pgx/internal/pgxmigrate",
	"e2e-security",
}

// LegacyPrefixCount is the number of legacy package prefixes of DESIGN.md section 10.1 still
// exempt. It may only decrease, down to zero at the WP16 cutover.
const LegacyPrefixCount = 31

// LegacyRelPrefixes returns the legacy package prefixes, relative to the module path, that are
// exempt until WP16.
func LegacyRelPrefixes() []string {
	out := make([]string, len(legacyRelPrefixes))
	copy(out, legacyRelPrefixes)
	return out
}

// LegacyExemptions returns the strangler exemptions of section 10.1 for one guard, removed by WP16.
// Any guard may register them: they are ratcheted centrally by LegacyRelPrefixes, never by a
// baseline line.
func LegacyExemptions(g GuardID) []Exemption {
	out := make([]Exemption, 0, len(legacyRelPrefixes))
	for _, rel := range legacyRelPrefixes {
		out = append(out, Exemption{Guard: g, Symbol: ModulePath + "/" + rel + "/...", RemovedBy: WP16})
	}
	return out
}

// IsLegacy reports whether e is one of the LegacyExemptions of its guard.
func IsLegacy(e Exemption) bool {
	if e.RemovedBy != WP16 || e.ReliesOnAbsenceOf != "" {
		return false
	}
	rel, ok := strings.CutPrefix(e.Symbol, ModulePath+"/")
	if !ok {
		return false
	}
	rel, ok = strings.CutSuffix(rel, "/...")
	return ok && slices.Contains(legacyRelPrefixes, rel)
}
