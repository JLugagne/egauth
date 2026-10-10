package journeytest

import (
	"reflect"
	"slices"
	"strings"

	"github.com/JLugagne/egauth"
)

// CellExemption is the typed G20 waiver of every cell of one primary x MFA pair, on any backend,
// carrier and tenancy. Symbol names the configuration field or Auth method that makes the pair
// meaningless, and ReliesOnAbsenceOf names the identifier whose appearance would make it meaningful
// again; both are resolved by reflection (see ResolveSymbol) so that a stale exemption fails the
// guard instead of silently skipping cells.
type CellExemption struct {
	Primary           Primary
	MFA               MFA
	Symbol            string
	ReliesOnAbsenceOf string
}

const registrationSymbol = "Config.Modules.Password.Registration"

var cellExemptions = []CellExemption{
	{Primary: PrimaryRegister, MFA: MFATOTP, Symbol: registrationSymbol, ReliesOnAbsenceOf: "Config.Modules.MFA.EnrollAtRegistration"},
	{Primary: PrimaryRegister, MFA: MFARecoveryCode, Symbol: registrationSymbol, ReliesOnAbsenceOf: "Config.Modules.MFA.EnrollAtRegistration"},
	{Primary: PrimaryRegister, MFA: MFAPasskeyStepUp, Symbol: registrationSymbol, ReliesOnAbsenceOf: "Config.Modules.MFA.EnrollAtRegistration"},
}

// MaxCellExemptions is the ratchet of the matrix exemptions: adding or removing one must raise or
// lower it in the same diff.
const MaxCellExemptions = 3

// CellExemptions returns a copy of the typed exemptions of the matrix.
func CellExemptions() []CellExemption {
	return slices.Clone(cellExemptions)
}

// Exempted returns the exemption that waives c, and false when c is a valid cell.
func Exempted(c Cell) (CellExemption, bool) {
	for _, e := range cellExemptions {
		if e.Primary == c.Primary && e.MFA == c.MFA {
			return e, true
		}
	}
	return CellExemption{}, false
}

// ResolveSymbol reports whether path resolves by reflection. A path starts with "Config", resolved
// against egauth.Config, or with "Auth", resolved against *egauth.Auth; each further segment is an
// exported field or a method, and pointers, slices and maps are walked through to their element
// type. An empty segment never resolves.
func ResolveSymbol(path string) bool {
	segments := strings.Split(path, ".")
	if slices.Contains(segments, "") {
		return false
	}
	switch segments[0] {
	case "Config":
		return walkSymbol(reflect.TypeFor[egauth.Config[struct{}]](), segments[1:])
	case "Auth":
		return len(segments) > 1 && walkSymbol(reflect.TypeFor[*egauth.Auth[struct{}]](), segments[1:])
	}
	return false
}

func walkSymbol(t reflect.Type, segments []string) bool {
	if len(segments) == 0 {
		return true
	}
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	name, rest := segments[0], segments[1:]
	if t.Kind() == reflect.Struct {
		if f, ok := t.FieldByName(name); ok && f.IsExported() {
			return walkSymbol(f.Type, rest)
		}
	}
	m, ok := reflect.PointerTo(t).MethodByName(name)
	if t.Kind() == reflect.Interface {
		m, ok = t.MethodByName(name)
	}
	if !ok {
		return false
	}
	if len(rest) == 0 {
		return true
	}
	return m.Type.NumOut() > 0 && walkSymbol(m.Type.Out(0), rest)
}
