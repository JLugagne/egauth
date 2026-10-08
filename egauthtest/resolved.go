package egauthtest

import (
	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/configcheck"
)

// Resolution is the read-only view of a configuration after the defaults registry was applied.
type Resolution struct {
	r        *configcheck.Resolved
	problems []string
}

// Resolved applies the library defaults to a copy of cfg without building an Auth, so a test can
// read back that a default took effect. Paths are dotted field names with [i] for elements, for
// example "Policy.IdleTimeout" or "Modules.APIKeys.Kinds[0]".
func Resolved[C any](cfg egauth.Config[C]) Resolution {
	r, errs := egauth.TestHookResolve(cfg)
	problems := make([]string, len(errs))
	for i, e := range errs {
		problems[i] = e.Field + ": " + e.Problem
	}
	return Resolution{r: r, problems: problems}
}

// Get returns the value at path after defaults, and false for an unknown path.
func (r Resolution) Get(path string) (any, bool) { return r.r.Get(path) }

// Defaulted reports whether the field at path was filled from the defaults registry.
func (r Resolution) Defaulted(path string) bool { return r.r.Defaulted(path) }

// Applied returns the sorted paths filled from the defaults registry.
func (r Resolution) Applied() []string { return r.r.Applied() }

// Problems returns every validation failure as "<field>: <problem>".
func (r Resolution) Problems() []string { return append([]string(nil), r.problems...) }
