package archtest

import (
	"slices"
	"strings"
)

// G20 is the guard that keeps exemptions honest.
const G20 GuardID = "G20"

// CheckG20 rejects exemptions whose Symbol does not resolve, whose ReliesOnAbsenceOf exists, whose
// RemovedBy is not one of KnownWorkPackages, whose guard is not one of KnownGuards, or that sit in
// a list of another guard. A "<path>/..." prefix must name a loaded package at <path> and may not
// cover the root of a loaded module, so a prefix can never waive a whole module or a bare directory.
func CheckG20(ws *Workspace, lists []ExemptionList) []Violation {
	var out []Violation
	guards := KnownGuards()
	wps := KnownWorkPackages()
	for _, l := range lists {
		if !slices.Contains(guards, l.Guard) {
			out = append(out, Violation{Guard: G20, Pkg: string(l.Guard), Pos: string(l.Guard), Msg: "exemption list of unknown guard " + string(l.Guard)})
		}
		for _, e := range l.Entries {
			add := func(msg string) {
				out = append(out, Violation{Guard: G20, Pkg: string(l.Guard), Pos: string(l.Guard) + ":" + e.Symbol, Msg: msg})
			}
			if e.Guard != l.Guard {
				add("exemption of " + string(e.Guard) + " sits in the list of " + string(l.Guard))
			}
			if !slices.Contains(guards, e.Guard) {
				add("exemption names unknown guard " + string(e.Guard))
			}
			if e.RemovedBy == "" {
				add("exemption has no RemovedBy")
			} else if !slices.Contains(wps, e.RemovedBy) {
				add("exemption has unknown RemovedBy " + string(e.RemovedBy))
			}
			if prefix, ok := strings.CutSuffix(e.Symbol, "/..."); ok {
				if ws.Package(prefix) == nil {
					add("prefix exemption has no package at " + prefix)
				}
				for _, mod := range ws.moduleRoots() {
					if within(mod, prefix) {
						add("prefix exemption covers module " + mod)
					}
				}
			}
			if err := ws.ResolveSymbol(e.Symbol); err != nil {
				add("stale exemption: " + err.Error())
			}
			if e.ReliesOnAbsenceOf != "" && ws.HasIdentifier(e.ReliesOnAbsenceOf) {
				add("ReliesOnAbsenceOf " + e.ReliesOnAbsenceOf + " now exists")
			}
		}
	}
	return out
}
