package archtest_test

import (
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g20 = "github.com/JLugagne/egauth/tools/archtest/testdata/g20/root"

func entry(sym, absent string, by archtest.WorkPackage) archtest.Exemption {
	return archtest.Exemption{Guard: archtest.G01, Symbol: sym, ReliesOnAbsenceOf: absent, RemovedBy: by}
}

func TestG20FixtureFires(t *testing.T) {
	ws, _ := fixture(t, "g20")
	good := []archtest.Exemption{
		entry(g20, "", archtest.WP16),
		entry(g20+".Thing", "", archtest.WP16),
		entry(g20+".Thing.Field", "", archtest.WP16),
		entry(g20+".Thing.Method", "", archtest.WP16),
		entry(g20+".Func", "", archtest.WP16),
		entry("net/http.Flusher", "", archtest.Permanent),
		entry("errors.As", "", archtest.Permanent),
		entry(g20+"/...", "", archtest.WP16),
		entry(g20+".Func", "NoSuchIdentifierAnywhere", archtest.WP16),
	}
	if vs := archtest.CheckG20(ws, []archtest.ExemptionList{{Guard: archtest.G01, MaxEntries: len(good), Entries: good}}); len(vs) != 0 {
		t.Fatalf("valid exemptions rejected: %v", vs)
	}

	bad := map[string]archtest.Exemption{
		"no such object":     entry(g20+".Missing", "", archtest.WP16),
		"no such member":     entry(g20+".Thing.Nope", "", archtest.WP16),
		"package not loaded": entry("example.invalid/pkg.X", "", archtest.WP16),
		"no package matches": entry(g20+"/gone/...", "", archtest.WP16),
		"empty symbol":       entry("", "", archtest.WP16),
		"RemovedBy":          entry(g20+".Func", "", ""),
		"ReliesOnAbsenceOf":  entry(g20+".Func", "Field", archtest.WP16),
		"ReliesOnAbsenceOf ": entry(g20+".Func", g20+".Thing", archtest.WP16),
		"unknown RemovedBy":  entry(g20+".Func", "", "someday"),
		"covers module":      entry(archtest.ModulePath+"/tools/...", "", archtest.WP16),
		"no package at":      entry(archtest.ModulePath+"/tools/archtest/testdata/g20/...", "", archtest.WP16),
	}
	for want, e := range bad {
		vs := archtest.CheckG20(ws, []archtest.ExemptionList{{Guard: archtest.G01, MaxEntries: 1, Entries: []archtest.Exemption{e}}})
		found := false
		for _, v := range vs {
			found = found || strings.Contains(v.Msg, want)
		}
		if !found {
			t.Errorf("%q: expected a violation mentioning %q, got %v", e.Symbol, want, vs)
		}
	}

	wrong := archtest.ExemptionList{Guard: archtest.G02, MaxEntries: 1, Entries: []archtest.Exemption{entry(g20+".Func", "", archtest.WP16)}}
	if vs := archtest.CheckG20(ws, []archtest.ExemptionList{wrong}); len(vs) != 1 {
		t.Errorf("an exemption in another guard's list must be rejected: %v", vs)
	}
}

func TestG20RejectsUnknownGuard(t *testing.T) {
	ws, _ := fixture(t, "g20")
	e := archtest.Exemption{Guard: "G99", Symbol: g20 + ".Func", RemovedBy: archtest.WP16}
	vs := archtest.CheckG20(ws, []archtest.ExemptionList{{Guard: "G99", MaxEntries: 1, Entries: []archtest.Exemption{e}}})
	found := 0
	for _, v := range vs {
		if strings.Contains(v.Msg, "unknown guard") {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("an unknown guard must be reported for the list and the entry: %v", vs)
	}
	misspelt := archtest.Exemption{Guard: "G7a", Symbol: g20 + ".Func", RemovedBy: archtest.Permanent}
	if vs := archtest.CheckG20(ws, []archtest.ExemptionList{{Guard: "G7a", MaxEntries: 1, Entries: []archtest.Exemption{misspelt}}}); len(vs) == 0 {
		t.Fatal("a guard ID spelt differently from the catalog must be rejected")
	}
}

func TestG20Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	for _, v := range archtest.CheckG20(ws, archtest.Lists()) {
		t.Errorf("%s", v)
	}
}
