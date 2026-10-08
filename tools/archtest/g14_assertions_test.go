package archtest_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g14 = "github.com/JLugagne/egauth/tools/archtest/testdata/g14/root"

func TestG14FixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g14")
	vs := archtest.CheckG14(ws, cfg)
	assertFires(t, vs,
		[]string{
			g14 + ".Sniff", g14 + ".Switch", g14 + ".Flush", g14 + ".Target", "fmt.Stringer", "error",
		},
		[]string{g14 + ".Concrete", g14 + ".ConcreteTarget", g14 + ".Generic", g14 + ".sniffInTest"})
}

func TestG14TypedExemptionsCoverTargets(t *testing.T) {
	ws, cfg := fixture(t, "g14")
	vs := archtest.CheckG14(ws, cfg)
	list := archtest.ExemptionList{Guard: archtest.G14, Entries: []archtest.Exemption{
		{Guard: archtest.G14, Symbol: "net/http.Flusher", RemovedBy: archtest.Permanent},
		{Guard: archtest.G14, Symbol: "errors.As", RemovedBy: archtest.Permanent},
	}}
	left := archtest.Filter(vs, list)
	got := symbols(left)
	if got[g14+".Flush"] || got[g14+".Target"] {
		t.Errorf("typed exemptions did not cover Flusher and errors.As: %v", left)
	}
	if !got[g14+".Sniff"] || !got[g14+".Switch"] {
		t.Errorf("unrelated assertions must stay reported: %v", left)
	}
}

func TestG14Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG14(ws, archtest.DefaultConfig()), archtest.G14Exemptions())
}

func TestG14GenericInstantiations(t *testing.T) {
	ws, cfg := fixture(t, "g14")
	vs := archtest.CheckG14(ws, cfg)
	assertFires(t, vs,
		[]string{
			g14 + ".SniffGeneric", g14 + ".SniffChain", g14 + ".SniffBox", g14 + ".SniffSwitch",
			g14 + ".SniffAsTarget", g14 + ".SniffAsType",
		},
		[]string{
			g14 + ".ConcreteGeneric", g14 + ".ConcreteChain", g14 + ".ConcreteAsType", g14 + ".NoAssert",
			g14 + ".as", g14 + ".viaChain", g14 + ".box.get", g14 + ".switcher", g14 + ".asTarget",
		})
	list := archtest.ExemptionList{Guard: archtest.G14, Entries: []archtest.Exemption{
		{Guard: archtest.G14, Symbol: "errors.As", RemovedBy: archtest.Permanent},
	}}
	left := symbols(archtest.Filter(vs, list))
	if left[g14+".SniffAsType"] || left[g14+".SniffAsTarget"] {
		t.Errorf("errors.AsType and generic errors.As targets must be covered by the errors.As entry: %v", left)
	}
	if !left[g14+".SniffGeneric"] {
		t.Errorf("generic assertions must stay reported: %v", left)
	}
}
