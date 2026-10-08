package archtest_test

import "testing"

func TestG11AssertionMustLiveInTheImplementationPackage(t *testing.T) {
	if m := g11Msgs(t)[g11+"/store/foo/plain.Plain"]; !hasMsg(m, "var _") || hasMsg(m, "Run suite") {
		t.Errorf("an assertion that only exists in a test file does not count: %v", m)
	}
}

func TestG11GenericImplementationsHaveObligations(t *testing.T) {
	if m := g11Msgs(t)[g11+"/store/foo/gen.Gen"]; !hasMsg(m, "var _") || !hasMsg(m, "Run suite") {
		t.Errorf("a generic implementation carries both obligations: %v", m)
	}
}

func TestG11OnlyTheInterfaceSuiteCounts(t *testing.T) {
	if m := g11Msgs(t)[g11+"/store/foo/fake.Fake"]; !hasMsg(m, "Run suite") || hasMsg(m, "var _") {
		t.Errorf("a Run of an unrelated *test package is not the storetest suite: %v", m)
	}
}

func TestG11OnlyTheFinalReturnIsCredited(t *testing.T) {
	if m := g11Msgs(t)[g11+"/store/foo/dead.Dead"]; !hasMsg(m, "Run suite") {
		t.Errorf("an implementation returned only from a dead branch is not passed to the suite: %v", m)
	}
	if m := g11Msgs(t)[g11+"/store/foo/memory.Memory"]; len(m) != 0 {
		t.Errorf("the final return of the suite literal is credited: %v", m)
	}
}
