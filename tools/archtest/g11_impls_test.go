package archtest_test

import (
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g11 = "github.com/JLugagne/egauth/tools/archtest/testdata/g11/root"

func g11Msgs(t *testing.T) map[string][]string {
	t.Helper()
	ws, cfg := fixture(t, "g11")
	out := map[string][]string{}
	for _, v := range archtest.CheckG11(ws, cfg) {
		out[v.Symbols[0]] = append(out[v.Symbols[0]], v.Msg)
	}
	return out
}

func hasMsg(msgs []string, part string) bool {
	for _, m := range msgs {
		if strings.Contains(m, part) {
			return true
		}
	}
	return false
}

func TestG11FixtureFires(t *testing.T) {
	got := g11Msgs(t)
	if m := got[g11+"/store/foo/lazy.Lazy"]; !hasMsg(m, "var _") || hasMsg(m, "Run suite") {
		t.Errorf("a missing assertion line alone must be reported: %v", m)
	}
	if m := got[g11+"/store/foo/norun.Norun"]; !hasMsg(m, "Run suite") || hasMsg(m, "var _") {
		t.Errorf("a missing suite call alone must be reported: %v", m)
	}
	if m := got[g11+"/store/foo/wrongtype.Wrongtype"]; !hasMsg(m, "Run suite") {
		t.Errorf("a suite fed an interface-typed expression must not count: %v", m)
	}
	if m := got[g11+"/store/bar/impl.Bar"]; !hasMsg(m, "var _") || !hasMsg(m, "Run suite") {
		t.Errorf("both obligations must be reported: %v", m)
	}
	if m := got[g11+"/store/bar.Store"]; !hasMsg(m, "no Run suite") {
		t.Errorf("an implemented interface without any suite must be reported once: %v", m)
	}
	if m := got[g11+"/kek/local.Local"]; !hasMsg(m, "var _") || !hasMsg(m, "Run suite") {
		t.Errorf("kek.KEK implementations carry both obligations: %v", m)
	}
	if m := got[g11+"/internal/session/stateful.Stateful"]; !hasMsg(m, "Run suite") || hasMsg(m, "var _") {
		t.Errorf("a Backend must be passed to backendtest.Run and needs no assertion line: %v", m)
	}
}

func TestG11CompliantImplementationsAreClean(t *testing.T) {
	got := g11Msgs(t)
	for _, sym := range []string{
		g11 + "/store/foo/memory.Memory", g11 + "/internal/session/jwt.Jwt", g11 + "/store/foo.Store",
		g11 + "/internal/session.Backend",
	} {
		if m := got[sym]; len(m) != 0 {
			t.Errorf("%s must be clean: %v", sym, m)
		}
	}
}

func TestG11Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG11(ws, archtest.DefaultConfig()), archtest.G11Exemptions())
}
