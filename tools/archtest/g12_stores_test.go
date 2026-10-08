package archtest_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g12 = "github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"

func TestG12FixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g12")
	vs := archtest.CheckG12(ws, cfg)
	assertFires(t, vs,
		[]string{g12 + "/nobase.Store", g12 + "/noreaper.Store", g12 + "/noerase.Store"},
		[]string{g12 + "/good.Store", g12 + "/erasing.Store", g12 + "/nested.Store"})
	want := map[string]string{
		g12 + "/nobase.Store":   "store.Base",
		g12 + "/noreaper.Store": "store.Reaper",
		g12 + "/noerase.Store":  "DeleteForSubject",
		g12 + "/account.Store":  "DeleteForSubject",
		g12 + "/owned.Store":    "DeleteForSubject",
	}
	for _, v := range vs {
		if slices.ContainsFunc([]string{"/rawuser.Store", "/chans.Store", "/foreign.Store", "/unnamed.Store"}, func(s string) bool { return strings.HasSuffix(v.Symbols[0], s) }) {
			continue
		}
		if w, ok := want[v.Symbols[0]]; !ok || !strings.Contains(v.Msg, w) {
			t.Errorf("unexpected message for %s: %s", v.Symbols[0], v.Msg)
		}
	}
}

func TestG12Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG12(ws, archtest.DefaultConfig()), archtest.G12Exemptions())
}
