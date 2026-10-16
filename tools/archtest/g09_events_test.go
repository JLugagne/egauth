package archtest_test

import (
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g09 = "github.com/JLugagne/egauth/tools/archtest/testdata/g09/root"

func g09Reserved() []archtest.Exemption {
	return []archtest.Exemption{
		{Guard: archtest.G09, Symbol: g09 + "/event.Reserved", RemovedBy: archtest.Permanent},
		{Guard: archtest.G09, Symbol: g09 + "/event.ReservedEmitted", RemovedBy: archtest.Permanent},
	}
}

func TestG09FixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g09")
	got := archtest.CheckG09(ws, cfg, g09Reserved())
	assertFires(t, got,
		[]string{g09 + "/event.Orphan", g09 + "/event.HelperUnused", g09 + "/event.TestOnly", g09 + "/event.ReservedEmitted", g09 + "/event.NoSeverity", g09 + "/event.Filtered"},
		[]string{g09 + "/event.Emitted", g09 + "/event.Wrapped", g09 + "/event.ViaHelper", g09 + "/event.Reserved"})
}

func TestG09MessagesNameTheDefect(t *testing.T) {
	ws, cfg := fixture(t, "g09")
	msgs := map[string]string{}
	for _, v := range archtest.CheckG09(ws, cfg, g09Reserved()) {
		msgs[v.Symbols[0]] = v.Msg
	}
	for symbol, want := range map[string]string{
		g09 + "/event.Orphan":          "no non-test audit emit site",
		g09 + "/event.ReservedEmitted": "has an emitter",
		g09 + "/event.NoSeverity":      "Severity case",
	} {
		if !strings.Contains(msgs[symbol], want) {
			t.Errorf("%s: message %q does not contain %q", symbol, msgs[symbol], want)
		}
	}
}

func TestG09ReservedEntryCoversAnUnemittedType(t *testing.T) {
	ws, cfg := fixture(t, "g09")
	reserved := append(g09Reserved(), archtest.Exemption{Guard: archtest.G09, Symbol: g09 + "/event.Orphan", RemovedBy: archtest.Permanent})
	assertFires(t, archtest.CheckG09(ws, cfg, reserved), nil, []string{g09 + "/event.Orphan"})
}

func TestG09Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	l := archtest.G09Exemptions()
	assertWorkspaceClean(t, archtest.CheckG09(ws, archtest.DefaultConfig(), l.Entries), l)
}
