package archtest_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g10 = "github.com/JLugagne/egauth/tools/archtest/testdata/g10/root"

func TestG10FixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g10")
	assertFires(t, archtest.CheckG10(ws, cfg),
		[]string{g10 + "/app.Literal", g10 + "/app.Converted", g10 + "/app.Plain", g10 + "/event.KeyFresh"},
		[]string{g10 + "/app.Good", g10 + "/app.Other", g10 + "/app.Unclassified", g10 + "/event.KeyMethod", g10 + "/event.KeyIP"})
}

func TestG10Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG10(ws, archtest.DefaultConfig()), archtest.G10Exemptions())
}
