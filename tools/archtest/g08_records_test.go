package archtest_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g08 = "github.com/JLugagne/egauth/tools/archtest/testdata/g08/root"

func TestG08ForwardFires(t *testing.T) {
	ws, cfg := fixture(t, "g08")
	assertFires(t, archtest.CheckG08(ws, cfg),
		[]string{g08 + "/store/tokens.BadRecord", g08 + "/store/ceremony.Record"},
		[]string{
			g08 + "/store/tokens.RefreshRecord", g08 + "/store/tokens.APIKey", g08 + "/store/tokens.Filter",
			g08 + "/store/sessions.Record",
		})
}

func TestG08InverseFires(t *testing.T) {
	ws, cfg := fixture(t, "g08")
	want := []string{
		g08 + "/events.Session.AMR", g08 + "/events.Session.RememberMe", g08 + "/events.Session.Epoch",
		g08 + "/events.Login.AuthTime", g08 + "/events.Login.MustChangePassword", g08 + "/events.Login.Interim",
		g08 + "/events.Login.ReturnTo", g08 + "/events.Login.Factors",
	}
	assertFires(t, archtest.CheckG08(ws, cfg), want,
		[]string{g08 + "/events.Session.Name", g08 + "/events.clean.AMR", g08 + "/events.Clean.Amr", g08 + "/internal/hidden.Session.AMR"})
}

func TestG08SealedFreeRecordsArePinned(t *testing.T) {
	got := archtest.SealedFreeRecords()
	if len(got) != 1 || got[0] != (archtest.RecordType{Rel: "store/tokens", Name: "APIKey"}) {
		t.Fatalf("only tokens.APIKey is listed by type: %v", got)
	}
	if len(archtest.ForbiddenRecordFields()) != 8 {
		t.Fatalf("the inverse field list is fixed by DESIGN.md section 9.2: %v", archtest.ForbiddenRecordFields())
	}
}

func TestG08Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG08(ws, archtest.DefaultConfig()), archtest.G08Exemptions())
}
