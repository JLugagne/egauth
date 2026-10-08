package archtest_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g06 = "github.com/JLugagne/egauth/tools/archtest/testdata/g06/root"

func g06Findings(t *testing.T) map[string][]string {
	t.Helper()
	ws, cfg := fixture(t, "g06")
	out := map[string][]string{}
	for _, v := range archtest.CheckG06(ws, cfg) {
		row, _, _ := strings.Cut(v.Msg, ":")
		out[row] = append(out[row], v.Pkg+" "+v.Msg)
	}
	return out
}

func TestG06FixtureFires(t *testing.T) {
	got := g06Findings(t)
	wantRows := map[string]int{
		"cookie": 2, "clientaddr": 2, "httpx": 6, "csrf": 2, "outbound": 7, "ctxvalue": 7, "kek": 10,
		"audit": 2, "producers": 3, "renew": 1, "unseal": 1, "accountstate": 1, "verified": 1,
		"backendstart": 4, "backendreissue": 1, "clock": 2, "jwt": 7, "redirect": 1, "newrecords": 1,
		"restore": 1, "fortest": 1, "normalise": 1, "totp": 1,
	}
	for row, n := range wantRows {
		if len(got[row]) != n {
			t.Errorf("row %s: want %d findings, got %d: %v", row, n, len(got[row]), got[row])
		}
	}
}

func TestG06OwnersAndDefiningPackagesAreClean(t *testing.T) {
	ws, cfg := fixture(t, "g06")
	for _, v := range archtest.CheckG06(ws, cfg) {
		if !strings.HasSuffix(v.Pkg, "/root/app") && !strings.HasSuffix(v.Pkg, "/root/event") && !strings.Contains(v.Pkg, "/root/structural/") && v.Pkg != g06 {
			t.Errorf("owner or declaring package flagged: %s", v)
		}
	}
}

func TestG06SymbolOwnerIsOneFunction(t *testing.T) {
	ws, cfg := fixture(t, "g06")
	assertFires(t, archtest.CheckG06(ws, cfg), []string{g06 + ".Sneaky"}, []string{g06 + ".UpgradeSecretsV016"})
}

func TestG06LiteralsOutsideOwnerFire(t *testing.T) {
	ws, cfg := fixture(t, "g06")
	assertFires(t, archtest.CheckG06(ws, cfg), []string{g06 + "/event.KeyAMR", g06 + "/app.Libs"}, []string{g06 + "/internal/session/jwt.claim"})
}

func TestG06TableIsPinned(t *testing.T) {
	var ids []string
	for _, r := range archtest.OwnerRows() {
		ids = append(ids, r.ID)
		if len(r.Owners) == 0 {
			t.Errorf("row %s has no owner", r.ID)
		}
	}
	want := []string{
		"cookie", "clientaddr", "httpx", "csrf", "outbound", "ctxvalue", "kek", "audit", "producers",
		"renew", "unseal", "accountstate", "verified", "backendstart", "backendreissue", "clock", "jwt",
		"redirect", "newrecords", "restore", "fortest", "normalise", "totp",
	}
	if !slices.Equal(ids, want) {
		t.Fatalf("the single-owner table is fixed by DESIGN.md section 9.2: %v", ids)
	}
}

func TestG06Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG06(ws, archtest.DefaultConfig()), archtest.G06Exemptions())
}
