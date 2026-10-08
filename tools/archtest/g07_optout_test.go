package archtest_test

import (
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g07 = "github.com/JLugagne/egauth/tools/archtest/testdata/g07/root"

func TestG07aFixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g07")
	assertFires(t, archtest.CheckG07a(ws, cfg),
		[]string{
			g07 + ".Config.AllowHTTP", g07 + ".Config.DisableRateLimit", g07 + ".SkipChecks", g07 + ".LegacyMode",
			g07 + ".TLSDisabled", g07 + ".Hooks.BypassAuth", g07 + ".Config.ExportPrefix",
			g07 + "/kek.LegacyOther", g07 + "/other.Options.ExportPII", g07 + "/other.Plain.ExportPII",
		},
		[]string{
			g07 + ".InsecureOptOuts", g07 + ".InsecureOptOuts.InsecureCookies", g07 + ".InsecureOptOuts.AllowHTTP",
			g07 + ".InsecureOptOuts.SkipCSRF", g07 + ".ResourceInsecure", g07 + ".ResourceInsecure.DisableAudience",
			g07 + ".Config.Insecure", g07 + ".Config.NoopLogger", g07 + ".Config.Nothing", g07 + ".Config.Name",
			g07 + ".Config.Validate", g07 + ".Hooks.Run", g07 + ".UpgradeSecretsV016",
			g07 + "/kek.LegacyOpener", g07 + "/kek.LegacyLocalV016", g07 + "/internal/x.SkipEverything",
			g07 + "/cmd/app.SkipMain", g07 + ".unexportedSkipX",
		})
}

func TestG07aEventTypeConstantsAreNotBlanketExempt(t *testing.T) {
	ws, cfg := fixture(t, "g07")
	assertFires(t, archtest.CheckG07a(ws, cfg), []string{g07 + "/event.AccountDisabled", g07 + "/event.SkipFlag"}, []string{g07 + "/event.TypeNotWritten"})
}

func TestG07aEventTypeExemptionsAreTyped(t *testing.T) {
	l := archtest.G07aExemptions()
	for _, e := range l.Entries {
		if archtest.IsLegacy(e) {
			continue
		}
		if !strings.HasPrefix(e.Symbol, archtest.ModulePath+"/event.") || strings.Contains(e.Symbol, "...") {
			t.Errorf("a G07a exemption names one event.Type constant: %v", e)
		}
	}
}

func TestG07aAllowancesArePinned(t *testing.T) {
	got := archtest.OptOutAllowances()
	want := []archtest.OptOutAllowance{
		{Rel: "adapters/otel", Name: "Options.ExportPII", RemovedBy: archtest.Permanent},
		{Rel: "kek", Name: "LegacyOpener", RemovedBy: archtest.WPV018},
		{Rel: "kek", Name: "LegacyLocalV016", RemovedBy: archtest.WPV018},
		{Rel: "", Name: "UpgradeSecretsV016", RemovedBy: archtest.WPV018},
	}
	if len(got) != len(want) {
		t.Fatalf("the typed opt-out names are fixed by DESIGN.md section 9.2: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("allowance %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

func TestG07aWorkspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG07a(ws, archtest.DefaultConfig()), archtest.G07aExemptions())
}
