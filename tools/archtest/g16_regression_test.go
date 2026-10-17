package archtest_test

import (
	"strings"
	"testing"
)

func g16RegFindings(t *testing.T, version, module string) string {
	t.Helper()
	var out []string
	for sym, msgs := range g16Findings(t, version) {
		if strings.HasSuffix(sym, "/reg.module"+module) {
			out = append(out, msgs...)
		}
	}
	return joined(out)
}

func TestG16RegisteredFSMustBeAnEmbeddedMigrationsFS(t *testing.T) {
	if m := g16RegFindings(t, "0.17.0", "Conv"); !strings.Contains(m, "nil-FS stub") {
		t.Errorf("a converted nil FS is a stub: %q", m)
	}
	if m := g16RegFindings(t, "0.17.0-dev", "Conv"); m != "" {
		t.Errorf("a converted nil FS is an allowed stub while -dev: %q", m)
	}
	for _, version := range []string{"0.17.0", "0.17.0-dev"} {
		for _, module := range []string{"Empty", "Dir"} {
			if m := g16RegFindings(t, version, module); !strings.Contains(m, "not an embedded migrations FS") {
				t.Errorf("%s at %s: a non-embedded FS must be reported: %q", module, version, m)
			}
		}
	}
}

func TestG16DOBlocksAreStructurallyGuarded(t *testing.T) {
	m := joined(g16Findings(t, "0.17.0-dev")[g16+"/dirty.FS"])
	for line := 1; line <= 5; line++ {
		if want := "002_do.sql:" + string(rune('0'+line)) + " DO block"; !strings.Contains(m, want) {
			t.Errorf("missing %q in:\n%s", want, m)
		}
	}
}

func TestG16EscapeStringCannotHideADrop(t *testing.T) {
	m := joined(g16Findings(t, "0.17.0-dev")[g16+"/dirty.FS"])
	if !strings.Contains(m, "002_do.sql:6 DROP is forbidden") {
		t.Errorf("a DROP after an E'\\'' escape string must be seen:\n%s", m)
	}
}

func TestG16AllowlistHasNoFalsePositives(t *testing.T) {
	if m := g16Findings(t, "0.17.0-dev")[g16+"/good.FS"]; len(m) != 0 {
		t.Errorf("a compliant FS must be clean: %v", m)
	}
}

func TestG16FieldAssignedFSIsChecked(t *testing.T) {
	got := g16Findings(t, "0.17.0")
	if m := joined(got[g16+"/side.Side"]); !strings.Contains(m, "outside register_*.go") {
		t.Errorf("an FS assigned to a Module field outside register_*.go must be reported: %q", m)
	}
	if m := joined(got[g16+"/side.Converted"]); !strings.Contains(m, "conversion to migrate.Module") {
		t.Errorf("a conversion to migrate.Module must be reported: %q", m)
	}
	if m := g16RegFindings(t, "0.17.0-dev", "Assign"); !strings.Contains(m, "not an embedded migrations FS") {
		t.Errorf("an FS assigned in register_*.go must be an embedded migrations FS: %q", m)
	}
}

func TestG16DOBlocksCannotSwallowOrCallFunctions(t *testing.T) {
	m := joined(g16Findings(t, "0.17.0-dev")[g16+"/dirty.FS"])
	for line := 1; line <= 7; line++ {
		if want := "003_swallow.sql:" + string(rune('0'+line)) + " "; !strings.Contains(m, want) {
			t.Errorf("missing a finding at %q in:\n%s", want, m)
		}
	}
}

func TestG16IndirectFieldAssignmentsAreChecked(t *testing.T) {
	got := g16Findings(t, "0.17.0")
	for _, sym := range []string{g16 + "/side.Tuple", g16 + "/side.Pointer", g16 + "/side.Ranged"} {
		if m := joined(got[sym]); !strings.Contains(m, "outside register_*.go") && !strings.Contains(m, "address of migrate.Module.FS") {
			t.Errorf("%s sets a Module FS outside register_*.go and must be reported: %q", sym, m)
		}
	}
}

func TestG16GuardSelectRejectsQuotedFunctionNames(t *testing.T) {
	m := joined(g16Findings(t, "0.17.0-dev")[g16+"/dirty.FS"])
	for _, line := range []string{"8", "9", "10"} {
		if want := "003_swallow.sql:" + line + " DO block"; !strings.Contains(m, want) {
			t.Errorf("missing %q in:\n%s", want, m)
		}
	}
}

func TestG16CreateTableAsGluedToParenthesesAndVolatileColumnDefaultsAreRejected(t *testing.T) {
	m := joined(g16Findings(t, "0.17.0-dev")[g16+"/dirty.FS"])
	if want := "003_swallow.sql:11 CREATE TABLE ... AS"; !strings.Contains(m, want) {
		t.Errorf("missing %q in:\n%s", want, m)
	}
	if want := "003_swallow.sql:12 ADD COLUMN default calls PG_TERMINATE_BACKEND"; !strings.Contains(m, want) {
		t.Errorf("missing %q in:\n%s", want, m)
	}
}
