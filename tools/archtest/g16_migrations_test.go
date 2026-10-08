package archtest_test

import (
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g16 = "github.com/JLugagne/egauth/tools/archtest/testdata/g16/root"

func g16Findings(t *testing.T, version string) map[string][]string {
	t.Helper()
	ws, cfg := fixture(t, "g16")
	out := map[string][]string{}
	for _, v := range archtest.CheckG16(ws, cfg, version) {
		out[v.Symbols[0]] = append(out[v.Symbols[0]], v.Pos+" "+v.Msg)
	}
	return out
}

func joined(msgs []string) string { return strings.Join(msgs, "\n") }

func TestG16RegistrationFires(t *testing.T) {
	got := g16Findings(t, "0.17.0-dev")
	if m := joined(got[g16+"/orphan.FS"]); !strings.Contains(m, "orphan") {
		t.Errorf("an unregistered FS must be reported: %q", m)
	}
	if m := joined(got[g16+"/dup.FS"]); !strings.Contains(m, "registered 2 times") {
		t.Errorf("a twice-registered FS must be reported: %q", m)
	}
	if m := joined(got[g16+"/misc.FS"]); !strings.Contains(m, "outside register_*.go") || !strings.Contains(m, "orphan") {
		t.Errorf("a registration outside register_*.go does not count: %q", m)
	}
	if m := got[g16+"/good.FS"]; len(m) != 0 {
		t.Errorf("a compliant FS must be clean: %v", m)
	}
}

func TestG16SQLAllowlist(t *testing.T) {
	m := joined(g16Findings(t, "0.17.0-dev")[g16+"/dirty.FS"])
	for _, want := range []string{
		"001_create.sql:1 statement outside the idempotent allowlist: CREATE TABLE T",
		"001_create.sql:2 DROP is forbidden",
		"001_create.sql:3 ALTER TABLE action outside ADD COLUMN IF NOT EXISTS",
		"001_create.sql:4 DO block outside the guarded allowlist",
		"001_create.sql:5 statement outside the idempotent allowlist: INSERT",
		"001_create.sql:6 DROP is forbidden",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("missing %q in:\n%s", want, m)
		}
	}
}

func TestG16NilFSStubsOnlyWhileDev(t *testing.T) {
	count := func(version string) int {
		n := 0
		for sym, msgs := range g16Findings(t, version) {
			if strings.Contains(sym, "reg.module") && strings.Contains(joined(msgs), "nil-FS stub") {
				n++
			}
		}
		return n
	}
	if n := count("0.17.0-dev"); n != 0 {
		t.Errorf("stubs are allowed while VERSION ends in -dev: %d", n)
	}
	if n := count("0.17.0"); n != 3 {
		t.Errorf("the omitted, nil and converted-nil stubs must be reported in a release: %d", n)
	}
}

func TestG16Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	version, err := archtest.ReleaseVersion(ws.Root)
	if err != nil {
		t.Fatal(err)
	}
	assertWorkspaceClean(t, archtest.CheckG16(ws, archtest.DefaultConfig(), version), archtest.G16Exemptions())
}
