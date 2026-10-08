package archtest_test

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

var (
	wsOnce sync.Once
	wsVal  *archtest.Workspace
	wsErr  error
)

func repoWorkspace(t *testing.T) *archtest.Workspace {
	t.Helper()
	wsOnce.Do(func() {
		root, err := archtest.FindRepoRoot()
		if err != nil {
			wsErr = err
			return
		}
		wsVal, wsErr = archtest.LoadWorkspace(root)
	})
	if wsErr != nil {
		t.Fatalf("load workspace: %v", wsErr)
	}
	return wsVal
}

func fixture(t *testing.T, name string) (*archtest.Workspace, archtest.Config) {
	t.Helper()
	ws, err := archtest.LoadFixture(toolsDir(t), "./archtest/testdata/"+name+"/...")
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return ws, archtest.Config{
		Root:     archtest.ModulePath + "/tools/archtest/testdata/" + name + "/root",
		UUIDPath: archtest.ModulePath + "/tools/archtest/testdata/uuid",
	}
}

func toolsDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func symbols(vs []archtest.Violation) map[string]bool {
	out := map[string]bool{}
	for _, v := range vs {
		for _, s := range v.Symbols {
			out[s] = true
		}
	}
	return out
}

func assertFires(t *testing.T, vs []archtest.Violation, want []string, mustNot []string) {
	t.Helper()
	got := symbols(vs)
	for _, w := range want {
		if !got[w] {
			t.Errorf("expected violation for %s; got %v", w, vs)
		}
	}
	for _, n := range mustNot {
		if got[n] {
			t.Errorf("unexpected violation for %s", n)
		}
	}
}

func assertWorkspaceClean(t *testing.T, vs []archtest.Violation, l archtest.ExemptionList) {
	t.Helper()
	for _, v := range archtest.Filter(vs, l) {
		t.Errorf("%s", v)
	}
}
