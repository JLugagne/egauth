package repoguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var workflowExpr = regexp.MustCompile(`\$\{\{\s*([^}]*?)\s*\}\}`)

func runnerOwnedExpr(expr string) bool {
	return strings.HasPrefix(expr, "runner.") || expr == "job.status"
}

func TestWorkflowRunBlocksTakeNoInterpolatedValues(t *testing.T) {
	dir := filepath.Join(repoRoot(t), ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	checked := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		checked++
		for _, p := range runInterpolations(string(raw)) {
			t.Errorf(".github/workflows/%s:%d interpolates ${{ %s }} into a run script; pass it through env and quote it", e.Name(), p.line, p.expr)
		}
	}
	if checked == 0 {
		t.Fatal("guard found no workflow files")
	}
}

func TestWorkflowGuardSeesAnInterpolatedRunLine(t *testing.T) {
	src := "jobs:\n  a:\n    steps:\n      - env:\n          TAG: ${{ steps.tag.outputs.tag }}\n        run: make sbom VERSION=${{ steps.tag.outputs.tag }}\n      - run: |\n          echo \"$TAG\"\n          echo ${{ github.event.release.tag_name }}\n          echo ${{ job.status }} ${{ runner.temp }}\n"
	got := runInterpolations(src)
	if len(got) != 2 || got[0].line != 6 || got[1].line != 9 {
		t.Fatalf("runInterpolations = %+v, want lines 6 and 9", got)
	}
}

type interpolation struct {
	line int
	expr string
}

func runInterpolations(src string) []interpolation {
	var out []interpolation
	inRun, runIndent := false, 0
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		if inRun && trimmed != "" && indent <= runIndent {
			inRun = false
		}
		key := strings.TrimPrefix(trimmed, "- ")
		if strings.HasPrefix(key, "run:") {
			inRun, runIndent = true, indent
		}
		if !inRun {
			continue
		}
		for _, m := range workflowExpr.FindAllStringSubmatch(line, -1) {
			if !runnerOwnedExpr(m[1]) {
				out = append(out, interpolation{line: i + 1, expr: m[1]})
			}
		}
	}
	return out
}

func TestSbomTargetReadsVersionOnlyFromTheEnvironment(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	mk := string(raw)
	if !strings.Contains(mk, "sbom: override export VERSION := $(value VERSION)") {
		t.Error("the sbom target must export VERSION unexpanded, so a $(...) in it is never evaluated by make")
	}
	recipe := targetRecipe(mk, "sbom")
	if recipe == "" {
		t.Fatal("Makefile has no sbom recipe")
	}
	if strings.Contains(recipe, "$(VERSION)") {
		t.Error("the sbom recipe substitutes $(VERSION) into the shell text; use \"$$VERSION\"")
	}
	if !strings.Contains(recipe, "grep -Eq '^v(0|[1-9][0-9]*)") {
		t.Error("the sbom recipe must validate VERSION as a semver tag before using it")
	}
}

func targetRecipe(mk, target string) string {
	var b strings.Builder
	in := false
	for line := range strings.SplitSeq(mk, "\n") {
		switch {
		case line == target+":":
			in = true
		case in && strings.HasPrefix(line, "\t"):
			b.WriteString(line + "\n")
		case in:
			return b.String()
		}
	}
	return b.String()
}
