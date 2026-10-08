package archtest_test

import (
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g04 = "github.com/JLugagne/egauth/tools/archtest/testdata/g04/root"

func TestG04FixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g04")
	vs := archtest.CheckG04(ws, cfg)
	assertFires(t, vs,
		[]string{
			g04 + ".Holder.Err", g04 + ".MustParse", g04 + ".Boom", g04 + ".Nested",
		},
		[]string{
			g04 + ".holderPrivate.Err", g04 + ".MyErr.Err", g04 + ".Policy.MustChange", g04 + ".MustBe",
			g04 + ".quiet", g04 + ".Calm", g04 + ".MustInTest", g04 + ".helperMustPanic",
		})
	literals := 0
	for _, v := range vs {
		if strings.Contains(v.Msg, "string literal") {
			literals++
		}
	}
	if literals != 6 {
		t.Errorf("want 6 misconfiguration literals and concatenations (test files excluded), got %d: %v", literals, vs)
	}
}

func TestG04Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG04(ws, archtest.DefaultConfig()), archtest.G04Exemptions())
}

func TestG04ErrorShapedFields(t *testing.T) {
	ws, cfg := fixture(t, "g04")
	assertFires(t, archtest.CheckG04(ws, cfg),
		[]string{g04 + ".Batch.Errs", g04 + ".Outcome.Detail", g04 + ".Indexed.ByKey"}, nil)
}

func TestG04PackageLevelLiteralIsNamed(t *testing.T) {
	ws, cfg := fixture(t, "g04")
	vs := archtest.CheckG04(ws, cfg)
	assertFires(t, vs, []string{g04 + ".ErrNo", g04 + ".ErrMis", g04 + ".ErrNoX"}, nil)
	narrow := archtest.ExemptionList{Guard: archtest.G04, Entries: []archtest.Exemption{
		{Guard: archtest.G04, Symbol: g04 + ".ErrNo", RemovedBy: archtest.WP4},
	}}
	if before, after := countLiterals(vs), countLiterals(archtest.Filter(vs, narrow)); after != before-1 {
		t.Errorf("a symbol exemption must cover only its own literal, want %d left, got %d", before-1, after)
	}
}

func countLiterals(vs []archtest.Violation) int {
	n := 0
	for _, v := range vs {
		if strings.Contains(v.Msg, "string literal") {
			n++
		}
	}
	return n
}

func TestG04ErrorFieldOfReachableUnexportedStruct(t *testing.T) {
	ws, cfg := fixture(t, "g04")
	assertFires(t, archtest.CheckG04(ws, cfg),
		[]string{g04 + ".result.Err"},
		[]string{g04 + ".unreachableResult.Err", g04 + ".holderPrivate.Err"})
}

func TestG04ConcreteErrorFields(t *testing.T) {
	ws, cfg := fixture(t, "g04")
	assertFires(t, archtest.CheckG04(ws, cfg),
		[]string{g04 + ".Result.Cause", g04 + ".ValResult.Cause", g04 + ".IfaceResult.Cause", g04 + ".ListResult.Causes"},
		[]string{g04 + ".CleanResult.Name", g04 + ".CauseErr", g04 + ".ValueErr"})
}

func TestG04InstantiatedGenerics(t *testing.T) {
	ws, cfg := fixture(t, "g04")
	assertFires(t, archtest.CheckG04(ws, cfg),
		[]string{g04 + ".Res.V", g04 + ".Last.P"},
		[]string{g04 + ".Opt.V"})
}

func TestG04ConcatenatedLiterals(t *testing.T) {
	ws, cfg := fixture(t, "g04")
	assertFires(t, archtest.CheckG04(ws, cfg),
		[]string{g04 + ".notConf", g04 + ".ErrConcat", g04 + ".Describe"},
		[]string{g04 + ".prefix"})
}

func TestG04MustAndPanicOutsideFuncDecls(t *testing.T) {
	ws, cfg := fixture(t, "g04")
	assertFires(t, archtest.CheckG04(ws, cfg),
		[]string{
			g04 + ".MustParseVar", g04 + ".MustNamed", g04 + ".BoomVar", g04 + ".Built", g04 + ".Pair",
			g04 + ".Getter.MustGet", g04 + ".Hooks.MustRun",
		},
		[]string{
			g04 + ".MustOK", g04 + ".MustFlag", g04 + ".calmVar", g04 + ".pairHidden", g04 + ".Getter.MustHave",
			g04 + ".Getter.Get", g04 + ".Hooks.MustCheck", g04 + ".Hooks.mustHide", g04 + ".MustFunc",
		})
}
