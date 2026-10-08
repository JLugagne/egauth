package archtest_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g02 = "github.com/JLugagne/egauth/tools/archtest/testdata/g02/root"

func TestG02FixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g02")
	vs := archtest.CheckG02(ws, cfg)
	assertFires(t, vs,
		[]string{
			g02 + ".Option", g02 + ".ErrOption", g02 + ".Sealed",
			g02 + ".WithFoo", g02 + ".DisableBar", g02 + ".WithTimeout",
		},
		[]string{
			g02 + ".RouteOption", g02 + ".APIRouteOption", g02 + ".Open", g02 + ".Mutator",
			g02 + ".RequireMFA", g02 + ".AcceptAPI", g02 + ".RequireSealed", g02 + ".AcceptErr", g02 + ".Build",
		})
}

func TestG02Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG02(ws, archtest.DefaultConfig()), archtest.G02Exemptions())
}

func TestG02OptionSlices(t *testing.T) {
	ws, cfg := fixture(t, "g02")
	assertFires(t, archtest.CheckG02(ws, cfg),
		[]string{g02 + ".Presets", g02 + ".Defaults"},
		[]string{g02 + ".RequireAll"})
}

func TestG02AliasedUnexportedAndUnnamedOptions(t *testing.T) {
	ws, cfg := fixture(t, "g02")
	assertFires(t, archtest.CheckG02(ws, cfg),
		[]string{
			g02 + ".AliasOption", g02 + ".WithAlias", g02 + ".option", g02 + ".WithHidden",
			g02 + ".sealedOpt", g02 + ".WithSealed", g02 + ".Plainly", g02 + ".WithPlain",
		},
		[]string{g02 + ".RequireHidden", g02 + ".NewAliased", g02 + ".BuildHidden", g02 + ".Configure", g02 + ".unusedOption"})
}

func TestG02ConstructorsOfSealedOptionImplementations(t *testing.T) {
	ws, cfg := fixture(t, "g02")
	assertFires(t, archtest.CheckG02(ws, cfg),
		[]string{g02 + ".WithRole", g02 + ".Fresh"},
		[]string{g02 + ".RequireAnyRole", g02 + ".AcceptMustChange", g02 + ".NewUnrelated", g02 + ".ClaimRequirement"})
}

func TestG02StructWrappedOptions(t *testing.T) {
	ws, cfg := fixture(t, "g02")
	assertFires(t, archtest.CheckG02(ws, cfg),
		[]string{g02 + ".Opt", g02 + ".WithWrapped", g02 + ".hiddenOpt", g02 + ".WithHiddenWrapped"},
		[]string{g02 + ".RequireWrapped", g02 + ".Plain", g02 + ".NewPlain", g02 + ".Many"})
}

func TestG02InternalAndMainPackages(t *testing.T) {
	ws, cfg := fixture(t, "g02")
	assertFires(t, archtest.CheckG02(ws, cfg),
		[]string{g02 + "/internal/opts.Option", g02 + "/internal/opts.WithX"},
		[]string{g02 + "/cmd/app.Option", g02 + "/cmd/app.WithX"})
}

func TestG02ExportedMethodOptionInterfaces(t *testing.T) {
	ws, cfg := fixture(t, "g02")
	assertFires(t, archtest.CheckG02(ws, cfg),
		[]string{
			g02 + ".Applier", g02 + ".ErrApplier", g02 + ".WithApplied", g02 + ".WithErrApplied", g02 + ".WithImpl",
		},
		[]string{g02 + ".RequireApplied", g02 + ".Handler", g02 + ".Chain", g02 + ".WithHandler", g02 + ".NewApplied"})
}
