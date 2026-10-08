package archtest_test

import (
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g01 = "github.com/JLugagne/egauth/tools/archtest/testdata/g01/root"

func TestG01FixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	vs := archtest.CheckG01(ws, cfg)
	assertFires(t, vs,
		[]string{
			g01 + ".BadHandler", g01 + ".BadHandlerFunc", g01 + ".BadMiddleware", g01 + ".Serve",
			g01 + ".ServeAfter", g01 + ".BadFunc", g01 + ".Surface.ServeX", g01 + ".Other.Mount",
			g01 + ".Reverse",
		},
		[]string{
			g01 + ".Routes.Handler", g01 + ".APIRoutes.Handler", g01 + ".PrincipalHandler",
			g01 + ".PrincipalHandler.ServeHTTP", g01 + ".Plain", g01 + "/internal/hidden.Handler",
		})
}

func TestG01Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG01(ws, archtest.DefaultConfig()), archtest.G01Exemptions())
}

func TestG01PromotedEmbeddedAndVars(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	vs := archtest.CheckG01(ws, cfg)
	assertFires(t, vs,
		[]string{
			g01 + ".Server.ServeHTTP", g01 + ".Server.Handler", g01 + ".Embeds.ServeHTTP",
			g01 + ".Mountable.ServeHTTP", g01 + ".Wrap", g01 + ".Default", g01 + ".Middleware", g01 + ".Chain",
		},
		[]string{g01 + ".Recorder.Header", g01 + ".Recorder.Write", g01 + ".Pattern", g01 + ".embedsPrivate.ServeHTTP"})
}

func TestG01HandlerShapedValuesOfUnexportedTypes(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	assertFires(t, archtest.CheckG01(ws, cfg),
		[]string{
			g01 + ".NewServer", g01 + ".NewAnon", g01 + ".DefaultServer", g01 + ".NewValueServer",
			g01 + ".server.ServeHTTP", g01 + ".builder.Mount",
		},
		[]string{g01 + ".unreachable.Mount"})
}

func TestG01UnnamedFuncsContainersAndFields(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	assertFires(t, archtest.CheckG01(ws, cfg),
		[]string{
			g01 + ".RawHandler", g01 + ".RawMiddleware", g01 + ".ErrHandler", g01 + ".HandlerSlice",
			g01 + ".HandlerMap", g01 + ".AnonIface", g01 + ".AnonStruct", g01 + ".Mux.H", g01 + ".handlers",
			g01 + ".RawVar", g01 + ".HandlerList", g01 + ".Opts.Wrap",
		},
		[]string{
			g01 + ".Plainer", g01 + ".Mux.Name", g01 + ".Opts.Name", g01 + ".Opts.Fn",
			g01 + ".NewOpts", g01 + ".Pattern",
		})
}

func TestG01InstantiatedGenerics(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	assertFires(t, archtest.CheckG01(ws, cfg),
		[]string{g01 + ".Getter.Get", g01 + ".Box.V", g01 + ".Pair.A", g01 + ".Pair.B", g01 + ".Slot.Cur", g01 + ".Current"},
		[]string{g01 + ".Safe.V", g01 + ".Count", g01 + ".Slot"})
}

func TestG01HandlersHandedThroughParameters(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	assertFires(t, archtest.CheckG01(ws, cfg),
		[]string{
			g01 + ".Fill", g01 + ".Expose", g01 + ".FillAll", g01 + ".Register", g01 + ".RegisterSink",
			g01 + ".SetHook",
		},
		[]string{g01 + ".Use", g01 + ".UseFunc", g01 + ".Take", g01 + ".Write", g01 + ".Sink.Put", g01 + ".Hook"})
}

func TestG01RequestAndWriterInAnyPosition(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	assertFires(t, archtest.CheckG01(ws, cfg), []string{g01 + ".NonAdjacent", g01 + ".Reverse"}, []string{g01 + ".Write"})
}

func TestG01SkipsMainPackages(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	assertFires(t, archtest.CheckG01(ws, cfg), nil,
		[]string{g01 + "/cmd/app.BuildServer", g01 + "/cmd/app.ServeIt", g01 + "/cmd/app.Exposed.H"})
}

func TestG01FieldsOfExternalTypes(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	assertFires(t, archtest.CheckG01(ws, cfg),
		[]string{g01 + ".HTTPServer", g01 + ".ServerBox.S"},
		[]string{g01 + ".HTTPClient"})
}

func TestG01LegacyExemptionDoesNotCoverNewExposure(t *testing.T) {
	ws, cfg := fixture(t, "g01")
	legacy := archtest.ExemptionList{Guard: archtest.G01, Entries: []archtest.Exemption{
		{Guard: archtest.G01, Symbol: g01 + "/legacy/...", RemovedBy: archtest.WP16},
	}}
	left := archtest.Filter(archtest.CheckG01(ws, cfg), legacy)
	assertFires(t, left, []string{g01 + "/legacy.Exposed.H"}, []string{g01 + "/legacy.Kept.H"})
}

func TestG01WorkspaceExamplesNeedNoExemption(t *testing.T) {
	ws := repoWorkspace(t)
	for _, v := range archtest.CheckG01(ws, archtest.DefaultConfig()) {
		if strings.HasPrefix(v.Pkg, archtest.ModulePath+"/examples/") {
			t.Errorf("package main exports are not public API: %s", v)
		}
	}
}
