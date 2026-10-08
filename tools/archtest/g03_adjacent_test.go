package archtest_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g03 = "github.com/JLugagne/egauth/tools/archtest/testdata/g03/root"

func TestG03FixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g03")
	vs := archtest.CheckG03(ws, cfg)
	assertFires(t, vs,
		[]string{
			g03 + ".BadStrings", g03 + ".BadUUIDs", g03 + ".BadBytes", g03 + ".BadInts",
			g03 + ".BadMixedInts", g03 + ".BadTenants", g03 + ".BadResults", g03 + ".Svc.BadMethod",
			g03 + ".Resolver.Lookup", g03 + ".internalResolver.find",
		},
		[]string{
			g03 + ".GoodSeparated", g03 + ".GoodTyped", g03 + ".GoodContexts", g03 + ".GoodMixedInts",
			g03 + ".GoodResults", g03 + ".unexportedBad", g03 + ".Svc.unexportedMethod",
			g03 + ".hidden.Exported", g03 + ".Good.Lookup",
		})
}

func TestG03Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG03(ws, archtest.DefaultConfig()), archtest.G03Exemptions())
}

func TestG03FuncTypesFieldsAndVars(t *testing.T) {
	ws, cfg := fixture(t, "g03")
	vs := archtest.CheckG03(ws, cfg)
	assertFires(t, vs,
		[]string{
			g03 + ".UserResolver", g03 + ".Config.Resolve", g03 + ".Config.Nested", g03 + ".Config.Callback",
			g03 + ".Lookup", g03 + ".TakesResolver",
		},
		[]string{
			g03 + ".GoodResolver", g03 + ".Config.Fine", g03 + ".Config.resolve", g03 + ".lookupPrivate",
			g03 + ".GoodTakesResolver", g03 + ".unexportedResolver",
		})
}

func TestG03NonAdjacentResults(t *testing.T) {
	ws, cfg := fixture(t, "g03")
	assertFires(t, archtest.CheckG03(ws, cfg), []string{g03 + ".NonAdjacentResults"}, nil)
}

func TestG03FuncTypesBehindNamesContainersAndAliases(t *testing.T) {
	ws, cfg := fixture(t, "g03")
	assertFires(t, archtest.CheckG03(ws, cfg),
		[]string{
			g03 + ".Hooks.Resolve", g03 + ".Hooks.Ptr", g03 + ".Hooks.Many", g03 + ".Hooks.ByName",
			g03 + ".Hooks.Pipe", g03 + ".SetResolver", g03 + ".GetResolver", g03 + ".AliasResolver",
			g03 + ".svc.Do", g03 + ".AnonLookup",
		},
		[]string{
			g03 + ".Hooks.Fine", g03 + ".GoodAlias", g03 + ".svc.fine", g03 + ".unreachableSvc.Do",
			g03 + ".resolver",
		})
}

func TestG03TypeParameters(t *testing.T) {
	ws, cfg := fixture(t, "g03")
	assertFires(t, archtest.CheckG03(ws, cfg),
		[]string{
			g03 + ".GenericAdj", g03 + ".GenericUnion", g03 + ".GenericTenant", g03 + ".GenericNamedConstraint",
			g03 + ".GenericResults",
		},
		[]string{g03 + ".GenericAny", g03 + ".GenericComparable", g03 + ".GenericFloat"})
}

func TestG03InstantiatedGenerics(t *testing.T) {
	ws, cfg := fixture(t, "g03")
	assertFires(t, archtest.CheckG03(ws, cfg),
		[]string{g03 + ".Fn", g03 + ".Two.Both", g03 + ".Keyed.Find"},
		[]string{g03 + ".FloatFn", g03 + ".TakeFn", g03 + ".TakeFloatFn"})
}

func TestG03DefaultUUIDPathResolvesInWorkspace(t *testing.T) {
	ws := repoWorkspace(t)
	if ws.Package(archtest.DefaultConfig().UUIDPath) == nil {
		t.Fatalf("the core module no longer loads %s: update DefaultConfig", archtest.DefaultConfig().UUIDPath)
	}
}

func TestG03DefinedStringIntegerAndByteTypes(t *testing.T) {
	ws, cfg := fixture(t, "g03")
	assertFires(t, archtest.CheckG03(ws, cfg),
		[]string{g03 + ".Swap", g03 + ".Range", g03 + ".Blobs"},
		[]string{g03 + ".Flags", g03 + ".Mixed", g03 + "/cmd/app.Swap"})
}

func TestG03ByteArrays(t *testing.T) {
	ws, cfg := fixture(t, "g03")
	assertFires(t, archtest.CheckG03(ws, cfg),
		[]string{g03 + ".SwapRef", g03 + ".Digests", g03 + ".RawDigests"},
		[]string{g03 + ".Points", g03 + ".MixedRefs"})
}
