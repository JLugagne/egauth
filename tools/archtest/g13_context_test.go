package archtest_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g13 = "github.com/JLugagne/egauth/tools/archtest/testdata/g13/root"

func TestG13FixtureFires(t *testing.T) {
	ws, cfg := fixture(t, "g13")
	vs := archtest.CheckG13(ws, cfg)
	assertFires(t, vs,
		[]string{
			g13 + ".ActorFromContext", g13 + ".ContextWithActor", g13 + ".FromContext",
			g13 + ".Store.UserFromContext", g13 + ".Store.ContextWithUser",
		},
		[]string{
			g13 + ".contextWithPrivate", g13 + ".Contextual", g13 + ".FromContextual",
			g13 + "/internal/hidden.FromContext", g13 + "/internal/hidden.ContextWithX",
		})
}

func TestG13Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG13(ws, archtest.DefaultConfig()), archtest.G13Exemptions())
}

func TestG13FuncVars(t *testing.T) {
	ws, cfg := fixture(t, "g13")
	assertFires(t, archtest.CheckG13(ws, cfg),
		[]string{g13 + ".UserFromContext", g13 + ".ContextWithTenant"},
		[]string{g13 + ".userFromContextPrivate"})
}

func TestG13AccessorsReachedThroughExportedValues(t *testing.T) {
	ws, cfg := fixture(t, "g13")
	assertFires(t, archtest.CheckG13(ws, cfg),
		[]string{g13 + ".ctxAccessors.ActorFromContext", g13 + ".hiddenFuncs.TenantFromContext", g13 + ".Anon.ContextWithRole"},
		[]string{g13 + ".ctxAccessors.Plain", g13 + ".hiddenFuncs.Other", g13 + ".unreachableAccessors.RoleFromContext"})
}

func TestG13SkipsMainPackages(t *testing.T) {
	ws, cfg := fixture(t, "g13")
	assertFires(t, archtest.CheckG13(ws, cfg), nil, []string{g13 + "/cmd/app.ActorFromContext"})
}
