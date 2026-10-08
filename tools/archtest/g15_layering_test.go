package archtest_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const g15 = "github.com/JLugagne/egauth/tools/archtest/testdata/g15/root"

func g15ByPkg(t *testing.T) ([]archtest.Violation, map[string][]string) {
	t.Helper()
	ws, cfg := fixture(t, "g15")
	vs := archtest.CheckG15(ws, cfg)
	byPkg := map[string][]string{}
	for _, v := range vs {
		byPkg[v.Pkg] = append(byPkg[v.Pkg], v.Msg)
	}
	return vs, byPkg
}

func TestG15FixtureFires(t *testing.T) {
	vs, byPkg := g15ByPkg(t)
	assertFires(t, vs,
		[]string{
			g15 + "/internal/core", g15 + "/internal/svc", g15 + "/lib", g15 + "/adapters/pgx",
			g15 + "/adapters/otel", g15 + "/event", g15 + "/kek",
		},
		[]string{
			g15 + "/memstore", g15 + "/egauthtest", g15 + "/principal", g15 + "/internal/redirect",
			g15 + "/store/ceremony", g15 + "/adapters/pgx/ok",
		})
	if len(byPkg[g15+"/lib"]) != 1 {
		t.Errorf("lib must be flagged once (the _test.go import is allowed): %v", byPkg[g15+"/lib"])
	}
	if len(byPkg[g15+"/adapters/otel"]) != 1 || !strings.Contains(byPkg[g15+"/adapters/otel"][0], "store") {
		t.Errorf("otel must be flagged only for store: %v", byPkg[g15+"/adapters/otel"])
	}
}

func TestG15CoreIsALeaf(t *testing.T) {
	_, byPkg := g15ByPkg(t)
	core := byPkg[g15+"/internal/core"]
	if len(core) != 4 {
		t.Fatalf("core must be flagged for internal/other, net/http, slog.Default and fmt.Println only: %v", core)
	}
	joined := strings.Join(core, "\n")
	if !strings.Contains(joined, "internal/other") || !strings.Contains(joined, "net/http") {
		t.Errorf("core findings must name internal/other and net/http: %v", core)
	}
}

func TestG15StoreContracts(t *testing.T) {
	_, byPkg := g15ByPkg(t)
	if s := byPkg[g15+"/store"]; len(s) != 1 || !strings.Contains(s[0], "internal/other") {
		t.Errorf("store must be flagged only for internal/other: %v", s)
	}
	leaky := strings.Join(byPkg[g15+"/store/leaky"], "\n")
	if len(byPkg[g15+"/store/leaky"]) != 2 || !strings.Contains(leaky, "internal/other") || !strings.Contains(leaky, "store/ceremony") {
		t.Errorf("a store contract may import only store, principal and event: %v", byPkg[g15+"/store/leaky"])
	}
}

func TestG15PgxAdapterLayer(t *testing.T) {
	_, byPkg := g15ByPkg(t)
	if m := byPkg[g15+"/adapters/pgx/mem"]; len(m) != 1 || !strings.Contains(m[0], "memstore") {
		t.Errorf("adapters/pgx must not import memstore: %v", m)
	}
}

func TestG15RootImportAllowancesArePinned(t *testing.T) {
	got := archtest.RootImportAllowances()
	want := []string{"memstore", "egauthtest", "internal/journeytest", "examples"}
	if !slices.Equal(got, want) {
		t.Fatalf("root import allowances must match DESIGN.md section 2.1 and the M11-03 brief: %v", got)
	}
}

func TestG15RootImportAllowancesMustResolve(t *testing.T) {
	ws, cfg := fixture(t, "g15")
	msgs := archtest.CheckRootImportAllowances(ws, cfg)
	joined := strings.Join(msgs, "\n")
	if len(msgs) != 1 || !strings.Contains(joined, "examples") {
		t.Fatalf("allowances without a package must be reported, present ones must not: %v", msgs)
	}
}

func TestG15Workspace(t *testing.T) {
	ws := repoWorkspace(t)
	assertWorkspaceClean(t, archtest.CheckG15(ws, archtest.DefaultConfig()), archtest.G15Exemptions())
}

func TestG15LeafLayerSubpackages(t *testing.T) {
	_, byPkg := g15ByPkg(t)
	for _, sub := range []string{"/kek/sub", "/event/sub", "/principal/sub"} {
		msgs := byPkg[g15+sub]
		if len(msgs) != 1 || !strings.Contains(msgs[0], "internal/other") {
			t.Errorf("%s is under a leaf layer and may not import internal/other: %v", sub, msgs)
		}
	}
	if msgs := byPkg[g15+"/internal/core/sub"]; len(msgs) != 1 || !strings.Contains(msgs[0], "net/http") {
		t.Errorf("internal/core/sub must be held to the core stdlib allowlist: %v", msgs)
	}
}

func TestG15StoreImplementations(t *testing.T) {
	_, byPkg := g15ByPkg(t)
	if msgs := byPkg[g15+"/store/x/memory"]; len(msgs) != 1 || !strings.Contains(msgs[0], "internal/other") {
		t.Errorf("a memory store may import only store contracts, principal, event, kek, signing and internal/clock: %v", msgs)
	}
	if msgs := byPkg[g15+"/store/x/storetest"]; len(msgs) != 1 || !strings.Contains(msgs[0], "memstore") {
		t.Errorf("a storetest package may not import memstore: %v", msgs)
	}
}

func TestG15CoreRestrictsLoggingAndPrinting(t *testing.T) {
	_, byPkg := g15ByPkg(t)
	joined := strings.Join(byPkg[g15+"/internal/core"], "\n")
	for _, want := range []string{"log/slog.Default", "fmt.Println"} {
		if !strings.Contains(joined, want) {
			t.Errorf("internal/core use of %s must be flagged: %v", want, joined)
		}
	}
	for _, allowed := range []string{"fmt.Sprintf", "slog.GroupValue", "slog.String", "log/slog.Value"} {
		if strings.Contains(joined, allowed) {
			t.Errorf("internal/core use of %s is a pure value helper and must pass: %v", allowed, joined)
		}
	}
}

func TestG15RootAndInternalMayNotImportHigherLayers(t *testing.T) {
	_, byPkg := g15ByPkg(t)
	root := strings.Join(byPkg[g15], "\n")
	for _, want := range []string{"store/x/memory", "adapters/otel", "webauthntest"} {
		if !strings.Contains(root, want) {
			t.Errorf("root import of %s must be flagged: %v", want, byPkg[g15])
		}
	}
	if len(byPkg[g15]) != 3 {
		t.Errorf("root may import internal/*, principal and store contracts: %v", byPkg[g15])
	}
	hidden := byPkg[g15+"/internal/hidden"]
	if j := strings.Join(hidden, "\n"); len(hidden) != 2 || !strings.Contains(j, "store/x/memory") || !strings.Contains(j, "store/x/storetest") {
		t.Errorf("internal/* may not import store implementations or storetest: %v", hidden)
	}
	if h := byPkg[g15+"/internal/harness"]; len(h) != 2 {
		t.Errorf("an internal package other than journeytest may not import egauthtest or memstore: %v", h)
	}
	if j := byPkg[g15+"/internal/journeytest"]; len(j) != 0 {
		t.Errorf("internal/journeytest is the typed harness allowance: %v", j)
	}
}

func TestG15HarnessImportAllowancesArePinned(t *testing.T) {
	got := archtest.HarnessImportAllowances()
	if len(got) != 1 || got["internal/journeytest"] == nil || !slices.Equal(got["internal/journeytest"], []string{"egauthtest", "memstore", "webauthntest"}) {
		t.Fatalf("harness allowances must match DESIGN.md sections 2.1 and 9.4: %v", got)
	}
}

func TestG15MemstoreEgauthtestAndJourneytestEdges(t *testing.T) {
	_, byPkg := g15ByPkg(t)
	if msgs := byPkg[g15+"/memstore/leak"]; len(msgs) != 1 || !strings.Contains(msgs[0], "internal/other") {
		t.Errorf("memstore may not import internal packages: %v", msgs)
	}
	if msgs := byPkg[g15+"/egauthtest/leak"]; len(msgs) != 1 || !strings.Contains(msgs[0], "memstore") {
		t.Errorf("egauthtest may not import memstore: %v", msgs)
	}
	if msgs := byPkg[g15+"/internal/uses"]; len(msgs) != 1 || !strings.Contains(msgs[0], "journeytest") {
		t.Errorf("internal/journeytest is importable from _test.go files only: %v", msgs)
	}
	if msgs := byPkg[g15+"/lib/journey"]; len(msgs) != 1 || !strings.Contains(msgs[0], "journeytest") {
		t.Errorf("internal/journeytest is importable from _test.go files only: %v", msgs)
	}
	for _, clean := range []string{"/memstore", "/egauthtest", "/internal/journeytest"} {
		if msgs := byPkg[g15+clean]; len(msgs) != 0 {
			t.Errorf("%s imports only what DESIGN.md section 2.1 allows: %v", clean, msgs)
		}
	}
}

func TestG15JourneytestMayDriveWebauthntest(t *testing.T) {
	_, byPkg := g15ByPkg(t)
	if j := byPkg[g15+"/internal/journeytest"]; len(j) != 0 {
		t.Errorf("internal/journeytest drives PasskeyDiscoverable through webauthntest: %v", j)
	}
	if h := byPkg[g15+"/internal/harness"]; len(h) != 2 {
		t.Errorf("only internal/journeytest is the harness: %v", h)
	}
}
