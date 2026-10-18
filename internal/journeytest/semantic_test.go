package journeytest_test

import (
	"errors"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
)

type exemption struct {
	Guard             string
	Symbol            string
	ReliesOnAbsenceOf string
	Variants          []string
	Probes            []string
}

const guardG7b = "G07b"

var exemptions = []exemption{
	{
		Guard: guardG7b, Symbol: "egauth.TenantFromRequest", ReliesOnAbsenceOf: "egauth.TenantFallback",
		Variants: []string{"Tenancy=TenantFromRequest"},
		Probes:   []string{"tenancy/"},
	},
	{
		Guard: guardG7b, Symbol: "egauth.ClaimsSource", ReliesOnAbsenceOf: "egauth.RoleFallback",
		Variants: []string{"Claims=AllRoles"},
		Probes:   []string{"facades/non-admin-", "facades/key-with-roles-beyond-the-callers"},
	},
	{
		Guard: guardG7b, Symbol: "egauth.Config.ExtraOrigins", ReliesOnAbsenceOf: "egauth.RelaxedOrigins",
		Variants: []string{"ExtraOrigins=EvilOrigin"},
		Probes:   []string{"csrf/cross-origin-with-cookie/", "csrf/cross-origin-referer-with-cookie/", "csrf/login-cross-origin-no-cookie/", "csrf/user-cross-origin-with-cookie/"},
	},
	{
		Guard: guardG7b, Symbol: "egauth.TrustedProxies", ReliesOnAbsenceOf: "egauth.TrustForwardedFromAnyone",
		Variants: []string{"Proxy=TrustedProxies"},
		Probes:   []string{"limits/forwarded-for-from-an-untrusted-peer-is-ignored"},
	},
}

const maxExemptions = 4

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "no go.mod above the test directory")
		dir = parent
	}
}

type symbols struct {
	names   map[string]bool
	members map[string]map[string]bool
}

func loadSymbols(t *testing.T, dir string) symbols {
	t.Helper()
	pkg, err := build.ImportDir(dir, 0)
	require.NoError(t, err)
	fset := token.NewFileSet()
	s := symbols{names: map[string]bool{}, members: map[string]map[string]bool{}}
	for _, name := range pkg.GoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					s.names[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					switch sp := sp.(type) {
					case *ast.TypeSpec:
						s.names[sp.Name.Name] = true
						s.members[sp.Name.Name] = membersOf(sp.Type)
					case *ast.ValueSpec:
						for _, n := range sp.Names {
							s.names[n.Name] = true
						}
					}
				}
			}
		}
	}
	return s
}

func membersOf(e ast.Expr) map[string]bool {
	out := map[string]bool{}
	switch x := e.(type) {
	case *ast.StructType:
		for _, f := range x.Fields.List {
			for _, n := range f.Names {
				out[n.Name] = true
			}
		}
	case *ast.InterfaceType:
		for _, f := range x.Methods.List {
			for _, n := range f.Names {
				out[n.Name] = true
			}
		}
	}
	return out
}

func packageDir(root, pkg string) string {
	if pkg == exportedPackage {
		return root
	}
	return filepath.Join(root, filepath.FromSlash(pkg))
}

func splitSymbol(sym string) (pkg, name, member string) {
	i := strings.LastIndex(sym, "/")
	head, tail := sym[:i+1], sym[i+1:]
	parts := strings.Split(tail, ".")
	pkg = head + parts[0]
	if len(parts) > 1 {
		name = parts[1]
	}
	if len(parts) > 2 {
		member = parts[2]
	}
	return pkg, name, member
}

func TestSemanticExemptionsAreTypedAndResolvable(t *testing.T) {
	require.Len(t, exemptions, maxExemptions, "adding or removing an exemption must raise or lower maxExemptions in the same diff")
	root := moduleRoot(t)
	for _, ex := range exemptions {
		require.Equal(t, guardG7b, ex.Guard)
		require.NotEmpty(t, ex.Variants)
		require.NotEmpty(t, ex.Probes)
		pkg, name, member := splitSymbol(ex.Symbol)
		syms := loadSymbols(t, packageDir(root, pkg))
		require.True(t, syms.names[name], "exemption symbol %s no longer resolves", ex.Symbol)
		if member != "" {
			require.True(t, syms.members[name][member] || resolvesByReflection(name, member), "exemption symbol %s no longer resolves", ex.Symbol)
		}
		for _, key := range ex.Variants {
			require.True(t, variantKeys(t)[key], "exemption %s names the variant %s, which the generator no longer produces", ex.Symbol, key)
		}
		apkg, aname, _ := splitSymbol(ex.ReliesOnAbsenceOf)
		require.False(t, loadSymbols(t, packageDir(root, apkg)).names[aname], "%s now exists: the exemption %s no longer holds", ex.ReliesOnAbsenceOf, ex.Symbol)
	}
}

func resolvesByReflection(name, member string) bool {
	switch name {
	case "Config":
		_, ok := reflect.TypeFor[egauth.Config[struct{}]]().FieldByName(member)
		return ok
	case "Auth":
		_, ok := reflect.TypeFor[*egauth.Auth[struct{}]]().MethodByName(member)
		return ok
	}
	return false
}

func variantKeys(t *testing.T) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	for _, v := range allVariants(t) {
		keys[v.key] = true
	}
	return keys
}

func variantsOfType(typ reflect.Type, wiring map[string]class) (out []variant, problems []string) {
	seen := map[string]bool{}
	for _, l := range leavesOf(typ, "") {
		vs, ok := variantsOf(l)
		_, wired := wiring[l.path]
		switch {
		case ok && wired:
			problems = append(problems, "leaf "+l.path+" is both classified and varied")
		case ok:
		case wired:
			continue
		default:
			problems = append(problems, "leaf "+l.path+" ("+l.typ.String()+") has no variant generator and is not classified: a new Config field must be varied by kind or classified")
			continue
		}
		for _, v := range vs {
			if seen[v.key] {
				problems = append(problems, "duplicate variant "+v.key)
				continue
			}
			seen[v.key] = true
			out = append(out, v)
		}
	}
	return out, problems
}

func allVariants(t *testing.T) []variant {
	t.Helper()
	vs, problems := variantsOfType(configType, classified)
	for _, p := range problems {
		t.Error(p)
	}
	return vs
}

func TestSemanticLeavesAreAllClassified(t *testing.T) {
	leaves := map[string]bool{}
	for _, l := range leavesOf(configType, "") {
		leaves[l.path] = true
	}
	for path := range classified {
		require.True(t, leaves[path], "classified path %s is not a leaf of Config", path)
	}
	vs := allVariants(t)
	require.NotEmpty(t, vs)
	kinds := map[variantKind]int{}
	for _, v := range vs {
		kinds[v.kind]++
	}
	for _, k := range []variantKind{vBool, vEnum, vFlag, vTime, vPolicy} {
		require.Positive(t, kinds[k], "no %s variant is generated", k)
	}
}

func TestSemanticOptOuts(t *testing.T) {
	full := exhaustive(t)
	golden := journeytest.NewWorld(t, journeytest.Settings{})
	goldenReport := journeytest.Collect(worldProbes(golden))
	goldenReport = append(goldenReport, journeytest.Collect(resourceProbes(journeytest.NewResourceWorld(t, journeytest.Settings{})))...)
	goldenReport.Check(t)
	goldenNames := goldenReport.Names()
	goldenServed := servedLabels(golden)

	used := map[string]bool{}
	var mu sync.Mutex
	sem := make(chan struct{}, 4)
	t.Run("variants", func(t *testing.T) {
		for _, v := range allVariants(t) {
			if v.golden || (!full && !v.short()) {
				continue
			}
			t.Run(v.key, func(t *testing.T) {
				t.Parallel()
				sem <- struct{}{}
				defer func() { <-sem }()
				w, err := journeytest.BuildWorld(t, settingsOf(v.opts))
				if err != nil {
					var ce *egauth.ConfigError
					require.ErrorAs(t, err, &ce, "variant %s failed outside New validation: %v", v.key, err)
					t.Logf("New rejects %s: %v", v.key, ce)
					return
				}
				optOuts := len(w.Auth.Posture().OptOuts) > 0
				require.Equal(t, v.kind == vFlag, optOuts, "variant %s: the Posture must list an opt-out exactly for Insecure variants", v.key)
				if !full && v.kind == vFlag {
					return
				}
				rep := journeytest.Collect(worldProbes(w))
				if w.Config.Transport != egauth.Cookies {
					rw, err := journeytest.BuildResourceWorld(t, settingsOf(v.opts))
					var ce *egauth.ConfigError
					switch {
					case errors.As(err, &ce):
						t.Logf("New rejects %s for the resource server's Auth: %v", v.key, ce)
					case err != nil:
						t.Fatalf("variant %s: the resource world failed outside New validation: %v", v.key, err)
					default:
						rep = append(rep, journeytest.Collect(resourceProbes(rw))...)
					}
				}
				t.Logf("%s: %d probes, %d failed", v.key, len(rep), len(rep.Failed()))
				mark := func(symbol string) {
					mu.Lock()
					defer mu.Unlock()
					used[symbol] = true
				}
				for _, f := range unexplained(v.key, optOuts, rep, mark) {
					t.Errorf("variant %s weakens probe %s (want %s, got %s) without New rejecting it, an Insecure field, or a typed exemption", v.key, f.Name, f.Want, f.Got)
				}
				facts := variantFacts{key: v.key, optOuts: optOuts, transport: w.Config.Transport, tenancy: w.Settings.Tenancy, lost: lostLabels(goldenServed, servedLabels(w))}
				for _, name := range vanished(facts, goldenNames, rep, mark) {
					t.Errorf("variant %s silently drops probe %s: a probe may disappear only when the variant unmounts its endpoint through a module, selects another transport or tenancy, sets an Insecure field, or carries a typed exemption", v.key, name)
				}
			})
		}
	})
	if full {
		for _, ex := range exemptions {
			require.True(t, used[ex.Symbol], "exemption %s explains no probe any more: remove it and lower maxExemptions", ex.Symbol)
		}
	}
}

func unexplained(variantKey string, optOuts bool, rep journeytest.Report, markUsed func(symbol string)) journeytest.Report {
	var out journeytest.Report
	for _, f := range rep.Failed() {
		if f.Control || optOuts {
			continue
		}
		if i := exemptionFor(variantKey, f.Name); i >= 0 {
			markUsed(exemptions[i].Symbol)
			continue
		}
		out = append(out, f)
	}
	return out
}

type variantFacts struct {
	key       string
	optOuts   bool
	transport egauth.Transport
	tenancy   journeytest.Tenancy
	lost      []string
}

func servedLabels(w *journeytest.World) map[string]bool {
	out := map[string]bool{}
	for _, tg := range newEnv(w).targets {
		out[tg.label()] = true
	}
	return out
}

func lostLabels(golden, variant map[string]bool) []string {
	var out []string
	for l := range golden {
		if !variant[l] {
			out = append(out, l)
		}
	}
	return out
}

var (
	cookieOnlyProbes = []string{"redirects//oauth/idp/link/", "csrf/user-cross-site-get-with-valid-cookie/", "csrf/user-same-origin-get-with-valid-cookie/", "tenancy/oauth-state-of-another-tenant"}
	bearerOnlyProbes = []string{"tenancy/mfa-flow-handle-of-another-tenant", "tenancy/oauth-exchange-handle-of-another-tenant", "ceremony-binding/oauth-exchange-", "resource-server/"}
)

func hasAnyPrefix(name string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(name, p) })
}

func (f variantFacts) transportExplains(name string) bool {
	switch f.transport {
	case egauth.Bearer:
		return strings.Contains(name+"/", "/cookie/") || hasAnyPrefix(name, cookieOnlyProbes)
	case egauth.Cookies:
		return strings.Contains(name+"/", "/bearer/") || hasAnyPrefix(name, bearerOnlyProbes)
	}
	return false
}

var moduleGatedProbes = map[string][]string{
	"Modules.LoginCode.Email":            {"tenancy/code-handle-of-another-tenant/email"},
	"Modules.LoginCode.SMS":              {"tenancy/code-handle-of-another-tenant/sms"},
	"Modules.Verification.Email":         {"tenancy/email-change-token-"},
	"Modules.Verification.RecoveryEmail": {"tenancy/recovery-email-token-"},
	"Modules.Verification.Phone":         {"tenancy/code-handle-of-another-tenant/sms"},
	"Modules.MFA.":                       {"tenancy/mfa-flow-handle-of-another-tenant"},
	"Modules.MagicLink.":                 {"tenancy/magic-link-token-", "ceremony-binding/magic-link-"},
	"Modules.Password.":                  {"tenancy/password-reset-token-", "tenancy/registration-token-"},
	"Modules.OAuth.":                     {"tenancy/oauth-state-", "tenancy/oauth-exchange-", "ceremony-binding/oauth-callback-", "ceremony-binding/oauth-exchange-"},
	"Modules.APIKeys.":                   {"facades/api-key-caller-on-a-facade", "credential-kind/"},
}

func (f variantFacts) moduleExplains(name string) bool {
	for module, probes := range moduleGatedProbes {
		if strings.HasPrefix(f.key, module) && hasAnyPrefix(name, probes) {
			return true
		}
	}
	return false
}

func (f variantFacts) mountingExplains(name string) bool {
	if !strings.HasPrefix(f.key, "Modules.") && !strings.HasPrefix(f.key, "Sessions=") {
		return false
	}
	return slices.ContainsFunc(f.lost, func(label string) bool {
		_, path, _ := strings.Cut(label, " ")
		return strings.HasSuffix(name, label) || strings.HasPrefix(name, "redirects/"+strings.TrimPrefix(path, "/auth")+"/")
	})
}

func vanished(f variantFacts, golden []string, rep journeytest.Report, markUsed func(symbol string)) []string {
	present := rep.ByName()
	var out []string
	for _, name := range golden {
		if _, ok := present[name]; ok || f.optOuts || f.transportExplains(name) || f.mountingExplains(name) || f.moduleExplains(name) {
			continue
		}
		if f.tenancy == journeytest.Single && strings.HasPrefix(name, "tenancy/") {
			continue
		}
		if i := exemptionFor(f.key, name); i >= 0 {
			markUsed(exemptions[i].Symbol)
			continue
		}
		out = append(out, name)
	}
	return out
}

func exemptionFor(variantKey, probe string) int {
	for i, ex := range exemptions {
		if slices.Contains(ex.Variants, variantKey) && slices.ContainsFunc(ex.Probes, func(p string) bool { return strings.HasPrefix(probe, p) }) {
			return i
		}
	}
	return -1
}

func TestSemanticGuardRejectsAnUnexplainedWeakening(t *testing.T) {
	trust := journeytest.Settings{}.Configure(func(c *egauth.Config[journeytest.Claims]) { c.ExtraOrigins = []string{evil} })
	w := journeytest.NewWorld(t, trust)
	rep := journeytest.Collect(worldProbes(w))
	require.NotEmpty(t, rep.Failed(), "trusting a foreign origin must fail the CSRF probes")
	none := func(string) {}
	require.Empty(t, unexplained("ExtraOrigins=EvilOrigin", false, rep, none), "the typed exemption explains it")
	require.NotEmpty(t, unexplained("RelaxedOrigins=flipped", false, rep, none), "a future RelaxedOrigins bool has no exemption, so it must fail whatever its name")
	require.Empty(t, unexplained("RelaxedOrigins=flipped", true, rep, none), "an Insecure field explains it")
}

func TestSemanticGuardVariesAFutureField(t *testing.T) {
	type future struct {
		RelaxedOrigins bool
		Mystery        string
	}
	vs, problems := variantsOfType(reflect.TypeFor[future](), nil)
	require.Len(t, vs, 1)
	require.Equal(t, "RelaxedOrigins=flipped", vs[0].key)
	require.Len(t, problems, 1)
	require.Contains(t, problems[0], "Mystery")
}

func TestSemanticGuardReachesLeavesInsideSliceElements(t *testing.T) {
	type provider struct {
		Name       string
		SkipIssuer bool
	}
	type oauth struct{ Providers []provider }
	type future struct{ OAuth *oauth }

	vs, problems := variantsOfType(reflect.TypeFor[future](), map[string]class{"OAuth.Providers[].Name": classWiring})
	require.Empty(t, problems)
	require.Len(t, vs, 1, "a bool added to a provider must be varied whatever its name")
	require.Equal(t, "OAuth.Providers[].SkipIssuer=flipped", vs[0].key)

	_, problems = variantsOfType(reflect.TypeFor[future](), nil)
	require.Len(t, problems, 1)
	require.Contains(t, problems[0], "OAuth.Providers[].Name")

	var f future
	fieldByPath(reflect.ValueOf(&f).Elem(), "OAuth.Providers[].SkipIssuer").SetBool(true)
	require.Len(t, f.OAuth.Providers, 1)
	require.True(t, f.OAuth.Providers[0].SkipIssuer)

	for _, l := range leavesOf(configType, "") {
		require.NotEqual(t, "Modules.OAuth.Providers", l.path, "Providers must be descended into, not classified as one wiring leaf")
	}
}

func TestSemanticGuardRejectsAVariantThatDropsProbes(t *testing.T) {
	golden := []string{
		"csrf/cross-origin-with-cookie/POST /auth/login",
		"tenancy/unresolvable-tenant/example.com/GET /app/profile",
		"sensitive/stale-primary-at/cookie/POST /auth/password/change",
		"control/valid-session-reads-its-session/bearer",
		"redirects//register/x",
	}
	rep := journeytest.Report{{Name: "control/valid-session-reads-its-session/bearer", Held: true}}
	none := func(string) {}

	silent := variantFacts{key: "Policy.Mystery=flipped", transport: egauth.CookiesAndBearer, tenancy: journeytest.Subdomain}
	require.ElementsMatch(t, append(append([]string{}, golden[:3]...), golden[4]), vanished(silent, golden, rep, none), "a variant that makes probes vanish for no stated reason is flagged")

	bearer := variantFacts{key: "Transport=Bearer", transport: egauth.Bearer, tenancy: journeytest.Subdomain}
	require.NotContains(t, vanished(bearer, golden, rep, none), golden[2], "dropping the cookie probes is what selecting Bearer means")
	require.Contains(t, vanished(bearer, golden, rep, none), golden[0])

	single := variantFacts{key: "Tenancy=SingleTenant", transport: egauth.CookiesAndBearer, tenancy: journeytest.Single}
	require.NotContains(t, vanished(single, golden, rep, none), golden[1])

	optOut := variantFacts{key: "Insecure.NoRateLimit=set", optOuts: true}
	require.Empty(t, vanished(optOut, golden, rep, none))

	unmounted := variantFacts{key: "Modules.Password.Registration=InviteOnly", lost: []string{"POST /auth/register", "POST /auth/login"}}
	got := vanished(unmounted, golden, rep, none)
	require.NotContains(t, got, golden[0], "an endpoint a module unmounts takes its probes with it")
	require.NotContains(t, got, golden[4])
	require.Contains(t, got, golden[1])

	notAModule := variantFacts{key: "Policy.Remember=Always", lost: []string{"POST /auth/login"}}
	require.Contains(t, vanished(notAModule, golden, rep, none), golden[0], "only a module or the backend may unmount an endpoint")
}
