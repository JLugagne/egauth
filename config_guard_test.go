package egauth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/configcheck"
)

type guardRoot struct {
	name      string
	typ       reflect.Type
	prefix    []string
	full      func(t *testing.T) reflect.Value
	check     func(t *testing.T, root reflect.Value) error
	resolve   func(root reflect.Value) (*configcheck.Resolved, []*configcheck.Error)
	options   func(t *testing.T) configcheck.Options
	setModule func(t *testing.T, root reflect.Value, path string, on bool)
}

func configRoot(root reflect.Value) egauth.Config[struct{}] {
	return root.Interface().(egauth.Config[struct{}])
}

var guardRoots = []guardRoot{
	{
		name: "Config",
		typ:  reflect.TypeFor[egauth.Config[struct{}]](),
		prefix: []string{
			"Storage.", "Policy.", "Pages.", "Modules.Password.", "Modules.Passkey.", "Modules.OAuth.",
			"Modules.External.", "Modules.MFA.", "Modules.APIKeys.",
		},
		full: func(t *testing.T) reflect.Value {
			cfg := fullConfig(t)
			return reflect.ValueOf(&cfg).Elem()
		},
		check: func(t *testing.T, root reflect.Value) error { return newErr(t, configRoot(root)) },
		resolve: func(root reflect.Value) (*configcheck.Resolved, []*configcheck.Error) {
			return egauth.Resolve(configRoot(root))
		},
		options: func(t *testing.T) configcheck.Options { return egauth.ConfigOptions(fullConfig(t)) },
		setModule: func(t *testing.T, root reflect.Value, path string, on bool) {
			setModule(t, root.Addr().Interface().(*egauth.Config[struct{}]), path, on)
		},
	},
}

func forEachGuardRoot(t *testing.T, run func(t *testing.T, root guardRoot)) {
	for _, root := range guardRoots {
		t.Run(root.name, func(t *testing.T) {
			require.True(t, root.full != nil && root.check != nil && root.resolve != nil && root.options != nil && root.setModule != nil,
				"guardRoots entry %s needs every hook so the G5 variants run on its fields", root.name)
			require.Equal(t, root.typ, root.full(t).Type(), "full of %s builds another type", root.name)
			run(t, root)
		})
	}
}

func TestG05EveryTaggedStructIsReachedFromARoot(t *testing.T) {
	reached := map[string]bool{}
	for _, root := range guardRoots {
		reachStructs(root.typ, reached)
	}
	tagged := taggedStructs(t)
	require.NotEmpty(t, tagged)
	for _, name := range tagged {
		require.True(t, reached[name],
			"%s holds egauth tags but no guardRoots entry reaches it: add it (for example ResourceConfig) to guardRoots", name)
	}
}

func reachStructs(t reflect.Type, seen map[string]bool) {
	for {
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			t = t.Elem()
			continue
		case reflect.Map:
			reachStructs(t.Key(), seen)
			t = t.Elem()
			continue
		}
		break
	}
	if t.Kind() != reflect.Struct {
		return
	}
	pkg := reflect.TypeFor[egauth.Modules]().PkgPath()
	if t.PkgPath() == pkg {
		name, _, _ := strings.Cut(t.Name(), "[")
		if seen[name] {
			return
		}
		seen[name] = true
	}
	for i := range t.NumField() {
		if f := t.Field(i); f.IsExported() {
			reachStructs(f.Type, seen)
		}
	}
}

func taggedStructs(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !ts.Name.IsExported() {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			if slices.ContainsFunc(st.Fields.List, func(fl *ast.Field) bool {
				return fl.Tag != nil && strings.Contains(fl.Tag.Value, configcheck.TagName+`:"`)
			}) {
				out = append(out, ts.Name.Name)
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

func guardFields(t *testing.T, root guardRoot) ([]configcheck.Field, configcheck.Options) {
	t.Helper()
	opts := root.options(t)
	fields, errs := configcheck.Fields(root.typ, opts)
	require.Empty(t, errs, "the egauth tags of %s are inconsistent", root.name)
	return fields, opts
}

func TestG05EveryRootSpecIsConsistent(t *testing.T) {
	forEachGuardRoot(t, func(t *testing.T, root guardRoot) {
		fields, _ := guardFields(t, root)
		for _, p := range root.prefix {
			require.True(t, slices.ContainsFunc(fields, func(f configcheck.Field) bool { return strings.HasPrefix(f.Path, p) }),
				"no tagged field under %s: the guard does not reach that struct", p)
		}
	})
}

func TestG05DefaultsRegistryMatchesTagsOneToOne(t *testing.T) {
	forEachGuardRoot(t, func(t *testing.T, root guardRoot) {
		fields, opts := guardFields(t, root)
		var tagged []string
		for _, f := range fields {
			if f.Tag.Requirement == configcheck.Defaulted && !slices.Contains(tagged, f.Tag.Default) {
				tagged = append(tagged, f.Tag.Default)
			}
		}
		var registry []string
		for k := range opts.Defaults {
			registry = append(registry, k)
		}
		sort.Strings(tagged)
		sort.Strings(registry)
		require.Equal(t, registry, tagged)
	})
}

func TestG05EveryFieldVariantFailsAtItsPath(t *testing.T) {
	forEachGuardRoot(t, func(t *testing.T, root guardRoot) {
		fields, opts := guardFields(t, root)
		require.NotEmpty(t, fields)
		for _, f := range fields {
			t.Run(f.Path, func(t *testing.T) {
				require.NotContains(t, f.Path, "[]", "extend the G5 guard to reach fields nested in slices")
				zeroVariant(t, root, f)
				kindVariants(t, root, f)
				for _, p := range f.Tag.Predicates {
					predicateVariant(t, root, f, p, opts)
				}
			})
		}
	})
}

func TestG05GuardRootHooksSeeTheirOwnRoot(t *testing.T) {
	forEachGuardRoot(t, func(t *testing.T, root guardRoot) {
		require.NoError(t, root.check(t, root.full(t)), "the full %s must be valid", root.name)
		_, errs := root.resolve(root.full(t))
		require.Empty(t, errs)
	})
}

func fieldAt(t *testing.T, root reflect.Value, path string) reflect.Value {
	t.Helper()
	v := root
	for _, seg := range strings.Split(path, ".") {
		for v.Kind() == reflect.Pointer {
			require.False(t, v.IsNil(), "%s crosses a nil pointer in the full config", path)
			v = v.Elem()
		}
		v = v.FieldByName(seg)
		require.True(t, v.IsValid(), "%s does not resolve", path)
	}
	return v
}

type rootMod func(t *testing.T, root reflect.Value)

func variant(t *testing.T, g guardRoot, path string, set func(reflect.Value), mods ...rootMod) error {
	t.Helper()
	root := g.full(t)
	for _, m := range mods {
		m(t, root)
	}
	set(fieldAt(t, root, path))
	return g.check(t, root)
}

func modules(g guardRoot, paths []string, on bool) rootMod {
	return func(t *testing.T, root reflect.Value) {
		for _, m := range paths {
			g.setModule(t, root, m, on)
		}
	}
}

func zero(v reflect.Value) { v.Set(reflect.Zero(v.Type())) }

func zeroVariant(t *testing.T, g guardRoot, f configcheck.Field) {
	switch f.Tag.Requirement {
	case configcheck.Required:
		requireField(t, variant(t, g, f.Path, zero), f.Path)
	case configcheck.Optional:
		requireNoField(t, variant(t, g, f.Path, zero), f.Path)
	case configcheck.Defaulted:
		require.NoError(t, variant(t, g, f.Path, zero))
		root := g.full(t)
		zero(fieldAt(t, root, f.Path))
		r, errs := g.resolve(root)
		require.Empty(t, errs)
		require.True(t, r.Defaulted(f.Path))
		got, ok := r.Get(f.Path)
		require.True(t, ok)
		require.False(t, reflect.ValueOf(got).IsZero(), "default of %s is zero", f.Path)
	case configcheck.ModuleDependent:
		for _, m := range f.Tag.Modules {
			requireField(t, variant(t, g, f.Path, zero, modules(g, f.Tag.Modules, false), modules(g, []string{m}, true)), f.Path)
		}
		requireNoField(t, variant(t, g, f.Path, zero, modules(g, f.Tag.Modules, false)), f.Path)
	default:
		t.Fatalf("no G5 variant for requirement %v", f.Tag.Requirement)
	}
}

func kindVariants(t *testing.T, g guardRoot, f configcheck.Field) {
	switch {
	case f.Type.Kind() == reflect.String:
		requireField(t, variant(t, g, f.Path, func(v reflect.Value) { v.SetString(" \t ") }), f.Path)
	case f.Type.Kind() == reflect.Slice:
		requireField(t, variant(t, g, f.Path, func(v reflect.Value) { v.Set(reflect.MakeSlice(v.Type(), 0, 0)) }), f.Path)
		requireField(t, variant(t, g, f.Path, func(v reflect.Value) { v.Set(reflect.MakeSlice(v.Type(), 1, 1)) }), f.Path+"[0]")
	case f.Type == reflect.TypeFor[time.Duration]():
		requireField(t, variant(t, g, f.Path, func(v reflect.Value) { v.SetInt(-1) }), f.Path)
	}
}

func predicateVariant(t *testing.T, g guardRoot, f configcheck.Field, p configcheck.Predicate, opts configcheck.Options) {
	switch p.Kind {
	case configcheck.NonEmpty:
		requireField(t, variant(t, g, f.Path, zero), f.Path)
	case configcheck.Origin, configcheck.Path, configcheck.Token:
		requireField(t, variant(t, g, f.Path, func(v reflect.Value) { v.Set(reflect.ValueOf(invalidFor(t, p.Kind))) }), f.Path)
	case configcheck.Each:
		bad := func(v reflect.Value) {
			s := reflect.MakeSlice(v.Type(), 1, 1)
			s.Index(0).Set(reflect.ValueOf(invalidFor(t, p.Elem.Kind)))
			v.Set(s)
		}
		requireField(t, variant(t, g, f.Path, bad), f.Path+"[0]")
	case configcheck.OneOfPrimary:
		requireField(t, variant(t, g, f.Path, func(reflect.Value) {}, modules(g, opts.Primary, false)), f.Path)
	case configcheck.BoundMax:
		requireField(t, variant(t, g, f.Path, func(v reflect.Value) { v.SetInt(int64(p.Max + time.Nanosecond)) }), f.Path)
	case configcheck.BoundLE:
		over := func(v reflect.Value) {
			ref := fieldAt(t, g.full(t), strings.TrimSuffix(f.Path, lastSegment(f.Path))+p.Ref)
			v.SetInt(ref.Int() + int64(time.Hour))
		}
		requireField(t, variant(t, g, f.Path, over), f.Path)
	default:
		t.Fatalf("no G5 variant for predicate %v", p.Kind)
	}
}

func lastSegment(path string) string {
	return path[strings.LastIndexByte(path, '.')+1:]
}

func invalidFor(t *testing.T, k configcheck.PredicateKind) any {
	switch k {
	case configcheck.Origin:
		return "https://app.example.com/path"
	case configcheck.Path:
		return "auth"
	case configcheck.Token:
		return "Not A Token"
	case configcheck.Provider:
		return federation.Provider{Name: "Not A Name"}
	case configcheck.External:
		return egauth.ExternalFactor(factorStub{name: "Not A Name"})
	}
	t.Fatalf("no invalid value for predicate %v", k)
	return nil
}

func setModule(t *testing.T, c *egauth.Config[struct{}], path string, on bool) {
	t.Helper()
	switch path {
	case "Sessions.JWT":
		c.Sessions = egauth.Stateful()
		if on {
			c.Sessions = egauth.JWT(egauth.TenantKeys())
		}
		return
	case "Sessions.Stateful":
		c.Sessions = egauth.JWT(egauth.TenantKeys())
		if on {
			c.Sessions = egauth.Stateful()
		}
		return
	case "Sessions.JWT.TenantKeys":
		c.Sessions = egauth.JWT(egauth.StaticKeys(edSigner(t, "static")))
		if on {
			c.Sessions = egauth.JWT(egauth.TenantKeys())
		}
		return
	}
	template := fullModules()
	head, leaf, nested := strings.Cut(path, ".")
	ptr := reflect.ValueOf(&c.Modules).Elem().FieldByName(head)
	require.True(t, ptr.IsValid() && ptr.Kind() == reflect.Pointer, "module %s does not resolve", path)
	if !nested {
		ptr.Set(reflect.Zero(ptr.Type()))
		if on {
			ptr.Set(reflect.ValueOf(template).FieldByName(head))
		}
		return
	}
	if ptr.IsNil() {
		ptr.Set(reflect.New(ptr.Type().Elem()))
	}
	toggle := ptr.Elem().FieldByName(leaf)
	require.True(t, toggle.IsValid() && toggle.Kind() == reflect.Bool, "module %s does not resolve", path)
	toggle.SetBool(on)
}
