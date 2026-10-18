package configcheck

import (
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// Defaults is the defaults registry: a default=<key> tag names an entry, and every entry must be
// named by at least one tag. A function receives the configuration as resolved so far (fields are
// resolved depth first, in declaration order) and returns a value assignable to the field; a nil or
// zero value is a problem, never a silent zero.
type Defaults map[string]func(*Resolved) any

// Options carries what the tags cannot: the registry and the facts module paths resolve against.
type Options struct {
	Defaults Defaults
	// Modules is the dotted path of the field holding the modules struct; module= paths resolve
	// against its fields (a non-nil pointer or a true bool is enabled). Empty means no modules.
	Modules string
	// Primary lists the module paths that satisfy oneof_primary.
	Primary []string
	// Switches declares module paths that are not fields of the modules struct (for example
	// Sessions.JWT) and whether each is enabled. A path may not be both.
	Switches map[string]bool
	// Raised replaces the bound=max ceiling of the named fields when larger; it can only raise.
	Raised map[string]time.Duration
	// Provider and External implement the provider and external predicates.
	Provider func(any) error
	External func(any) error
}

// Error is one problem, located by the dotted field path (with [i] for slice elements, [] in
// Fields). Field is empty for a defaults registry problem.
type Error struct {
	Field   string
	Problem string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return "configcheck: " + e.Problem
	}
	return "configcheck: " + e.Field + ": " + e.Problem
}

// Field is a tagged field found by Fields.
type Field struct {
	Path string
	Type reflect.Type
	Tag  Tag
}

var durationType = reflect.TypeFor[time.Duration]()

type inspector struct {
	o           Options
	modules     reflect.Type
	usedDefault map[string]bool
	boundMax    map[string]bool
	stack       map[reflect.Type]bool
	fields      []Field
	errs        []*Error
}

// Fields parses every tag reachable from t (a struct or a pointer to one) and checks the spec
// itself: grammar, predicate and kind compatibility, module and bound=le paths, registry keys
// against tags and tags against the registry, Raised keys, and untagged fields. Nested structs are walked when an egauth tag is
// reachable from them; untagged fields are allowed only for bools and the toggles of the modules
// struct. A tag reachable only through an unexported field or a map value is a problem, since
// Validate could not enforce it. G5 drives its probes from the returned fields.
func Fields(t reflect.Type, o Options) ([]Field, []*Error) {
	in := &inspector{
		o:           o,
		usedDefault: map[string]bool{},
		boundMax:    map[string]bool{},
		stack:       map[reflect.Type]bool{},
	}
	if t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil, []*Error{{Problem: "the configuration type must be a struct"}}
	}
	in.resolveModulesType(t)
	in.walk(t, "", false)
	in.checkRegistry()
	return in.fields, in.errs
}

func (in *inspector) fail(field, problem string) {
	in.errs = append(in.errs, &Error{Field: field, Problem: problem})
}

func (in *inspector) resolveModulesType(root reflect.Type) {
	if in.o.Modules == "" {
		return
	}
	t := root
	for seg := range strings.SplitSeq(in.o.Modules, ".") {
		f, ok := exportedField(t, seg)
		if !ok {
			in.fail(in.o.Modules, "modules path does not resolve")
			return
		}
		t = derefType(f.Type)
	}
	if t.Kind() != reflect.Struct {
		in.fail(in.o.Modules, "modules path is not a struct")
		return
	}
	in.modules = t
}

func (in *inspector) walk(t reflect.Type, path string, inModules bool) {
	if in.stack[t] {
		return
	}
	in.stack[t] = true
	defer delete(in.stack, t)
	for f := range t.Fields() {
		fp := join(path, f.Name)
		raw, tagged := f.Tag.Lookup(TagName)
		if !f.IsExported() {
			switch {
			case tagged:
				in.fail(fp, "tag on an unexported field")
			case isSpec(f.Type):
				in.fail(fp, "unexported field holds egauth-tagged fields")
			}
			continue
		}
		if !tagged {
			if !inModules && f.Type.Kind() != reflect.Bool {
				in.fail(fp, "untagged field")
			}
			in.descend(f.Type, fp, inModules)
			continue
		}
		tag, err := ParseTag(raw)
		if err != nil {
			in.fail(fp, err.Error())
			continue
		}
		in.checkTag(fp, f.Type, tag, t)
		in.fields = append(in.fields, Field{Path: fp, Type: f.Type, Tag: tag})
		in.descend(f.Type, fp, false)
	}
}

func (in *inspector) descend(ft reflect.Type, fp string, module bool) {
	ft = derefType(ft)
	if ft.Kind() == reflect.Map && isSpec(ft.Elem()) {
		in.fail(fp, "map values cannot hold egauth-tagged fields")
		return
	}
	if ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
		ft, fp = derefType(ft.Elem()), fp+"[]"
	}
	if ft.Kind() != reflect.Struct {
		return
	}
	if ft == in.modules {
		in.walk(ft, fp, true)
		return
	}
	if module || isSpec(ft) {
		in.walk(ft, fp, false)
	}
}

func (in *inspector) checkTag(fp string, ft reflect.Type, tag Tag, enclosing reflect.Type) {
	switch tag.Requirement {
	case Defaulted:
		if _, ok := in.o.Defaults[tag.Default]; !ok {
			in.fail(fp, "default key "+quote(tag.Default)+" is missing from the defaults registry")
		}
		in.usedDefault[tag.Default] = true
	case ModuleDependent:
		for _, m := range tag.Modules {
			if problem := in.modulePathProblem(m); problem != "" {
				in.fail(fp, problem)
			}
		}
	}
	for _, p := range tag.Predicates {
		in.checkPredicate(fp, ft, p, enclosing)
	}
}

func (in *inspector) checkPredicate(fp string, ft reflect.Type, p Predicate, enclosing reflect.Type) {
	kind := ft.Kind()
	switch p.Kind {
	case NonEmpty:
		if kind != reflect.String && kind != reflect.Slice && kind != reflect.Array {
			in.fail(fp, "nonempty needs a string or a slice")
		}
	case Origin, Path, Token:
		if kind != reflect.String {
			in.fail(fp, p.Kind.String()+" needs a string")
		}
	case Provider:
		if in.o.Provider == nil {
			in.fail(fp, "provider predicate has no validator in Options")
		}
	case External:
		if in.o.External == nil {
			in.fail(fp, "external predicate has no validator in Options")
		}
	case OneOfPrimary:
		in.checkOneOfPrimary(fp)
	case BoundMax:
		if ft != durationType {
			in.fail(fp, "bound needs a time.Duration")
		}
		in.boundMax[fp] = true
	case BoundLE:
		if ft != durationType {
			in.fail(fp, "bound needs a time.Duration")
		}
		if rt, ok := typeAt(enclosing, p.Ref); !ok || rt != durationType {
			in.fail(fp, "bound=le path "+quote(p.Ref)+" does not resolve to a sibling time.Duration")
		}
	case Each:
		if kind != reflect.Slice && kind != reflect.Array {
			in.fail(fp, "each needs a slice or an array")
			return
		}
		in.checkPredicate(fp+"[]", ft.Elem(), *p.Elem, enclosing)
	}
}

func (in *inspector) checkOneOfPrimary(fp string) {
	if in.o.Modules == "" || fp != in.o.Modules {
		in.fail(fp, "oneof_primary is valid only on the modules field")
		return
	}
	if len(in.o.Primary) == 0 {
		in.fail(fp, "oneof_primary needs Options.Primary")
	}
	for _, m := range in.o.Primary {
		if problem := in.modulePathProblem(m); problem != "" {
			in.fail(fp, "primary "+problem)
		}
	}
}

func (in *inspector) modulePathProblem(path string) string {
	_, isSwitch := in.o.Switches[path]
	viaModules := in.modules != nil && moduleTypeResolves(in.modules, path)
	switch {
	case isSwitch && viaModules:
		return "module path " + quote(path) + " is both a modules field and a switch"
	case isSwitch || viaModules:
		return ""
	}
	return "module path " + quote(path) + " does not resolve"
}

func moduleTypeResolves(t reflect.Type, path string) bool {
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		f, ok := exportedField(t, seg)
		if !ok {
			return false
		}
		if i == len(segs)-1 {
			return f.Type.Kind() == reflect.Bool || (f.Type.Kind() == reflect.Pointer && f.Type.Elem().Kind() == reflect.Struct)
		}
		t = derefType(f.Type)
		if t.Kind() != reflect.Struct {
			return false
		}
	}
	return false
}

func (in *inspector) checkRegistry() {
	keys := make([]string, 0, len(in.o.Defaults))
	for k := range in.o.Defaults {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !in.usedDefault[k] {
			in.fail("", "defaults registry key "+quote(k)+" matches no tag")
		}
		if in.o.Defaults[k] == nil {
			in.fail("", "defaults registry key "+quote(k)+" has a nil function")
		}
	}
	raised := make([]string, 0, len(in.o.Raised))
	for k := range in.o.Raised {
		raised = append(raised, k)
	}
	sort.Strings(raised)
	for _, k := range raised {
		if !in.boundMax[k] {
			in.fail(k, "Options.Raised names a field without bound=max")
		}
	}
}

var specCache sync.Map

func isSpec(t reflect.Type) bool {
	if v, ok := specCache.Load(t); ok {
		return v.(bool)
	}
	found := reachesTag(t, map[reflect.Type]bool{})
	specCache.Store(t, found)
	return found
}

func reachesTag(t reflect.Type, seen map[reflect.Type]bool) bool {
	t = derefType(t)
	for t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		t = derefType(t.Elem())
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return false
	}
	seen[t] = true
	for f := range t.Fields() {
		if _, ok := f.Tag.Lookup(TagName); ok {
			return true
		}
		if reachesTag(f.Type, seen) {
			return true
		}
	}
	return false
}

func exportedField(t reflect.Type, name string) (reflect.StructField, bool) {
	if t.Kind() != reflect.Struct {
		return reflect.StructField{}, false
	}
	f, ok := t.FieldByName(name)
	if !ok || !f.IsExported() {
		return reflect.StructField{}, false
	}
	return f, true
}

func typeAt(t reflect.Type, path string) (reflect.Type, bool) {
	for seg := range strings.SplitSeq(path, ".") {
		f, ok := exportedField(derefType(t), seg)
		if !ok {
			return nil, false
		}
		t = f.Type
	}
	return t, true
}

func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
