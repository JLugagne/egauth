package configcheck

import (
	"reflect"
	"regexp"
	"strings"
	"time"
)

type validator struct {
	o           Options
	r           *Resolved
	modulesType reflect.Type
	modules     reflect.Value
	errs        []*Error
	absent      map[string]bool
}

type node struct {
	v         reflect.Value
	path      string
	inModules bool
}

var indexRE = regexp.MustCompile(`\[\d+\]`)

// Validate checks the spec of *cfg with Fields, then applies registry defaults to zero Defaulted
// fields in place, then checks every field and returns every problem with its exact path. cfg must
// be a non-nil pointer to a struct. Defaults may have been applied even when problems are returned;
// the Resolved view is returned only when there is none.
//
// Beyond the tags, every tagged field obeys these rules: a whitespace-only string, an empty non-nil
// slice, a negative time.Duration and a zero slice element (a zero nested spec, or a pointer to a
// zero value, included) are problems; an interface holding a nil pointer counts as zero.
//
// An optional nested struct left zero is absent, like a nil optional pointer: the required fields
// inside it are not demanded, while its defaults are still applied and its module dependencies and
// predicates still checked.
func Validate(cfg any, o Options) (*Resolved, []*Error) {
	rv := reflect.ValueOf(cfg)
	if !rv.IsValid() || rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return nil, []*Error{{Problem: "Validate needs a non-nil pointer to a struct"}}
	}
	if _, errs := Fields(rv.Type(), o); len(errs) > 0 {
		return nil, errs
	}
	root := rv.Elem()
	vd := &validator{o: o, r: &Resolved{root: root, applied: map[string]bool{}}, absent: map[string]bool{}}
	if t, ok := typeAt(root.Type(), o.Modules); ok {
		vd.modulesType = derefType(t)
	}
	vd.applyDefaults(root, "", false)
	vd.modules, _ = valueAt(root, o.Modules)
	vd.check(root, "", false, false)
	if len(vd.errs) > 0 {
		return nil, vd.errs
	}
	return vd.r, nil
}

func (vd *validator) fail(field, problem string) {
	vd.errs = append(vd.errs, &Error{Field: field, Problem: problem})
}

func (vd *validator) applyDefaults(sv reflect.Value, path string, inModules bool) {
	t := sv.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		fv, fp := sv.Field(i), join(path, f.Name)
		raw, tagged := f.Tag.Lookup(TagName)
		if tagged {
			tag, _ := ParseTag(raw)
			if tag.Requirement == Defaulted && isUnset(fv) {
				vd.applyDefault(fv, fp, tag.Default)
			}
			if tag.Requirement == Optional && fv.Kind() == reflect.Struct && fv.IsZero() {
				vd.absent[fp] = true
			}
		}
		for _, c := range vd.children(fv, fp, !tagged && inModules) {
			vd.applyDefaults(c.v, c.path, c.inModules)
		}
	}
}

func (vd *validator) applyDefault(fv reflect.Value, fp, key string) {
	val := vd.o.Defaults[key](vd.r)
	if val == nil {
		vd.fail(fp, "default "+quote(key)+" produced nil")
		return
	}
	dv := reflect.ValueOf(val)
	if !dv.Type().AssignableTo(fv.Type()) {
		vd.fail(fp, "default "+quote(key)+" has type "+dv.Type().String()+", the field needs "+fv.Type().String())
		return
	}
	if isZero(dv) {
		vd.fail(fp, "default "+quote(key)+" produced a zero value")
		return
	}
	fv.Set(dv)
	vd.r.applied[fp] = true
}

func (vd *validator) check(sv reflect.Value, path string, inModules, absent bool) {
	t := sv.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		fv, fp := sv.Field(i), join(path, f.Name)
		raw, tagged := f.Tag.Lookup(TagName)
		if tagged {
			tag, _ := ParseTag(raw)
			vd.checkField(fv, fp, tag, sv, absent)
		}
		for _, c := range vd.children(fv, fp, !tagged && inModules) {
			vd.check(c.v, c.path, c.inModules, absent || vd.absent[fp])
		}
	}
}

func (vd *validator) checkField(fv reflect.Value, fp string, tag Tag, enclosing reflect.Value, absent bool) {
	switch {
	case fv.Kind() == reflect.String && fv.Len() > 0 && strings.TrimSpace(fv.String()) == "":
		vd.fail(fp, "is whitespace only")
		return
	case fv.Kind() == reflect.Slice && !fv.IsNil() && fv.Len() == 0:
		vd.fail(fp, "is an empty non-nil slice")
		return
	case fv.Type() == durationType && fv.Int() < 0:
		vd.fail(fp, "is negative")
		return
	}
	if isZero(fv) {
		switch tag.Requirement {
		case Required:
			if !absent {
				vd.fail(fp, "is required")
			}
		case ModuleDependent:
			if m := vd.firstEnabled(tag.Modules); m != "" {
				vd.fail(fp, "is required when "+m+" is enabled")
			}
		}
		return
	}
	for _, p := range tag.Predicates {
		vd.predicate(fv, fp, p, enclosing)
	}
	if fv.Kind() == reflect.Slice || fv.Kind() == reflect.Array {
		for i := range fv.Len() {
			if isZeroElem(fv.Index(i)) {
				vd.fail(indexPath(fp, i), "is a zero element")
			}
		}
	}
}

func (vd *validator) predicate(fv reflect.Value, fp string, p Predicate, enclosing reflect.Value) {
	if problem := vd.predicateProblem(fv, fp, p, enclosing); problem != "" {
		vd.fail(fp, problem)
	}
}

func (vd *validator) predicateProblem(fv reflect.Value, fp string, p Predicate, enclosing reflect.Value) string {
	switch p.Kind {
	case NonEmpty:
		if isZero(fv) {
			return "is empty"
		}
	case Origin:
		return originProblem(fv.String())
	case Path:
		return pathProblem(fv.String())
	case Token:
		return tokenProblem(fv.String())
	case Provider:
		return errText(vd.o.Provider(fv.Interface()))
	case External:
		return errText(vd.o.External(fv.Interface()))
	case OneOfPrimary:
		if vd.firstEnabled(vd.o.Primary) == "" {
			return "enables no primary module (one of " + strings.Join(vd.o.Primary, ", ") + ")"
		}
	case BoundMax:
		limit := p.Max
		if raised, ok := vd.o.Raised[indexRE.ReplaceAllString(fp, "[]")]; ok && raised > limit {
			limit = raised
		}
		return durationProblem(time.Duration(fv.Int()), limit, "the bound of "+limit.String())
	case BoundLE:
		other, ok := valueAt(enclosing, p.Ref)
		if !ok || other.Type() != durationType {
			return "bound=le path " + quote(p.Ref) + " is unset"
		}
		limit := time.Duration(other.Int())
		return durationProblem(time.Duration(fv.Int()), limit, p.Ref+" ("+limit.String()+")")
	case Each:
		for i := range fv.Len() {
			e := fv.Index(i)
			if !isZeroElem(e) {
				vd.predicate(e, indexPath(fp, i), *p.Elem, enclosing)
			}
		}
	}
	return ""
}

func durationProblem(d, limit time.Duration, name string) string {
	switch {
	case d <= 0:
		return "must be positive"
	case d > limit:
		return "exceeds " + name
	}
	return ""
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (vd *validator) firstEnabled(paths []string) string {
	for _, p := range paths {
		if vd.enabled(p) {
			return p
		}
	}
	return ""
}

func (vd *validator) enabled(path string) bool {
	if on, ok := vd.o.Switches[path]; ok {
		return on
	}
	cur := vd.modules
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		cur = derefValue(cur)
		if !cur.IsValid() || cur.Kind() != reflect.Struct {
			return false
		}
		f, ok := exportedField(cur.Type(), seg)
		if !ok {
			return false
		}
		fv, err := cur.FieldByIndexErr(f.Index)
		if err != nil {
			return false
		}
		if i < len(segs)-1 {
			cur = fv
			continue
		}
		switch fv.Kind() {
		case reflect.Bool:
			return fv.Bool()
		case reflect.Pointer:
			return !fv.IsNil()
		}
	}
	return false
}

func (vd *validator) children(fv reflect.Value, fp string, module bool) []node {
	fv = derefValue(fv)
	if !fv.IsValid() {
		return nil
	}
	if fv.Kind() == reflect.Slice || fv.Kind() == reflect.Array {
		var out []node
		for i := range fv.Len() {
			if n, ok := vd.structNode(derefValue(fv.Index(i)), indexPath(fp, i), module); ok {
				out = append(out, n)
			}
		}
		return out
	}
	if n, ok := vd.structNode(fv, fp, module); ok {
		return []node{n}
	}
	return nil
}

func (vd *validator) structNode(v reflect.Value, path string, module bool) (node, bool) {
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return node{}, false
	}
	if v.Type() == vd.modulesType {
		return node{v: v, path: path, inModules: true}, true
	}
	if module || isSpec(v.Type()) {
		return node{v: v, path: path}, true
	}
	return node{}, false
}

func isUnset(v reflect.Value) bool {
	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return true
		}
		switch e := v.Elem(); e.Kind() {
		case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
			return e.IsNil()
		}
		return false
	}
	return v.IsZero()
}

func isZeroElem(v reflect.Value) bool {
	if v.Kind() != reflect.Pointer {
		return isZero(v)
	}
	d := derefValue(v)
	return !d.IsValid() || isZero(d)
}

func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Slice:
		return v.Len() == 0
	case reflect.String:
		return strings.TrimSpace(v.String()) == ""
	}
	return isUnset(v)
}
