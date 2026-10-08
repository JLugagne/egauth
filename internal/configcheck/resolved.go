package configcheck

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Resolved is a read-only view of a configuration after defaults were applied. Paths are dotted
// field names with [i] for slice and array elements, for example "Modules.APIKeys.Kinds[0]".
// During Validate the view is live: a default function sees the fields resolved before it.
type Resolved struct {
	root    reflect.Value
	applied map[string]bool
}

// Get returns the value at path. It reports false for an unknown or unexported field, an index out
// of range, or a path through a nil pointer.
func (r *Resolved) Get(path string) (any, bool) {
	if r == nil {
		return nil, false
	}
	v, ok := valueAt(r.root, path)
	if !ok || !v.CanInterface() {
		return nil, false
	}
	return v.Interface(), true
}

// Defaulted reports whether the field at path was filled from the defaults registry.
func (r *Resolved) Defaulted(path string) bool {
	return r != nil && r.applied[path]
}

// Applied returns the paths filled from the defaults registry, sorted.
func (r *Resolved) Applied() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.applied))
	for p := range r.applied {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func valueAt(v reflect.Value, path string) (reflect.Value, bool) {
	if path == "" || !v.IsValid() {
		return reflect.Value{}, false
	}
	for _, seg := range strings.Split(path, ".") {
		name, indices, ok := splitIndices(seg)
		if !ok {
			return reflect.Value{}, false
		}
		v = derefValue(v)
		if !v.IsValid() || v.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}
		f, ok := exportedField(v.Type(), name)
		if !ok {
			return reflect.Value{}, false
		}
		fv, err := v.FieldByIndexErr(f.Index)
		if err != nil {
			return reflect.Value{}, false
		}
		v = fv
		for _, i := range indices {
			v = derefValue(v)
			if !v.IsValid() || (v.Kind() != reflect.Slice && v.Kind() != reflect.Array) || i >= v.Len() {
				return reflect.Value{}, false
			}
			v = v.Index(i)
		}
	}
	return v, true
}

func splitIndices(seg string) (string, []int, bool) {
	open := strings.IndexByte(seg, '[')
	if open < 0 {
		return seg, nil, seg != ""
	}
	name, rest := seg[:open], seg[open:]
	var out []int
	for rest != "" {
		end := strings.IndexByte(rest, ']')
		if rest[0] != '[' || end < 0 {
			return "", nil, false
		}
		i, err := strconv.Atoi(rest[1:end])
		if err != nil || i < 0 {
			return "", nil, false
		}
		out = append(out, i)
		rest = rest[end+1:]
	}
	return name, out, name != ""
}

func derefValue(v reflect.Value) reflect.Value {
	for v.IsValid() && v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

func indexPath(path string, i int) string {
	return path + "[" + strconv.Itoa(i) + "]"
}
